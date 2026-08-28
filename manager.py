#!/usr/bin/env python3

import json
import os
import shlex
import subprocess
import tempfile
import shutil
import socket
import time
import re
import urllib.request
from html.parser import HTMLParser
from datetime import datetime, timezone

from monitor_heard import fetch_heard, fetch_icon
from monitor_raw import fetch_raw
from monitor_traffic import (
    traffic_subscribe,
    traffic_unsubscribe,
    traffic_status,
    sse_encode
)
from monitor_messages import fetch_messages

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
    session,
    Response,
    stream_with_context
)

from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash


BASE_DIR = "/opt/dxlaprs-manager"
CONFIG_FILE = os.path.join(BASE_DIR, "data", "config.json")
ACTIVE_CONFIG_FILE = os.path.join(BASE_DIR, "data", "active_config.json")
OPTIONS_FILE = os.path.join(BASE_DIR, "data", "options.json")
BACKUP_DIR = os.path.join(BASE_DIR, "backup")

SECTIONS = [
    "general",
    "aprsis",
    "radio",
    "beacon",
    "heard",
    "tcp",
    "web",
    "srtm",
    "logging",
    "advanced"
]

app = Flask(__name__)
app.secret_key = "dxlaprs-manager-local"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_config():
    return load_json(CONFIG_FILE)


def load_active_config():

    if os.path.isfile(ACTIVE_CONFIG_FILE):
        return load_json(ACTIVE_CONFIG_FILE)

    return load_config()


def admin_authenticated():
    return session.get("admin_authenticated") is True


def admin_required(function):

    @wraps(function)
    def wrapped(*args, **kwargs):

        if not admin_authenticated():

            session["admin_next"] = request.path

            return redirect(
                url_for("admin_login")
            )

        return function(*args, **kwargs)

    return wrapped


def ensure_admin_config(cfg):

    admin = cfg.setdefault(
        "admin",
        {}
    )

    admin.setdefault(
        "username",
        "admin"
    )

    # Primo avvio: password predefinita "admin".
    # Nel JSON viene salvato soltanto l'hash.
    if not admin.get("password_hash"):

        admin["password_hash"] = generate_password_hash(
            "admin"
        )

        return True

    return False


def load_options():
    return load_json(OPTIONS_FILE)


def save_config(cfg):
    os.makedirs(BACKUP_DIR, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = os.path.join(
        BACKUP_DIR,
        f"config-{stamp}.json"
    )

    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as src:
            old = src.read()

        with open(backup, "w", encoding="utf-8") as dst:
            dst.write(old)

    directory = os.path.dirname(CONFIG_FILE)

    fd, tmp = tempfile.mkstemp(
        prefix="config-",
        suffix=".json",
        dir=directory
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                cfg,
                f,
                indent=2,
                ensure_ascii=False
            )
            f.write("\n")

        os.replace(tmp, CONFIG_FILE)

    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)

    if os.path.exists(backup):
        return backup

    return None



class ConnectionsParser(HTMLParser):
    def __init__(self):
        super().__init__()

        self.in_connections_table = False
        self.in_row = False
        self.in_cell = False

        self.current_row = []
        self.current_cell = []

        self.headers = []
        self.rows = []

    def handle_starttag(self, tag, attrs):

        attrs = dict(attrs)

        if tag.lower() == "table":
            table_id = attrs.get("id", "")

            if table_id == "connections":
                self.in_connections_table = True

        if not self.in_connections_table:
            return

        if tag.lower() == "tr":
            self.in_row = True
            self.current_row = []

        elif tag.lower() in ("td", "th") and self.in_row:
            self.in_cell = True
            self.current_cell = []

    def handle_data(self, data):

        if self.in_cell:
            self.current_cell.append(data)

    def handle_endtag(self, tag):

        if not self.in_connections_table:
            return

        if tag.lower() in ("td", "th") and self.in_cell:

            text = " ".join(
                "".join(self.current_cell).split()
            )

            self.current_row.append(text)

            self.current_cell = []
            self.in_cell = False

        elif tag.lower() == "tr" and self.in_row:

            row = self.current_row

            if row:

                # Riga intestazione reale:
                # Dir IPnum Port Call/Port ...
                if (
                    len(row) >= 5
                    and row[0] == "Dir"
                ):
                    self.headers = row

                # Righe connessione
                elif (
                    len(row) >= 14
                    and row[0] in ("in", "out")
                ):
                    self.rows.append(row[:14])

            self.current_row = []
            self.in_row = False

        elif tag.lower() == "table":
            self.in_connections_table = False



# ============================================================
# RATE TCP NATIVI UDPGATE4
# ============================================================

_socket_rate_previous = {}


def _split_socket_address(value):

    value = str(value or "").strip()

    if not value:
        return None, None

    m = re.match(
        r"^\[(.+)\]:(\d+)$",
        value
    )

    if m:
        return (
            m.group(1),
            int(m.group(2))
        )

    m = re.match(
        r"^(.*):(\d+)$",
        value
    )

    if not m:
        return None, None

    return (
        m.group(1),
        int(m.group(2))
    )


def sample_udpgate_socket_rates():

    """
    Legge i contatori TCP reali del kernel:

        bytes_sent
        bytes_received

    e calcola il delta rispetto al precedente aggiornamento
    della Dashboard.

    Restituisce:
        {
            ("in", peer_ip, peer_port): {
                "tx_bps": ...,
                "rx_bps": ...
            },

            ("out", peer_ip, peer_port): {...}
        }
    """

    global _socket_rate_previous

    try:

        output = subprocess.check_output(
            [
                "ss",
                "-tinp"
            ],
            text=True,
            errors="replace",
            timeout=3
        )

    except Exception:

        return {}


    now = time.monotonic()

    current = {}

    lines = output.splitlines()

    i = 0

    while i < len(lines):

        line = lines[i]

        if (
            "ESTAB" not in line
            or "udpgate4" not in line
        ):
            i += 1
            continue


        parts = line.split()

        if len(parts) < 5:
            i += 1
            continue


        local_ip, local_port = (
            _split_socket_address(
                parts[3]
            )
        )

        peer_ip, peer_port = (
            _split_socket_address(
                parts[4]
            )
        )


        info = ""

        if i + 1 < len(lines):
            info = lines[i + 1]


        sent_match = re.search(
            r"\bbytes_sent:(\d+)",
            info
        )

        recv_match = re.search(
            r"\bbytes_received:(\d+)",
            info
        )


        if (
            sent_match
            and recv_match
            and local_port is not None
            and peer_port is not None
        ):

            bytes_sent = int(
                sent_match.group(1)
            )

            bytes_received = int(
                recv_match.group(1)
            )


            if local_port == 14580:

                key = (
                    "in",
                    peer_ip,
                    peer_port
                )

            elif peer_port == 14580:

                key = (
                    "out",
                    peer_ip,
                    peer_port
                )

            else:

                key = None


            if key is not None:

                segout_match = re.search(
                    r"\bdata_segs_out:(\d+)",
                    info
                )

                segin_match = re.search(
                    r"\bdata_segs_in:(\d+)",
                    info
                )

                current[key] = {
                    "time": now,
                    "bytes_sent": bytes_sent,
                    "bytes_received":
                        bytes_received,
                    "data_segs_out":
                        int(segout_match.group(1))
                        if segout_match
                        else 0,
                    "data_segs_in":
                        int(segin_match.group(1))
                        if segin_match
                        else 0
                }


        i += 1


    rates = {}


    for key, cur in current.items():

        prev = _socket_rate_previous.get(
            key
        )

        tx_bps = 0.0
        rx_bps = 0.0


        if prev:

            elapsed = (
                cur["time"]
                - prev["time"]
            )

            if elapsed > 0:

                sent_delta = max(
                    0,
                    cur["bytes_sent"]
                    - prev["bytes_sent"]
                )

                recv_delta = max(
                    0,
                    cur["bytes_received"]
                    - prev["bytes_received"]
                )

                tx_bps = (
                    sent_delta * 8.0
                    / elapsed
                )

                rx_bps = (
                    recv_delta * 8.0
                    / elapsed
                )


        rates[key] = {
            "tx_bps": round(
                tx_bps,
                1
            ),
            "rx_bps": round(
                rx_bps,
                1
            ),
            "bytes_sent":
                cur["bytes_sent"],
            "bytes_received":
                cur["bytes_received"],
            "data_segs_out":
                cur["data_segs_out"],
            "data_segs_in":
                cur["data_segs_in"]
        }


    _socket_rate_previous = current

    return rates



def fetch_udpgate_connections():

    """
    Legge le connessioni dal collector nativo.

    Non utilizza più:
        http://127.0.0.1:14501/connects
    """

    import sqlite3

    db_file = os.path.join(
        BASE_DIR,
        "data",
        "monitor.db"
    )

    try:

        conn = sqlite3.connect(
            db_file,
            timeout=3
        )

        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT
                direction,
                ip,
                local_port,
                remote_port,
                callsign,
                verified,
                software,
                filter,
                connected_at,
                active,
                rx_frames_live,
                rx_bytes_live,
                rx_bps_live,
                tcp_tx_frame_offset,
                tcp_rx_frame_offset
            FROM connections
            WHERE active = 1
            ORDER BY id
            """
        ).fetchall()

        conn.close()

    except Exception as exc:

        return {
            "ok": False,
            "error": str(exc),
            "server": {},
            "connections": []
        }


    connections = []

    # Rate TX/RX reali calcolati sui contatori TCP
    # del kernel.
    socket_rates = (
        sample_udpgate_socket_rates()
    )

    # --------------------------------------------------------
    # FILTRI APRS-IS DALLA CONFIGURAZIONE ATTIVA
    # --------------------------------------------------------
    #
    # I filtri dei client TCP vengono raccolti dal loro
    # logresp e sono già presenti nel database.
    #
    # Per APRS-IS outbound il filtro è invece contenuto
    # nell'opzione -g della configurazione attiva:
    #
    #     host:porta#filtro
    #
    # Esempio:
    #
    #     example.aprs.server:14580#m/1,-t/t
    #
    # Usiamo active_config.json perché rappresenta la
    # configurazione realmente applicata a udpgate4.
    # --------------------------------------------------------

    aprsis_filters = {}

    try:

        active_cfg = load_active_config()

        options = active_cfg.get(
            "udpgate4_options",
            {}
        )

        g_option = options.get(
            "-g",
            {}
        )

        if g_option.get("enabled"):

            values = g_option.get(
                "values",
                []
            )

            # Compatibilità nel caso -g sia memorizzato
            # come singolo valore.
            if not values and g_option.get("value"):
                values = [
                    g_option.get("value")
                ]

            for value in values:

                value = str(
                    value or ""
                ).strip()

                if not value:
                    continue

                target, separator, filt = (
                    value.partition("#")
                )

                target = target.strip()

                if ":" not in target:
                    continue

                host, port_text = (
                    target.rsplit(":", 1)
                )

                host = host.strip().lower()

                try:
                    aprsis_port = int(
                        port_text.strip()
                    )
                except Exception:
                    continue

                aprsis_filters[
                    (host, aprsis_port)
                ] = (
                    filt.strip()
                    if separator
                    else ""
                )

    except Exception:
        aprsis_filters = {}


    now = datetime.now(
        timezone.utc
    )


    for row in rows:

        # Connessione interna utilizzata dal monitor.
        # Non deve comparire nella Dashboard.
        if (
            row["callsign"]
            and row["callsign"].upper() == "DXLMON"
        ):
            continue


        # ----------------------------------------------------
        # UPTIME DELLA CONNESSIONE
        # ----------------------------------------------------

        uptime = "—"
        connection_seconds = 0

        connected_at = row["connected_at"]

        if connected_at:

            try:

                started = datetime.fromisoformat(
                    connected_at
                )

                if started.tzinfo is None:
                    started = started.replace(
                        tzinfo=timezone.utc
                    )

                seconds = max(
                    0,
                    int(
                        (
                            now -
                            started.astimezone(
                                timezone.utc
                            )
                        ).total_seconds()
                    )
                )

                connection_seconds = seconds

                days, seconds = divmod(
                    seconds,
                    86400
                )

                hours, seconds = divmod(
                    seconds,
                    3600
                )

                minutes, seconds = divmod(
                    seconds,
                    60
                )

                if days:
                    uptime = (
                        f"{days}d "
                        f"{hours:02d}:"
                        f"{minutes:02d}:"
                        f"{seconds:02d}"
                    )
                else:
                    uptime = (
                        f"{hours:02d}:"
                        f"{minutes:02d}:"
                        f"{seconds:02d}"
                    )

            except Exception:
                pass


        # Per le connessioni IN la porta mostrata dalla
        # vecchia interfaccia era la porta locale 14580.
        #
        # Per APRS-IS OUT mostriamo invece la porta remota.
        if row["direction"] == "in":

            port = (
                row["local_port"]
                or row["remote_port"]
                or ""
            )

        else:

            port = (
                row["remote_port"]
                or row["local_port"]
                or ""
            )


        # ----------------------------------------------------
        # TX/RX RATE DEL SOCKET
        # ----------------------------------------------------

        socket_tx_bps = 0.0
        socket_rx_bps = 0.0

        socket_tx_bytes = 0
        socket_rx_bytes_raw = 0

        socket_tx_segments = 0
        socket_rx_segments = 0


        if row["direction"] == "in":

            rate_key = (
                "in",
                row["ip"],
                int(
                    row["remote_port"]
                    or 0
                )
            )

            rate = socket_rates.get(
                rate_key
            )

            if rate:

                socket_tx_bps = (
                    rate["tx_bps"]
                )

                socket_rx_bps = (
                    rate["rx_bps"]
                )

                socket_tx_bytes = int(
                    rate["bytes_sent"]
                )

                socket_rx_bytes_raw = int(
                    rate["bytes_received"]
                )

                socket_tx_segments = int(
                    rate["data_segs_out"]
                )

                socket_rx_segments = int(
                    rate["data_segs_in"]
                )


        else:

            # APRS-IS nel DB è salvato col nome host,
            # mentre ss mostra normalmente l'IP.
            #
            # Essendoci una sola connessione outbound attiva,
            # prendiamo il socket OUT sulla stessa porta.
            for key, rate in socket_rates.items():

                if (
                    key[0] == "out"
                    and int(key[2]) ==
                        int(
                            row["remote_port"]
                            or 0
                        )
                ):

                    socket_tx_bps = (
                        rate["tx_bps"]
                    )

                    socket_rx_bps = (
                        rate["rx_bps"]
                    )

                    socket_tx_bytes = int(
                        rate["bytes_sent"]
                    )

                    socket_rx_bytes_raw = int(
                        rate["bytes_received"]
                    )

                    socket_tx_segments = int(
                        rate["data_segs_out"]
                    )

                    socket_rx_segments = int(
                        rate["data_segs_in"]
                    )

                    break


        # ----------------------------------------------------
        # CONTATORI STILE UDPGATE4
        # ----------------------------------------------------

        tx_frame_offset = int(
            row["tcp_tx_frame_offset"]
            or 0
        )

        rx_frame_offset = int(
            row["tcp_rx_frame_offset"]
            or 0
        )

        socket_tx_frames = max(
            0,
            socket_tx_segments
            + tx_frame_offset
        )

        socket_rx_frames = max(
            0,
            socket_rx_segments
            + rx_frame_offset
        )

        # bytes_received del kernel include il terminatore
        # di riga ricevuto per ciascun frame.
        socket_rx_bytes = max(
            0,
            socket_rx_bytes_raw
            - socket_rx_frames
        )


        # ----------------------------------------------------
        # BIT/S COMPATIBILE CON UDPGATE4
        # ----------------------------------------------------
        #
        # La vecchia pagina /connects NON mostra un rate
        # istantaneo.
        #
        # Formula verificata:
        #
        #   bit/s = byte_totali * 8 / uptime_connessione
        #
        # ----------------------------------------------------

        if connection_seconds > 0:

            socket_tx_bps = int(
                (
                    socket_tx_bytes * 8
                )
                / connection_seconds
            )

            socket_rx_bps = int(
                (
                    socket_rx_bytes * 8
                )
                / connection_seconds
            )

        else:

            socket_tx_bps = 0
            socket_rx_bps = 0


        # ----------------------------------------------------
        # FILTRO DA VISUALIZZARE
        # ----------------------------------------------------

        display_filter = (
            row["filter"] or ""
        )

        if row["direction"] == "out":

            key = (
                str(
                    row["ip"] or ""
                ).strip().lower(),
                int(
                    row["remote_port"] or 0
                )
            )

            if key in aprsis_filters:
                display_filter = (
                    aprsis_filters[key]
                )


        connections.append(
            {
                "direction":
                    row["direction"] or "",

                "ip":
                    row["ip"] or "",

                "port":
                    str(port),

                "callsign":
                    row["callsign"] or "",

                "v":
                    "v"
                    if row["verified"]
                    else "",

                "software":
                    row["software"] or "",

                "filter":
                    display_filter,

                # Contatori equivalenti alla vecchia
                # pagina /connects.
                "tx_bytes":
                    socket_tx_bytes,

                "tx_frames":
                    socket_tx_frames,

                "tx_bps":
                    socket_tx_bps,

                "rx_bytes":
                    socket_rx_bytes,

                "rx_frames":
                    socket_rx_frames,

                "rx_bps":
                    socket_rx_bps,

                "uptime":
                    uptime
            }
        )


    # --------------------------------------------------------
    # DATI SERVER
    # --------------------------------------------------------

    cfg = load_active_config()

    options = cfg.get(
        "udpgate4_options",
        {}
    )

    server_call = (
        options.get("-s", {}).get("value")
        or
        options.get("-S", {}).get("value")
        or
        ""
    )

    server_port = (
        options.get("-t", {}).get("value")
        or
        ""
    )


    server = {
        "callsign": server_call,
        "port": server_port,
        "version": "0.80",
        "maxusers": "",
        "uptime": get_udpgate_uptime()
    }


    return {
        "ok": True,
        "server": server,
        "connections": connections
    }



def get_udpgate_uptime():

    """
    Uptime reale del processo udpgate4 letto da /proc.
    """

    try:

        output = subprocess.check_output(
            [
                "systemctl",
                "show",
                UDPGATE_SERVICE,
                "--property=ActiveEnterTimestampMonotonic",
                "--value"
            ],
            text=True,
            timeout=2
        ).strip()

        started = int(output or "0")

        if started <= 0:
            return "—"

        with open(
            "/proc/uptime",
            "r",
            encoding="utf-8"
        ) as f:

            system_seconds = float(
                f.read().split()[0]
            )

        # systemd usa microsecondi monotonic.
        start_seconds = (
            started / 1000000.0
        )

        seconds = max(
            0,
            int(
                system_seconds -
                start_seconds
            )
        )

        days, seconds = divmod(
            seconds,
            86400
        )

        hours, seconds = divmod(
            seconds,
            3600
        )

        minutes, seconds = divmod(
            seconds,
            60
        )

        if days:

            return (
                f"{days}d "
                f"{hours:02d}:"
                f"{minutes:02d}:"
                f"{seconds:02d}"
            )

        return (
            f"{hours:02d}:"
            f"{minutes:02d}:"
            f"{seconds:02d}"
        )

    except Exception:

        return "—"



UDPGATE_SERVICE = "dxlaprs-udpgate.service"


def atomic_copy_file(source, destination):

    directory = os.path.dirname(destination)

    fd, tmp = tempfile.mkstemp(
        prefix="active-config-",
        suffix=".json",
        dir=directory
    )

    try:

        with open(source, "rb") as src, \
             os.fdopen(fd, "wb") as dst:

            shutil.copyfileobj(
                src,
                dst
            )

            dst.flush()
            os.fsync(
                dst.fileno()
            )

        os.replace(
            tmp,
            destination
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def wait_tcp_port(port, timeout=90):

    deadline = time.time() + timeout

    while time.time() < deadline:

        try:

            with socket.create_connection(
                ("127.0.0.1", int(port)),
                timeout=0.75
            ):
                return True

        except OSError:
            time.sleep(0.5)

    return False


def expected_tcp_ports(cfg):

    ports = []

    options = cfg.get(
        "udpgate4_options",
        {}
    )

    # --------------------------------------------------------
    # TCP APRS locale: -t
    # --------------------------------------------------------

    tcp = options.get(
        "-t",
        {}
    )

    if tcp.get("enabled"):

        try:

            port = int(
                str(
                    tcp.get(
                        "value",
                        ""
                    )
                ).strip()
            )

            if 1 <= port <= 65535:
                ports.append(
                    (
                        "TCP APRS",
                        port
                    )
                )

        except ValueError:
            pass


    # --------------------------------------------------------
    # WEB ORIGINALE: -w
    #
    # Se web.mode == manager, build_command/run_udpgate
    # non devono utilizzare -w.
    # --------------------------------------------------------

    web_mode = cfg.get(
        "web",
        {}
    ).get(
        "mode",
        "original"
    )

    web = options.get(
        "-w",
        {}
    )

    if (
        web_mode != "manager"
        and web.get("enabled")
    ):

        try:

            port = int(
                str(
                    web.get(
                        "value",
                        ""
                    )
                ).strip()
            )

            if 1 <= port <= 65535:
                ports.append(
                    (
                        "WEB udpgate4",
                        port
                    )
                )

        except ValueError:
            pass


    return ports


def restart_udpgate_service(cfg=None):

    if cfg is None:
        cfg = load_active_config()


    result = subprocess.run(
        [
            "systemctl",
            "restart",
            UDPGATE_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )


    if result.returncode != 0:

        return (
            False,
            "systemctl restart: "
            + (
                result.stderr.strip()
                or result.stdout.strip()
                or "errore sconosciuto"
            )
        )


    # --------------------------------------------------------
    # ATTENDO CHE SYSTEMD VEDA IL SERVIZIO ACTIVE
    # --------------------------------------------------------

    deadline = time.time() + 15

    while time.time() < deadline:

        active = subprocess.run(
            [
                "systemctl",
                "is-active",
                "--quiet",
                UDPGATE_SERVICE
            ]
        )

        if active.returncode == 0:
            break

        time.sleep(0.5)

    else:

        return (
            False,
            "dxlaprs-udpgate.service non è diventato active"
        )


    # --------------------------------------------------------
    # ATTENDO LE PORTE REALMENTE CONFIGURATE
    # --------------------------------------------------------

    for label, port in expected_tcp_ports(cfg):

        if not wait_tcp_port(
            port,
            timeout=90
        ):

            return (
                False,
                f"udpgate4 è attivo ma la porta {label} "
                f"{port} non è diventata disponibile"
            )


    # --------------------------------------------------------
    # CONTROLLO FINALE PROCESSO
    # --------------------------------------------------------

    active = subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            UDPGATE_SERVICE
        ]
    )

    if active.returncode != 0:

        return (
            False,
            "udpgate4 si è arrestato dopo l'avvio"
        )


    return (
        True,
        ""
    )


def apply_udpgate_config():

    # --------------------------------------------------------
    # config.json       = configurazione salvata / draft
    # active_config     = configurazione realmente applicata
    # --------------------------------------------------------

    if not os.path.isfile(
        CONFIG_FILE
    ):

        return (
            False,
            "config.json non trovato"
        )


    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )


    stamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )


    previous_active = os.path.join(
        BACKUP_DIR,
        f"active-before-apply-{stamp}.json"
    )


    # --------------------------------------------------------
    # BACKUP DELLA VERA CONFIGURAZIONE ATTIVA
    # --------------------------------------------------------

    if os.path.isfile(
        ACTIVE_CONFIG_FILE
    ):

        shutil.copy2(
            ACTIVE_CONFIG_FILE,
            previous_active
        )

    else:

        shutil.copy2(
            CONFIG_FILE,
            previous_active
        )


    # --------------------------------------------------------
    # PROMUOVO LA CONFIGURAZIONE SALVATA AD ACTIVE
    # --------------------------------------------------------

    try:

        atomic_copy_file(
            CONFIG_FILE,
            ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            "Impossibile creare active_config.json: "
            + str(exc)
        )


    candidate = load_active_config()


    # --------------------------------------------------------
    # PRIMO AVVIO
    # --------------------------------------------------------

    ok, error = restart_udpgate_service(
        candidate
    )


    if ok:

        # ----------------------------------------------------
        # CONFIGURAZIONE VALIDA:
        # abilitiamo i servizi runtime anche ai prossimi boot.
        # ----------------------------------------------------

        runtime_services = [
            ["systemctl", "enable", UDPGATE_SERVICE],
            [
                "systemctl",
                "enable",
                "--now",
                "dxlaprs-collector.service"
            ],
            [
                "systemctl",
                "enable",
                "--now",
                "dxlaprs-reconcile.timer"
            ],
        ]

        for command in runtime_services:

            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:

                return (
                    False,
                    "Configurazione udpgate4 applicata e attiva, "
                    "ma l'attivazione di un servizio ausiliario "
                    "è fallita. La configurazione NON è stata "
                    "ripristinata: "
                    + (
                        result.stderr.strip()
                        or result.stdout.strip()
                        or "errore sconosciuto"
                    )
                )

        return (
            True,
            ""
        )


    first_error = error


    # --------------------------------------------------------
    # ROLLBACK DELLA CONFIGURAZIONE ATTIVA
    # --------------------------------------------------------

    try:

        atomic_copy_file(
            previous_active,
            ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            first_error
            + " - ATTENZIONE: impossibile ripristinare "
            + "active_config.json: "
            + str(exc)
        )


    restored = load_active_config()


    rollback_ok, rollback_error = (
        restart_udpgate_service(
            restored
        )
    )


    if rollback_ok:

        return (
            False,
            first_error
            + " - configurazione attiva precedente "
            + "ripristinata automaticamente. "
            + "Le modifiche restano salvate in config.json."
        )


    return (
        False,
        first_error
        + " - ATTENZIONE: anche il rollback non è riuscito: "
        + rollback_error
    )



def process_running(name):
    result = subprocess.run(
        ["pgrep", "-x", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def common():
    return {
        "cfg": load_config(),
        "catalog": load_options(),
        "running": process_running("udpgate4")
    }


def build_command(cfg):
    binary = cfg["dxlaprs"]["binary"]
    options = cfg.get("udpgate4_options", {})

    cmd = [binary]

    # Manteniamo un ordine stabile e leggibile.
    order = [
        "-s", "-S",
        "-R", "-M",
        "-H", "-I", "-C", "-B", "-u", "-F",
        "-A", "-a", "-Y",
        "-d", "-E", "-K", "-O", "-o", "-q", "-V", "-X", "-x",
        "-g", "-f", "-e", "-k", "-T", "-0", "-c",
        "-p", "-Q",
        "-t", "-m",
        "-w", "-D", "-W",
        "-l", "-r", "-v",
        "-n"
    ]

    web_mode = cfg.get("web", {}).get("mode", "original")

    for flag in order:
        item = options.get(flag)

        # -v è obbligatorio per DxlAprs Manager.
        #
        # Il collector nativo utilizza l'output verbose di
        # udpgate4 per ricostruire connessioni e traffico.
        # Deve quindi essere sempre presente nel comando,
        # indipendentemente dal valore salvato nel JSON.
        if flag == "-v":
            cmd.append("-v")
            continue

        if not item or not item.get("enabled"):
            continue

        # Quando viene scelta l'interfaccia DxlAprs Manager,
        # il web server originale di udpgate4 non viene avviato.
        if web_mode == "manager" and flag in ("-D", "-W", "-w"):
            continue

        if "values" in item:
            for value in item.get("values", []):
                value = str(value).strip()

                if value:
                    cmd.extend([flag, value])

        elif "value" in item:
            value = str(item.get("value", "")).strip()

            if value:
                cmd.extend([flag, value])

        else:
            cmd.append(flag)

    return " ".join(
        shlex.quote(str(x))
        for x in cmd
    )


def get_section(section_name):
    catalog = load_options()

    if section_name not in catalog:
        abort(404)

    return catalog[section_name]



@app.route("/monitor/connections")
def monitor_connections():

    return render_template(
        "monitor_connections.html",
        cfg=load_config(),
        running=process_running("udpgate4")
    )


@app.route("/api/monitor/connections")
def api_monitor_connections():

    data = fetch_udpgate_connections()

    if not data.get("ok"):

        return data, 503

    return data









@app.route("/traffic")
def public_traffic():

    return render_template(
        "traffic.html",
        running=process_running("udpgate4")
    )


@app.route("/api/monitor/traffic/status")
def api_monitor_traffic_status():

    return traffic_status()


@app.route("/api/monitor/traffic/stream")
def api_monitor_traffic_stream():

    q = traffic_subscribe()


    @stream_with_context
    def generate():

        try:

            # Stato iniziale.
            yield sse_encode({
                "type": "status",
                **traffic_status()
            })


            while True:

                try:

                    message = q.get(
                        timeout=15
                    )

                    yield sse_encode(
                        message
                    )


                except Exception:

                    # Commento SSE = keepalive.
                    yield ": keepalive\n\n"


        finally:

            traffic_unsubscribe(
                q
            )


    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":
                "no-cache, no-transform",

            "X-Accel-Buffering":
                "no",

            "Connection":
                "keep-alive"
        }
    )


@app.route("/messages")
def public_messages():

    return render_template(
        "messages.html",
        cfg=load_config(),
        running=process_running("udpgate4")
    )


@app.route("/api/monitor/messages")
def api_monitor_messages():

    data = fetch_messages()

    if not data.get("ok"):
        return data, 503

    return data




@app.route("/raw/<callsign>")
def public_raw(callsign):

    data = fetch_raw(
        callsign
    )

    if not data.get("ok"):

        return render_template(
            "raw_packets.html",
            data=data
        ), 404

    return render_template(
        "raw_packets.html",
        data=data
    )


@app.route("/heard")
def public_heard():

    return render_template(
        "heard.html",
        cfg=load_config(),
        running=process_running("udpgate4")
    )


@app.route("/api/monitor/heard")
def api_monitor_heard():

    data = fetch_heard()

    if not data.get("ok"):
        return data, 503

    return data


@app.route("/dxl-icon/<name>")
def dxl_icon(name):

    try:

        data = fetch_icon(
            name
        )

    except Exception:
        abort(404)

    return app.response_class(
        data,
        mimetype="image/gif",
        headers={
            "Cache-Control":
                "public, max-age=86400"
        }
    )


@app.route("/admin", methods=["GET", "POST"])
def admin_login():

    if admin_authenticated():

        return redirect(
            url_for(
                "config_section",
                section_name="general"
            )
        )

    cfg = load_config()

    if ensure_admin_config(cfg):
        save_config(cfg)

    error = False

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        admin = cfg.get(
            "admin",
            {}
        )

        username_ok = (
            username ==
            admin.get("username", "admin")
        )

        password_ok = check_password_hash(
            admin.get("password_hash", ""),
            password
        )

        if username_ok and password_ok:

            session.clear()

            session["admin_authenticated"] = True
            session["admin_username"] = username

            destination = request.form.get(
                "next",
                ""
            )

            if (
                not destination
                or not destination.startswith("/")
                or destination.startswith("//")
            ):
                destination = "/config/general"

            return redirect(destination)

        error = True

    return render_template(
        "admin_login.html",
        error=error,
        running=process_running("udpgate4")
    )


@app.route("/admin/logout")
def admin_logout():

    session.clear()

    return redirect(
        url_for("dashboard")
    )


@app.route(
    "/config/admin",
    methods=["GET", "POST"]
)
@admin_required
def config_admin():

    cfg = load_config()

    if ensure_admin_config(cfg):
        save_config(cfg)

    admin = cfg.setdefault(
        "admin",
        {}
    )

    error = None

    if request.method == "POST":

        username = request.form.get(
            "admin_username",
            ""
        ).strip()

        password = request.form.get(
            "admin_password",
            ""
        )

        confirm = request.form.get(
            "admin_password_confirm",
            ""
        )

        if not username:

            error = "username"

        elif password and password != confirm:

            error = "password_match"

        else:

            admin["username"] = username

            if password:

                admin["password_hash"] = generate_password_hash(
                    password
                )

            save_config(cfg)

            session["admin_username"] = username

            flash(
                "admin_saved",
                "success"
            )

            return redirect(
                url_for("config_admin")
            )

    return render_template(
        "config_admin.html",
        cfg=cfg,
        admin=admin,
        error=error,
        running=process_running("udpgate4")
    )


@app.route("/")
def dashboard():
    data = common()
    data["command"] = build_command(data["cfg"])

    return render_template(
        "dashboard.html",
        **data
    )


@app.route("/config")
@admin_required
def config_index():
    return redirect(
        url_for(
            "config_section",
            section_name="general"
        )
    )


@app.route("/config/aprsis", methods=["GET", "POST"])
@admin_required
def config_aprsis():
    cfg = load_config()
    catalog = load_options()

    values = cfg.setdefault(
        "udpgate4_options",
        {}
    )

    aprsis = cfg.setdefault(
        "aprsis",
        {}
    )

    aprsis.setdefault("mode", "servers")
    aprsis.setdefault("server_file", "")
    aprsis.setdefault("servers", [])

    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )

        # Riavvia la configurazione GIA' salvata.
        # Eventuali modifiche presenti nel form vengono ignorate.
        if action == "restart":

            ok, error = restart_udpgate_service()

            if ok:

                flash(
                    "restarted",
                    "success"
                )

            else:

                flash(
                    error,
                    "service_error"
                )

            return redirect(
                request.path
            )

        mode = request.form.get(
            "aprsis_mode",
            "servers"
        )

        if mode not in ("servers", "file"):
            mode = "servers"

        aprsis["mode"] = mode

        # ----------------------------------------------------
        # SERVER APRS-IS
        # ----------------------------------------------------

        hosts = request.form.getlist(
            "server_host[]"
        )

        ports = request.form.getlist(
            "server_port[]"
        )

        filters = request.form.getlist(
            "server_filter[]"
        )

        enabled_indexes = set(
            request.form.getlist(
                "server_enabled[]"
            )
        )

        servers = []

        count = max(
            len(hosts),
            len(ports),
            len(filters)
        )

        for i in range(count):

            host = (
                hosts[i].strip()
                if i < len(hosts)
                else ""
            )

            port_raw = (
                ports[i].strip()
                if i < len(ports)
                else "14580"
            )

            filt = (
                filters[i].strip()
                if i < len(filters)
                else ""
            )

            if not host:
                continue

            try:
                port = int(port_raw)
            except ValueError:
                port = 14580

            if port < 1 or port > 65535:
                port = 14580

            servers.append({
                "host": host,
                "port": port,
                "filter": filt,
                "enabled": str(i) in enabled_indexes
            })

        aprsis["servers"] = servers

        aprsis["server_file"] = request.form.get(
            "server_file",
            ""
        ).strip()

        # ----------------------------------------------------
        # RICOSTRUZIONE -g
        # ----------------------------------------------------

        g = values.setdefault(
            "-g",
            {}
        )

        g_values = []

        if mode == "file":

            filename = aprsis["server_file"]

            if filename:
                g_values.append(
                    ":" + filename
                )

        else:

            for server in servers:

                if not server.get("enabled"):
                    continue

                raw = (
                    f'{server["host"]}:'
                    f'{server["port"]}'
                )

                if server.get("filter"):
                    raw += "#" + server["filter"]

                g_values.append(raw)

        g["values"] = g_values
        g["enabled"] = bool(g_values)

        # ----------------------------------------------------
        # ALTRI PARAMETRI APRS-IS
        # ----------------------------------------------------

        aprsis_flags = [
            "-f",
            "-e",
            "-k",
            "-T",
            "-0",
            "-c"
        ]

        booleans = {
            "-0",
            "-c"
        }

        for flag in aprsis_flags:

            item = values.setdefault(
                flag,
                {}
            )

            item["enabled"] = (
                request.form.get(
                    f"enabled_{flag}"
                ) == "on"
            )

            if flag not in booleans:

                item["value"] = request.form.get(
                    f"value_{flag}",
                    item.get("value", "")
                ).strip()

        save_config(cfg)

        if action == "apply":

            ok, error = apply_udpgate_config()

            if ok:

                flash(
                    "applied",
                    "success"
                )

            else:

                flash(
                    error,
                    "service_error"
                )

        else:

            flash(
                "saved",
                "success"
            )

        return redirect(
            url_for("config_aprsis")
        )

    return render_template(
        "config_aprsis.html",
        cfg=cfg,
        catalog=catalog,
        values=values,
        aprsis=aprsis,
        running=process_running("udpgate4"),
        command=build_command(cfg)
    )


@app.route("/config/web", methods=["GET", "POST"])
@admin_required
def config_web():
    cfg = load_config()
    catalog = load_options()
    values = cfg.setdefault("udpgate4_options", {})
    web = cfg.setdefault("web", {})

    web.setdefault("mode", "manager")
    web.setdefault("manager_path", "/")

    # Porte riservate all'architettura DxlAprs Manager.
    # Non sono configurabili dall'utente perché Apache,
    # web_router.py e il backend devono restare sincronizzati.
    web["manager_port"] = 8085
    web["public_port"] = 14501
    web["original_backend_port"] = 14502

    cfg.setdefault("manager", {})["port"] = 8085

    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )

        # Riavvia la configurazione GIA' salvata.
        # Eventuali modifiche presenti nel form vengono ignorate.
        if action == "restart":

            ok, error = restart_udpgate_service()

            if ok:

                flash(
                    "restarted",
                    "success"
                )

            else:

                flash(
                    error,
                    "service_error"
                )

            return redirect(
                request.path
            )

        mode = request.form.get("web_mode", "original")

        if mode not in ("original", "manager"):
            mode = "original"

        web["mode"] = mode

        # Conserviamo SEMPRE i valori, anche quando
        # l'interfaccia originale non è selezionata.
        values.setdefault("-D", {})
        values.setdefault("-W", {})
        values.setdefault("-w", {})

        values["-D"]["value"] = request.form.get(
            "original_web_root", ""
        ).strip()

        values["-W"]["value"] = request.form.get(
            "original_web_max_file", "4000"
        ).strip()

        # Porta interna del web originale riservata.
        # Apache espone sempre pubblicamente la porta 14501.
        values["-w"]["value"] = "14502"

        # -D e -w sono attivi solo usando la pagina originale.
        # -W conserva invece la scelta corrente, perché è un
        # parametro opzionale con default interno di udpgate4.
        original = (mode == "original")

        values["-D"]["enabled"] = original
        values["-w"]["enabled"] = original

        use_max_file = (
            request.form.get("original_web_max_file_enabled")
            == "on"
        )

        values["-W"]["enabled"] = original and use_max_file

        web["manager_path"] = request.form.get(
            "manager_path", "/"
        ).strip() or "/"

        # Le porte dell'infrastruttura sono fisse.
        web["manager_port"] = 8085
        web["public_port"] = 14501
        web["original_backend_port"] = 14502

        cfg.setdefault("manager", {})["port"] = 8085

        save_config(cfg)

        if action == "apply":

            ok, error = apply_udpgate_config()

            if ok:

                flash(
                    "applied",
                    "success"
                )

            else:

                flash(
                    error,
                    "service_error"
                )

        else:

            flash(
                "saved",
                "success"
            )

        return redirect(url_for("config_web"))

    return render_template(
        "config_web.html",
        cfg=cfg,
        catalog=catalog,
        values=values,
        web=web,
        running=process_running("udpgate4"),
        command=build_command(cfg)
    )


@app.route(
    "/config/<section_name>",
    methods=["GET", "POST"]
)
@admin_required
def config_section(section_name):
    if section_name not in SECTIONS:
        abort(404)

    cfg = load_config()
    catalog = load_options()
    section = catalog[section_name]

    values = cfg.setdefault(
        "udpgate4_options",
        {}
    )

    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )

        # Riavvia la configurazione GIA' salvata.
        # Eventuali modifiche presenti nel form vengono ignorate.
        if action == "restart":

            ok, error = restart_udpgate_service()

            if ok:

                flash(
                    "restarted",
                    "success"
                )

            else:

                flash(
                    error,
                    "service_error"
                )

            return redirect(
                request.path
            )

        for option in section["options"]:

            flag = option["flag"]

            current = values.setdefault(
                flag,
                {}
            )

            current["enabled"] = (
                request.form.get(
                    f"enabled_{flag}"
                ) == "on"
            )

            if option.get("repeat"):

                raw = request.form.get(
                    f"value_{flag}",
                    ""
                )

                rows = []

                for line in raw.splitlines():
                    line = line.strip()

                    if line:
                        rows.append(line)

                current["values"] = rows

            elif not option.get("boolean"):

                current["value"] = request.form.get(
                    f"value_{flag}",
                    ""
                ).strip()

        save_config(cfg)

        if action == "apply":

            ok, error = apply_udpgate_config()

            if ok:

                flash(
                    "applied",
                    "success"
                )

            else:

                flash(
                    error,
                    "service_error"
                )

        else:

            flash(
                "saved",
                "success"
            )

        return redirect(
            url_for(
                "config_section",
                section_name=section_name
            )
        )

    return render_template(
        "config_section.html",
        cfg=cfg,
        catalog=catalog,
        section=section,
        section_name=section_name,
        values=values,
        running=process_running("udpgate4"),
        command=build_command(cfg)
    )


@app.route("/health")
def health():
    return {
        "manager": "ok",
        "udpgate4": process_running("udpgate4")
    }


if __name__ == "__main__":
    cfg = load_config()

    manager = cfg.get(
        "manager",
        {}
    )

    app.run(
        host=manager.get(
            "listen_address",
            "0.0.0.0"
        ),
        port=int(
            manager.get(
                "port",
                8085
            )
        ),
        debug=False
    )
