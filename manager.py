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
    #     aprs.example.net:14580#m/1,-t/t
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




# ============================================================
# DXLAPRS SERVICES MONITOR
# ============================================================

DXLAPRS_MONITOR_SERVICES = [

    {
        "key": "udpgate4",
        "name": "udpgate4",
        "unit": "dxlaprs-udpgate.service",
        "managed": True,
    },

    {
        "key": "udpbox",
        "name": "udpbox",
        "unit": "dxlaprs-udpbox.service",
        "managed": True,
    },

    {
        "key": "udphub",
        "name": "udphub",
        "unit": "dxlaprs-udphub.service",
        "managed": True,
    },

    {
        "key": "udpflex",
        "name": "udpflex",
        "unit": "dxlaprs-udpflex.service",
        "managed": True,
    },

    {
        "key": "lorarx",
        "name": "lorarx",
        "unit": "dxlaprs-lorarx.service",
        "managed": True,
    },

    {
        "key": "loratx",
        "name": "loratx",
        "unit": "dxlaprs-loratx.service",
        "managed": True,
    },

    {
        "key": "fsk4rx",
        "name": "fsk4rx",
        "unit": "dxlaprs-fsk4rx.service",
        "managed": True,
    },

    {
        "key": "ra02",
        "name": "ra02",
        "unit": "dxlaprs-ra02.service",
        "managed": True,
    },

    {
        "key": "ra02waterfall",
        "name": "ra02waterfall",
        "unit": "dxlaprs-ra02waterfall.service",
        "managed": True,
    },

    {
        "key": "sdrtst",
        "name": "sdrtst",
        "unit": "dxlaprs-sdrtst.service",
        "managed": True,
    },

    {
        "key": "afskmodem",
        "name": "afskmodem",
        "unit": "dxlaprs-afskmodem.service",
        "managed": True,
    },

    {
        "key": "gps2aprs",
        "name": "gps2aprs",
        "unit": "dxlaprs-gps2aprs.service",
        "managed": True,
    },

    {
        "key": "hostint",
        "name": "hostint",
        "unit": "dxlaprs-hostint.service",
        "managed": True,
    },

    {
        "key": "l2cat",
        "name": "l2cat",
        "unit": "dxlaprs-l2cat.service",
        "managed": True,
    },

    {
        "key": "sondeudp",
        "name": "sondeudp",
        "unit": "dxlaprs-sondeudp.service",
        "managed": True,
    },

    {
        "key": "sondemod",
        "name": "sondemod",
        "unit": "dxlaprs-sondemod.service",
        "managed": True,
    },

    {
        "key": "ttytee",
        "name": "ttytee",
        "unit": "dxlaprs-ttytee.service",
        "managed": True,
    },

    {
        "key": "adsb2aprs",
        "name": "adsb2aprs",
        "unit": "dxlaprs-adsb2aprs.service",
        "managed": True,
    },

    {
        "key": "collector",
        "name": "collector",
        "unit": "dxlaprs-collector.service",
        "managed": False,
    },

    {
        "key": "manager",
        "name": "DxlAprs Manager",
        "unit": "dxlaprs-manager.service",
        "managed": False,
    },
]


def dxlaprs_monitor_service_state(item):

    import subprocess

    unit = item["unit"]

    active_p = subprocess.run(
        [
            "systemctl",
            "is-active",
            unit
        ],
        text=True,
        capture_output=True
    )

    active = (
        active_p.stdout.strip()
        or "unknown"
    )

    enabled_p = subprocess.run(
        [
            "systemctl",
            "is-enabled",
            unit
        ],
        text=True,
        capture_output=True
    )

    enabled = (
        enabled_p.stdout.strip()
        or "unknown"
    )

    pid_p = subprocess.run(
        [
            "systemctl",
            "show",
            unit,
            "--property=MainPID",
            "--value"
        ],
        text=True,
        capture_output=True
    )

    pid = pid_p.stdout.strip()

    result = dict(item)

    result.update(
        {
            "active": active,
            "enabled": enabled,
            "pid": pid,
        }
    )

    return result


@app.route("/monitor/services")
def monitor_services():

    from flask import request

    services = [
        dxlaprs_monitor_service_state(x)
        for x in DXLAPRS_MONITOR_SERVICES
    ]

    totals = {
        "active": sum(
            1
            for x in services
            if x["active"] == "active"
        ),
        "inactive": sum(
            1
            for x in services
            if x["active"] != "active"
        ),
        "enabled": sum(
            1
            for x in services
            if x["enabled"] == "enabled"
        ),
    }

    return render_template(
        "monitor_services.html",
        cfg=load_config(),
        running=process_running("udpgate4"),
        services=services,
        totals=totals,
        ok=request.args.get("ok") == "1",
        message=request.args.get("message", "")
    )


@app.route(
    "/monitor/services/action",
    methods=["POST"]
)
def monitor_services_action():

    import subprocess

    from flask import (
        request,
        redirect,
        url_for
    )

    service_key = (
        request.form.get(
            "service",
            ""
        ).strip()
    )

    action = (
        request.form.get(
            "action",
            ""
        ).strip()
    )

    allowed_actions = {
        "start",
        "stop",
        "restart",
        "enable",
        "disable",
    }

    item = next(
        (
            x
            for x in DXLAPRS_MONITOR_SERVICES
            if x["key"] == service_key
        ),
        None
    )

    if not item:

        return redirect(
            url_for(
                "monitor_services",
                ok="0",
                message="Servizio non valido."
            )
        )

    if not item.get("managed"):

        return redirect(
            url_for(
                "monitor_services",
                ok="0",
                message="Servizio protetto."
            )
        )

    if action not in allowed_actions:

        return redirect(
            url_for(
                "monitor_services",
                ok="0",
                message="Azione non valida."
            )
        )

    p = subprocess.run(
        [
            "systemctl",
            action,
            item["unit"]
        ],
        text=True,
        capture_output=True
    )

    if p.returncode == 0:

        return redirect(
            url_for(
                "monitor_services",
                ok="1",
                message=(
                    item["name"]
                    + ": "
                    + action
                    + " OK"
                )
            )
        )

    detail = (
        p.stderr
        or p.stdout
        or "Errore systemctl"
    ).strip()

    return redirect(
        url_for(
            "monitor_services",
            ok="0",
            message=(
                item["name"]
                + ": "
                + detail
            )
        )
    )



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



# ============================================================
# UDPBOX
# ============================================================

UDPBOX_SERVICE = "dxlaprs-udpbox.service"

UDPBOX_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udpbox_config.json"
)

UDPBOX_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udpbox_active_config.json"
)


UDPBOX_CATALOG = [

    {
        "flag": "-a",
        "it": "Percorso ACK messaggi utente",
        "en": "User message ACK path",
        "syntax": "<path>",
        "help_it": "Percorso usato per gli ACK dei messaggi utente, ad esempio WIDE2-2 oppure - per nessun path."
    },

    {
        "flag": "-b",
        "it": "Beacon",
        "en": "Beacon",
        "syntax": "<secondi>:<file>",
        "help_it": "Invia periodicamente il beacon leggendo testo e path dal file specificato."
    },

    {
        "flag": "-c",
        "it": "Uscita monitor testo CR/LF",
        "en": "Text monitor CR/LF output",
        "syntax": "<ip>:<porta>",
        "help_it": "Invia frame monitor testuali UDP terminati CR/LF."
    },

    {
        "flag": "-D",
        "it": "Dati decodificati su stdout",
        "en": "Decoded data to stdout",
        "syntax": "",
        "boolean": True,
        "help_it": "Mostra su stdout i dati decodificati."
    },

    {
        "flag": "-d",
        "it": "Digipeater / filtro duplicati",
        "en": "Digipeater / duplicate filter",
        "syntax": "<call>",
        "help_it": "Abilita il digipeater con il nominativo indicato. Usare - come valore per il solo filtro duplicati senza modifica dei dati."
    },

    {
        "flag": "-e",
        "it": "Echo uscita filtrata",
        "en": "Echo filtered output",
        "syntax": "",
        "boolean": True,
        "help_it": "Mostra l'ultima uscita dopo l'applicazione dei filtri."
    },

    {
        "flag": "-f",
        "it": "Filtro payload UI",
        "en": "UI payload filter",
        "syntax": "<parametri>",
        "help_it": "Filtro sul primo carattere dei frame UI. Esempi: p58,110 oppure d32,65-79."
    },

    {
        "flag": "-k",
        "it": "Filtro distanza",
        "en": "Distance filter",
        "syntax": "<lat>/<lon>/<km>",
        "help_it": "Filtra in base a centro geografico e raggio."
    },

    {
        "flag": "-L",
        "it": "Ingresso monitor RF-link",
        "en": "RF-link monitor input",
        "syntax": "<ip>:<porta>:<netname>",
        "help_it": "Legge frame monitor con header RF-link e nome della rete."
    },

    {
        "flag": "-l",
        "it": "Uscita AXUDP passthrough",
        "en": "AXUDP passthrough output",
        "syntax": "<ip>:<porta>",
        "help_it": "Invia frame AXUDP raw mantenendo l'header AXUDP2."
    },

    {
        "flag": "-M",
        "it": "Ingresso monitor testo",
        "en": "Text monitor input",
        "syntax": "<ip>:<porta>",
        "help_it": "Legge frame monitor testuali UDP. Sono supportate anche le modalità stdin speciali documentate da udpbox."
    },

    {
        "flag": "-m",
        "it": "Uscita monitor testo zero-terminated",
        "en": "Zero-terminated text monitor output",
        "syntax": "<ip>:<porta>",
        "help_it": "Invia frame monitor testuali UDP terminati da zero."
    },

    {
        "flag": "-n",
        "it": "Uscita payload raw",
        "en": "Raw payload output",
        "syntax": "<ip>:<porta>",
        "help_it": "Invia solamente il payload raw senza header AXUDP e senza CRC."
    },

    {
        "flag": "-p",
        "it": "Regole digipeater",
        "en": "Digipeater rules",
        "syntax": "<n>,<n>...",
        "help_it": "Controlla routing SSID, WIDE/TRACE/RELAY/GATE e le altre regole avanzate del digipeater."
    },

    {
        "flag": "-P",
        "it": "Piggyback beacon",
        "en": "Beacon piggyback time",
        "syntax": "<secondi>",
        "help_it": "Permette di anticipare il beacon quando viene già trasmesso altro traffico."
    },

    {
        "flag": "-R",
        "it": "Ingresso AXUDP raw",
        "en": "Raw AXUDP input",
        "syntax": "<ip>:<porta>",
        "help_it": "Legge frame AXUDP raw. Esempio: 0.0.0.0:2000."
    },

    {
        "flag": "-r",
        "it": "Uscita AXUDP raw",
        "en": "Raw AXUDP output",
        "syntax": "<ip>:<porta>",
        "help_it": "Invia frame AXUDP raw."
    },

    {
        "flag": "-S",
        "it": "Modalità Satgate",
        "en": "Satgate mode",
        "syntax": "",
        "boolean": True,
        "help_it": "Filtra l'uplink quando il percorso contiene una via senza H-bit."
    },

    {
        "flag": "-s",
        "it": "Passa anche frame non-UI",
        "en": "Pass non-UI frames",
        "syntax": "",
        "boolean": True,
        "help_it": "Permette il passaggio anche dei frame packet radio non-UI come SABM e RR."
    },

    {
        "flag": "-t",
        "it": "Tempi filtro duplicati",
        "en": "Duplicate filter times",
        "syntax": "<secondi>,<secondi>",
        "help_it": "Tempo filtro duplicati generale e tempo per i retry dei messaggi utente. Esempio: 1740,28."
    },

    {
        "flag": "-u",
        "it": "Ricezione messaggi utente",
        "en": "User message reception",
        "syntax": "<call>:<file>",
        "repeat": True,
        "help_it": "Riceve e conferma messaggi destinati al call indicato e li salva nel file. Il parametro può essere ripetuto."
    },

    {
        "flag": "-v",
        "it": "Verbose",
        "en": "Verbose",
        "syntax": "",
        "boolean": True,
        "help_it": "Mostra frame e analisi su stdout."
    },

    {
        "flag": "-X",
        "it": "Passa solo determinati call",
        "en": "Pass only selected calls",
        "syntax": "<call>{,<call>}",
        "help_it": "Passa solamente i frame contenenti i nominativi indicati."
    },

    {
        "flag": "-x",
        "it": "Escludi determinati call",
        "en": "Exclude selected calls",
        "syntax": "<call>{,<call>}",
        "help_it": "Elimina i frame contenenti i nominativi indicati in un campo indirizzo."
    }
]


def load_udpbox_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def load_udpbox_config():

    return load_udpbox_json(
        UDPBOX_CONFIG_FILE
    )


def load_udpbox_active_config():

    if os.path.isfile(
        UDPBOX_ACTIVE_CONFIG_FILE
    ):
        return load_udpbox_json(
            UDPBOX_ACTIVE_CONFIG_FILE
        )

    return load_udpbox_config()


def save_udpbox_config(cfg):

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    if os.path.isfile(
        UDPBOX_CONFIG_FILE
    ):

        stamp = datetime.now().strftime(
            "%Y%m%d-%H%M%S-%f"
        )

        shutil.copy2(
            UDPBOX_CONFIG_FILE,
            os.path.join(
                BACKUP_DIR,
                f"udpbox-config-{stamp}.json"
            )
        )

    directory = os.path.dirname(
        UDPBOX_CONFIG_FILE
    )

    fd, tmp = tempfile.mkstemp(
        prefix="udpbox-config-",
        suffix=".json",
        dir=directory
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                ensure_ascii=False,
                indent=2
            )

            f.write("\n")
            f.flush()
            os.fsync(
                f.fileno()
            )

        os.replace(
            tmp,
            UDPBOX_CONFIG_FILE
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def udpbox_build_argv(cfg, manager_cfg=None):

    if manager_cfg is None:
        manager_cfg = load_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    if not bin_dir:
        binary = "udpbox"
    else:
        binary = os.path.join(
            bin_dir,
            "udpbox"
        )

    options = cfg.get(
        "options",
        {}
    )

    order = [
        "-a", "-b", "-c", "-D",
        "-d", "-e", "-f", "-k",
        "-L", "-l", "-M", "-m",
        "-n", "-p", "-P",
        "-R", "-r",
        "-S", "-s",
        "-t", "-u", "-v",
        "-X", "-x"
    ]

    boolean_flags = {
        "-D",
        "-e",
        "-S",
        "-s",
        "-v"
    }

    argv = [binary]

    for flag in order:

        item = options.get(
            flag,
            {}
        )

        if not item.get(
            "enabled"
        ):
            continue

        if flag in boolean_flags:

            argv.append(
                flag
            )

            continue

        if "values" in item:

            for value in item.get(
                "values",
                []
            ):

                value = str(
                    value
                ).strip()

                if value:

                    argv.extend(
                        [
                            flag,
                            value
                        ]
                    )

            continue

        value = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if value:

            argv.extend(
                [
                    flag,
                    value
                ]
            )

    return argv


def udpbox_build_command(cfg, manager_cfg=None):

    return " ".join(
        shlex.quote(
            str(x)
        )
        for x in udpbox_build_argv(
            cfg,
            manager_cfg
        )
    )


def udpbox_config_has_options(cfg):

    return len(
        udpbox_build_argv(
            cfg
        )
    ) > 1


def udpbox_service_running():

    result = subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            UDPBOX_SERVICE
        ]
    )

    return result.returncode == 0


def udpbox_service_enabled():

    result = subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            UDPBOX_SERVICE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def verify_udpbox_service(timeout=10):

    deadline = time.time() + timeout

    while time.time() < deadline:

        state = subprocess.run(
            [
                "systemctl",
                "show",
                UDPBOX_SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--property=ExecMainStatus",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        values = state.stdout.splitlines()

        active_state = values[0].strip() if len(values) > 0 else ""
        sub_state = values[1].strip() if len(values) > 1 else ""
        exec_status = values[2].strip() if len(values) > 2 else ""

        # Configurazione partita e rimasta stabile.
        if active_state == "active" and sub_state == "running":

            time.sleep(2)

            stable = subprocess.run(
                [
                    "systemctl",
                    "is-active",
                    "--quiet",
                    UDPBOX_SERVICE
                ]
            )

            if stable.returncode == 0:
                return True, ""


        # Se systemd è già entrato nel ciclo di auto-restart,
        # non aspettiamo i retry: il candidato è fallito.
        if (
            active_state == "failed"
            or sub_state == "auto-restart"
        ):

            # Cancella immediatamente eventuale retry pendente.
            subprocess.run(
                [
                    "systemctl",
                    "stop",
                    UDPBOX_SERVICE
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            journal = subprocess.run(
                [
                    "journalctl",
                    "-u",
                    UDPBOX_SERVICE,
                    "-n",
                    "12",
                    "--no-pager"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            lines = [
                x.strip()
                for x in journal.stdout.splitlines()
                if x.strip()
            ]

            detail = ""

            for line in reversed(lines):

                if (
                    "error" in line.lower()
                    or "abort" in line.lower()
                    or "exited" in line.lower()
                ):
                    detail = line
                    break

            return (
                False,
                detail
                or (
                    "udpbox terminato durante l'avvio"
                    + (
                        f" (exit status {exec_status})"
                        if exec_status
                        else ""
                    )
                )
            )

        time.sleep(0.25)


    return (
        False,
        "udpbox non è diventato stabile entro il timeout"
    )


def start_udpbox_service():

    cfg = load_udpbox_active_config()

    if not udpbox_config_has_options(
        cfg
    ):

        return (
            False,
            "Nessuna opzione udpbox attiva nella configurazione applicata"
        )


    result = subprocess.run(
        [
            "systemctl",
            "start",
            UDPBOX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'avvio di udpbox"
        )


    return verify_udpbox_service()


def stop_udpbox_service():

    result = subprocess.run(
        [
            "systemctl",
            "stop",
            UDPBOX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'arresto di udpbox"
        )


    deadline = time.time() + 10

    while time.time() < deadline:

        if not udpbox_service_running():

            return (
                True,
                ""
            )

        time.sleep(
            0.25
        )


    return (
        False,
        "udpbox non si è arrestato entro il timeout"
    )


def restart_udpbox_service():

    cfg = load_udpbox_active_config()

    if not udpbox_config_has_options(
        cfg
    ):

        return (
            False,
            "Nessuna opzione udpbox attiva nella configurazione applicata"
        )


    result = subprocess.run(
        [
            "systemctl",
            "restart",
            UDPBOX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante il riavvio di udpbox"
        )


    return verify_udpbox_service()


def apply_udpbox_config():

    if not os.path.isfile(
        UDPBOX_CONFIG_FILE
    ):

        return (
            False,
            "udpbox_config.json non trovato"
        )


    was_running = udpbox_service_running()


    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )


    stamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )


    previous_active = os.path.join(
        BACKUP_DIR,
        f"udpbox-active-before-apply-{stamp}.json"
    )


    if os.path.isfile(
        UDPBOX_ACTIVE_CONFIG_FILE
    ):

        shutil.copy2(
            UDPBOX_ACTIVE_CONFIG_FILE,
            previous_active
        )

    else:

        shutil.copy2(
            UDPBOX_CONFIG_FILE,
            previous_active
        )


    try:

        atomic_copy_file(
            UDPBOX_CONFIG_FILE,
            UDPBOX_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            "Impossibile creare udpbox_active_config.json: "
            + str(exc)
        )


    # Se il componente era fermo, l'applicazione
    # aggiorna semplicemente la configurazione attiva.
    if not was_running:

        return (
            True,
            ""
        )


    ok, error = restart_udpbox_service()

    if ok:

        return (
            True,
            ""
        )


    first_error = error


    try:

        atomic_copy_file(
            previous_active,
            UDPBOX_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            first_error
            + " - ATTENZIONE: impossibile ripristinare "
            + "udpbox_active_config.json: "
            + str(exc)
        )


    rollback_ok, rollback_error = (
        restart_udpbox_service()
    )


    if rollback_ok:

        return (
            False,
            first_error
            + " - configurazione udpbox precedente "
            + "ripristinata automaticamente. "
            + "Le modifiche restano salvate nel draft."
        )


    return (
        False,
        first_error
        + " - ATTENZIONE: anche il rollback udpbox "
        + "non è riuscito: "
        + rollback_error
    )


def udpbox_journal():

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            UDPBOX_SERVICE,
            "-n",
            "30",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    return (
        result.stdout.strip()
        or "Nessun log disponibile."
    )


def update_udpbox_from_form(cfg):

    options = cfg.setdefault(
        "options",
        {}
    )


    for item in UDPBOX_CATALOG:

        flag = item["flag"]

        state = options.setdefault(
            flag,
            {}
        )

        state["enabled"] = (
            f"enabled_{flag}"
            in request.form
        )


        if item.get(
            "boolean"
        ):

            state.pop(
                "value",
                None
            )

            state.pop(
                "values",
                None
            )

            continue


        if item.get(
            "repeat"
        ):

            text = request.form.get(
                f"value_{flag}",
                ""
            )

            state["values"] = [
                line.strip()
                for line in text.splitlines()
                if line.strip()
            ]

            state.pop(
                "value",
                None
            )

            continue


        state["value"] = request.form.get(
            f"value_{flag}",
            ""
        ).strip()


    return cfg


@app.route(
    "/config/udpbox",
    methods=[
        "GET",
        "POST"
    ]
)
def config_udpbox():

    cfg = load_udpbox_config()


    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )


        # --------------------------------------------
        # Azioni service: NON usano modifiche
        # eventualmente presenti ma non salvate.
        # --------------------------------------------

        if action == "start":

            ok, error = start_udpbox_service()

            if ok:

                flash(
                    "UDPBOX_START_OK"
                )

            else:

                flash(
                    "UDPBOX_ERROR: "
                    + error
                )

            return redirect(
                "/config/udpbox"
            )


        if action == "stop":

            ok, error = stop_udpbox_service()

            if ok:

                flash(
                    "UDPBOX_STOP_OK"
                )

            else:

                flash(
                    "UDPBOX_ERROR: "
                    + error
                )

            return redirect(
                "/config/udpbox"
            )


        if action == "restart":

            ok, error = restart_udpbox_service()

            if ok:

                flash(
                    "UDPBOX_RESTART_OK"
                )

            else:

                flash(
                    "UDPBOX_ERROR: "
                    + error
                )

            return redirect(
                "/config/udpbox"
            )


        # --------------------------------------------
        # SAVE / APPLY
        # --------------------------------------------

        cfg = update_udpbox_from_form(
            cfg
        )

        save_udpbox_config(
            cfg
        )


        if action == "apply":

            ok, error = apply_udpbox_config()

            if ok:

                if udpbox_service_running():

                    flash(
                        "UDPBOX_APPLY_RESTART_OK"
                    )

                else:

                    flash(
                        "UDPBOX_APPLY_STOPPED_OK"
                    )

            else:

                flash(
                    "UDPBOX_ERROR: "
                    + error
                )

        else:

            flash(
                "UDPBOX_SAVE_OK"
            )


        return redirect(
            "/config/udpbox"
        )


    cfg = load_udpbox_config()

    active_cfg = load_udpbox_active_config()


    return render_template(
        "config_udpbox.html",
        cfg=cfg,
        catalog=UDPBOX_CATALOG,
        values=cfg.get(
            "options",
            {}
        ),
        running=udpbox_service_running(),
        enabled=udpbox_service_enabled(),
        command=udpbox_build_command(
            cfg,
            load_config()
        ),
        active_command=udpbox_build_command(
            active_cfg,
            load_active_config()
        ),
        journal=udpbox_journal()
    )



# UDPHUB
# ============================================================

UDPHUB_SERVICE = "dxlaprs-udphub.service"

UDPHUB_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udphub_config.json"
)

UDPHUB_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udphub_active_config.json"
)


UDPHUB_CATALOG = [

    {
        "flag": "-a",
        "it": "Routing utente-digi e utente-utente",
        "en": "User-to-digi and user-to-user routing",
        "syntax": "",
        "boolean": True,
        "help_it": "Abilita il routing sia utente-digi sia utente-utente.",
        "help_en": "Enables both user-to-digi and user-to-user routing."
    },

    {
        "flag": "-b",
        "it": "Destinazione broadcast",
        "en": "Broadcast destination",
        "syntax": "<call>",
        "help_it": "Nominativo AX.25 utilizzato come destinazione broadcast.",
        "help_en": "AX.25 callsign used as broadcast destination."
    },

    {
        "flag": "-d",
        "it": "Filtro duplicati",
        "en": "Duplicate filter",
        "syntax": "<millisecondi>",
        "help_it": "Scarta frame con lo stesso CRC entro l'intervallo indicato in millisecondi.",
        "help_en": "Discards frames with the same CRC within the specified interval in milliseconds."
    },

    {
        "flag": "-I",
        "it": "Broadcast INPUT nuovi utenti",
        "en": "New users broadcast INPUT",
        "syntax": "",
        "boolean": True,
        "help_it": "Abilita per i nuovi utenti la ricezione broadcast in ingresso.",
        "help_en": "Enables incoming broadcast reception for new users."
    },

    {
        "flag": "-i",
        "it": "File iniziale routing",
        "en": "Routing initialization file",
        "syntax": "<file>",
        "help_it": "Carica le rotte iniziali e le eventuali voci protette dal file.",
        "help_en": "Loads initial routes and optional protected entries from the file."
    },

    {
        "flag": "-l",
        "it": "Durata voci tabella",
        "en": "Table entry lifetime",
        "syntax": "<minuti>",
        "help_it": "Tempo di permanenza in minuti delle voci dinamiche della tabella.",
        "help_en": "Lifetime in minutes of dynamic routing table entries."
    },

    {
        "flag": "-m",
        "it": "Numero massimo voci",
        "en": "Maximum entries",
        "syntax": "<numero>",
        "help_it": "Numero massimo di voci; oltre il limite vengono eliminate le più vecchie.",
        "help_en": "Maximum number of entries; oldest entries are removed when exceeded."
    },

    {
        "flag": "-O",
        "it": "Broadcast OUTPUT nuovi utenti",
        "en": "New users broadcast OUTPUT",
        "syntax": "",
        "boolean": True,
        "help_it": "Abilita per i nuovi utenti il broadcast in uscita.",
        "help_en": "Enables outgoing broadcast for new users."
    },

    {
        "flag": "-p",
        "it": "Porta UDP utenti",
        "en": "User UDP port",
        "syntax": "<porta>",
        "help_it": "Porta UDP sulla quale udphub gestisce gli utenti.",
        "help_en": "UDP port used by udphub for users."
    },

    {
        "flag": "-u",
        "it": "Collegamento AXUDP digi",
        "en": "Digi AXUDP link",
        "syntax": "<ip>:<porta-destinazione>:<porta-ascolto>",
        "help_it": "Configura indirizzo, porta destinazione e porta di ascolto del collegamento AXUDP verso il digi.",
        "help_en": "Configures address, destination port and listen port of the AXUDP digi link."
    },

    {
        "flag": "-v",
        "it": "Verbose",
        "en": "Verbose",
        "syntax": "",
        "boolean": True,
        "help_it": "Abilita l'output diagnostico verbose.",
        "help_en": "Enables verbose diagnostic output."
    },

    {
        "flag": "-V",
        "it": "Verbose con testo frame",
        "en": "Verbose with frame text",
        "syntax": "",
        "boolean": True,
        "help_it": "Output verbose mostrando anche il testo dei frame.",
        "help_en": "Verbose output including frame text."
    },

    {
        "flag": "-w",
        "it": "Salvataggio tabella utenti",
        "en": "User table file",
        "syntax": "<file>",
        "help_it": "Scrive la tabella utenti nel file quando compaiono nuove voci, al massimo ogni 15 secondi.",
        "help_en": "Writes the user table when new entries appear, at most every 15 seconds."
    }

]

def load_udphub_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def load_udphub_config():

    return load_udphub_json(
        UDPHUB_CONFIG_FILE
    )


def load_udphub_active_config():

    if os.path.isfile(
        UDPHUB_ACTIVE_CONFIG_FILE
    ):
        return load_udphub_json(
            UDPHUB_ACTIVE_CONFIG_FILE
        )

    return load_udphub_config()


def save_udphub_config(cfg):

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    if os.path.isfile(
        UDPHUB_CONFIG_FILE
    ):

        stamp = datetime.now().strftime(
            "%Y%m%d-%H%M%S-%f"
        )

        shutil.copy2(
            UDPHUB_CONFIG_FILE,
            os.path.join(
                BACKUP_DIR,
                f"udphub-config-{stamp}.json"
            )
        )

    directory = os.path.dirname(
        UDPHUB_CONFIG_FILE
    )

    fd, tmp = tempfile.mkstemp(
        prefix="udphub-config-",
        suffix=".json",
        dir=directory
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                ensure_ascii=False,
                indent=2
            )

            f.write("\n")
            f.flush()
            os.fsync(
                f.fileno()
            )

        os.replace(
            tmp,
            UDPHUB_CONFIG_FILE
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def udphub_build_argv(cfg, manager_cfg=None):

    if manager_cfg is None:
        manager_cfg = load_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    if not bin_dir:
        binary = "udphub"
    else:
        binary = os.path.join(
            bin_dir,
            "udphub"
        )

    options = cfg.get(
        "options",
        {}
    )

    order = [
        "-a",
        "-b",
        "-d",
        "-I",
        "-i",
        "-l",
        "-m",
        "-O",
        "-p",
        "-u",
        "-v",
        "-V",
        "-w"
    ]


    boolean_flags = {
        "-a",
        "-I",
        "-O",
        "-v",
        "-V"
    }

    argv = [binary]

    for flag in order:

        item = options.get(
            flag,
            {}
        )

        if not item.get(
            "enabled"
        ):
            continue

        if flag in boolean_flags:

            argv.append(
                flag
            )

            continue

        if "values" in item:

            for value in item.get(
                "values",
                []
            ):

                value = str(
                    value
                ).strip()

                if value:

                    argv.extend(
                        [
                            flag,
                            value
                        ]
                    )

            continue

        value = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if value:

            argv.extend(
                [
                    flag,
                    value
                ]
            )

    return argv


def udphub_build_command(cfg, manager_cfg=None):

    return " ".join(
        shlex.quote(
            str(x)
        )
        for x in udphub_build_argv(
            cfg,
            manager_cfg
        )
    )


def udphub_config_has_options(cfg):

    return len(
        udphub_build_argv(
            cfg
        )
    ) > 1


def udphub_service_running():

    result = subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            UDPHUB_SERVICE
        ]
    )

    return result.returncode == 0


def udphub_service_enabled():

    result = subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            UDPHUB_SERVICE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def verify_udphub_service(timeout=10):

    deadline = time.time() + timeout

    while time.time() < deadline:

        state = subprocess.run(
            [
                "systemctl",
                "show",
                UDPHUB_SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--property=ExecMainStatus",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        values = state.stdout.splitlines()

        active_state = values[0].strip() if len(values) > 0 else ""
        sub_state = values[1].strip() if len(values) > 1 else ""
        exec_status = values[2].strip() if len(values) > 2 else ""

        # Configurazione partita e rimasta stabile.
        if active_state == "active" and sub_state == "running":

            time.sleep(2)

            stable = subprocess.run(
                [
                    "systemctl",
                    "is-active",
                    "--quiet",
                    UDPHUB_SERVICE
                ]
            )

            if stable.returncode == 0:
                return True, ""


        # Se systemd è già entrato nel ciclo di auto-restart,
        # non aspettiamo i retry: il candidato è fallito.
        if (
            active_state == "failed"
            or sub_state == "auto-restart"
        ):

            # Cancella immediatamente eventuale retry pendente.
            subprocess.run(
                [
                    "systemctl",
                    "stop",
                    UDPHUB_SERVICE
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            journal = subprocess.run(
                [
                    "journalctl",
                    "-u",
                    UDPHUB_SERVICE,
                    "-n",
                    "12",
                    "--no-pager"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            lines = [
                x.strip()
                for x in journal.stdout.splitlines()
                if x.strip()
            ]

            detail = ""

            for line in reversed(lines):

                if (
                    "error" in line.lower()
                    or "abort" in line.lower()
                    or "exited" in line.lower()
                ):
                    detail = line
                    break

            return (
                False,
                detail
                or (
                    "udphub terminato durante l'avvio"
                    + (
                        f" (exit status {exec_status})"
                        if exec_status
                        else ""
                    )
                )
            )

        time.sleep(0.25)


    return (
        False,
        "udphub non è diventato stabile entro il timeout"
    )


def start_udphub_service():

    cfg = load_udphub_active_config()

    if not udphub_config_has_options(
        cfg
    ):

        return (
            False,
            "Nessuna opzione udphub attiva nella configurazione applicata"
        )


    result = subprocess.run(
        [
            "systemctl",
            "start",
            UDPHUB_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'avvio di udphub"
        )


    return verify_udphub_service()


def stop_udphub_service():

    result = subprocess.run(
        [
            "systemctl",
            "stop",
            UDPHUB_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'arresto di udphub"
        )


    deadline = time.time() + 10

    while time.time() < deadline:

        if not udphub_service_running():

            return (
                True,
                ""
            )

        time.sleep(
            0.25
        )


    return (
        False,
        "udphub non si è arrestato entro il timeout"
    )


def restart_udphub_service():

    cfg = load_udphub_active_config()

    if not udphub_config_has_options(
        cfg
    ):

        return (
            False,
            "Nessuna opzione udphub attiva nella configurazione applicata"
        )


    result = subprocess.run(
        [
            "systemctl",
            "restart",
            UDPHUB_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante il riavvio di udphub"
        )


    return verify_udphub_service()


def apply_udphub_config():

    if not os.path.isfile(
        UDPHUB_CONFIG_FILE
    ):

        return (
            False,
            "udphub_config.json non trovato"
        )


    was_running = udphub_service_running()


    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )


    stamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )


    previous_active = os.path.join(
        BACKUP_DIR,
        f"udphub-active-before-apply-{stamp}.json"
    )


    if os.path.isfile(
        UDPHUB_ACTIVE_CONFIG_FILE
    ):

        shutil.copy2(
            UDPHUB_ACTIVE_CONFIG_FILE,
            previous_active
        )

    else:

        shutil.copy2(
            UDPHUB_CONFIG_FILE,
            previous_active
        )


    try:

        atomic_copy_file(
            UDPHUB_CONFIG_FILE,
            UDPHUB_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            "Impossibile creare udphub_active_config.json: "
            + str(exc)
        )


    # Se il componente era fermo, l'applicazione
    # aggiorna semplicemente la configurazione attiva.
    if not was_running:

        return (
            True,
            ""
        )


    ok, error = restart_udphub_service()

    if ok:

        return (
            True,
            ""
        )


    first_error = error


    try:

        atomic_copy_file(
            previous_active,
            UDPHUB_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            first_error
            + " - ATTENZIONE: impossibile ripristinare "
            + "udphub_active_config.json: "
            + str(exc)
        )


    rollback_ok, rollback_error = (
        restart_udphub_service()
    )


    if rollback_ok:

        return (
            False,
            first_error
            + " - configurazione udphub precedente "
            + "ripristinata automaticamente. "
            + "Le modifiche restano salvate nel draft."
        )


    return (
        False,
        first_error
        + " - ATTENZIONE: anche il rollback udphub "
        + "non è riuscito: "
        + rollback_error
    )


def udphub_journal():

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            UDPHUB_SERVICE,
            "-n",
            "30",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    return (
        result.stdout.strip()
        or "Nessun log disponibile."
    )


def update_udphub_from_form(cfg):

    options = cfg.setdefault(
        "options",
        {}
    )


    for item in UDPHUB_CATALOG:

        flag = item["flag"]

        state = options.setdefault(
            flag,
            {}
        )

        state["enabled"] = (
            f"enabled_{flag}"
            in request.form
        )


        if item.get(
            "boolean"
        ):

            state.pop(
                "value",
                None
            )

            state.pop(
                "values",
                None
            )

            continue


        if item.get(
            "repeat"
        ):

            text = request.form.get(
                f"value_{flag}",
                ""
            )

            state["values"] = [
                line.strip()
                for line in text.splitlines()
                if line.strip()
            ]

            state.pop(
                "value",
                None
            )

            continue


        state["value"] = request.form.get(
            f"value_{flag}",
            ""
        ).strip()


    return cfg


@app.route(
    "/config/udphub",
    methods=[
        "GET",
        "POST"
    ]
)
def config_udphub():

    cfg = load_udphub_config()


    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )


        # --------------------------------------------
        # Azioni service: NON usano modifiche
        # eventualmente presenti ma non salvate.
        # --------------------------------------------

        if action == "start":

            ok, error = start_udphub_service()

            if ok:

                flash(
                    "UDPHUB_START_OK"
                )

            else:

                flash(
                    "UDPHUB_ERROR: "
                    + error
                )

            return redirect(
                "/config/udphub"
            )


        if action == "stop":

            ok, error = stop_udphub_service()

            if ok:

                flash(
                    "UDPHUB_STOP_OK"
                )

            else:

                flash(
                    "UDPHUB_ERROR: "
                    + error
                )

            return redirect(
                "/config/udphub"
            )


        if action == "restart":

            ok, error = restart_udphub_service()

            if ok:

                flash(
                    "UDPHUB_RESTART_OK"
                )

            else:

                flash(
                    "UDPHUB_ERROR: "
                    + error
                )

            return redirect(
                "/config/udphub"
            )


        # --------------------------------------------
        # SAVE / APPLY
        # --------------------------------------------

        cfg = update_udphub_from_form(
            cfg
        )

        save_udphub_config(
            cfg
        )


        if action == "apply":

            ok, error = apply_udphub_config()

            if ok:

                if udphub_service_running():

                    flash(
                        "UDPHUB_APPLY_RESTART_OK"
                    )

                else:

                    flash(
                        "UDPHUB_APPLY_STOPPED_OK"
                    )

            else:

                flash(
                    "UDPHUB_ERROR: "
                    + error
                )

        else:

            flash(
                "UDPHUB_SAVE_OK"
            )


        return redirect(
            "/config/udphub"
        )


    cfg = load_udphub_config()

    active_cfg = load_udphub_active_config()


    return render_template(
        "config_udphub.html",
        cfg=cfg,
        catalog=UDPHUB_CATALOG,
        values=cfg.get(
            "options",
            {}
        ),
        running=udphub_service_running(),
        enabled=udphub_service_enabled(),
        command=udphub_build_command(
            cfg,
            load_config()
        ),
        active_command=udphub_build_command(
            active_cfg,
            load_active_config()
        ),
        journal=udphub_journal()
    )



# UDPFLEX
# ============================================================

UDPFLEX_SERVICE = "dxlaprs-udpflex.service"

UDPFLEX_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udpflex_config.json"
)

UDPFLEX_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udpflex_active_config.json"
)


UDPFLEX_CATALOG = [

    {
        "flag": "-A",
        "it": "Modalità ASCII TAPR",
        "en": "ASCII TAPR mode",
        "syntax": "",
        "boolean": True,
        "help_it": "Utilizza la modalità ASCII TAPR.",
        "help_en": "Uses ASCII TAPR mode."
    },

    {
        "flag": "-a",
        "it": "Selezione automatica KISS/FLEX/SMACK",
        "en": "Automatic KISS/FLEX/SMACK selection",
        "syntax": "",
        "boolean": True,
        "help_it": "Seleziona automaticamente KISS, FLEX o SMACK. Utilizzabile soltanto con una porta.",
        "help_en": "Automatically switches to KISS, FLEX or SMACK mode. Only usable with one port."
    },

    {
        "flag": "-d",
        "it": "Ritardo inizializzazione KISS",
        "en": "KISS initialization delay",
        "syntax": "<ms>",
        "help_it": "Ritardo in millisecondi tra l'attivazione KISS e l'invio dei parametri -p. Default del programma: 2500 ms.",
        "help_en": "Delay in milliseconds between enabling KISS and sending -p parameters. Program default: 2500 ms."
    },

    {
        "flag": "-i",
        "it": "File inizializzazione TTY",
        "en": "TTY initialization file",
        "syntax": "<file>",
        "help_it": "Invia il contenuto del file alla TTY per attivare la modalità KISS.",
        "help_en": "Sends the file contents to the TTY to enable KISS mode."
    },

    {
        "flag": "-K",
        "it": "TCP keepalive",
        "en": "TCP keepalive",
        "syntax": "<idle>:<intervallo>:<conteggio>",
        "help_it": "Parametri TCP keepalive: tempo idle, intervallo e numero tentativi in secondi. Default indicato dal programma: 180:30:2.",
        "help_en": "TCP keepalive idle time, interval and count in seconds. Program default shown as 180:30:2."
    },

    {
        "flag": "-k",
        "it": "Attiva KISS TNC2/TF",
        "en": "Enable TNC2/TF KISS",
        "syntax": "",
        "boolean": True,
        "help_it": "Invia al TNC2/TF il comando per attivare la modalità KISS.",
        "help_en": "Switches a TNC2/TF device into KISS mode."
    },

    {
        "flag": "-p",
        "it": "Parametro TNC2/KISS",
        "en": "TNC2/KISS parameter",
        "syntax": "<comando>:<valore>",
        "repeat": True,
        "help_it": "Parametro TNC2/KISS ripetibile. Esempi del programma: 1=TX delay, 2=persistence, 3=slot time, 128:0 abilita SMACK, 255:13 esce da KISS.",
        "help_en": "Repeatable TNC2/KISS parameter. Examples: 1=TX delay, 2=persistence, 3=slot time, 128:0 enables SMACK, 255:13 exits KISS."
    },

    {
        "flag": "-r",
        "it": "CRC RMNC",
        "en": "RMNC CRC",
        "syntax": "",
        "boolean": True,
        "help_it": "Utilizza il CRC RMNC.",
        "help_en": "Uses RMNC CRC."
    },

    {
        "flag": "-s",
        "it": "SMACK CRC",
        "en": "SMACK CRC",
        "syntax": "",
        "boolean": True,
        "help_it": "Abilita la modalità SMACK con CRC.",
        "help_en": "Enables SMACK mode with CRC."
    },

    {
        "flag": "-t",
        "it": "TTY / pipe",
        "en": "TTY / pipe",
        "syntax": "<tty>:<baud>",
        "help_it": "Interfaccia seriale e baud rate, ad esempio /dev/ttyS0:9600, oppure nome di una pipe.",
        "help_en": "Serial interface and baud rate, for example /dev/ttyS0:9600, or a pipe filename."
    },

    {
        "flag": "-T",
        "it": "TCP-KISS",
        "en": "TCP-KISS",
        "syntax": "[ip]:[porta]",
        "help_it": "Connessione TCP-KISS, ad esempio verso Dire Wolf. Con 0.0.0.0:<porta> udpflex resta in ascolto per una connessione TCP-KISS.",
        "help_en": "TCP-KISS connection, for example to Dire Wolf. With 0.0.0.0:<port>, udpflex listens for a TCP-KISS connection."
    },

    {
        "flag": "-U",
        "it": "Porta AXUDP",
        "en": "AXUDP port",
        "syntax": "<ip>:<porta-destinazione>:<porta-ascolto>",
        "repeat": True,
        "help_it": "Collegamento AXUDP ripetibile per configurare più porte.",
        "help_en": "Repeatable AXUDP link for configuring multiple ports."
    },

    {
        "flag": "-u",
        "it": "Riconnessione automatica TTY",
        "en": "Automatic TTY reconnect",
        "syntax": "",
        "boolean": True,
        "help_it": "Riprova automaticamente dopo il reinserimento di una TTY USB e reinizializza KISS in caso di errore.",
        "help_en": "Automatically retries after a USB TTY is replugged and reinitializes KISS after errors."
    },

    {
        "flag": "-v",
        "it": "Errori verbose",
        "en": "Verbose errors",
        "syntax": "",
        "boolean": True,
        "help_it": "Mostra messaggi di errore dettagliati.",
        "help_en": "Shows verbose error messages."
    },

    {
        "flag": "-V",
        "it": "Verbose e monitor frame",
        "en": "Verbose and frame monitor",
        "syntax": "",
        "boolean": True,
        "help_it": "Mostra errori dettagliati e dati monitorati su stdout.",
        "help_en": "Shows verbose errors and monitored data on stdout."
    }

]

def load_udpflex_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def load_udpflex_config():

    return load_udpflex_json(
        UDPFLEX_CONFIG_FILE
    )


def load_udpflex_active_config():

    if os.path.isfile(
        UDPFLEX_ACTIVE_CONFIG_FILE
    ):
        return load_udpflex_json(
            UDPFLEX_ACTIVE_CONFIG_FILE
        )

    return load_udpflex_config()


def save_udpflex_config(cfg):

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    if os.path.isfile(
        UDPFLEX_CONFIG_FILE
    ):

        stamp = datetime.now().strftime(
            "%Y%m%d-%H%M%S-%f"
        )

        shutil.copy2(
            UDPFLEX_CONFIG_FILE,
            os.path.join(
                BACKUP_DIR,
                f"udpflex-config-{stamp}.json"
            )
        )

    directory = os.path.dirname(
        UDPFLEX_CONFIG_FILE
    )

    fd, tmp = tempfile.mkstemp(
        prefix="udpflex-config-",
        suffix=".json",
        dir=directory
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                ensure_ascii=False,
                indent=2
            )

            f.write("\n")
            f.flush()
            os.fsync(
                f.fileno()
            )

        os.replace(
            tmp,
            UDPFLEX_CONFIG_FILE
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def udpflex_build_argv(cfg, manager_cfg=None):

    if manager_cfg is None:
        manager_cfg = load_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    if not bin_dir:
        binary = "udpflex"
    else:
        binary = os.path.join(
            bin_dir,
            "udpflex"
        )

    options = cfg.get(
        "options",
        {}
    )

    order = [
        "-A",
        "-a",
        "-d",
        "-i",
        "-K",
        "-k",
        "-p",
        "-r",
        "-s",
        "-t",
        "-T",
        "-U",
        "-u",
        "-v",
        "-V"
    ]


    boolean_flags = {
        "-A",
        "-a",
        "-k",
        "-r",
        "-s",
        "-u",
        "-v",
        "-V"
    }

    argv = [binary]

    for flag in order:

        item = options.get(
            flag,
            {}
        )

        if not item.get(
            "enabled"
        ):
            continue

        if flag in boolean_flags:

            argv.append(
                flag
            )

            continue

        if "values" in item:

            for value in item.get(
                "values",
                []
            ):

                value = str(
                    value
                ).strip()

                if value:

                    argv.extend(
                        [
                            flag,
                            value
                        ]
                    )

            continue

        value = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if value:

            argv.extend(
                [
                    flag,
                    value
                ]
            )

    return argv


def udpflex_build_command(cfg, manager_cfg=None):

    return " ".join(
        shlex.quote(
            str(x)
        )
        for x in udpflex_build_argv(
            cfg,
            manager_cfg
        )
    )


def udpflex_config_has_options(cfg):

    return len(
        udpflex_build_argv(
            cfg
        )
    ) > 1


def udpflex_service_running():

    result = subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            UDPFLEX_SERVICE
        ]
    )

    return result.returncode == 0


def udpflex_service_enabled():

    result = subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            UDPFLEX_SERVICE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def verify_udpflex_service(timeout=10):

    deadline = time.time() + timeout

    while time.time() < deadline:

        state = subprocess.run(
            [
                "systemctl",
                "show",
                UDPFLEX_SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--property=ExecMainStatus",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        values = state.stdout.splitlines()

        active_state = values[0].strip() if len(values) > 0 else ""
        sub_state = values[1].strip() if len(values) > 1 else ""
        exec_status = values[2].strip() if len(values) > 2 else ""

        # Configurazione partita e rimasta stabile.
        if active_state == "active" and sub_state == "running":

            time.sleep(2)

            stable = subprocess.run(
                [
                    "systemctl",
                    "is-active",
                    "--quiet",
                    UDPFLEX_SERVICE
                ]
            )

            if stable.returncode == 0:
                return True, ""


        # Se systemd è già entrato nel ciclo di auto-restart,
        # non aspettiamo i retry: il candidato è fallito.
        if (
            active_state == "failed"
            or sub_state == "auto-restart"
        ):

            # Cancella immediatamente eventuale retry pendente.
            subprocess.run(
                [
                    "systemctl",
                    "stop",
                    UDPFLEX_SERVICE
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            journal = subprocess.run(
                [
                    "journalctl",
                    "-u",
                    UDPFLEX_SERVICE,
                    "-n",
                    "12",
                    "--no-pager"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            lines = [
                x.strip()
                for x in journal.stdout.splitlines()
                if x.strip()
            ]

            detail = ""

            for line in reversed(lines):

                if (
                    "error" in line.lower()
                    or "abort" in line.lower()
                    or "exited" in line.lower()
                ):
                    detail = line
                    break

            return (
                False,
                detail
                or (
                    "udpflex terminato durante l'avvio"
                    + (
                        f" (exit status {exec_status})"
                        if exec_status
                        else ""
                    )
                )
            )

        time.sleep(0.25)


    return (
        False,
        "udpflex non è diventato stabile entro il timeout"
    )


def start_udpflex_service():

    cfg = load_udpflex_active_config()

    if not udpflex_config_has_options(
        cfg
    ):

        return (
            False,
            "Nessuna opzione udpflex attiva nella configurazione applicata"
        )


    result = subprocess.run(
        [
            "systemctl",
            "start",
            UDPFLEX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'avvio di udpflex"
        )


    return verify_udpflex_service()


def stop_udpflex_service():

    result = subprocess.run(
        [
            "systemctl",
            "stop",
            UDPFLEX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'arresto di udpflex"
        )


    deadline = time.time() + 10

    while time.time() < deadline:

        if not udpflex_service_running():

            return (
                True,
                ""
            )

        time.sleep(
            0.25
        )


    return (
        False,
        "udpflex non si è arrestato entro il timeout"
    )


def restart_udpflex_service():

    cfg = load_udpflex_active_config()

    if not udpflex_config_has_options(
        cfg
    ):

        return (
            False,
            "Nessuna opzione udpflex attiva nella configurazione applicata"
        )


    result = subprocess.run(
        [
            "systemctl",
            "restart",
            UDPFLEX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante il riavvio di udpflex"
        )


    return verify_udpflex_service()


def apply_udpflex_config():

    if not os.path.isfile(
        UDPFLEX_CONFIG_FILE
    ):

        return (
            False,
            "udpflex_config.json non trovato"
        )


    was_running = udpflex_service_running()


    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )


    stamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )


    previous_active = os.path.join(
        BACKUP_DIR,
        f"udpflex-active-before-apply-{stamp}.json"
    )


    if os.path.isfile(
        UDPFLEX_ACTIVE_CONFIG_FILE
    ):

        shutil.copy2(
            UDPFLEX_ACTIVE_CONFIG_FILE,
            previous_active
        )

    else:

        shutil.copy2(
            UDPFLEX_CONFIG_FILE,
            previous_active
        )


    try:

        atomic_copy_file(
            UDPFLEX_CONFIG_FILE,
            UDPFLEX_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            "Impossibile creare udpflex_active_config.json: "
            + str(exc)
        )


    # Se il componente era fermo, l'applicazione
    # aggiorna semplicemente la configurazione attiva.
    if not was_running:

        return (
            True,
            ""
        )


    ok, error = restart_udpflex_service()

    if ok:

        return (
            True,
            ""
        )


    first_error = error


    try:

        atomic_copy_file(
            previous_active,
            UDPFLEX_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            first_error
            + " - ATTENZIONE: impossibile ripristinare "
            + "udpflex_active_config.json: "
            + str(exc)
        )


    rollback_ok, rollback_error = (
        restart_udpflex_service()
    )


    if rollback_ok:

        return (
            False,
            first_error
            + " - configurazione udpflex precedente "
            + "ripristinata automaticamente. "
            + "Le modifiche restano salvate nel draft."
        )


    return (
        False,
        first_error
        + " - ATTENZIONE: anche il rollback udpflex "
        + "non è riuscito: "
        + rollback_error
    )


def udpflex_journal():

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            UDPFLEX_SERVICE,
            "-n",
            "30",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    return (
        result.stdout.strip()
        or "Nessun log disponibile."
    )


def update_udpflex_from_form(cfg):

    options = cfg.setdefault(
        "options",
        {}
    )


    for item in UDPFLEX_CATALOG:

        flag = item["flag"]

        state = options.setdefault(
            flag,
            {}
        )

        state["enabled"] = (
            f"enabled_{flag}"
            in request.form
        )


        if item.get(
            "boolean"
        ):

            state.pop(
                "value",
                None
            )

            state.pop(
                "values",
                None
            )

            continue


        if item.get(
            "repeat"
        ):

            text = request.form.get(
                f"value_{flag}",
                ""
            )

            state["values"] = [
                line.strip()
                for line in text.splitlines()
                if line.strip()
            ]

            state.pop(
                "value",
                None
            )

            continue


        state["value"] = request.form.get(
            f"value_{flag}",
            ""
        ).strip()


    return cfg


@app.route(
    "/config/udpflex",
    methods=[
        "GET",
        "POST"
    ]
)
def config_udpflex():

    cfg = load_udpflex_config()


    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )


        # --------------------------------------------
        # Azioni service: NON usano modifiche
        # eventualmente presenti ma non salvate.
        # --------------------------------------------

        if action == "start":

            ok, error = start_udpflex_service()

            if ok:

                flash(
                    "UDPFLEX_START_OK"
                )

            else:

                flash(
                    "UDPFLEX_ERROR: "
                    + error
                )

            return redirect(
                "/config/udpflex"
            )


        if action == "stop":

            ok, error = stop_udpflex_service()

            if ok:

                flash(
                    "UDPFLEX_STOP_OK"
                )

            else:

                flash(
                    "UDPFLEX_ERROR: "
                    + error
                )

            return redirect(
                "/config/udpflex"
            )


        if action == "restart":

            ok, error = restart_udpflex_service()

            if ok:

                flash(
                    "UDPFLEX_RESTART_OK"
                )

            else:

                flash(
                    "UDPFLEX_ERROR: "
                    + error
                )

            return redirect(
                "/config/udpflex"
            )


        # --------------------------------------------
        # SAVE / APPLY
        # --------------------------------------------

        cfg = update_udpflex_from_form(
            cfg
        )

        save_udpflex_config(
            cfg
        )


        if action == "apply":

            ok, error = apply_udpflex_config()

            if ok:

                if udpflex_service_running():

                    flash(
                        "UDPFLEX_APPLY_RESTART_OK"
                    )

                else:

                    flash(
                        "UDPFLEX_APPLY_STOPPED_OK"
                    )

            else:

                flash(
                    "UDPFLEX_ERROR: "
                    + error
                )

        else:

            flash(
                "UDPFLEX_SAVE_OK"
            )


        return redirect(
            "/config/udpflex"
        )


    cfg = load_udpflex_config()

    active_cfg = load_udpflex_active_config()


    return render_template(
        "config_udpflex.html",
        cfg=cfg,
        catalog=UDPFLEX_CATALOG,
        values=cfg.get(
            "options",
            {}
        ),
        running=udpflex_service_running(),
        enabled=udpflex_service_enabled(),
        command=udpflex_build_command(
            cfg,
            load_config()
        ),
        active_command=udpflex_build_command(
            active_cfg,
            load_active_config()
        ),
        journal=udpflex_journal()
    )





# =============================================================================

# LORATX
# ============================================================

LORATX_SERVICE = "dxlaprs-loratx.service"

LORATX_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "loratx_config.json"
)

LORATX_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "loratx_active_config.json"
)


LORATX_CATALOG = [

    {
        "flag": "-i",
        "group": "io",
        "it": "File di ingresso",
        "en": "Input file",
        "syntax": "<file>",
        "placeholder": "<input-file>",
        "help_it": "File contenente il testo o i byte da codificare. Necessario per avviare loratx.",
        "help_en": "File containing the text or bytes to encode. Required to start loratx."
    },

    {
        "flag": "-o",
        "group": "io",
        "it": "File IQ di uscita",
        "en": "Output IQ file",
        "syntax": "<file>",
        "placeholder": "<output-file>",
        "help_it": "File IQ generato da loratx. Necessario per avviare il programma.",
        "help_en": "IQ file generated by loratx. Required to start the program."
    },

    {
        "flag": "-f",
        "group": "io",
        "it": "Formato IQ",
        "en": "IQ format",
        "syntax": "<u8|i16|f32>",
        "select": ["u8", "i16", "f32"],
        "help_it": "Formato dei campioni IQ in uscita. Default del programma: u8.",
        "help_en": "Output IQ sample format. Program default: u8."
    },

    {
        "flag": "-r",
        "group": "io",
        "it": "Sample rate",
        "en": "Sample rate",
        "syntax": "<Hz>",
        "placeholder": "125000",
        "help_it": "Frequenza di campionamento IQ in Hz. Deve essere maggiore di zero e almeno pari alla larghezza di banda.",
        "help_en": "IQ sample rate in Hz. Must be greater than zero and at least equal to the bandwidth."
    },


    {
        "flag": "-b",
        "group": "lora",
        "it": "Larghezza di banda",
        "en": "Bandwidth",
        "syntax": "<indice|Hz>",
        "placeholder": "7",
        "help_it": "Indice 0..9 oppure valore diretto in Hz. Indici: 0=7.8, 1=10.4, 2=15.6, 3=20.8, 4=31.25, 5=41.7, 6=62.5, 7=125, 8=250, 9=500 kHz.",
        "help_en": "Index 0..9 or direct value in Hz. Indexes: 0=7.8, 1=10.4, 2=15.6, 3=20.8, 4=31.25, 5=41.7, 6=62.5, 7=125, 8=250, 9=500 kHz."
    },

    {
        "flag": "-s",
        "group": "lora",
        "it": "Spread factor",
        "en": "Spread factor",
        "syntax": "<SF>",
        "placeholder": "12",
        "help_it": "Spread factor 5..12. Il parser accetta anche -5..-12: il valore negativo abilita l'inversione IQ.",
        "help_en": "Spread factor 5..12. The parser also accepts -5..-12: a negative value enables IQ inversion."
    },

    {
        "flag": "-c",
        "group": "lora",
        "it": "Coding rate",
        "en": "Coding rate",
        "syntax": "<4..8>",
        "placeholder": "5",
        "help_it": "Coding rate LoRa da 4 a 8. Default del programma: 5.",
        "help_en": "LoRa coding rate from 4 to 8. Program default: 5."
    },

    {
        "flag": "-C",
        "group": "lora",
        "it": "CRC",
        "en": "CRC",
        "syntax": "",
        "boolean": True,
        "help_it": "Aggiunge il CRC al frame LoRa.",
        "help_en": "Adds CRC to the LoRa frame."
    },

    {
        "flag": "-I",
        "group": "lora",
        "it": "Header implicito",
        "en": "Implicit header",
        "syntax": "",
        "boolean": True,
        "help_it": "Utilizza la modalità implicit header. Necessaria con SF 5 o 6.",
        "help_en": "Uses implicit header mode. Required with SF 5 or 6."
    },

    {
        "flag": "-N",
        "group": "lora",
        "it": "Network ID / sync symbols",
        "en": "Network ID / sync symbols",
        "syntax": "<hex>",
        "placeholder": "12",
        "help_it": "Network ID / simboli di sincronizzazione espressi in esadecimale.",
        "help_en": "Network ID / synchronization symbols expressed in hexadecimal."
    },

    {
        "flag": "-O",
        "group": "lora",
        "it": "Optimize",
        "en": "Optimize",
        "syntax": "<0|1>",
        "placeholder": "1",
        "help_it": "Forza l'ottimizzazione LoRa: 0 disabilitata, 1 abilitata. Se non configurata viene scelta automaticamente.",
        "help_en": "Forces LoRa optimization: 0 disabled, 1 enabled. When not configured it is selected automatically."
    },

    {
        "flag": "-p",
        "group": "lora",
        "it": "Lunghezza preambolo",
        "en": "Preamble length",
        "syntax": "<chirps>",
        "placeholder": "8",
        "help_it": "Numero di chirp del preambolo. Default del programma: 8.",
        "help_en": "Number of preamble chirps. Program default: 8."
    },

    {
        "flag": "-q",
        "group": "lora",
        "it": "Inverti IQ",
        "en": "Invert IQ",
        "syntax": "",
        "boolean": True,
        "help_it": "Inverte I e Q. Può essere attivato anche utilizzando uno spread factor negativo.",
        "help_en": "Inverts I and Q. It can also be enabled by using a negative spread factor."
    },

    {
        "flag": "-j",
        "group": "lora",
        "it": "Prefisso 3C FF 01",
        "en": "3C FF 01 prefix",
        "syntax": "",
        "boolean": True,
        "help_it": "Inserisce i byte esadecimali 3C FF 01 prima del testo.",
        "help_en": "Inserts hexadecimal bytes 3C FF 01 before the text."
    },


    {
        "flag": "-g",
        "group": "signal",
        "it": "Guadagno uscita",
        "en": "Output gain",
        "syntax": "<fattore>",
        "placeholder": "1.0",
        "help_it": "Livello del segnale in uscita. Normalmente 0.0..1.0; con formato f32 sono possibili valori superiori.",
        "help_en": "Output signal level. Normally 0.0..1.0; values above 1 are possible with f32 output."
    },

    {
        "flag": "-S",
        "group": "signal",
        "it": "Shift di frequenza",
        "en": "Frequency shift",
        "syntax": "<Hz>",
        "placeholder": "0",
        "help_it": "Sposta il segnale all'interno della banda IQ della quantità indicata in Hz.",
        "help_en": "Shifts the signal inside the IQ band by the specified number of Hz."
    },


    {
        "flag": "-B",
        "group": "test",
        "it": "Tono interferente",
        "en": "Interfering tone",
        "syntax": "<Hz> <livello>",
        "repeat": True,
        "placeholder": "1000 0.2\n-1500 0.1",
        "help_it": "Aggiunge uno o più toni interferenti. Opzione ripetibile: una coppia Hz/livello per riga.",
        "help_en": "Adds one or more interfering tones. Repeatable option: one Hz/level pair per line."
    },

    {
        "flag": "-E",
        "group": "test",
        "it": "Eco multipath",
        "en": "Multipath echo",
        "syntax": "<ritardo-s> <gain>",
        "placeholder": "0.0005 0.5",
        "help_it": "Aggiunge un eco con ritardo in secondi e guadagno. Il ritardo viene quantizzato a campioni interi.",
        "help_en": "Adds an echo with delay in seconds and gain. Delay is quantized to whole sample steps."
    },

    {
        "flag": "-P",
        "group": "test",
        "it": "Rumore impulsivo",
        "en": "Pulse noise",
        "syntax": "<durata> <densità> <livello>",
        "placeholder": "4 0.5 0.9",
        "help_it": "Aggiunge impulsi di rumore specificando durata in campioni, densità casuale e livello.",
        "help_en": "Adds pulse noise specifying duration in samples, random density and level."
    },

    {
        "flag": "-R",
        "group": "test",
        "it": "Seed casuale",
        "en": "Random seed",
        "syntax": "<x>",
        "placeholder": "0.0",
        "help_it": "Seed utilizzato per la generazione del rumore casuale.",
        "help_en": "Seed used for random noise generation."
    },

    {
        "flag": "-T",
        "group": "test",
        "it": "Test FEC / chirp",
        "en": "FEC / chirp test",
        "syntax": "<n> <shift>",
        "repeat": True,
        "placeholder": "10 0\n20 -1",
        "help_it": "Modifica il chirp numero n per test FEC. Opzione ripetibile: una coppia n/shift per riga.",
        "help_en": "Modifies chirp number n for FEC tests. Repeatable option: one n/shift pair per line."
    },

    {
        "flag": "-w",
        "group": "test",
        "it": "Rumore bianco",
        "en": "White noise",
        "syntax": "<livello>",
        "placeholder": "0.1",
        "help_it": "Aggiunge rumore bianco con il livello indicato.",
        "help_en": "Adds white noise at the specified level."
    },

    {
        "flag": "-Z",
        "group": "test",
        "it": "Chirp prima dei dati",
        "en": "Chirps before data",
        "syntax": "<n>",
        "placeholder": "0",
        "help_it": "Aggiunge chirp a zero o di rumore prima dei dati.",
        "help_en": "Adds zero or noise chirps before the data."
    },

    {
        "flag": "-z",
        "group": "test",
        "it": "Chirp finali",
        "en": "Trailing chirps",
        "syntax": "<n>",
        "placeholder": "0",
        "help_it": "Aggiunge chirp a zero o di rumore alla fine.",
        "help_en": "Adds zero or noise chirps at the end."
    },


    {
        "flag": "-H",
        "group": "debug",
        "it": "Input esadecimale",
        "en": "Hexadecimal input",
        "syntax": "",
        "boolean": True,
        "help_it": "Interpreta il contenuto del file di ingresso come testo esadecimale.",
        "help_en": "Interprets the input file contents as hexadecimal text."
    },

    {
        "flag": "-v",
        "group": "debug",
        "it": "Verbose",
        "en": "Verbose",
        "syntax": "",
        "boolean": True,
        "help_it": "Abilita le informazioni diagnostiche.",
        "help_en": "Enables diagnostic information."
    },

    {
        "flag": "-V",
        "group": "debug",
        "it": "Verbose esteso",
        "en": "Extended verbose",
        "syntax": "",
        "boolean": True,
        "help_it": "Abilita un livello di diagnostica più dettagliato.",
        "help_en": "Enables a more detailed diagnostic level."
    }
]


LORATX_BOOLEAN_FLAGS = {
    "-C",
    "-H",
    "-I",
    "-j",
    "-q",
    "-v",
    "-V"
}


LORATX_ARITY = {
    "-B": 2,
    "-E": 2,
    "-P": 3,
    "-T": 2
}


LORATX_ORDER = [
    "-i",
    "-o",
    "-f",
    "-r",
    "-b",
    "-s",
    "-c",
    "-C",
    "-I",
    "-N",
    "-O",
    "-p",
    "-q",
    "-j",
    "-g",
    "-S",
    "-B",
    "-E",
    "-P",
    "-R",
    "-T",
    "-w",
    "-Z",
    "-z",
    "-H",
    "-v",
    "-V"
]


def load_loratx_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def load_loratx_config():

    return load_loratx_json(
        LORATX_CONFIG_FILE
    )


def load_loratx_active_config():

    if os.path.isfile(
        LORATX_ACTIVE_CONFIG_FILE
    ):

        return load_loratx_json(
            LORATX_ACTIVE_CONFIG_FILE
        )

    return load_loratx_config()


def save_loratx_config(cfg):

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    if os.path.isfile(
        LORATX_CONFIG_FILE
    ):

        stamp = datetime.now().strftime(
            "%Y%m%d-%H%M%S-%f"
        )

        shutil.copy2(
            LORATX_CONFIG_FILE,
            os.path.join(
                BACKUP_DIR,
                f"loratx-config-{stamp}.json"
            )
        )

    directory = os.path.dirname(
        LORATX_CONFIG_FILE
    )

    fd, tmp = tempfile.mkstemp(
        prefix="loratx-config-",
        suffix=".json",
        dir=directory
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                ensure_ascii=False,
                indent=2
            )

            f.write("\n")
            f.flush()
            os.fsync(
                f.fileno()
            )

        os.replace(
            tmp,
            LORATX_CONFIG_FILE
        )

    finally:

        if os.path.exists(
            tmp
        ):
            os.unlink(
                tmp
            )


def loratx_parse_args(flag, value):

    try:

        parts = shlex.split(
            str(value)
        )

    except ValueError:

        return []

    wanted = LORATX_ARITY.get(
        flag
    )

    if wanted and len(parts) != wanted:
        return []

    return parts


def loratx_build_argv(cfg, manager_cfg=None):

    if manager_cfg is None:
        manager_cfg = load_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    if not bin_dir:
        binary = "loratx"
    else:
        binary = os.path.join(
            bin_dir,
            "loratx"
        )

    options = cfg.get(
        "options",
        {}
    )

    argv = [
        binary
    ]

    for flag in LORATX_ORDER:

        item = options.get(
            flag,
            {}
        )

        if not item.get(
            "enabled"
        ):
            continue

        if flag in LORATX_BOOLEAN_FLAGS:

            argv.append(
                flag
            )

            continue

        if "values" in item:

            for value in item.get(
                "values",
                []
            ):

                value = str(
                    value
                ).strip()

                if not value:
                    continue

                parts = loratx_parse_args(
                    flag,
                    value
                )

                if parts:

                    argv.append(
                        flag
                    )

                    argv.extend(
                        parts
                    )

            continue

        value = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if not value:
            continue

        argv.append(
            flag
        )

        if flag in LORATX_ARITY:

            parts = loratx_parse_args(
                flag,
                value
            )

            if parts:
                argv.extend(
                    parts
                )

            else:
                argv.pop()

        else:

            argv.append(
                value
            )

    return argv


def loratx_build_command(cfg, manager_cfg=None):

    return " ".join(
        shlex.quote(
            str(x)
        )
        for x in loratx_build_argv(
            cfg,
            manager_cfg
        )
    )


def loratx_validate_config(cfg):

    options = cfg.get(
        "options",
        {}
    )

    for flag in (
        "-i",
        "-o"
    ):

        item = options.get(
            flag,
            {}
        )

        if not item.get(
            "enabled"
        ) or not str(
            item.get(
                "value",
                ""
            )
        ).strip():

            return (
                False,
                f"{flag} non configurato"
            )

    for flag, arity in LORATX_ARITY.items():

        item = options.get(
            flag,
            {}
        )

        if not item.get(
            "enabled"
        ):
            continue

        if "values" in item:

            values = item.get(
                "values",
                []
            )

            for value in values:

                if len(
                    loratx_parse_args(
                        flag,
                        value
                    )
                ) != arity:

                    return (
                        False,
                        f"{flag} richiede {arity} valori"
                    )

        else:

            value = str(
                item.get(
                    "value",
                    ""
                )
            ).strip()

            if len(
                loratx_parse_args(
                    flag,
                    value
                )
            ) != arity:

                return (
                    False,
                    f"{flag} richiede {arity} valori"
                )

    value = options.get(
        "-f",
        {}
    )

    if value.get(
        "enabled"
    ):

        if value.get(
            "value"
        ) not in {
            "u8",
            "i16",
            "f32"
        }:

            return (
                False,
                "-f deve essere u8, i16 oppure f32"
            )

    value = options.get(
        "-c",
        {}
    )

    if value.get(
        "enabled"
    ):

        try:
            cr = int(
                value.get(
                    "value",
                    ""
                )
            )
        except Exception:
            return (
                False,
                "-c non valido"
            )

        if cr < 4 or cr > 8:
            return (
                False,
                "-c deve essere compreso tra 4 e 8"
            )

    value = options.get(
        "-s",
        {}
    )

    if value.get(
        "enabled"
    ):

        try:
            sf = int(
                value.get(
                    "value",
                    ""
                )
            )
        except Exception:
            return (
                False,
                "-s non valido"
            )

        if abs(
            sf
        ) < 5 or abs(
            sf
        ) > 12:

            return (
                False,
                "-s deve essere 5..12 oppure -5..-12"
            )

    value = options.get(
        "-O",
        {}
    )

    if value.get(
        "enabled"
    ):

        if str(
            value.get(
                "value",
                ""
            )
        ).strip() not in {
            "0",
            "1"
        }:

            return (
                False,
                "-O deve essere 0 oppure 1"
            )

    return (
        True,
        ""
    )


def loratx_service_running():

    result = subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            LORATX_SERVICE
        ]
    )

    return result.returncode == 0


def loratx_service_enabled():

    result = subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            LORATX_SERVICE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def verify_loratx_service(timeout=10):

    deadline = time.time() + timeout

    running_since = None

    while time.time() < deadline:

        state = subprocess.run(
            [
                "systemctl",
                "show",
                LORATX_SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--property=Result",
                "--property=ExecMainStatus",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        values = state.stdout.splitlines()

        active_state = (
            values[0].strip()
            if len(values) > 0
            else ""
        )

        sub_state = (
            values[1].strip()
            if len(values) > 1
            else ""
        )

        result_state = (
            values[2].strip()
            if len(values) > 2
            else ""
        )

        exec_status = (
            values[3].strip()
            if len(values) > 3
            else ""
        )


        # Batch completato correttamente.
        if (
            active_state == "inactive"
            and sub_state == "dead"
            and result_state == "success"
            and exec_status in {
                "",
                "0"
            }
        ):
            return (
                True,
                ""
            )


        # È ancora in esecuzione.
        if (
            active_state == "active"
            and sub_state == "running"
        ):

            if running_since is None:
                running_since = time.time()

            elif time.time() - running_since >= 2:
                return (
                    True,
                    ""
                )

        else:
            running_since = None


        if (
            active_state == "failed"
            or result_state == "failed"
            or (
                exec_status
                and exec_status != "0"
                and active_state != "active"
            )
        ):

            journal = subprocess.run(
                [
                    "journalctl",
                    "-u",
                    LORATX_SERVICE,
                    "-n",
                    "12",
                    "--no-pager"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            lines = [
                x.strip()
                for x in journal.stdout.splitlines()
                if x.strip()
            ]

            detail = ""

            for line in reversed(
                lines
            ):

                low = line.lower()

                if (
                    "error" in low
                    or "abort" in low
                    or "failed" in low
                    or "exited" in low
                ):

                    detail = line
                    break

            return (
                False,
                detail
                or (
                    "loratx terminato con errore"
                    + (
                        f" (exit status {exec_status})"
                        if exec_status
                        else ""
                    )
                )
            )

        time.sleep(
            0.25
        )


    return (
        False,
        "impossibile verificare l'avvio di loratx entro il timeout"
    )


def start_loratx_service():

    cfg = load_loratx_active_config()

    ok, error = loratx_validate_config(
        cfg
    )

    if not ok:
        return (
            False,
            error
        )

    result = subprocess.run(
        [
            "systemctl",
            "start",
            LORATX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'avvio di loratx"
        )

    return verify_loratx_service()


def stop_loratx_service():

    result = subprocess.run(
        [
            "systemctl",
            "stop",
            LORATX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'arresto di loratx"
        )

    return (
        True,
        ""
    )


def restart_loratx_service():

    cfg = load_loratx_active_config()

    ok, error = loratx_validate_config(
        cfg
    )

    if not ok:
        return (
            False,
            error
        )

    result = subprocess.run(
        [
            "systemctl",
            "restart",
            LORATX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante il riavvio di loratx"
        )

    return verify_loratx_service()


def apply_loratx_config():

    if not os.path.isfile(
        LORATX_CONFIG_FILE
    ):

        return (
            False,
            "loratx_config.json non trovato"
        )

    was_running = loratx_service_running()

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    stamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )

    previous_active = os.path.join(
        BACKUP_DIR,
        f"loratx-active-before-apply-{stamp}.json"
    )

    if os.path.isfile(
        LORATX_ACTIVE_CONFIG_FILE
    ):

        shutil.copy2(
            LORATX_ACTIVE_CONFIG_FILE,
            previous_active
        )

    else:

        shutil.copy2(
            LORATX_CONFIG_FILE,
            previous_active
        )

    try:

        atomic_copy_file(
            LORATX_CONFIG_FILE,
            LORATX_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            "Impossibile creare loratx_active_config.json: "
            + str(
                exc
            )
        )


    # Batch fermo: Apply aggiorna soltanto la config attiva.
    if not was_running:

        return (
            True,
            ""
        )


    ok, error = restart_loratx_service()

    if ok:

        return (
            True,
            ""
        )


    first_error = error

    try:

        atomic_copy_file(
            previous_active,
            LORATX_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            first_error
            + " - ATTENZIONE: impossibile ripristinare "
            + "loratx_active_config.json: "
            + str(
                exc
            )
        )


    rollback_ok, rollback_error = (
        restart_loratx_service()
    )

    if rollback_ok:

        return (
            False,
            first_error
            + " - configurazione loratx precedente "
            + "ripristinata automaticamente. "
            + "Le modifiche restano salvate nel draft."
        )


    return (
        False,
        first_error
        + " - ATTENZIONE: anche il rollback loratx "
        + "non è riuscito: "
        + rollback_error
    )


def loratx_journal():

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            LORATX_SERVICE,
            "-n",
            "30",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    return (
        result.stdout.strip()
        or "Nessun log disponibile."
    )


def update_loratx_from_form(cfg):

    options = cfg.setdefault(
        "options",
        {}
    )

    for item in LORATX_CATALOG:

        flag = item[
            "flag"
        ]

        state = options.setdefault(
            flag,
            {}
        )

        state["enabled"] = (
            f"enabled_{flag}"
            in request.form
        )

        if item.get(
            "boolean"
        ):

            state.pop(
                "value",
                None
            )

            state.pop(
                "values",
                None
            )

            continue

        if item.get(
            "repeat"
        ):

            text = request.form.get(
                f"value_{flag}",
                ""
            )

            state["values"] = [
                line.strip()
                for line in text.splitlines()
                if line.strip()
            ]

            state.pop(
                "value",
                None
            )

            continue

        state["value"] = request.form.get(
            f"value_{flag}",
            ""
        ).strip()

    return cfg


@app.route(
    "/config/loratx",
    methods=[
        "GET",
        "POST"
    ]
)
def config_loratx():

    cfg = load_loratx_config()

    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )


        if action == "start":

            ok, error = start_loratx_service()

            if ok:
                flash(
                    "LORATX_START_OK"
                )
            else:
                flash(
                    "LORATX_ERROR: "
                    + error
                )

            return redirect(
                "/config/loratx"
            )


        if action == "stop":

            ok, error = stop_loratx_service()

            if ok:
                flash(
                    "LORATX_STOP_OK"
                )
            else:
                flash(
                    "LORATX_ERROR: "
                    + error
                )

            return redirect(
                "/config/loratx"
            )


        if action == "restart":

            ok, error = restart_loratx_service()

            if ok:
                flash(
                    "LORATX_RESTART_OK"
                )
            else:
                flash(
                    "LORATX_ERROR: "
                    + error
                )

            return redirect(
                "/config/loratx"
            )


        cfg = update_loratx_from_form(
            cfg
        )

        save_loratx_config(
            cfg
        )


        if action == "apply":

            ok, error = apply_loratx_config()

            if ok:

                if loratx_service_running():

                    flash(
                        "LORATX_APPLY_RESTART_OK"
                    )

                else:

                    flash(
                        "LORATX_APPLY_STOPPED_OK"
                    )

            else:

                flash(
                    "LORATX_ERROR: "
                    + error
                )

        else:

            flash(
                "LORATX_SAVE_OK"
            )


        return redirect(
            "/config/loratx"
        )


    cfg = load_loratx_config()

    active_cfg = load_loratx_active_config()

    return render_template(
        "config_loratx.html",
        cfg=cfg,
        catalog=LORATX_CATALOG,
        values=cfg.get(
            "options",
            {}
        ),
        running=loratx_service_running(),
        enabled=loratx_service_enabled(),
        command=loratx_build_command(
            cfg,
            load_config()
        ),
        active_command=loratx_build_command(
            active_cfg,
            load_active_config()
        ),
        journal=loratx_journal()
    )



# =============================================================================


# LORARX
# =============================================================================

LORARX_SERVICE = "dxlaprs-lorarx.service"

LORARX_CONFIG_FILE = (
    "/opt/dxlaprs-manager/data/lorarx_config.json"
)

LORARX_ACTIVE_CONFIG_FILE = (
    "/opt/dxlaprs-manager/data/lorarx_active_config.json"
)

LORARX_WRAPPER = (
    "/opt/dxlaprs-manager/run_lorarx.py"
)


def lorarx_load_json(path):
    import json

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def lorarx_load_config():
    return lorarx_load_json(
        LORARX_CONFIG_FILE
    )


def lorarx_load_active_config():
    if os.path.exists(
        LORARX_ACTIVE_CONFIG_FILE
    ):
        return lorarx_load_json(
            LORARX_ACTIVE_CONFIG_FILE
        )

    return lorarx_load_config()


def lorarx_atomic_write(cfg):
    import json
    import tempfile

    directory = os.path.dirname(
        LORARX_CONFIG_FILE
    )

    fd, temp = tempfile.mkstemp(
        prefix=".lorarx-",
        dir=directory,
        text=True
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                indent=2,
                ensure_ascii=False
            )

            f.write("\n")

        os.replace(
            temp,
            LORARX_CONFIG_FILE
        )

    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def lorarx_build_argv(
    cfg,
    manager_cfg=None
):
    import os

    if manager_cfg is None:
        manager_cfg = load_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    binary = (
        os.path.join(
            bin_dir,
            "lorarx"
        )
        if bin_dir
        else "lorarx"
    )

    argv = [binary]

    g = cfg.get(
        "global",
        {}
    )

    def get_value(
        item,
        name
    ):
        v = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if not v:
            raise ValueError(
                f"{name}: valore mancante"
            )

        return v


    global_values = (
        ("input_file","-i"),
        ("format","-f"),
        ("bandwidth","-b"),
        ("gain_correction","-g"),
        ("sample_rate","-r"),
        ("fir_length","-w"),
        ("offset","-o"),
        ("frequency_mhz","-M"),
        ("autonotch","-W"),
    )

    for key,flag in global_values:

        item = g.get(
            key,
            {}
        )

        if item.get("enabled"):

            v = get_value(
                item,
                flag
            )

            if (
                flag == "-f"
                and v not in (
                    "u8",
                    "i16",
                    "f32"
                )
            ):
                raise ValueError(
                    "-f deve essere u8, i16 o f32"
                )

            if flag == "-b":
                try:
                    n = int(v)
                except ValueError:
                    raise ValueError(
                        "-b deve essere 0..9"
                    )

                if n < 0 or n > 9:
                    raise ValueError(
                        "-b deve essere 0..9"
                    )

            argv.extend([
                flag,
                v
            ])


    notch = g.get(
        "notch",
        {}
    )

    if notch.get("enabled"):

        for row in notch.get(
            "values",
            []
        ):
            parts = str(
                row
            ).split()

            if len(parts) != 2:
                raise ValueError(
                    "-n richiede due frequenze "
                    "per ogni riga"
                )

            argv.extend([
                "-n",
                parts[0],
                parts[1]
            ])


    z = g.get(
        "noise_blanker",
        {}
    )

    if z.get("enabled"):

        up = str(
            z.get(
                "up",
                ""
            )
        ).strip()

        down = str(
            z.get(
                "down",
                ""
            )
        ).strip()

        if not up or not down:
            raise ValueError(
                "-Z richiede upspeed "
                "e downspeed"
            )

        argv.extend([
            "-Z",
            up,
            down
        ])


    global_bools = (
        ("no_multipath","-R"),
        ("no_crc_repair","-E"),
        ("no_max_block_fec","-F"),
        ("ascii","-H"),
        ("newline","-N"),
        ("crc_only","-Q"),
        ("verbose","-v"),
        ("very_verbose","-V"),
    )

    for key,flag in global_bools:

        if g.get(
            key,
            {}
        ).get("enabled"):

            argv.append(flag)


    y = g.get(
        "debug_iq",
        {}
    )

    if y.get("enabled"):

        mode = str(
            y.get(
                "mode",
                ""
            )
        ).strip()

        val = str(
            y.get(
                "value",
                ""
            )
        ).strip()

        if mode not in (
            "d",
            "f",
            "b"
        ):
            raise ValueError(
                "-Y deve usare d, f oppure b"
            )

        if not val:
            raise ValueError(
                "-Y: valore mancante"
            )

        argv.extend([
            "-Y",
            mode,
            val
        ])


    for nr,dem in enumerate(
        cfg.get(
            "demodulators",
            []
        ),
        start=1
    ):

        if not dem.get("enabled"):
            continue

        sf = str(
            dem.get(
                "sf",
                ""
            )
        ).strip()

        try:
            sf_num = int(sf)
        except ValueError:
            raise ValueError(
                f"Demodulatore {nr}: "
                "spread factor non valido"
            )

        if (
            abs(sf_num) < 5
            or abs(sf_num) > 12
        ):
            raise ValueError(
                f"Demodulatore {nr}: "
                "-s deve essere ±5..±12"
            )

        #
        # -s DEVE precedere tutte le opzioni
        # del relativo demodulatore.
        #
        argv.extend([
            "-s",
            sf
        ])


        dem_values = (
            ("afc","-a"),
            ("coding_rate","-c"),
            ("data_length","-l"),
            ("squelch","-S"),
            ("network_id","-X"),
            ("optimize","-O"),
            ("ppm","-P"),
        )

        for key,flag in dem_values:

            item = dem.get(
                key,
                {}
            )

            if not item.get("enabled"):
                continue

            v = get_value(
                item,
                f"Demodulatore {nr} {flag}"
            )

            if flag == "-c":

                try:
                    n = int(v)
                except ValueError:
                    raise ValueError(
                        f"Demodulatore {nr}: "
                        "-c deve essere 4..8"
                    )

                if n < 4 or n > 8:
                    raise ValueError(
                        f"Demodulatore {nr}: "
                        "-c deve essere 4..8"
                    )


            if flag == "-l":

                try:
                    n = int(v)
                except ValueError:
                    raise ValueError(
                        f"Demodulatore {nr}: "
                        "-l deve essere 2..255"
                    )

                if n < 2 or n > 255:
                    raise ValueError(
                        f"Demodulatore {nr}: "
                        "-l deve essere 2..255"
                    )


            if (
                flag == "-O"
                and v not in (
                    "0",
                    "1"
                )
            ):
                raise ValueError(
                    f"Demodulatore {nr}: "
                    "-O deve essere 0 oppure 1"
                )


            argv.extend([
                flag,
                v
            ])


        dem_bools = (
            ("frame_chaining","-A"),
            ("implicit_crc","-C"),
            ("continue_dcd","-D"),
            ("disable_collision","-d"),
            ("invert_iq","-q"),
        )

        for key,flag in dem_bools:

            if dem.get(key):
                argv.append(flag)


        ax = dem.get(
            "axudp",
            {}
        )

        mode = str(
            ax.get(
                "mode",
                ""
            )
        ).strip()

        val = str(
            ax.get(
                "value",
                ""
            )
        ).strip()

        if mode:

            if mode not in (
                "U",
                "L"
            ):
                raise ValueError(
                    f"Demodulatore {nr}: "
                    "tipo AXUDP non valido"
                )

            if not val:
                raise ValueError(
                    f"Demodulatore {nr}: "
                    "indirizzo AXUDP mancante"
                )

            argv.extend([
                "-" + mode,
                val
            ])


        raw = dem.get(
            "raw_udp",
            {}
        )

        mode = str(
            raw.get(
                "mode",
                ""
            )
        ).strip()

        val = str(
            raw.get(
                "value",
                ""
            )
        ).strip()

        if mode:

            if mode not in (
                "u",
                "t"
            ):
                raise ValueError(
                    f"Demodulatore {nr}: "
                    "tipo UDP raw non valido"
                )

            if not val:
                raise ValueError(
                    f"Demodulatore {nr}: "
                    "indirizzo UDP raw mancante"
                )

            argv.extend([
                "-" + mode,
                val
            ])


    #
    # JSON UDP globale.
    #
    # Viene emesso dopo i blocchi dei demodulatori
    # per non interferire con hasudp durante la
    # costruzione degli stessi.
    #
    j = g.get(
        "json_udp",
        {}
    )

    if j.get("enabled"):

        argv.extend([
            "-J",
            get_value(
                j,
                "-J"
            )
        ])


    if len(argv) == 1:
        raise ValueError(
            "Nessuna opzione lorarx abilitata"
        )

    return argv


def lorarx_build_command(
    cfg,
    manager_cfg=None
):
    import shlex

    try:

        argv = lorarx_build_argv(
            cfg,
            manager_cfg
        )

        return " ".join(
            shlex.quote(
                str(x)
            )
            for x in argv
        )

    except Exception as exc:

        return (
            "ERRORE: "
            + str(exc)
        )


def lorarx_service_running():

    p = subprocess.run(
        [
            "systemctl",
            "is-active",
            LORARX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    return (
        p.stdout.strip()
        == "active"
    )


def lorarx_service_enabled():

    p = subprocess.run(
        [
            "systemctl",
            "is-enabled",
            LORARX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True
    )

    value = p.stdout.strip()

    return (
        value
        if value
        else "disabled"
    )


def lorarx_verify_service(
    timeout=10
):
    import time

    end = (
        time.time()
        + timeout
    )

    while time.time() < end:

        p = subprocess.run(
            [
                "systemctl",
                "show",
                LORARX_SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--property=ExecMainStatus",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        values = (
            p.stdout.splitlines()
        )

        active = (
            values[0].strip()
            if len(values) >= 1
            else ""
        )

        sub = (
            values[1].strip()
            if len(values) >= 2
            else ""
        )


        if (
            active == "active"
            and sub == "running"
        ):

            time.sleep(2)

            if lorarx_service_running():
                return True, ""



        if (
            active == "failed"
            or sub == "auto-restart"
        ):

            subprocess.run(
                [
                    "systemctl",
                    "stop",
                    LORARX_SERVICE
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            j = subprocess.run(
                [
                    "journalctl",
                    "-u",
                    LORARX_SERVICE,
                    "-n",
                    "15",
                    "--no-pager"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            return (
                False,
                j.stdout.strip()
            )


        time.sleep(.25)


    return (
        False,
        "lorarx non è diventato stabile "
        "entro il timeout"
    )


def lorarx_start():

    subprocess.run(
        [
            "/usr/bin/python3",
            LORARX_WRAPPER,
            "--check"
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    subprocess.run(
        [
            "systemctl",
            "start",
            LORARX_SERVICE
        ],
        check=True
    )

    return lorarx_verify_service()


def lorarx_stop():
    import time

    subprocess.run(
        [
            "systemctl",
            "stop",
            LORARX_SERVICE
        ],
        check=True
    )

    end = (
        time.time()
        + 10
    )

    while time.time() < end:

        if not lorarx_service_running():
            return True, ""

        time.sleep(.25)


    return (
        False,
        "lorarx non si è arrestato "
        "entro il timeout"
    )


def lorarx_restart():

    subprocess.run(
        [
            "/usr/bin/python3",
            LORARX_WRAPPER,
            "--check"
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    subprocess.run(
        [
            "systemctl",
            "restart",
            LORARX_SERVICE
        ],
        check=True
    )

    return lorarx_verify_service()


def lorarx_apply():
    import shutil
    import time

    was_running = (
        lorarx_service_running()
    )

    rollback = None

    if os.path.exists(
        LORARX_ACTIVE_CONFIG_FILE
    ):

        rollback = (
            LORARX_ACTIVE_CONFIG_FILE
            + ".rollback"
        )

        shutil.copy2(
            LORARX_ACTIVE_CONFIG_FILE,
            rollback
        )


    shutil.copy2(
        LORARX_CONFIG_FILE,
        LORARX_ACTIVE_CONFIG_FILE
    )


    if not was_running:

        if (
            rollback
            and os.path.exists(rollback)
        ):
            os.unlink(rollback)

        return (
            True,
            "Configurazione applicata. "
            "lorarx era fermo e non è stato avviato."
        )


    try:

        ok,detail = (
            lorarx_restart()
        )

    except Exception as exc:

        ok = False
        detail = str(exc)


    if ok:

        if (
            rollback
            and os.path.exists(rollback)
        ):
            os.unlink(rollback)

        return (
            True,
            "Configurazione lorarx applicata"
        )


    #
    # ROLLBACK
    #
    if (
        rollback
        and os.path.exists(rollback)
    ):

        shutil.copy2(
            rollback,
            LORARX_ACTIVE_CONFIG_FILE
        )

        os.unlink(rollback)

        subprocess.run(
            [
                "systemctl",
                "restart",
                LORARX_SERVICE
            ],
            check=False
        )

        lorarx_verify_service()


    else:

        subprocess.run(
            [
                "systemctl",
                "stop",
                LORARX_SERVICE
            ],
            check=False
        )


    return (
        False,
        "Applicazione fallita. "
        "La configurazione attiva precedente "
        "è stata ripristinata. "
        "Le modifiche restano salvate nel draft.\n"
        + detail
    )


def lorarx_journal():

    p = subprocess.run(
        [
            "journalctl",
            "-u",
            LORARX_SERVICE,
            "-n",
            "80",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    return p.stdout


def lorarx_from_form(
    form,
    old_cfg
):
    import copy

    cfg = copy.deepcopy(
        old_cfg
    )

    g = cfg.setdefault(
        "global",
        {}
    )


    value_items = (
        "input_file",
        "format",
        "bandwidth",
        "gain_correction",
        "sample_rate",
        "fir_length",
        "offset",
        "frequency_mhz",
        "autonotch",
        "json_udp",
    )


    for key in value_items:

        item = g.setdefault(
            key,
            {}
        )

        item["enabled"] = (
            f"g_{key}_enabled"
            in form
        )

        item["value"] = (
            form.get(
                f"g_{key}_value",
                ""
            ).strip()
        )


    notch = g.setdefault(
        "notch",
        {}
    )

    notch["enabled"] = (
        "g_notch_enabled"
        in form
    )

    notch["values"] = [
        x.strip()
        for x in form.get(
            "g_notch_values",
            ""
        ).splitlines()
        if x.strip()
    ]


    z = g.setdefault(
        "noise_blanker",
        {}
    )

    z["enabled"] = (
        "g_noise_blanker_enabled"
        in form
    )

    z["up"] = form.get(
        "g_noise_blanker_up",
        ""
    ).strip()

    z["down"] = form.get(
        "g_noise_blanker_down",
        ""
    ).strip()


    y = g.setdefault(
        "debug_iq",
        {}
    )

    y["enabled"] = (
        "g_debug_iq_enabled"
        in form
    )

    y["mode"] = form.get(
        "g_debug_iq_mode",
        "d"
    ).strip()

    y["value"] = form.get(
        "g_debug_iq_value",
        ""
    ).strip()


    for key in (
        "no_multipath",
        "no_crc_repair",
        "no_max_block_fec",
        "ascii",
        "newline",
        "crc_only",
        "verbose",
        "very_verbose",
    ):

        item = g.setdefault(
            key,
            {}
        )

        item["enabled"] = (
            f"g_{key}_enabled"
            in form
        )


    try:

        count = int(
            form.get(
                "demod_count",
                "0"
            )
        )

    except ValueError:

        count = 0


    demods = []


    for i in range(
        max(
            0,
            count
        )
    ):

        def checked(name):

            return (
                f"d_{i}_{name}"
                in form
            )


        def value(name):

            return form.get(
                f"d_{i}_{name}",
                ""
            ).strip()


        demods.append({

            "enabled":
                checked("enabled"),

            "sf":
                value("sf") or "12",

            "afc": {
                "enabled":
                    checked("afc_enabled"),
                "value":
                    value("afc_value")
            },

            "coding_rate": {
                "enabled":
                    checked("coding_rate_enabled"),
                "value":
                    value("coding_rate_value")
            },

            "data_length": {
                "enabled":
                    checked("data_length_enabled"),
                "value":
                    value("data_length_value")
            },

            "squelch": {
                "enabled":
                    checked("squelch_enabled"),
                "value":
                    value("squelch_value")
            },

            "network_id": {
                "enabled":
                    checked("network_id_enabled"),
                "value":
                    value("network_id_value")
            },

            "optimize": {
                "enabled":
                    checked("optimize_enabled"),
                "value":
                    value("optimize_value")
            },

            "ppm": {
                "enabled":
                    checked("ppm_enabled"),
                "value":
                    value("ppm_value")
            },

            "frame_chaining":
                checked("frame_chaining"),

            "implicit_crc":
                checked("implicit_crc"),

            "continue_dcd":
                checked("continue_dcd"),

            "disable_collision":
                checked("disable_collision"),

            "invert_iq":
                checked("invert_iq"),

            "axudp": {
                "mode":
                    value("axudp_mode"),
                "value":
                    value("axudp_value")
            },

            "raw_udp": {
                "mode":
                    value("raw_udp_mode"),
                "value":
                    value("raw_udp_value")
            }
        })


    cfg["demodulators"] = demods

    return cfg


@app.route(
    "/config/lorarx",
    methods=[
        "GET",
        "POST"
    ]
)
def config_lorarx():

    message = ""
    error = ""


    if request.method == "POST":

        action = request.form.get(
            "action",
            ""
        )


        try:

            if action == "start":

                ok,detail = (
                    lorarx_start()
                )

                if ok:
                    message = (
                        "lorarx avviato"
                    )
                else:
                    error = detail


            elif action == "stop":

                ok,detail = (
                    lorarx_stop()
                )

                if ok:
                    message = (
                        "lorarx arrestato"
                    )
                else:
                    error = detail


            elif action == "restart":

                ok,detail = (
                    lorarx_restart()
                )

                if ok:
                    message = (
                        "lorarx riavviato"
                    )
                else:
                    error = detail


            elif action in (
                "save",
                "apply"
            ):

                current = (
                    lorarx_load_config()
                )

                cfg = lorarx_from_form(
                    request.form,
                    current
                )


                #
                # Valida ciò che è abilitato.
                # È ammesso salvare una configurazione
                # completamente vuota.
                #
                try:

                    lorarx_build_argv(
                        cfg,
                        load_config()
                    )

                except ValueError as exc:

                    if (
                        "Nessuna opzione"
                        not in str(exc)
                    ):
                        raise


                lorarx_atomic_write(
                    cfg
                )


                if action == "save":

                    message = (
                        "Configurazione lorarx salvata. "
                        "Il servizio non è stato riavviato."
                    )


                else:

                    ok,detail = (
                        lorarx_apply()
                    )

                    if ok:
                        message = detail
                    else:
                        error = detail


        except subprocess.CalledProcessError as exc:

            error = (
                getattr(
                    exc,
                    "stderr",
                    ""
                )
                or str(exc)
            )


        except Exception as exc:

            error = str(exc)


    cfg = lorarx_load_config()

    active_cfg = (
        lorarx_load_active_config()
    )


    manager_draft = (
        load_config()
    )


    try:
        manager_active = (
            load_active_config()
        )

    except Exception:
        manager_active = (
            manager_draft
        )


    saved_command = (
        lorarx_build_command(
            cfg,
            manager_draft
        )
    )


    active_command = (
        lorarx_build_command(
            active_cfg,
            manager_active
        )
    )


    service_state = (
        "active"
        if lorarx_service_running()
        else "inactive"
    )


    return render_template(
        "config_lorarx.html",

        cfg=cfg,

        service_state=
            service_state,

        service_enabled=
            lorarx_service_enabled(),

        saved_command=
            saved_command,

        active_command=
            active_command,

        journal=
            lorarx_journal(),

        message=
            message,

        error=
            error
    )



# =============================================================================
# FSK4RX
# =============================================================================

FSK4RX_SERVICE = "dxlaprs-fsk4rx.service"

FSK4RX_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "fsk4rx_config.json"
)

FSK4RX_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "fsk4rx_active_config.json"
)


def load_fsk4rx_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_fsk4rx_config():
    return load_fsk4rx_json(FSK4RX_CONFIG_FILE)


def load_fsk4rx_active_config():
    if os.path.isfile(FSK4RX_ACTIVE_CONFIG_FILE):
        return load_fsk4rx_json(FSK4RX_ACTIVE_CONFIG_FILE)

    return load_fsk4rx_config()


def save_fsk4rx_config(cfg):

    os.makedirs(BACKUP_DIR, exist_ok=True)

    if os.path.isfile(FSK4RX_CONFIG_FILE):

        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")

        shutil.copy2(
            FSK4RX_CONFIG_FILE,
            os.path.join(
                BACKUP_DIR,
                f"fsk4rx-config-{stamp}.json"
            )
        )

    directory = os.path.dirname(FSK4RX_CONFIG_FILE)

    fd, tmp = tempfile.mkstemp(
        prefix="fsk4rx-config-",
        suffix=".json",
        dir=directory
    )

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                cfg,
                f,
                ensure_ascii=False,
                indent=2
            )
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        os.replace(
            tmp,
            FSK4RX_CONFIG_FILE
        )

    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def fsk4rx_build_argv(cfg, manager_cfg=None):

    if manager_cfg is None:
        manager_cfg = load_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    binary = (
        os.path.join(bin_dir, "fsk4rx")
        if bin_dir
        else "fsk4rx"
    )

    g = cfg.get("global", {})

    argv = [binary]

    def add(flag, key):

        item = g.get(key, {})

        if not item.get("enabled"):
            return

        value = str(
            item.get("value", "")
        ).strip()

        if value:
            argv.extend([flag, value])

    add("-i", "input")
    add("-f", "format")
    add("-r", "sample_rate")
    add("-I", "callsign")
    add("-J", "json_udp")

    axudp = g.get("axudp", {})

    if axudp.get("enabled"):

        for row in axudp.get("values", []):

            row = str(row).strip()

            if not row:
                continue

            if row.startswith("L "):
                value = row[2:].strip()
                if value:
                    argv.extend(["-L", value])

            elif row.startswith("U "):
                value = row[2:].strip()
                if value:
                    argv.extend(["-U", value])

            else:
                argv.extend(["-U", row])

    add("-A", "ais_file")
    add("-C", "callbook")
    add("-Y", "country_db")
    add("-T", "ship_beacon")
    add("-q", "squelch")

    if g.get("verbose", {}).get("enabled"):
        argv.append("-v")

    if g.get("very_verbose", {}).get("enabled"):
        argv.append("-V")

    for d in cfg.get("demodulators", []):

        if not d.get("enabled"):
            continue

        mode = str(
            d.get("mode", "4")
        ).strip()

        if mode == "4":

            mvalue = "4"

        elif mode == "a":

            mvalue = "a,{},{},{},{}".format(
                d.get("afsk_baud", "1200"),
                d.get("afsk_low", "1200"),
                d.get("afsk_high", "2200"),
                d.get("fsk_if_width", "16000")
            )

        elif mode == "f":

            mvalue = "f,{},{},{}".format(
                d.get("fsk_baud", "9600"),
                d.get("fsk_if_width", "16000"),
                d.get("scramble", "1")
            )

        elif mode == "0":

            mvalue = "0,{},{},{}".format(
                d.get("audio_rate", "16000"),
                d.get("audio_if_width", "12500"),
                d.get("audio_squelch", "0")
            )

        else:
            continue

        argv.extend(["-m", mvalue])

        argv.extend([
            "-M",
            str(d.get("frequency_mhz", "0")),
            "-n",
            str(d.get("bfo", "1500"))
        ])

        if mode == "4":
            argv.extend([
                "-b",
                str(d.get("baud", "100")),
                "-D",
                str(d.get("spacing", "270")),
                "-W",
                str(d.get("if_width", "3240"))
            ])

        audio_mode = str(
            d.get("audio_mode", "")
        ).strip()

        audio_file = str(
            d.get("audio_file", "")
        ).strip()

        if audio_mode and audio_file:

            if audio_mode == "FM":
                argv.extend(["-F", audio_file])

            elif audio_mode == "USB":
                argv.extend(["-S", audio_file])

        tune = str(
            d.get("tune", "0")
        ).strip() or "0"

        afc = str(
            d.get("afc", "0")
        ).strip() or "0"

        argv.extend([
            "-t",
            tune + "," + afc
        ])

    return argv


def fsk4rx_build_command(cfg, manager_cfg=None):

    return " ".join(
        shlex.quote(str(x))
        for x in fsk4rx_build_argv(
            cfg,
            manager_cfg
        )
    )


def fsk4rx_validate_config(cfg):

    g = cfg.get("global", {})

    for key, flag in (
        ("input", "-i"),
        ("sample_rate", "-r")
    ):

        item = g.get(key, {})

        if (
            not item.get("enabled")
            or not str(
                item.get("value", "")
            ).strip()
        ):
            return (
                False,
                f"{flag} non configurato"
            )

    fmt = g.get("format", {})

    if fmt.get("enabled"):

        if fmt.get("value") not in {
            "u8",
            "i16",
            "f32"
        }:
            return (
                False,
                "-f deve essere u8, i16 oppure f32"
            )

    try:
        sample_rate = int(
            g.get(
                "sample_rate",
                {}
            ).get(
                "value",
                ""
            )
        )

    except Exception:
        return (
            False,
            "-r non valido"
        )

    if sample_rate < 100:
        return (
            False,
            "-r deve essere almeno 100 Hz"
        )

    demods = [
        d
        for d in cfg.get(
            "demodulators",
            []
        )
        if d.get("enabled")
    ]

    if not demods:
        return (
            False,
            "Nessun demodulatore fsk4rx attivo"
        )

    for number, d in enumerate(demods, 1):

        mode = str(
            d.get("mode", "")
        ).strip()

        if mode not in {
            "4",
            "a",
            "f",
            "0"
        }:
            return (
                False,
                f"Demodulatore {number}: modo non valido"
            )

        try:
            tune = int(
                str(
                    d.get("tune", "0")
                )
            )

        except Exception:
            return (
                False,
                f"Demodulatore {number}: -t non valido"
            )

        if abs(tune) * 2 > sample_rate:
            return (
                False,
                f"Demodulatore {number}: offset fuori banda"
            )

        audio_mode = str(
            d.get("audio_mode", "")
        ).strip()

        if audio_mode not in {
            "",
            "FM",
            "USB"
        }:
            return (
                False,
                f"Demodulatore {number}: uscita audio non valida"
            )

        if (
            audio_mode
            and not str(
                d.get("audio_file", "")
            ).strip()
        ):
            return (
                False,
                f"Demodulatore {number}: file/pipe audio mancante"
            )

    return (
        True,
        ""
    )


def fsk4rx_service_running():

    result = subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            FSK4RX_SERVICE
        ]
    )

    return result.returncode == 0


def fsk4rx_service_enabled():

    result = subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            FSK4RX_SERVICE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def fsk4rx_journal():

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            FSK4RX_SERVICE,
            "-n",
            "30",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    return (
        result.stdout.strip()
        or "Nessun log disponibile."
    )


def verify_fsk4rx_service(timeout=10):

    deadline = time.time() + timeout

    while time.time() < deadline:

        state = subprocess.run(
            [
                "systemctl",
                "show",
                FSK4RX_SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--property=ExecMainStatus",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        values = state.stdout.splitlines()

        active_state = (
            values[0].strip()
            if len(values) > 0
            else ""
        )

        sub_state = (
            values[1].strip()
            if len(values) > 1
            else ""
        )

        exec_status = (
            values[2].strip()
            if len(values) > 2
            else ""
        )

        if (
            active_state == "active"
            and sub_state == "running"
        ):

            time.sleep(2)

            stable = subprocess.run(
                [
                    "systemctl",
                    "is-active",
                    "--quiet",
                    FSK4RX_SERVICE
                ]
            )

            if stable.returncode == 0:
                return (
                    True,
                    ""
                )

        if (
            active_state == "failed"
            or sub_state == "auto-restart"
        ):

            subprocess.run(
                [
                    "systemctl",
                    "stop",
                    FSK4RX_SERVICE
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            lines = [
                x.strip()
                for x in fsk4rx_journal().splitlines()
                if x.strip()
            ]

            detail = (
                lines[-1]
                if lines
                else ""
            )

            return (
                False,
                detail
                or (
                    "fsk4rx terminato durante l'avvio"
                    + (
                        f" (exit status {exec_status})"
                        if exec_status
                        else ""
                    )
                )
            )

        time.sleep(0.25)

    return (
        False,
        "fsk4rx non è diventato stabile entro il timeout"
    )


def start_fsk4rx_service():

    cfg = load_fsk4rx_active_config()

    ok, error = fsk4rx_validate_config(cfg)

    if not ok:
        return (
            False,
            error
        )

    result = subprocess.run(
        [
            "systemctl",
            "start",
            FSK4RX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'avvio di fsk4rx"
        )

    return verify_fsk4rx_service()


def stop_fsk4rx_service():

    result = subprocess.run(
        [
            "systemctl",
            "stop",
            FSK4RX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'arresto di fsk4rx"
        )

    return (
        True,
        ""
    )


def restart_fsk4rx_service():

    cfg = load_fsk4rx_active_config()

    ok, error = fsk4rx_validate_config(cfg)

    if not ok:
        return (
            False,
            error
        )

    result = subprocess.run(
        [
            "systemctl",
            "restart",
            FSK4RX_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante il riavvio di fsk4rx"
        )

    return verify_fsk4rx_service()


def apply_fsk4rx_config():

    if not os.path.isfile(FSK4RX_CONFIG_FILE):
        return (
            False,
            "fsk4rx_config.json non trovato"
        )

    was_running = fsk4rx_service_running()

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    stamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )

    previous_active = os.path.join(
        BACKUP_DIR,
        f"fsk4rx-active-before-apply-{stamp}.json"
    )

    if os.path.isfile(
        FSK4RX_ACTIVE_CONFIG_FILE
    ):

        shutil.copy2(
            FSK4RX_ACTIVE_CONFIG_FILE,
            previous_active
        )

    else:

        shutil.copy2(
            FSK4RX_CONFIG_FILE,
            previous_active
        )

    try:

        atomic_copy_file(
            FSK4RX_CONFIG_FILE,
            FSK4RX_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            "Impossibile creare fsk4rx_active_config.json: "
            + str(exc)
        )

    if not was_running:
        return (
            True,
            ""
        )

    ok, error = restart_fsk4rx_service()

    if ok:
        return (
            True,
            ""
        )

    first_error = error

    try:

        atomic_copy_file(
            previous_active,
            FSK4RX_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            first_error
            + " - ATTENZIONE: impossibile ripristinare "
            + "fsk4rx_active_config.json: "
            + str(exc)
        )

    rollback_ok, rollback_error = (
        restart_fsk4rx_service()
    )

    if rollback_ok:

        return (
            False,
            first_error
            + " - configurazione fsk4rx precedente "
            + "ripristinata automaticamente. "
            + "Le modifiche restano salvate nel draft."
        )

    return (
        False,
        first_error
        + " - ATTENZIONE: anche il rollback fsk4rx "
        + "non è riuscito: "
        + rollback_error
    )


def update_fsk4rx_from_form(cfg):

    g = cfg.setdefault(
        "global",
        {}
    )

    simple = [
        "input",
        "format",
        "sample_rate",
        "callsign",
        "json_udp",
        "ais_file",
        "callbook",
        "country_db",
        "ship_beacon",
        "squelch"
    ]

    for key in simple:

        state = g.setdefault(
            key,
            {}
        )

        state["enabled"] = (
            f"g_enabled_{key}"
            in request.form
        )

        state["value"] = request.form.get(
            f"g_value_{key}",
            ""
        ).strip()

    axudp = g.setdefault(
        "axudp",
        {}
    )

    axudp["enabled"] = (
        "g_enabled_axudp"
        in request.form
    )

    axudp["values"] = [
        x.strip()
        for x in request.form.get(
            "g_value_axudp",
            ""
        ).splitlines()
        if x.strip()
    ]

    for key in (
        "verbose",
        "very_verbose"
    ):

        state = g.setdefault(
            key,
            {}
        )

        state["enabled"] = (
            f"g_enabled_{key}"
            in request.form
        )

    try:
        count = int(
            request.form.get(
                "demod_count",
                "1"
            )
        )

    except Exception:
        count = 1

    old = cfg.get(
        "demodulators",
        []
    )

    demods = []

    fields = [
        "mode",
        "tune",
        "afc",
        "frequency_mhz",
        "bfo",
        "baud",
        "spacing",
        "if_width",
        "afsk_baud",
        "afsk_low",
        "afsk_high",
        "fsk_baud",
        "fsk_if_width",
        "scramble",
        "audio_rate",
        "audio_if_width",
        "audio_squelch",
        "audio_mode",
        "audio_file"
    ]

    for i in range(count):

        if i < len(old):
            d = dict(old[i])
        else:
            d = {}

        d["enabled"] = (
            f"d{i}_enabled"
            in request.form
        )

        for key in fields:

            d[key] = request.form.get(
                f"d{i}_{key}",
                d.get(key, "")
            ).strip()

        demods.append(d)

    cfg["demodulators"] = demods

    return cfg


@app.route(
    "/config/fsk4rx",
    methods=[
        "GET",
        "POST"
    ]
)
def config_fsk4rx():

    cfg = load_fsk4rx_config()

    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )

        if action == "start":

            ok, error = start_fsk4rx_service()

            if ok:
                flash("FSK4RX_START_OK")
            else:
                flash(
                    "FSK4RX_ERROR: "
                    + error
                )

            return redirect(
                "/config/fsk4rx"
            )

        if action == "stop":

            ok, error = stop_fsk4rx_service()

            if ok:
                flash("FSK4RX_STOP_OK")
            else:
                flash(
                    "FSK4RX_ERROR: "
                    + error
                )

            return redirect(
                "/config/fsk4rx"
            )

        if action == "restart":

            ok, error = restart_fsk4rx_service()

            if ok:
                flash(
                    "FSK4RX_RESTART_OK"
                )
            else:
                flash(
                    "FSK4RX_ERROR: "
                    + error
                )

            return redirect(
                "/config/fsk4rx"
            )

        cfg = update_fsk4rx_from_form(
            cfg
        )

        save_fsk4rx_config(
            cfg
        )

        if action == "apply":

            ok, error = apply_fsk4rx_config()

            if ok:

                if fsk4rx_service_running():
                    flash(
                        "FSK4RX_APPLY_RESTART_OK"
                    )

                else:
                    flash(
                        "FSK4RX_APPLY_STOPPED_OK"
                    )

            else:
                flash(
                    "FSK4RX_ERROR: "
                    + error
                )

        else:
            flash("FSK4RX_SAVE_OK")

        return redirect(
            "/config/fsk4rx"
        )

    cfg = load_fsk4rx_config()

    active_cfg = load_fsk4rx_active_config()

    return render_template(
        "config_fsk4rx.html",
        cfg=cfg,
        G=cfg.get(
            "global",
            {}
        ),
        demodulators=cfg.get(
            "demodulators",
            []
        ),
        running=fsk4rx_service_running(),
        enabled=fsk4rx_service_enabled(),
        command=fsk4rx_build_command(
            cfg,
            load_config()
        ),
        active_command=fsk4rx_build_command(
            active_cfg,
            load_active_config()
        ),
        journal=fsk4rx_journal()
    )



# =============================================================================
# RA02
# =============================================================================

RA02_SERVICE = "dxlaprs-ra02.service"

RA02_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "ra02_config.json"
)

RA02_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "ra02_active_config.json"
)


def load_ra02_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


def load_ra02_config():

    return load_ra02_json(
        RA02_CONFIG_FILE
    )


def load_ra02_active_config():

    if os.path.isfile(
        RA02_ACTIVE_CONFIG_FILE
    ):

        return load_ra02_json(
            RA02_ACTIVE_CONFIG_FILE
        )

    return load_ra02_config()


def save_ra02_config(cfg):

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    if os.path.isfile(
        RA02_CONFIG_FILE
    ):

        stamp = datetime.now().strftime(
            "%Y%m%d-%H%M%S-%f"
        )

        shutil.copy2(
            RA02_CONFIG_FILE,
            os.path.join(
                BACKUP_DIR,
                f"ra02-config-{stamp}.json"
            )
        )

    directory = os.path.dirname(
        RA02_CONFIG_FILE
    )

    fd, tmp = tempfile.mkstemp(
        prefix="ra02-config-",
        suffix=".json",
        dir=directory
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                ensure_ascii=False,
                indent=2
            )

            f.write("\n")
            f.flush()
            os.fsync(
                f.fileno()
            )

        os.replace(
            tmp,
            RA02_CONFIG_FILE
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def ra02_add_value(
    argv,
    flag,
    state
):

    if not state.get(
        "enabled"
    ):
        return

    value = str(
        state.get(
            "value",
            ""
        )
    ).strip()

    if value:
        argv.extend(
            [
                flag,
                value
            ]
        )


def ra02_add_bool(
    argv,
    flag,
    state
):

    if state.get(
        "enabled"
    ):
        argv.append(flag)


def ra02_build_argv(
    cfg,
    manager_cfg=None
):

    if manager_cfg is None:
        manager_cfg = load_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    binary = (
        os.path.join(
            bin_dir,
            "ra02"
        )
        if bin_dir
        else "ra02"
    )

    argv = [binary]

    g = cfg.get(
        "global",
        {}
    )

    poll = g.get(
        "poll",
        {}
    )

    if poll.get(
        "enabled"
    ):

        argv.extend([
            "-u",
            str(
                poll.get(
                    "rx_us",
                    "30000"
                )
            ),
            str(
                poll.get(
                    "tx_us",
                    "10000"
                )
            )
        ])

    for chip in cfg.get(
        "chips",
        []
    ):

        if not chip.get(
            "enabled"
        ):
            continue

        gpio = chip.get(
            "gpio",
            {}
        )

        argv.extend([
            "-p",
            str(gpio.get("nss", "")).strip(),
            str(gpio.get("mosi", "")).strip(),
            str(gpio.get("miso", "")).strip(),
            str(gpio.get("sck", "")).strip()
        ])

        rx = chip.get(
            "rx",
            {}
        )

        for key, flag in (
            ("frequency", "-f"),
            ("sf", "-s"),
            ("bandwidth", "-b"),
            ("coding_rate", "-c"),
            ("network_id", "-n"),
            ("gfsk_baud", "-g"),
            ("lna_gain", "-e"),
            ("lna_boost", "-l"),
            ("rssi_correction", "-r"),
            ("optimize", "-o"),
            ("ppm", "-P"),
            ("datarate", "-X"),
            ("preamble_limit", "-W"),
            ("pa_ramp", "-R"),
            ("ocp", "-Z")
        ):

            ra02_add_value(
                argv,
                flag,
                rx.get(
                    key,
                    {}
                )
            )

        for key, flag in (
            ("agc", "-a"),
            ("implicit", "-i"),
            ("invert_iq", "-q")
        ):

            ra02_add_bool(
                argv,
                flag,
                rx.get(
                    key,
                    {}
                )
            )

        json_udp = g.get(
            "json_udp",
            {}
        )

        if json_udp.get(
            "enabled"
        ):

            value = str(
                json_udp.get(
                    "value",
                    ""
                )
            ).strip()

            if value:
                argv.extend([
                    "-J",
                    value
                ])

        for tx in chip.get(
            "tx_contexts",
            []
        ):

            if not tx.get(
                "enabled"
            ):
                continue

            transport = str(
                tx.get(
                    "transport",
                    "L"
                )
            ).strip().upper()

            endpoint = str(
                tx.get(
                    "endpoint",
                    ""
                )
            ).strip()

            if (
                transport
                not in {
                    "L",
                    "U"
                }
            ):
                continue

            if not endpoint:
                continue

            argv.extend([
                "-" + transport,
                endpoint
            ])

            for key, flag in (
                ("frequency", "-F"),
                ("sf", "-S"),
                ("bandwidth", "-B"),
                ("coding_rate", "-C"),
                ("network_id", "-N"),
                ("power", "-w"),
                ("preamble", "-H"),
                ("tx_delay", "-T"),
                ("deviation", "-D"),
                ("gfsk_baud", "-G"),
                ("optimize", "-O")
            ):

                ra02_add_value(
                    argv,
                    flag,
                    tx.get(
                        key,
                        {}
                    )
                )

            for key, flag in (
                ("afsk", "-A"),
                ("raw_fsk", "-E"),
                ("raw_lora", "-K"),
                ("implicit", "-I"),
                ("dcd", "-d"),
                ("invert_iq", "-Q")
            ):

                ra02_add_bool(
                    argv,
                    flag,
                    tx.get(
                        key,
                        {}
                    )
                )

    if g.get(
        "verbose",
        {}
    ).get(
        "enabled"
    ):
        argv.append("-v")

    if g.get(
        "very_verbose",
        {}
    ).get(
        "enabled"
    ):
        argv.append("-V")

    return argv


def ra02_build_command(
    cfg,
    manager_cfg=None
):

    return " ".join(
        shlex.quote(
            str(x)
        )
        for x in ra02_build_argv(
            cfg,
            manager_cfg
        )
    )


def ra02_int(
    value,
    label,
    minimum=None,
    maximum=None,
    absolute=False
):

    try:
        n = int(
            str(value).strip()
        )

    except Exception:
        return (
            False,
            f"{label} non valido"
        )

    check = (
        abs(n)
        if absolute
        else n
    )

    if (
        minimum is not None
        and check < minimum
    ):
        return (
            False,
            f"{label} fuori intervallo"
        )

    if (
        maximum is not None
        and check > maximum
    ):
        return (
            False,
            f"{label} fuori intervallo"
        )

    return (
        True,
        n
    )


def ra02_float(
    value,
    label,
    minimum=None,
    maximum=None
):

    try:
        n = float(
            str(value).strip()
        )

    except Exception:
        return (
            False,
            f"{label} non valido"
        )

    if (
        minimum is not None
        and n < minimum
    ):
        return (
            False,
            f"{label} fuori intervallo"
        )

    if (
        maximum is not None
        and n > maximum
    ):
        return (
            False,
            f"{label} fuori intervallo"
        )

    return (
        True,
        n
    )


def ra02_validate_config(cfg):

    g = cfg.get(
        "global",
        {}
    )

    poll = g.get(
        "poll",
        {}
    )

    if poll.get(
        "enabled"
    ):

        for key in (
            "rx_us",
            "tx_us"
        ):

            ok, error = ra02_int(
                poll.get(
                    key,
                    ""
                ),
                "-u",
                minimum=0
            )

            if not ok:
                return (
                    False,
                    error
                )

    json_udp = g.get(
        "json_udp",
        {}
    )

    if (
        json_udp.get(
            "enabled"
        )
        and not str(
            json_udp.get(
                "value",
                ""
            )
        ).strip()
    ):
        return (
            False,
            "-J attivo ma destinazione vuota"
        )

    chips = [
        chip
        for chip in cfg.get(
            "chips",
            []
        )
        if chip.get(
            "enabled"
        )
    ]

    if not chips:
        return (
            False,
            "Nessun chip ra02 attivo"
        )

    for ci, chip in enumerate(
        chips,
        1
    ):

        gpio = chip.get(
            "gpio",
            {}
        )

        for key in (
            "nss",
            "mosi",
            "miso",
            "sck"
        ):

            ok, error = ra02_int(
                gpio.get(
                    key,
                    ""
                ),
                f"Chip {ci} GPIO {key}",
                minimum=0,
                maximum=1023
            )

            if not ok:
                return (
                    False,
                    error
                )

        rx = chip.get(
            "rx",
            {}
        )

        numeric_rx = [
            (
                "frequency",
                "-f",
                ra02_float,
                137,
                1020,
                False
            ),
            (
                "sf",
                "-s",
                ra02_int,
                6,
                12,
                True
            ),
            (
                "bandwidth",
                "-b",
                ra02_int,
                0,
                9,
                False
            ),
            (
                "coding_rate",
                "-c",
                ra02_int,
                5,
                8,
                False
            ),
            (
                "lna_gain",
                "-e",
                ra02_int,
                1,
                6,
                False
            ),
            (
                "lna_boost",
                "-l",
                ra02_int,
                0,
                3,
                False
            ),
            (
                "ppm",
                "-P",
                ra02_float,
                -133,
                133,
                False
            ),
            (
                "datarate",
                "-X",
                ra02_float,
                -133,
                133,
                False
            ),
            (
                "pa_ramp",
                "-R",
                ra02_int,
                0,
                15,
                False
            )
        ]

        for (
            key,
            flag,
            parser,
            minimum,
            maximum,
            absolute
        ) in numeric_rx:

            state = rx.get(
                key,
                {}
            )

            if not state.get(
                "enabled"
            ):
                continue

            if parser is ra02_int:

                ok, error = parser(
                    state.get(
                        "value",
                        ""
                    ),
                    f"Chip {ci} {flag}",
                    minimum=minimum,
                    maximum=maximum,
                    absolute=absolute
                )

            else:

                ok, error = parser(
                    state.get(
                        "value",
                        ""
                    ),
                    f"Chip {ci} {flag}",
                    minimum=minimum,
                    maximum=maximum
                )

            if not ok:
                return (
                    False,
                    error
                )

        for key, flag in (
            ("optimize", "-o"),
        ):

            state = rx.get(
                key,
                {}
            )

            if state.get(
                "enabled"
            ):

                if str(
                    state.get(
                        "value",
                        ""
                    )
                ).strip() not in {
                    "-1",
                    "0",
                    "1"
                }:

                    return (
                        False,
                        f"Chip {ci} {flag} deve essere -1, 0 oppure 1"
                    )

        gfsk = rx.get(
            "gfsk_baud",
            {}
        )

        if gfsk.get(
            "enabled"
        ):

            ok, value = ra02_int(
                gfsk.get(
                    "value",
                    ""
                ),
                f"Chip {ci} -g",
                minimum=490,
                maximum=250000,
                absolute=True
            )

            if not ok:
                return (
                    False,
                    value
                )

        for ti, tx in enumerate(
            [
                x
                for x in chip.get(
                    "tx_contexts",
                    []
                )
                if x.get(
                    "enabled"
                )
            ],
            1
        ):

            transport = str(
                tx.get(
                    "transport",
                    ""
                )
            ).strip().upper()

            if transport not in {
                "L",
                "U"
            }:

                return (
                    False,
                    f"Chip {ci} TX {ti}: trasporto deve essere L oppure U"
                )

            if not str(
                tx.get(
                    "endpoint",
                    ""
                )
            ).strip():

                return (
                    False,
                    f"Chip {ci} TX {ti}: endpoint AXUDP mancante"
                )

            tx_checks = [
                (
                    "frequency",
                    "-F",
                    ra02_float,
                    137,
                    1020,
                    False
                ),
                (
                    "sf",
                    "-S",
                    ra02_int,
                    6,
                    12,
                    True
                ),
                (
                    "bandwidth",
                    "-B",
                    ra02_int,
                    0,
                    9,
                    False
                ),
                (
                    "coding_rate",
                    "-C",
                    ra02_int,
                    5,
                    8,
                    False
                ),
                (
                    "power",
                    "-w",
                    ra02_int,
                    0,
                    17,
                    False
                ),
                (
                    "tx_delay",
                    "-T",
                    ra02_int,
                    0,
                    250,
                    False
                ),
                (
                    "deviation",
                    "-D",
                    ra02_int,
                    0,
                    20000,
                    False
                )
            ]

            for (
                key,
                flag,
                parser,
                minimum,
                maximum,
                absolute
            ) in tx_checks:

                state = tx.get(
                    key,
                    {}
                )

                if not state.get(
                    "enabled"
                ):
                    continue

                if parser is ra02_int:

                    ok, error = parser(
                        state.get(
                            "value",
                            ""
                        ),
                        f"Chip {ci} TX {ti} {flag}",
                        minimum=minimum,
                        maximum=maximum,
                        absolute=absolute
                    )

                else:

                    ok, error = parser(
                        state.get(
                            "value",
                            ""
                        ),
                        f"Chip {ci} TX {ti} {flag}",
                        minimum=minimum,
                        maximum=maximum
                    )

                if not ok:
                    return (
                        False,
                        error
                    )

            optimize = tx.get(
                "optimize",
                {}
            )

            if optimize.get(
                "enabled"
            ):

                if str(
                    optimize.get(
                        "value",
                        ""
                    )
                ).strip() not in {
                    "-1",
                    "0",
                    "1"
                }:

                    return (
                        False,
                        f"Chip {ci} TX {ti} -O deve essere -1, 0 oppure 1"
                    )

            gfsk = tx.get(
                "gfsk_baud",
                {}
            )

            if gfsk.get(
                "enabled"
            ):

                ok, error = ra02_int(
                    gfsk.get(
                        "value",
                        ""
                    ),
                    f"Chip {ci} TX {ti} -G",
                    minimum=490,
                    maximum=250000,
                    absolute=True
                )

                if not ok:
                    return (
                        False,
                        error
                    )

    return (
        True,
        ""
    )


def ra02_service_running():

    result = subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            RA02_SERVICE
        ]
    )

    return result.returncode == 0


def ra02_service_enabled():

    result = subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            RA02_SERVICE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return result.returncode == 0


def ra02_journal():

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            RA02_SERVICE,
            "-n",
            "30",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    return (
        result.stdout.strip()
        or "Nessun log disponibile."
    )


def verify_ra02_service(
    timeout=10
):

    deadline = time.time() + timeout

    while time.time() < deadline:

        state = subprocess.run(
            [
                "systemctl",
                "show",
                RA02_SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--property=ExecMainStatus",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )

        values = state.stdout.splitlines()

        active_state = (
            values[0].strip()
            if len(values) > 0
            else ""
        )

        sub_state = (
            values[1].strip()
            if len(values) > 1
            else ""
        )

        exec_status = (
            values[2].strip()
            if len(values) > 2
            else ""
        )

        if (
            active_state == "active"
            and sub_state == "running"
        ):

            time.sleep(2)

            stable = subprocess.run(
                [
                    "systemctl",
                    "is-active",
                    "--quiet",
                    RA02_SERVICE
                ]
            )

            if stable.returncode == 0:
                return (
                    True,
                    ""
                )

        if (
            active_state == "failed"
            or sub_state == "auto-restart"
        ):

            subprocess.run(
                [
                    "systemctl",
                    "stop",
                    RA02_SERVICE
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            lines = [
                x.strip()
                for x in ra02_journal().splitlines()
                if x.strip()
            ]

            detail = (
                lines[-1]
                if lines
                else ""
            )

            return (
                False,
                detail
                or (
                    "ra02 terminato durante l'avvio"
                    + (
                        f" (exit status {exec_status})"
                        if exec_status
                        else ""
                    )
                )
            )

        time.sleep(0.25)

    return (
        False,
        "ra02 non è diventato stabile entro il timeout"
    )


def start_ra02_service():

    cfg = load_ra02_active_config()

    ok, error = ra02_validate_config(
        cfg
    )

    if not ok:
        return (
            False,
            error
        )

    result = subprocess.run(
        [
            "systemctl",
            "start",
            RA02_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'avvio di ra02"
        )

    return verify_ra02_service()


def stop_ra02_service():

    result = subprocess.run(
        [
            "systemctl",
            "stop",
            RA02_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante l'arresto di ra02"
        )

    return (
        True,
        ""
    )


def restart_ra02_service():

    cfg = load_ra02_active_config()

    ok, error = ra02_validate_config(
        cfg
    )

    if not ok:
        return (
            False,
            error
        )

    result = subprocess.run(
        [
            "systemctl",
            "restart",
            RA02_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore durante il riavvio di ra02"
        )

    return verify_ra02_service()


def apply_ra02_config():

    if not os.path.isfile(
        RA02_CONFIG_FILE
    ):

        return (
            False,
            "ra02_config.json non trovato"
        )

    was_running = (
        ra02_service_running()
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
        f"ra02-active-before-apply-{stamp}.json"
    )

    if os.path.isfile(
        RA02_ACTIVE_CONFIG_FILE
    ):

        shutil.copy2(
            RA02_ACTIVE_CONFIG_FILE,
            previous_active
        )

    else:

        shutil.copy2(
            RA02_CONFIG_FILE,
            previous_active
        )

    try:

        atomic_copy_file(
            RA02_CONFIG_FILE,
            RA02_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            "Impossibile creare ra02_active_config.json: "
            + str(exc)
        )

    if not was_running:

        return (
            True,
            ""
        )

    ok, error = (
        restart_ra02_service()
    )

    if ok:

        return (
            True,
            ""
        )

    first_error = error

    try:

        atomic_copy_file(
            previous_active,
            RA02_ACTIVE_CONFIG_FILE
        )

    except Exception as exc:

        return (
            False,
            first_error
            + " - ATTENZIONE: impossibile ripristinare "
            + "ra02_active_config.json: "
            + str(exc)
        )

    rollback_ok, rollback_error = (
        restart_ra02_service()
    )

    if rollback_ok:

        return (
            False,
            first_error
            + " - configurazione ra02 precedente "
            + "ripristinata automaticamente. "
            + "Le modifiche restano salvate nel draft."
        )

    return (
        False,
        first_error
        + " - ATTENZIONE: anche il rollback ra02 "
        + "non è riuscito: "
        + rollback_error
    )


RA02_RX_VALUE_FIELDS = [
    "frequency",
    "sf",
    "bandwidth",
    "coding_rate",
    "network_id",
    "gfsk_baud",
    "lna_gain",
    "lna_boost",
    "rssi_correction",
    "optimize",
    "ppm",
    "datarate",
    "preamble_limit",
    "pa_ramp",
    "ocp"
]

RA02_RX_BOOL_FIELDS = [
    "agc",
    "implicit",
    "invert_iq"
]

RA02_TX_VALUE_FIELDS = [
    "frequency",
    "sf",
    "bandwidth",
    "coding_rate",
    "network_id",
    "power",
    "preamble",
    "tx_delay",
    "deviation",
    "gfsk_baud",
    "optimize"
]

RA02_TX_BOOL_FIELDS = [
    "afsk",
    "raw_fsk",
    "raw_lora",
    "implicit",
    "dcd",
    "invert_iq"
]


def ra02_default_chip():

    return {
        "enabled": False,
        "gpio": {
            "nss": "8",
            "mosi": "10",
            "miso": "9",
            "sck": "11"
        },
        "rx": {
            "frequency": {
                "enabled": False,
                "value": "433.775"
            },
            "sf": {
                "enabled": False,
                "value": "12"
            },
            "bandwidth": {
                "enabled": False,
                "value": "7"
            },
            "coding_rate": {
                "enabled": False,
                "value": "5"
            },
            "network_id": {
                "enabled": False,
                "value": "12"
            },
            "gfsk_baud": {
                "enabled": False,
                "value": ""
            },
            "lna_gain": {
                "enabled": False,
                "value": "1"
            },
            "lna_boost": {
                "enabled": False,
                "value": "3"
            },
            "rssi_correction": {
                "enabled": False,
                "value": "0"
            },
            "optimize": {
                "enabled": False,
                "value": "-1"
            },
            "ppm": {
                "enabled": False,
                "value": "0"
            },
            "datarate": {
                "enabled": False,
                "value": "0"
            },
            "preamble_limit": {
                "enabled": False,
                "value": "250"
            },
            "pa_ramp": {
                "enabled": False,
                "value": "9"
            },
            "ocp": {
                "enabled": False,
                "value": ""
            },
            "agc": {
                "enabled": False
            },
            "implicit": {
                "enabled": False
            },
            "invert_iq": {
                "enabled": False
            }
        },
        "tx_contexts": [
            ra02_default_tx()
        ]
    }


def ra02_default_tx():

    return {
        "enabled": False,
        "transport": "L",
        "endpoint": "",
        "frequency": {
            "enabled": False,
            "value": "433.775"
        },
        "sf": {
            "enabled": False,
            "value": "12"
        },
        "bandwidth": {
            "enabled": False,
            "value": "7"
        },
        "coding_rate": {
            "enabled": False,
            "value": "5"
        },
        "network_id": {
            "enabled": False,
            "value": "12"
        },
        "power": {
            "enabled": False,
            "value": "10"
        },
        "preamble": {
            "enabled": False,
            "value": "8"
        },
        "tx_delay": {
            "enabled": False,
            "value": "6"
        },
        "deviation": {
            "enabled": False,
            "value": "3000"
        },
        "gfsk_baud": {
            "enabled": False,
            "value": ""
        },
        "optimize": {
            "enabled": False,
            "value": "-1"
        },
        "afsk": {
            "enabled": False
        },
        "raw_fsk": {
            "enabled": False
        },
        "raw_lora": {
            "enabled": False
        },
        "implicit": {
            "enabled": False
        },
        "dcd": {
            "enabled": False
        },
        "invert_iq": {
            "enabled": False
        }
    }


def update_ra02_from_form(cfg):

    g = cfg.setdefault(
        "global",
        {}
    )

    poll = g.setdefault(
        "poll",
        {}
    )

    poll["enabled"] = (
        "g_poll_enabled"
        in request.form
    )

    poll["rx_us"] = request.form.get(
        "g_poll_rx",
        "30000"
    ).strip()

    poll["tx_us"] = request.form.get(
        "g_poll_tx",
        "10000"
    ).strip()

    json_udp = g.setdefault(
        "json_udp",
        {}
    )

    json_udp["enabled"] = (
        "g_json_enabled"
        in request.form
    )

    json_udp["value"] = request.form.get(
        "g_json_value",
        ""
    ).strip()

    for key in (
        "verbose",
        "very_verbose"
    ):

        state = g.setdefault(
            key,
            {}
        )

        state["enabled"] = (
            f"g_{key}"
            in request.form
        )

    try:

        chip_count = int(
            request.form.get(
                "chip_count",
                "1"
            )
        )

    except Exception:

        chip_count = 1

    old_chips = cfg.get(
        "chips",
        []
    )

    chips = []

    for ci in range(
        chip_count
    ):

        if ci < len(
            old_chips
        ):

            chip = old_chips[ci]

        else:

            chip = {
                "enabled": False,
                "gpio": {},
                "rx": {},
                "tx_contexts": []
            }

        chip["enabled"] = (
            f"chip{ci}_enabled"
            in request.form
        )

        gpio = chip.setdefault(
            "gpio",
            {}
        )

        for key, default in (
            ("nss", "8"),
            ("mosi", "10"),
            ("miso", "9"),
            ("sck", "11")
        ):

            gpio[key] = request.form.get(
                f"chip{ci}_gpio_{key}",
                default
            ).strip()

        rx = chip.setdefault(
            "rx",
            {}
        )

        for key in RA02_RX_VALUE_FIELDS:

            state = rx.setdefault(
                key,
                {}
            )

            state["enabled"] = (
                f"chip{ci}_rx_{key}_enabled"
                in request.form
            )

            state["value"] = request.form.get(
                f"chip{ci}_rx_{key}",
                state.get(
                    "value",
                    ""
                )
            ).strip()

        for key in RA02_RX_BOOL_FIELDS:

            state = rx.setdefault(
                key,
                {}
            )

            state["enabled"] = (
                f"chip{ci}_rx_{key}_enabled"
                in request.form
            )

        try:

            tx_count = int(
                request.form.get(
                    f"chip{ci}_tx_count",
                    "1"
                )
            )

        except Exception:

            tx_count = 1

        old_tx = chip.get(
            "tx_contexts",
            []
        )

        tx_contexts = []

        for ti in range(
            tx_count
        ):

            if ti < len(
                old_tx
            ):

                tx = old_tx[ti]

            else:

                tx = {
                    "enabled": False
                }

            tx["enabled"] = (
                f"chip{ci}_tx{ti}_enabled"
                in request.form
            )

            tx["transport"] = request.form.get(
                f"chip{ci}_tx{ti}_transport",
                tx.get(
                    "transport",
                    "L"
                )
            ).strip().upper()

            tx["endpoint"] = request.form.get(
                f"chip{ci}_tx{ti}_endpoint",
                tx.get(
                    "endpoint",
                    ""
                )
            ).strip()

            for key in RA02_TX_VALUE_FIELDS:

                state = tx.setdefault(
                    key,
                    {}
                )

                state["enabled"] = (
                    f"chip{ci}_tx{ti}_{key}_enabled"
                    in request.form
                )

                state["value"] = request.form.get(
                    f"chip{ci}_tx{ti}_{key}",
                    state.get(
                        "value",
                        ""
                    )
                ).strip()

            for key in RA02_TX_BOOL_FIELDS:

                state = tx.setdefault(
                    key,
                    {}
                )

                state["enabled"] = (
                    f"chip{ci}_tx{ti}_{key}_enabled"
                    in request.form
                )

            tx_contexts.append(
                tx
            )

        chip["tx_contexts"] = (
            tx_contexts
        )

        chips.append(
            chip
        )

    cfg["chips"] = chips

    return cfg


@app.route(
    "/config/ra02",
    methods=[
        "GET",
        "POST"
    ]
)
def config_ra02():

    cfg = load_ra02_config()

    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )

        if action == "start":

            ok, error = (
                start_ra02_service()
            )

            if ok:
                flash(
                    "RA02_START_OK"
                )
            else:
                flash(
                    "RA02_ERROR: "
                    + error
                )

            return redirect(
                "/config/ra02"
            )

        if action == "stop":

            ok, error = (
                stop_ra02_service()
            )

            if ok:
                flash(
                    "RA02_STOP_OK"
                )
            else:
                flash(
                    "RA02_ERROR: "
                    + error
                )

            return redirect(
                "/config/ra02"
            )

        if action == "restart":

            ok, error = (
                restart_ra02_service()
            )

            if ok:
                flash(
                    "RA02_RESTART_OK"
                )
            else:
                flash(
                    "RA02_ERROR: "
                    + error
                )

            return redirect(
                "/config/ra02"
            )

        cfg = update_ra02_from_form(
            cfg
        )

        save_ra02_config(
            cfg
        )

        if action == "apply":

            ok, error = (
                apply_ra02_config()
            )

            if ok:

                if ra02_service_running():

                    flash(
                        "RA02_APPLY_RESTART_OK"
                    )

                else:

                    flash(
                        "RA02_APPLY_STOPPED_OK"
                    )

            else:

                flash(
                    "RA02_ERROR: "
                    + error
                )

        else:

            flash(
                "RA02_SAVE_OK"
            )

        return redirect(
            "/config/ra02"
        )

    cfg = load_ra02_config()

    active_cfg = (
        load_ra02_active_config()
    )

    return render_template(
        "config_ra02.html",
        cfg=cfg,
        G=cfg.get(
            "global",
            {}
        ),
        chips=cfg.get(
            "chips",
            []
        ),
        running=ra02_service_running(),
        enabled=ra02_service_enabled(),
        command=ra02_build_command(
            cfg,
            load_config()
        ),
        active_command=ra02_build_command(
            active_cfg,
            load_active_config()
        ),
        journal=ra02_journal()
    )



# =============================================================================
# RA02WATERFALL
# =============================================================================

RA02WATERFALL_SERVICE = "dxlaprs-ra02waterfall.service"

RA02WATERFALL_CONFIG_FILE = os.path.join(
    BASE_DIR, "data", "ra02waterfall_config.json"
)

RA02WATERFALL_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR, "data", "ra02waterfall_active_config.json"
)


def load_ra02waterfall_json(path):

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_ra02waterfall_config():

    return load_ra02waterfall_json(
        RA02WATERFALL_CONFIG_FILE
    )


def load_ra02waterfall_active_config():

    if os.path.isfile(RA02WATERFALL_ACTIVE_CONFIG_FILE):
        return load_ra02waterfall_json(
            RA02WATERFALL_ACTIVE_CONFIG_FILE
        )

    return load_ra02waterfall_config()


def save_ra02waterfall_config(cfg):

    os.makedirs(BACKUP_DIR, exist_ok=True)

    if os.path.isfile(RA02WATERFALL_CONFIG_FILE):

        stamp = datetime.now().strftime(
            "%Y%m%d-%H%M%S-%f"
        )

        shutil.copy2(
            RA02WATERFALL_CONFIG_FILE,
            os.path.join(
                BACKUP_DIR,
                f"ra02waterfall-config-{stamp}.json"
            )
        )

    directory = os.path.dirname(
        RA02WATERFALL_CONFIG_FILE
    )

    fd, tmp = tempfile.mkstemp(
        prefix="ra02waterfall-config-",
        suffix=".json",
        dir=directory
    )

    try:

        with os.fdopen(fd, "w", encoding="utf-8") as f:

            json.dump(
                cfg,
                f,
                ensure_ascii=False,
                indent=2
            )

            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        os.replace(
            tmp,
            RA02WATERFALL_CONFIG_FILE
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def ra02waterfall_add_value(argv, flag, state):

    if not state.get("enabled"):
        return

    value = str(
        state.get("value", "")
    ).strip()

    if value:
        argv.extend([flag, value])


def ra02waterfall_add_bool(argv, flag, state):

    if state.get("enabled"):
        argv.append(flag)


def ra02waterfall_build_argv(cfg, manager_cfg=None):

    if manager_cfg is None:
        manager_cfg = load_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs", {}
        ).get(
            "bin_dir", ""
        )
    ).strip()

    binary = (
        os.path.join(bin_dir, "ra02waterfall")
        if bin_dir
        else "ra02waterfall"
    )

    argv = [binary]

    gpio = cfg.get("gpio", {})

    if gpio.get("enabled"):

        argv.extend([
            "-p",
            str(gpio.get("nss", "")).strip(),
            str(gpio.get("mosi", "")).strip(),
            str(gpio.get("miso", "")).strip(),
            str(gpio.get("sck", "")).strip()
        ])

    radio = cfg.get("radio", {})

    ra02waterfall_add_bool(
        argv,
        "-l",
        radio.get("lna_boost", {})
    )

    ra02waterfall_add_value(
        argv,
        "-P",
        radio.get("ppm", {})
    )

    freq = cfg.get("frequency", {})

    if freq.get("enabled"):

        mode = str(
            freq.get("mode", "range")
        ).strip()

        if mode == "range":

            argv.extend([
                "-f",
                str(freq.get("start_mhz", "")).strip(),
                str(freq.get("end_mhz", "")).strip()
            ])

        elif mode == "table":

            table = str(
                freq.get("table", "")
            ).strip()

            if table:
                argv.extend([
                    "-f",
                    table
                ])

    image = cfg.get("image", {})

    for key, flag in (
        ("filename", "-w"),
        ("xsize", "-x"),
        ("ysize", "-y"),
        ("roll", "-r"),
        ("spectrum", "-s"),
        ("delay", "-d")
    ):

        ra02waterfall_add_value(
            argv,
            flag,
            image.get(key, {})
        )

    for key, flag in (
        ("scale", "-R"),
        ("timestamps", "-T"),
        ("transparent", "-t"),
        ("mirror", "-m")
    ):

        ra02waterfall_add_bool(
            argv,
            flag,
            image.get(key, {})
        )

    external = cfg.get("external", {})

    for key, flag in (
        ("colour_file", "-c"),
        ("gps", "-g"),
        ("level_file", "-j")
    ):

        ra02waterfall_add_value(
            argv,
            flag,
            external.get(key, {})
        )

    debug = cfg.get("debug", {})

    ra02waterfall_add_bool(
        argv,
        "-v",
        debug.get("verbose", {})
    )

    ra02waterfall_add_bool(
        argv,
        "-V",
        debug.get("very_verbose", {})
    )

    return argv


def ra02waterfall_build_command(cfg, manager_cfg=None):

    return " ".join(
        shlex.quote(str(x))
        for x in ra02waterfall_build_argv(
            cfg,
            manager_cfg
        )
    )


def ra02waterfall_validate(cfg):

    gpio = cfg.get("gpio", {})

    if gpio.get("enabled"):

        for key in (
            "nss",
            "mosi",
            "miso",
            "sck"
        ):

            try:
                n = int(str(gpio.get(key, "")).strip())
            except Exception:
                return False, f"GPIO {key} non valido"

            if n < 0 or n >= 1024:
                return False, f"GPIO {key} fuori intervallo"

    radio = cfg.get("radio", {})

    ppm = radio.get("ppm", {})

    if ppm.get("enabled"):

        try:
            n = float(str(ppm.get("value", "")).strip())
        except Exception:
            return False, "-P ppm non valido"

        if n < -133 or n > 133:
            return False, "-P deve essere compreso tra -133 e +133"

    freq = cfg.get("frequency", {})

    if freq.get("enabled"):

        mode = str(
            freq.get("mode", "range")
        ).strip()

        if mode == "range":

            try:
                start = float(
                    str(freq.get("start_mhz", "")).strip()
                )

                end = float(
                    str(freq.get("end_mhz", "")).strip()
                )

            except Exception:
                return False, "Intervallo -f non valido"

            if start < 137 or start > 1020:
                return False, "Frequenza iniziale fuori intervallo"

            if end < 137 or end > 1020:
                return False, "Frequenza finale fuori intervallo"

            if start >= end:
                return False, "La frequenza iniziale deve essere inferiore alla finale"

        elif mode == "table":

            table = str(
                freq.get("table", "")
            ).strip()

            if not table:
                return False, "Tabella frequenze vuota"

            for entry in table.split(","):

                entry = entry.strip()

                if "/" not in entry:
                    return False, f"Voce tabella non valida: {entry}"

                f, bw = entry.split("/", 1)

                try:
                    mhz = float(f)
                    bandwidth = int(bw)
                except Exception:
                    return False, f"Voce tabella non valida: {entry}"

                if mhz < 137 or mhz > 1020:
                    return False, f"Frequenza fuori intervallo: {mhz}"

                if bandwidth < 0:
                    return False, f"Bandwidth non valida: {bandwidth}"

        else:

            return False, "Modalità frequenza non valida"

    image = cfg.get("image", {})

    checks = (
        ("xsize", "-x", 32, 31999),
        ("ysize", "-y", 1, 31999),
        ("spectrum", "-s", 32, 255),
        ("roll", "-r", 0, None),
        ("delay", "-d", 0, None)
    )

    for key, flag, minimum, maximum in checks:

        state = image.get(key, {})

        if not state.get("enabled"):
            continue

        try:
            n = int(
                str(state.get("value", "")).strip()
            )
        except Exception:
            return False, f"{flag} non valido"

        if n < minimum:
            return False, f"{flag} fuori intervallo"

        if maximum is not None and n > maximum:
            return False, f"{flag} fuori intervallo"

    for section_name, section, keys in (
        (
            "image",
            image,
            ("filename",)
        ),
        (
            "external",
            cfg.get("external", {}),
            ("colour_file", "gps", "level_file")
        )
    ):

        for key in keys:

            state = section.get(key, {})

            if (
                state.get("enabled")
                and not str(
                    state.get("value", "")
                ).strip()
            ):
                return False, f"{section_name}.{key}: valore mancante"

    return True, ""


def ra02waterfall_service_running():

    return subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            RA02WATERFALL_SERVICE
        ]
    ).returncode == 0


def ra02waterfall_service_enabled():

    return subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            RA02WATERFALL_SERVICE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).returncode == 0


def ra02waterfall_journal():

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            RA02WATERFALL_SERVICE,
            "-n",
            "30",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    return (
        result.stdout.strip()
        or "Nessun log disponibile."
    )


def verify_ra02waterfall_service(timeout=10):

    deadline = time.time() + timeout

    while time.time() < deadline:

        if ra02waterfall_service_running():

            time.sleep(2)

            if ra02waterfall_service_running():
                return True, ""

        state = subprocess.run(
            [
                "systemctl",
                "show",
                RA02WATERFALL_SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        ).stdout

        if "failed" in state or "auto-restart" in state:

            subprocess.run(
                [
                    "systemctl",
                    "stop",
                    RA02WATERFALL_SERVICE
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            lines = [
                x.strip()
                for x in ra02waterfall_journal().splitlines()
                if x.strip()
            ]

            return (
                False,
                lines[-1] if lines else "ra02waterfall terminato durante l'avvio"
            )

        time.sleep(0.25)

    return False, "ra02waterfall non è diventato stabile entro il timeout"


def start_ra02waterfall_service():

    cfg = load_ra02waterfall_active_config()

    ok, error = ra02waterfall_validate(cfg)

    if not ok:
        return False, error

    result = subprocess.run(
        [
            "systemctl",
            "start",
            RA02WATERFALL_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore avvio ra02waterfall"
        )

    return verify_ra02waterfall_service()


def stop_ra02waterfall_service():

    result = subprocess.run(
        [
            "systemctl",
            "stop",
            RA02WATERFALL_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        return False, result.stderr.strip() or "Errore arresto ra02waterfall"

    return True, ""


def restart_ra02waterfall_service():

    cfg = load_ra02waterfall_active_config()

    ok, error = ra02waterfall_validate(cfg)

    if not ok:
        return False, error

    result = subprocess.run(
        [
            "systemctl",
            "restart",
            RA02WATERFALL_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        return False, result.stderr.strip() or "Errore riavvio ra02waterfall"

    return verify_ra02waterfall_service()


def apply_ra02waterfall_config():

    was_running = ra02waterfall_service_running()

    os.makedirs(BACKUP_DIR, exist_ok=True)

    stamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )

    previous = os.path.join(
        BACKUP_DIR,
        f"ra02waterfall-active-before-apply-{stamp}.json"
    )

    if os.path.isfile(RA02WATERFALL_ACTIVE_CONFIG_FILE):

        shutil.copy2(
            RA02WATERFALL_ACTIVE_CONFIG_FILE,
            previous
        )

    else:

        shutil.copy2(
            RA02WATERFALL_CONFIG_FILE,
            previous
        )

    atomic_copy_file(
        RA02WATERFALL_CONFIG_FILE,
        RA02WATERFALL_ACTIVE_CONFIG_FILE
    )

    if not was_running:
        return True, ""

    ok, error = restart_ra02waterfall_service()

    if ok:
        return True, ""

    atomic_copy_file(
        previous,
        RA02WATERFALL_ACTIVE_CONFIG_FILE
    )

    rollback_ok, rollback_error = restart_ra02waterfall_service()

    if rollback_ok:

        return (
            False,
            error
            + " - configurazione precedente ripristinata automaticamente"
        )

    return (
        False,
        error
        + " - ATTENZIONE: rollback non riuscito: "
        + rollback_error
    )


def update_ra02waterfall_from_form(cfg):

    gpio = cfg.setdefault("gpio", {})

    gpio["enabled"] = "gpio_enabled" in request.form

    for key, default in (
        ("nss", "8"),
        ("mosi", "10"),
        ("miso", "9"),
        ("sck", "11")
    ):

        gpio[key] = request.form.get(
            f"gpio_{key}",
            default
        ).strip()

    radio = cfg.setdefault("radio", {})

    radio.setdefault("lna_boost", {})["enabled"] = (
        "radio_lna_boost" in request.form
    )

    ppm = radio.setdefault("ppm", {})

    ppm["enabled"] = "radio_ppm_enabled" in request.form
    ppm["value"] = request.form.get("radio_ppm", "0").strip()

    freq = cfg.setdefault("frequency", {})

    freq["enabled"] = "frequency_enabled" in request.form
    freq["mode"] = request.form.get("frequency_mode", "range").strip()
    freq["start_mhz"] = request.form.get("frequency_start", "430.0").strip()
    freq["end_mhz"] = request.form.get("frequency_end", "440.0").strip()
    freq["table"] = request.form.get("frequency_table", "").strip()

    image = cfg.setdefault("image", {})

    for key in (
        "filename",
        "xsize",
        "ysize",
        "roll",
        "spectrum",
        "delay"
    ):

        state = image.setdefault(key, {})

        state["enabled"] = (
            f"image_{key}_enabled" in request.form
        )

        state["value"] = request.form.get(
            f"image_{key}",
            state.get("value", "")
        ).strip()

    for key in (
        "scale",
        "timestamps",
        "transparent",
        "mirror"
    ):

        image.setdefault(key, {})["enabled"] = (
            f"image_{key}" in request.form
        )

    external = cfg.setdefault("external", {})

    for key in (
        "colour_file",
        "gps",
        "level_file"
    ):

        state = external.setdefault(key, {})

        state["enabled"] = (
            f"external_{key}_enabled" in request.form
        )

        state["value"] = request.form.get(
            f"external_{key}",
            state.get("value", "")
        ).strip()

    debug = cfg.setdefault("debug", {})

    debug.setdefault("verbose", {})["enabled"] = (
        "debug_verbose" in request.form
    )

    debug.setdefault("very_verbose", {})["enabled"] = (
        "debug_very_verbose" in request.form
    )

    return cfg


@app.route(
    "/config/ra02waterfall",
    methods=["GET", "POST"]
)
def config_ra02waterfall():

    cfg = load_ra02waterfall_config()

    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )

        if action == "start":

            ok, error = start_ra02waterfall_service()

            flash(
                "RA02WATERFALL_START_OK"
                if ok
                else "RA02WATERFALL_ERROR: " + error
            )

            return redirect("/config/ra02waterfall")

        if action == "stop":

            ok, error = stop_ra02waterfall_service()

            flash(
                "RA02WATERFALL_STOP_OK"
                if ok
                else "RA02WATERFALL_ERROR: " + error
            )

            return redirect("/config/ra02waterfall")

        if action == "restart":

            ok, error = restart_ra02waterfall_service()

            flash(
                "RA02WATERFALL_RESTART_OK"
                if ok
                else "RA02WATERFALL_ERROR: " + error
            )

            return redirect("/config/ra02waterfall")

        cfg = update_ra02waterfall_from_form(cfg)

        ok, error = ra02waterfall_validate(cfg)

        if not ok:

            flash("RA02WATERFALL_ERROR: " + error)
            return redirect("/config/ra02waterfall")

        save_ra02waterfall_config(cfg)

        if action == "apply":

            ok, error = apply_ra02waterfall_config()

            flash(
                "RA02WATERFALL_APPLY_OK"
                if ok
                else "RA02WATERFALL_ERROR: " + error
            )

        else:

            flash("RA02WATERFALL_SAVE_OK")

        return redirect("/config/ra02waterfall")

    cfg = load_ra02waterfall_config()
    active_cfg = load_ra02waterfall_active_config()

    return render_template(
        "config_ra02waterfall.html",
        cfg=cfg,
        GPIO=cfg.get("gpio", {}),
        RADIO=cfg.get("radio", {}),
        FREQ=cfg.get("frequency", {}),
        IMAGE=cfg.get("image", {}),
        EXTERNAL=cfg.get("external", {}),
        DEBUG=cfg.get("debug", {}),
        running=ra02waterfall_service_running(),
        enabled=ra02waterfall_service_enabled(),
        command=ra02waterfall_build_command(
            cfg,
            load_config()
        ),
        active_command=ra02waterfall_build_command(
            active_cfg,
            load_active_config()
        ),
        journal=ra02waterfall_journal()
    )



# =============================================================================
# SDRTST
# =============================================================================

SDRTST_SERVICE = "dxlaprs-sdrtst.service"

SDRTST_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "sdrtst_config.json"
)

SDRTST_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "sdrtst_active_config.json"
)


def load_sdrtst_json(path):

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_sdrtst_config():

    return load_sdrtst_json(
        SDRTST_CONFIG_FILE
    )


def load_sdrtst_active_config():

    if os.path.isfile(
        SDRTST_ACTIVE_CONFIG_FILE
    ):
        return load_sdrtst_json(
            SDRTST_ACTIVE_CONFIG_FILE
        )

    return load_sdrtst_config()


def save_sdrtst_config(cfg):

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    if os.path.isfile(
        SDRTST_CONFIG_FILE
    ):

        stamp = datetime.now().strftime(
            "%Y%m%d-%H%M%S-%f"
        )

        shutil.copy2(
            SDRTST_CONFIG_FILE,
            os.path.join(
                BACKUP_DIR,
                f"sdrtst-config-{stamp}.json"
            )
        )

    directory = os.path.dirname(
        SDRTST_CONFIG_FILE
    )

    fd, tmp = tempfile.mkstemp(
        prefix="sdrtst-config-",
        suffix=".json",
        dir=directory
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                ensure_ascii=False,
                indent=2
            )

            f.write("\n")
            f.flush()
            os.fsync(f.fileno())

        os.replace(
            tmp,
            SDRTST_CONFIG_FILE
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def sdrtst_add_value(
    argv,
    flag,
    state
):

    if not state.get("enabled"):
        return

    value = str(
        state.get("value", "")
    ).strip()

    if value:
        argv.extend([
            flag,
            value
        ])


def sdrtst_add_bool(
    argv,
    flag,
    state
):

    if state.get("enabled"):
        argv.append(flag)


def sdrtst_build_argv(
    cfg,
    manager_cfg=None
):

    if manager_cfg is None:
        manager_cfg = load_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    binary = (
        os.path.join(
            bin_dir,
            "sdrtst"
        )
        if bin_dir
        else "sdrtst"
    )

    argv = [binary]


    # ---------------------------------------------------------
    # INPUT
    # ---------------------------------------------------------

    inp = cfg.get(
        "input",
        {}
    )

    sdrtst_add_value(
        argv,
        "-t",
        inp.get("source", {})
    )

    sdrtst_add_value(
        argv,
        "-f",
        inp.get("format", {})
    )

    sdrtst_add_value(
        argv,
        "-i",
        inp.get("iq_rate", {})
    )

    sdrtst_add_value(
        argv,
        "-T",
        inp.get("manual_tune", {})
    )

    sdrtst_add_value(
        argv,
        "-O",
        inp.get("center_offset", {})
    )

    sdrtst_add_value(
        argv,
        "-o",
        inp.get("converter_offset", {})
    )

    sdrtst_add_bool(
        argv,
        "-k",
        inp.get("reconnect", {})
    )


    # ---------------------------------------------------------
    # CHANNEL CONFIG
    # ---------------------------------------------------------

    channels = cfg.get(
        "channels",
        {}
    )

    sdrtst_add_value(
        argv,
        "-c",
        channels.get(
            "config_source",
            {}
        )
    )


    # ---------------------------------------------------------
    # AUDIO
    # ---------------------------------------------------------

    audio = cfg.get(
        "audio",
        {}
    )

    out = audio.get(
        "output",
        {}
    )

    if out.get("enabled"):

        mode = str(
            out.get(
                "mode",
                "s16"
            )
        ).strip()

        value = str(
            out.get(
                "value",
                ""
            )
        ).strip()

        flags = {
            "s16": "-s",
            "u8": "-S",
            "alaw": "-A"
        }

        if (
            mode in flags
            and value
        ):
            argv.extend([
                flags[mode],
                value
            ])

    for key, flag in (
        ("sample_rate", "-r"),
        ("downsample", "-d"),
        ("mix_channels", "-m"),
        ("buffer_samples", "-B")
    ):

        sdrtst_add_value(
            argv,
            flag,
            audio.get(key, {})
        )

    sdrtst_add_bool(
        argv,
        "-q",
        audio.get(
            "stop_when_squelched",
            {}
        )
    )

    sdrtst_add_bool(
        argv,
        "-e",
        audio.get(
            "watermark",
            {}
        )
    )


    # ---------------------------------------------------------
    # RECEIVER / CPU
    # ---------------------------------------------------------

    rx = cfg.get(
        "receiver",
        {}
    )

    sdrtst_add_value(
        argv,
        "-a",
        rx.get(
            "max_active",
            {}
        )
    )

    sdrtst_add_value(
        argv,
        "-w",
        rx.get(
            "max_awake",
            {}
        )
    )

    ps = rx.get(
        "powersave",
        {}
    )

    if ps.get("enabled"):

        mode = str(
            ps.get(
                "mode",
                "normal"
            )
        ).strip()

        value = str(
            ps.get(
                "value",
                ""
            )
        ).strip()

        if value:

            if mode == "normal":
                argv.extend([
                    "-z",
                    value
                ])

            elif mode == "fast":
                argv.extend([
                    "-Z",
                    value
                ])

    sdrtst_add_value(
        argv,
        "-F",
        rx.get(
            "afc_speed",
            {}
        )
    )


    # ---------------------------------------------------------
    # TELEMETRY
    # ---------------------------------------------------------

    telemetry = cfg.get(
        "telemetry",
        {}
    )

    for value in telemetry.get(
        "level_destinations",
        []
    ):

        value = str(value).strip()

        if value:
            argv.extend([
                "-L",
                value
            ])

    for value in telemetry.get(
        "noise_destinations",
        []
    ):

        value = str(value).strip()

        if value:
            argv.extend([
                "-N",
                value
            ])


    # ---------------------------------------------------------
    # RTL_TCP PARAMETERS
    # ---------------------------------------------------------

    rtl = cfg.get(
        "rtl_tcp",
        {}
    )

    for item in rtl.get(
        "parameters",
        []
    ):

        if not item.get(
            "enabled",
            True
        ):
            continue

        cmd = str(
            item.get(
                "cmd",
                ""
            )
        ).strip()

        value = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if cmd and value:

            argv.extend([
                "-p",
                cmd,
                value
            ])


    # ---------------------------------------------------------
    # DEBUG
    # ---------------------------------------------------------

    debug = cfg.get(
        "debug",
        {}
    )

    sdrtst_add_value(
        argv,
        "-D",
        debug.get(
            "iq_dump",
            {}
        )
    )

    sdrtst_add_bool(
        argv,
        "-v",
        debug.get(
            "verbose",
            {}
        )
    )

    return argv


def sdrtst_build_command(
    cfg,
    manager_cfg=None
):

    return " ".join(
        shlex.quote(str(x))
        for x in sdrtst_build_argv(
            cfg,
            manager_cfg
        )
    )


def sdrtst_validate(cfg):

    inp = cfg.get(
        "input",
        {}
    )


    # ---------------------------------------------------------
    # FORMAT
    # ---------------------------------------------------------

    fmt_state = inp.get(
        "format",
        {}
    )

    fmt = str(
        fmt_state.get(
            "value",
            "u8"
        )
    ).strip()

    if (
        fmt_state.get("enabled")
        and fmt not in (
            "u8",
            "i16",
            "f32"
        )
    ):
        return False, "-f deve essere u8, i16 oppure f32"


    # ---------------------------------------------------------
    # IQ RATE
    # ---------------------------------------------------------

    iq_state = inp.get(
        "iq_rate",
        {}
    )

    if iq_state.get("enabled"):

        try:
            iqrate = int(
                str(
                    iq_state.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-i sample rate IQ non valido"

        effective_fmt = (
            fmt
            if fmt_state.get("enabled")
            else "u8"
        )

        if effective_fmt == "f32":

            if (
                iqrate < 1000000
                or iqrate > 3000000
            ):
                return False, "-i con f32 deve essere 1000000..3000000"

        else:

            if not (
                iqrate == 1024000
                or (
                    2000000
                    <= iqrate
                    <= 2500000
                )
            ):
                return False, "-i con u8/i16 deve essere 1024000 oppure 2000000..2500000"


    # ---------------------------------------------------------
    # MANUAL TUNE
    # ---------------------------------------------------------

    tune = inp.get(
        "manual_tune",
        {}
    )

    if tune.get("enabled"):

        try:
            mhz = float(
                str(
                    tune.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-T MHz non valido"

        if (
            mhz < 0
            or mhz > 4294.967295
        ):
            return False, "-T fuori intervallo"


    # ---------------------------------------------------------
    # CENTER OFFSET
    # ---------------------------------------------------------

    center = inp.get(
        "center_offset",
        {}
    )

    if center.get("enabled"):

        try:
            n = int(
                str(
                    center.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-O Hz non valido"

        if (
            n < 0
            or n > 25000000
        ):
            return False, "-O deve essere 0..25000000"


    # ---------------------------------------------------------
    # CONVERTER OFFSET
    # ---------------------------------------------------------

    converter = inp.get(
        "converter_offset",
        {}
    )

    if converter.get("enabled"):

        try:
            float(
                str(
                    converter.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-o MHz non valido"


    # ---------------------------------------------------------
    # REQUIRED STRING VALUES
    # ---------------------------------------------------------

    required_states = (
        (
            "-t",
            inp.get("source", {})
        ),
        (
            "-c",
            cfg.get(
                "channels",
                {}
            ).get(
                "config_source",
                {}
            )
        ),
        (
            "-D",
            cfg.get(
                "debug",
                {}
            ).get(
                "iq_dump",
                {}
            )
        )
    )

    for flag, state in required_states:

        if (
            state.get("enabled")
            and not str(
                state.get(
                    "value",
                    ""
                )
            ).strip()
        ):
            return False, f"{flag}: valore mancante"


    # ---------------------------------------------------------
    # AUDIO
    # ---------------------------------------------------------

    audio = cfg.get(
        "audio",
        {}
    )

    output = audio.get(
        "output",
        {}
    )

    if output.get("enabled"):

        mode = str(
            output.get(
                "mode",
                ""
            )
        ).strip()

        if mode not in (
            "s16",
            "u8",
            "alaw"
        ):
            return False, "Formato uscita audio non valido"

        if not str(
            output.get(
                "value",
                ""
            )
        ).strip():
            return False, "Destinazione audio mancante"


    sample_rate = None

    sr = audio.get(
        "sample_rate",
        {}
    )

    if sr.get("enabled"):

        try:
            sample_rate = int(
                str(
                    sr.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-r sample rate non valido"

        if (
            sample_rate < 0
            or sample_rate > 256000
        ):
            return False, "-r deve essere 0..256000"


    ds = audio.get(
        "downsample",
        {}
    )

    if ds.get("enabled"):

        try:
            downsample = int(
                str(
                    ds.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-d sample rate non valido"

        if downsample < 0:
            return False, "-d non può essere negativo"

        effective_sr = (
            sample_rate
            if sample_rate is not None
            else 16000
        )

        if downsample > effective_sr:
            return False, "-d non può superare -r"


    mix = audio.get(
        "mix_channels",
        {}
    )

    if mix.get("enabled"):

        try:
            n = int(
                str(
                    mix.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-m non valido"

        if n not in (1, 2):
            return False, "-m deve essere 1 oppure 2"


    buffer_state = audio.get(
        "buffer_samples",
        {}
    )

    if buffer_state.get("enabled"):

        try:
            n = int(
                str(
                    buffer_state.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-B non valido"

        if (
            n < 0
            or n > 1024
        ):
            return False, "-B deve essere 0..1024"


    # ---------------------------------------------------------
    # RECEIVER
    # ---------------------------------------------------------

    rx = cfg.get(
        "receiver",
        {}
    )

    for key, flag in (
        ("max_active", "-a"),
        ("max_awake", "-w")
    ):

        state = rx.get(
            key,
            {}
        )

        if state.get("enabled"):

            try:
                n = int(
                    str(
                        state.get(
                            "value",
                            ""
                        )
                    ).strip()
                )
            except Exception:
                return False, f"{flag} non valido"

            if n < 0:
                return False, f"{flag} non può essere negativo"


    ps = rx.get(
        "powersave",
        {}
    )

    if ps.get("enabled"):

        if str(
            ps.get(
                "mode",
                ""
            )
        ).strip() not in (
            "normal",
            "fast"
        ):
            return False, "Modalità powersave non valida"

        try:
            n = int(
                str(
                    ps.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-z/-Z non valido"

        if n < 0:
            return False, "-z/-Z non può essere negativo"


    afc = rx.get(
        "afc_speed",
        {}
    )

    if afc.get("enabled"):

        try:
            n = int(
                str(
                    afc.get(
                        "value",
                        ""
                    )
                ).strip()
            )
        except Exception:
            return False, "-F non valido"

        if (
            n < 0
            or n > 1000
        ):
            return False, "-F deve essere 0..1000"


    # ---------------------------------------------------------
    # RTL_TCP PARAMETERS
    # ---------------------------------------------------------

    seen = set()

    for item in cfg.get(
        "rtl_tcp",
        {}
    ).get(
        "parameters",
        []
    ):

        if not item.get(
            "enabled",
            True
        ):
            continue

        cmd_text = str(
            item.get(
                "cmd",
                ""
            )
        ).strip()

        value_text = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if not cmd_text and not value_text:
            continue

        try:
            cmd = int(cmd_text)
        except Exception:
            return False, "-p cmd non valido"

        if (
            cmd < 0
            or cmd > 255
        ):
            return False, "-p cmd deve essere 0..255"

        if cmd in seen:
            return False, f"-p cmd {cmd} duplicato"

        seen.add(cmd)

        try:
            int(value_text)
        except Exception:
            return False, f"-p {cmd}: value deve essere intero"


    # ---------------------------------------------------------
    # TELEMETRY
    # ---------------------------------------------------------

    telemetry = cfg.get(
        "telemetry",
        {}
    )

    for key, flag in (
        (
            "level_destinations",
            "-L"
        ),
        (
            "noise_destinations",
            "-N"
        )
    ):

        for value in telemetry.get(
            key,
            []
        ):

            if not str(value).strip():
                return False, f"{flag}: destinazione vuota"


    return True, ""


def sdrtst_service_running():

    return subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            SDRTST_SERVICE
        ]
    ).returncode == 0


def sdrtst_service_enabled():

    return subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            SDRTST_SERVICE
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).returncode == 0


def sdrtst_journal():

    result = subprocess.run(
        [
            "journalctl",
            "-u",
            SDRTST_SERVICE,
            "-n",
            "30",
            "--no-pager"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    return (
        result.stdout.strip()
        or "Nessun log disponibile."
    )


def verify_sdrtst_service(
    timeout=10
):

    deadline = time.time() + timeout

    while time.time() < deadline:

        if sdrtst_service_running():

            time.sleep(2)

            if sdrtst_service_running():
                return True, ""

        state = subprocess.run(
            [
                "systemctl",
                "show",
                SDRTST_SERVICE,
                "--property=ActiveState",
                "--property=SubState",
                "--value"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        ).stdout

        if (
            "failed" in state
            or "auto-restart" in state
        ):

            subprocess.run(
                [
                    "systemctl",
                    "stop",
                    SDRTST_SERVICE
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            lines = [
                x.strip()
                for x in sdrtst_journal().splitlines()
                if x.strip()
            ]

            return (
                False,
                lines[-1]
                if lines
                else "sdrtst terminato durante l'avvio"
            )

        time.sleep(0.25)

    return (
        False,
        "sdrtst non è diventato stabile entro il timeout"
    )


def start_sdrtst_service():

    cfg = load_sdrtst_active_config()

    ok, error = sdrtst_validate(cfg)

    if not ok:
        return False, error

    result = subprocess.run(
        [
            "systemctl",
            "start",
            SDRTST_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:

        return (
            False,
            result.stderr.strip()
            or result.stdout.strip()
            or "Errore avvio sdrtst"
        )

    return verify_sdrtst_service()


def stop_sdrtst_service():

    result = subprocess.run(
        [
            "systemctl",
            "stop",
            SDRTST_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        return (
            False,
            result.stderr.strip()
            or "Errore arresto sdrtst"
        )

    return True, ""


def restart_sdrtst_service():

    cfg = load_sdrtst_active_config()

    ok, error = sdrtst_validate(cfg)

    if not ok:
        return False, error

    result = subprocess.run(
        [
            "systemctl",
            "restart",
            SDRTST_SERVICE
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if result.returncode != 0:
        return (
            False,
            result.stderr.strip()
            or "Errore riavvio sdrtst"
        )

    return verify_sdrtst_service()


def apply_sdrtst_config():

    was_running = sdrtst_service_running()

    os.makedirs(
        BACKUP_DIR,
        exist_ok=True
    )

    stamp = datetime.now().strftime(
        "%Y%m%d-%H%M%S-%f"
    )

    previous = os.path.join(
        BACKUP_DIR,
        f"sdrtst-active-before-apply-{stamp}.json"
    )

    if os.path.isfile(
        SDRTST_ACTIVE_CONFIG_FILE
    ):
        shutil.copy2(
            SDRTST_ACTIVE_CONFIG_FILE,
            previous
        )
    else:
        shutil.copy2(
            SDRTST_CONFIG_FILE,
            previous
        )

    atomic_copy_file(
        SDRTST_CONFIG_FILE,
        SDRTST_ACTIVE_CONFIG_FILE
    )

    if not was_running:
        return True, ""

    ok, error = restart_sdrtst_service()

    if ok:
        return True, ""

    atomic_copy_file(
        previous,
        SDRTST_ACTIVE_CONFIG_FILE
    )

    rollback_ok, rollback_error = (
        restart_sdrtst_service()
    )

    if rollback_ok:

        return (
            False,
            error
            + " - configurazione precedente ripristinata automaticamente"
        )

    return (
        False,
        error
        + " - ATTENZIONE: rollback non riuscito: "
        + rollback_error
    )


def update_sdrtst_from_form(cfg):

    inp = cfg.setdefault(
        "input",
        {}
    )

    mapping = (
        ("source", "input_source"),
        ("format", "input_format"),
        ("iq_rate", "input_iq_rate"),
        ("manual_tune", "input_manual_tune"),
        ("center_offset", "input_center_offset"),
        ("converter_offset", "input_converter_offset")
    )

    for key, name in mapping:

        state = inp.setdefault(
            key,
            {}
        )

        state["enabled"] = (
            f"{name}_enabled"
            in request.form
        )

        state["value"] = request.form.get(
            name,
            state.get(
                "value",
                ""
            )
        ).strip()

    inp.setdefault(
        "reconnect",
        {}
    )["enabled"] = (
        "input_reconnect"
        in request.form
    )


    # ---------------------------------------------------------
    # CHANNEL CONFIG
    # ---------------------------------------------------------

    channels = cfg.setdefault(
        "channels",
        {}
    )

    state = channels.setdefault(
        "config_source",
        {}
    )

    state["enabled"] = (
        "channels_config_source_enabled"
        in request.form
    )

    state["value"] = request.form.get(
        "channels_config_source",
        ""
    ).strip()


    # ---------------------------------------------------------
    # AUDIO
    # ---------------------------------------------------------

    audio = cfg.setdefault(
        "audio",
        {}
    )

    out = audio.setdefault(
        "output",
        {}
    )

    out["enabled"] = (
        "audio_output_enabled"
        in request.form
    )

    out["mode"] = request.form.get(
        "audio_output_mode",
        "s16"
    ).strip()

    out["value"] = request.form.get(
        "audio_output",
        ""
    ).strip()


    for key, name in (
        ("sample_rate", "audio_sample_rate"),
        ("downsample", "audio_downsample"),
        ("mix_channels", "audio_mix_channels"),
        ("buffer_samples", "audio_buffer_samples")
    ):

        state = audio.setdefault(
            key,
            {}
        )

        state["enabled"] = (
            f"{name}_enabled"
            in request.form
        )

        state["value"] = request.form.get(
            name,
            state.get(
                "value",
                ""
            )
        ).strip()


    audio.setdefault(
        "stop_when_squelched",
        {}
    )["enabled"] = (
        "audio_stop_when_squelched"
        in request.form
    )

    audio.setdefault(
        "watermark",
        {}
    )["enabled"] = (
        "audio_watermark"
        in request.form
    )


    # ---------------------------------------------------------
    # RECEIVER
    # ---------------------------------------------------------

    rx = cfg.setdefault(
        "receiver",
        {}
    )

    for key, name in (
        ("max_active", "receiver_max_active"),
        ("max_awake", "receiver_max_awake"),
        ("afc_speed", "receiver_afc_speed")
    ):

        state = rx.setdefault(
            key,
            {}
        )

        state["enabled"] = (
            f"{name}_enabled"
            in request.form
        )

        state["value"] = request.form.get(
            name,
            state.get(
                "value",
                ""
            )
        ).strip()


    ps = rx.setdefault(
        "powersave",
        {}
    )

    ps["enabled"] = (
        "receiver_powersave_enabled"
        in request.form
    )

    ps["mode"] = request.form.get(
        "receiver_powersave_mode",
        "normal"
    ).strip()

    ps["value"] = request.form.get(
        "receiver_powersave",
        "100"
    ).strip()


    # ---------------------------------------------------------
    # TELEMETRY
    # ---------------------------------------------------------

    telemetry = cfg.setdefault(
        "telemetry",
        {}
    )

    telemetry["level_destinations"] = [
        x.strip()
        for x in request.form.getlist(
            "level_destination"
        )
        if x.strip()
    ]

    telemetry["noise_destinations"] = [
        x.strip()
        for x in request.form.getlist(
            "noise_destination"
        )
        if x.strip()
    ]


    # ---------------------------------------------------------
    # RTL_TCP PARAMETERS
    #
    # Poiché i checkbox non selezionati non vengono inviati
    # dal browser, ogni riga presente viene considerata attiva.
    # Le righe possono essere eliminate con il pulsante ×.
    # ---------------------------------------------------------

    cmds = request.form.getlist(
        "rtl_param_cmd"
    )

    values = request.form.getlist(
        "rtl_param_value"
    )

    params = []

    for cmd, value in zip(
        cmds,
        values
    ):

        cmd = cmd.strip()
        value = value.strip()

        if not cmd and not value:
            continue

        params.append({
            "enabled": True,
            "cmd": cmd,
            "value": value
        })

    cfg.setdefault(
        "rtl_tcp",
        {}
    )["parameters"] = params


    # ---------------------------------------------------------
    # DEBUG
    # ---------------------------------------------------------

    debug = cfg.setdefault(
        "debug",
        {}
    )

    iq_dump = debug.setdefault(
        "iq_dump",
        {}
    )

    iq_dump["enabled"] = (
        "debug_iq_dump_enabled"
        in request.form
    )

    iq_dump["value"] = request.form.get(
        "debug_iq_dump",
        ""
    ).strip()

    debug.setdefault(
        "verbose",
        {}
    )["enabled"] = (
        "debug_verbose"
        in request.form
    )

    return cfg


@app.route(
    "/config/sdrtst",
    methods=["GET", "POST"]
)
def config_sdrtst():

    cfg = load_sdrtst_config()

    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )

        if action == "start":

            ok, error = start_sdrtst_service()

            flash(
                "SDRTST_START_OK"
                if ok
                else "SDRTST_ERROR: " + error
            )

            return redirect(
                "/config/sdrtst"
            )


        if action == "stop":

            ok, error = stop_sdrtst_service()

            flash(
                "SDRTST_STOP_OK"
                if ok
                else "SDRTST_ERROR: " + error
            )

            return redirect(
                "/config/sdrtst"
            )


        if action == "restart":

            ok, error = restart_sdrtst_service()

            flash(
                "SDRTST_RESTART_OK"
                if ok
                else "SDRTST_ERROR: " + error
            )

            return redirect(
                "/config/sdrtst"
            )


        cfg = update_sdrtst_from_form(
            cfg
        )

        ok, error = sdrtst_validate(cfg)

        if not ok:

            flash(
                "SDRTST_ERROR: "
                + error
            )

            return redirect(
                "/config/sdrtst"
            )


        save_sdrtst_config(cfg)


        if action == "apply":

            ok, error = (
                apply_sdrtst_config()
            )

            flash(
                "SDRTST_APPLY_OK"
                if ok
                else "SDRTST_ERROR: " + error
            )

        else:

            flash(
                "SDRTST_SAVE_OK"
            )


        return redirect(
            "/config/sdrtst"
        )


    cfg = load_sdrtst_config()

    active_cfg = (
        load_sdrtst_active_config()
    )

    return render_template(
        "config_sdrtst.html",
        cfg=cfg,
        INPUT=cfg.get(
            "input",
            {}
        ),
        CHANNELS=cfg.get(
            "channels",
            {}
        ),
        AUDIO=cfg.get(
            "audio",
            {}
        ),
        RECEIVER=cfg.get(
            "receiver",
            {}
        ),
        TELEMETRY=cfg.get(
            "telemetry",
            {}
        ),
        RTL=cfg.get(
            "rtl_tcp",
            {}
        ),
        DEBUG=cfg.get(
            "debug",
            {}
        ),
        running=sdrtst_service_running(),
        enabled=sdrtst_service_enabled(),
        command=sdrtst_build_command(
            cfg,
            load_config()
        ),
        active_command=sdrtst_build_command(
            active_cfg,
            load_active_config()
        ),
        journal=sdrtst_journal()
    )



# ============================================================
# AFSKMODEM
# ============================================================

AFSKMODEM_SERVICE = "dxlaprs-afskmodem.service"
AFSKMODEM_CONFIG = "/opt/dxlaprs-manager/data/afskmodem_config.json"
AFSKMODEM_ACTIVE_CONFIG = "/opt/dxlaprs-manager/data/afskmodem_active_config.json"


def afskmodem_json(path):
    import json
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def afskmodem_write(path, cfg):
    import json, os, tempfile
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".afskmodem-", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def afskmodem_default_channel(n):
    return {
        "enabled": False,
        "number": n,
        "ptt": {"enabled": False, "device": "", "value": "", "bit": ""},
        "close_ptt_tty": {"enabled": False},
        "duplex": {"enabled": True, "value": "0"},
        "gm900_delay": {"enabled": True, "value": "0"},
        "random_wait": {"enabled": True, "value": "800"}
    }


def afskmodem_default_modem(n):
    return {
        "enabled": False,
        "number": n,
        "fsk": {"enabled": False},
        "baud": {"enabled": True, "value": "1200"},
        "bert": {"enabled": False, "value": ""},
        "audio_channel": {"enabled": True, "value": "0"},
        "dcd_level": {"enabled": True, "value": "56"},
        "equalizer": {"enabled": True, "value": "0"},
        "afsk_mid": {"enabled": True, "value": "1700"},
        "scrambler": {"enabled": False},
        "tx_highpass": {"enabled": True, "value": "0"},
        "ignore_kiss_parameters": {"enabled": False},
        "kiss_port": {"enabled": True, "value": "0"},
        "monitor": {"enabled": True, "value": "2"},
        "nyquist": {"enabled": True, "value": "65"},
        "pll_speed": {"enabled": True, "value": "16"},
        "quiet_level": {"enabled": True, "value": "0"},
        "afsk_shift": {"enabled": True, "value": "1000"},
        "txdelay": {"enabled": True, "value": "300"},
        "tx_timeout": {"enabled": True, "value": "60"},
        "axudp": {"enabled": False, "mode": "U", "value": ""},
        "tx_volume": {"enabled": True, "value": "100"},
        "txdelay_pattern": {"enabled": True, "value": "126"},
        "txtail": {"enabled": False, "value": "20"},
        "dc_clamp": {"enabled": True, "value": "996"}
    }


def load_afskmodem_config():
    cfg = afskmodem_json(AFSKMODEM_CONFIG)
    cfg["channels"] = [
        next((x for x in cfg.get("channels", []) if int(x.get("number",-1)) == n),
             afskmodem_default_channel(n))
        for n in range(2)
    ]
    cfg["modems"] = [
        next((x for x in cfg.get("modems", []) if int(x.get("number",-1)) == n),
             afskmodem_default_modem(n))
        for n in range(8)
    ]
    return cfg


def load_afskmodem_active_config():
    cfg = afskmodem_json(AFSKMODEM_ACTIVE_CONFIG)
    cfg["channels"] = [
        next((x for x in cfg.get("channels", []) if int(x.get("number",-1)) == n),
             afskmodem_default_channel(n))
        for n in range(2)
    ]
    cfg["modems"] = [
        next((x for x in cfg.get("modems", []) if int(x.get("number",-1)) == n),
             afskmodem_default_modem(n))
        for n in range(8)
    ]
    return cfg


def afskmodem_build_command(cfg, manager_cfg):
    import shlex

    bin_dir = str(manager_cfg.get("dxlaprs", {}).get("bin_dir", "")).strip()
    binary = (bin_dir.rstrip("/") + "/afskmodem") if bin_dir else "afskmodem"
    a = [binary]

    def val(flag, state):
        if state.get("enabled"):
            v = str(state.get("value","")).strip()
            if v:
                a.extend([flag,v])

    def boo(flag,state):
        if state.get("enabled"):
            a.append(flag)

    g=cfg.get("global",{})
    boo("-a",g.get("abort_sound_error",{}))
    val("-b",g.get("tx_dac_buffers",{}))
    boo("-B",g.get("bad_sound_driver",{}))
    val("-c",g.get("max_channels",{}))
    val("-D",g.get("debug_file",{}))
    val("-e",g.get("ptt_hold_buffers",{}))
    val("-f",g.get("sample_rate",{}))
    val("-i",g.get("kiss_pipe",{}))
    val("-k",g.get("kiss_buffers",{}))
    val("-l",g.get("adc_buffer_length",{}))
    val("-m",g.get("mixer",{}))
    val("-o",g.get("sound_device",{}))
    val("-s",g.get("fragment_size",{}))

    for c in cfg.get("channels",[]):
        if not c.get("enabled"):
            continue
        a += ["-C",str(c["number"])]
        p=c.get("ptt",{})
        if p.get("enabled"):
            a += ["-p",str(p.get("device","")),str(p.get("bit",""))]
        boo("-u",c.get("close_ptt_tty",{}))
        val("-f",c.get("duplex",{}))
        val("-g",c.get("gm900_delay",{}))
        val("-r",c.get("random_wait",{}))

    for m in cfg.get("modems",[]):
        if not m.get("enabled"):
            continue
        a += ["-M",str(m["number"])]
        boo("-a",m.get("fsk",{}))
        val("-b",m.get("baud",{}))
        val("-B",m.get("bert",{}))
        val("-c",m.get("audio_channel",{}))
        val("-d",m.get("dcd_level",{}))
        val("-e",m.get("equalizer",{}))
        val("-f",m.get("afsk_mid",{}))
        boo("-g",m.get("scrambler",{}))
        val("-H",m.get("tx_highpass",{}))
        boo("-i",m.get("ignore_kiss_parameters",{}))
        val("-k",m.get("kiss_port",{}))
        val("-m",m.get("monitor",{}))
        val("-n",m.get("nyquist",{}))
        val("-p",m.get("pll_speed",{}))
        val("-q",m.get("quiet_level",{}))
        val("-s",m.get("afsk_shift",{}))
        val("-t",m.get("txdelay",{}))
        val("-T",m.get("tx_timeout",{}))
        ax=m.get("axudp",{})
        if ax.get("enabled") and str(ax.get("value","")).strip():
            a += [{"U":"-U","L":"-L","P":"-P"}.get(ax.get("mode"),"-U"),
                  str(ax["value"]).strip()]
        val("-v",m.get("tx_volume",{}))
        val("-w",m.get("txdelay_pattern",{}))
        val("-x",m.get("txtail",{}))
        val("-z",m.get("dc_clamp",{}))

    return " ".join(shlex.quote(x) for x in a)


def afskmodem_service_running():
    import subprocess
    return subprocess.run(
        ["systemctl","is-active","--quiet",AFSKMODEM_SERVICE]
    ).returncode == 0


def afskmodem_service_enabled():
    import subprocess
    return subprocess.run(
        ["systemctl","is-enabled","--quiet",AFSKMODEM_SERVICE]
    ).returncode == 0


def afskmodem_systemctl(action):
    import subprocess
    p=subprocess.run(
        ["systemctl",action,AFSKMODEM_SERVICE],
        text=True,capture_output=True
    )
    return p.returncode == 0, (p.stderr or p.stdout).strip()


def start_afskmodem_service():
    return afskmodem_systemctl("start")


def stop_afskmodem_service():
    return afskmodem_systemctl("stop")


def restart_afskmodem_service():
    return afskmodem_systemctl("restart")


def afskmodem_journal():
    import subprocess
    p=subprocess.run(
        ["journalctl","-u",AFSKMODEM_SERVICE,"-n","40","--no-pager"],
        text=True,capture_output=True
    )
    return p.stdout


def afskmodem_validate(cfg):
    try:
        g=cfg.get("global",{})
        if g.get("sample_rate",{}).get("enabled"):
            n=int(g["sample_rate"]["value"])
            if not 8000 <= n <= 96000:
                return False,"Sample rate deve essere 8000..96000"

        if g.get("max_channels",{}).get("enabled"):
            if int(g["max_channels"]["value"]) not in (1,2):
                return False,"Canali audio deve essere 1 oppure 2"

        for c in cfg.get("channels",[]):
            if not c.get("enabled"):
                continue
            if int(c["number"]) not in (0,1):
                return False,"Numero canale non valido"
            if int(c["duplex"]["value"]) not in range(4):
                return False,f"Canale {c['number']}: duplex deve essere 0..3"

        for m in cfg.get("modems",[]):
            if not m.get("enabled"):
                continue
            n=int(m["number"])
            if not 0 <= n <= 7:
                return False,"Numero modem non valido"
            if not 1 <= int(m["baud"]["value"]) <= 32000:
                return False,f"Modem {n}: baud deve essere 1..32000"
            if int(m["audio_channel"]["value"]) not in (0,1):
                return False,f"Modem {n}: canale deve essere 0 o 1"
            if not 0 <= int(m["dcd_level"]["value"]) <= 100:
                return False,f"Modem {n}: DCD deve essere 0..100"
            if not -999 <= int(m["equalizer"]["value"]) <= 999:
                return False,f"Modem {n}: equalizer deve essere -999..999"
            if not 0 <= int(m["kiss_port"]["value"]) <= 7:
                return False,f"Modem {n}: KISS port deve essere 0..7"
            if not 0 <= int(m["monitor"]["value"]) <= 3:
                return False,f"Modem {n}: monitor deve essere 0..3"
            if not 0 <= int(m["tx_highpass"]["value"]) <= 100:
                return False,f"Modem {n}: TX highpass deve essere 0..100"
            if not 0 <= int(m["tx_volume"]["value"]) <= 100:
                return False,f"Modem {n}: TX volume deve essere 0..100"
            if not 0 <= int(m["txdelay_pattern"]["value"]) <= 255:
                return False,f"Modem {n}: pattern deve essere 0..255"
            if m.get("axudp",{}).get("enabled") and not str(m["axudp"].get("value","")).strip():
                return False,f"Modem {n}: destinazione AXUDP mancante"

        return True,""

    except Exception as e:
        return False,str(e)


def update_afskmodem_from_form(cfg):
    f=request.form
    g=cfg["global"]

    mapping={
      "abort_sound_error":("g_abort",None),
      "tx_dac_buffers":("g_buffers","g_buffers"),
      "bad_sound_driver":("g_bad",None),
      "max_channels":("g_channels","g_channels"),
      "debug_file":("g_debug","g_debug"),
      "ptt_hold_buffers":("g_hold","g_hold"),
      "sample_rate":("g_rate","g_rate"),
      "kiss_pipe":("g_kisspipe","g_kisspipe"),
      "kiss_buffers":("g_kissbuf","g_kissbuf"),
      "adc_buffer_length":("g_adcbuf","g_adcbuf"),
      "mixer":("g_mixer","g_mixer"),
      "sound_device":("g_sound","g_sound"),
      "fragment_size":("g_fragment","g_fragment")
    }

    for key,(check,valname) in mapping.items():
        g[key]["enabled"]=check in f
        if valname:
            g[key]["value"]=f.get(valname,"").strip()

    channels=[]
    for n in range(2):
        c=afskmodem_default_channel(n)
        c["enabled"]=f"ch{n}_enabled" in f
        c["ptt"]["enabled"]=f"ch{n}_ptt_enabled" in f
        c["ptt"]["device"]=f.get(f"ch{n}_ptt_device","").strip()
        c["ptt"]["value"]=c["ptt"]["device"]
        c["ptt"]["bit"]=f.get(f"ch{n}_ptt_bit","").strip()
        c["close_ptt_tty"]["enabled"]=f"ch{n}_close" in f
        c["duplex"]["value"]=f.get(f"ch{n}_duplex","0").strip()
        c["gm900_delay"]["value"]=f.get(f"ch{n}_gm","0").strip()
        c["random_wait"]["value"]=f.get(f"ch{n}_random","800").strip()
        channels.append(c)
    cfg["channels"]=channels

    modems=[]
    for n in range(8):
        m=afskmodem_default_modem(n)
        m["enabled"]=f"m{n}_enabled" in f
        m["fsk"]["enabled"]=f"m{n}_fsk" in f
        m["scrambler"]["enabled"]=f"m{n}_scrambler" in f
        m["ignore_kiss_parameters"]["enabled"]=f"m{n}_ignore" in f

        fields={
          "baud":"baud","audio_channel":"channel","dcd_level":"dcd",
          "equalizer":"eq","afsk_mid":"mid","tx_highpass":"hp",
          "kiss_port":"kiss","monitor":"monitor","nyquist":"nyquist",
          "pll_speed":"pll","quiet_level":"quiet","afsk_shift":"shift",
          "txdelay":"txdelay","tx_timeout":"timeout","tx_volume":"volume",
          "txdelay_pattern":"pattern","txtail":"tail","dc_clamp":"clamp",
          "bert":"bert"
        }

        for key,suffix in fields.items():
            v=f.get(f"m{n}_{suffix}",m[key].get("value","")).strip()
            m[key]["value"]=v

        m["bert"]["enabled"]=bool(m["bert"]["value"])
        m["txtail"]["enabled"]=bool(m["txtail"]["value"])
        m["axudp"]["enabled"]=f"m{n}_axenabled" in f
        m["axudp"]["mode"]=f.get(f"m{n}_axmode","U")
        m["axudp"]["value"]=f.get(f"m{n}_axudp","").strip()
        modems.append(m)

    cfg["modems"]=modems
    return cfg


def apply_afskmodem_config():
    import shutil, subprocess, time

    was_running=afskmodem_service_running()
    old=None

    if __import__("os").path.exists(AFSKMODEM_ACTIVE_CONFIG):
        with open(AFSKMODEM_ACTIVE_CONFIG,"rb") as f:
            old=f.read()

    try:
        shutil.copy2(AFSKMODEM_CONFIG,AFSKMODEM_ACTIVE_CONFIG)

        if was_running:
            ok,error=restart_afskmodem_service()
            if not ok:
                raise RuntimeError(error)

            time.sleep(1)

            if not afskmodem_service_running():
                p=subprocess.run(
                    ["systemctl","show",AFSKMODEM_SERVICE,
                     "-p","ExecMainStatus","--value"],
                    text=True,capture_output=True
                )
                raise RuntimeError(
                    "afskmodem non rimane attivo; ExecMainStatus="
                    + p.stdout.strip()
                )

        return True,""

    except Exception as e:
        if old is not None:
            with open(AFSKMODEM_ACTIVE_CONFIG,"wb") as f:
                f.write(old)
            if was_running:
                restart_afskmodem_service()
        return False,str(e)


@app.route("/config/afskmodem",methods=["GET","POST"])
def config_afskmodem():

    cfg=load_afskmodem_config()

    if request.method=="POST":
        action=request.form.get("action","save")

        if action=="start":
            ok,error=start_afskmodem_service()
            flash("AFSKMODEM_START_OK" if ok else "AFSKMODEM_ERROR: "+error)
            return redirect("/config/afskmodem")

        if action=="stop":
            ok,error=stop_afskmodem_service()
            flash("AFSKMODEM_STOP_OK" if ok else "AFSKMODEM_ERROR: "+error)
            return redirect("/config/afskmodem")

        if action=="restart":
            ok,error=restart_afskmodem_service()
            flash("AFSKMODEM_RESTART_OK" if ok else "AFSKMODEM_ERROR: "+error)
            return redirect("/config/afskmodem")

        cfg=update_afskmodem_from_form(cfg)

        ok,error=afskmodem_validate(cfg)
        if not ok:
            flash("AFSKMODEM_ERROR: "+error)
            return redirect("/config/afskmodem")

        afskmodem_write(AFSKMODEM_CONFIG,cfg)

        if action=="apply":
            ok,error=apply_afskmodem_config()
            flash("AFSKMODEM_APPLY_OK" if ok else "AFSKMODEM_ERROR: "+error)
        else:
            flash("AFSKMODEM_SAVE_OK")

        return redirect("/config/afskmodem")

    active=load_afskmodem_active_config()

    return render_template(
        "config_afskmodem.html",
        cfg=cfg,
        G=cfg.get("global",{}),
        CHANNELS=cfg.get("channels",[]),
        MODEMS=cfg.get("modems",[]),
        running=afskmodem_service_running(),
        enabled=afskmodem_service_enabled(),
        command=afskmodem_build_command(cfg,load_config()),
        active_command=afskmodem_build_command(active,load_active_config()),
        journal=afskmodem_journal()
    )




# ============================================================
# GPS2APRS
# ============================================================

GPS2APRS_SERVICE = "dxlaprs-gps2aprs.service"
GPS2APRS_CONFIG = "/opt/dxlaprs-manager/data/gps2aprs_config.json"
GPS2APRS_ACTIVE_CONFIG = "/opt/dxlaprs-manager/data/gps2aprs_active_config.json"


def gps2aprs_load(path):
    import json
    with open(path,"r",encoding="utf-8") as f:
        return json.load(f)


def gps2aprs_write(path,cfg):
    import json,os,tempfile

    d=os.path.dirname(path)
    fd,tmp=tempfile.mkstemp(prefix=".gps2aprs-",dir=d)

    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(cfg,f,indent=2)
            f.write("\n")
        os.replace(tmp,path)

    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_gps2aprs_config():
    return gps2aprs_load(GPS2APRS_CONFIG)


def load_gps2aprs_active_config():
    return gps2aprs_load(GPS2APRS_ACTIVE_CONFIG)


def gps2aprs_service_running():
    import subprocess
    return subprocess.run(
        ["systemctl","is-active","--quiet",GPS2APRS_SERVICE]
    ).returncode==0


def gps2aprs_service_enabled():
    import subprocess
    return subprocess.run(
        ["systemctl","is-enabled","--quiet",GPS2APRS_SERVICE]
    ).returncode==0


def gps2aprs_systemctl(action):
    import subprocess

    p=subprocess.run(
        ["systemctl",action,GPS2APRS_SERVICE],
        text=True,
        capture_output=True
    )

    return p.returncode==0,(p.stderr or p.stdout).strip()


def start_gps2aprs_service():
    return gps2aprs_systemctl("start")


def stop_gps2aprs_service():
    return gps2aprs_systemctl("stop")


def restart_gps2aprs_service():
    return gps2aprs_systemctl("restart")


def gps2aprs_journal():
    import subprocess

    p=subprocess.run(
        ["journalctl","-u",GPS2APRS_SERVICE,"-n","40","--no-pager"],
        text=True,
        capture_output=True
    )

    return p.stdout


def gps2aprs_build_command(cfg,manager_cfg):
    import shlex

    bin_dir=str(
        manager_cfg.get("dxlaprs",{}).get("bin_dir","")
    ).strip()

    binary=(
        bin_dir.rstrip("/")+"/gps2aprs"
        if bin_dir else "gps2aprs"
    )

    a=[binary]

    def val(flag,state):
        if state.get("enabled"):
            v=str(state.get("value","")).strip()
            if v:
                a.extend([flag,v])

    def boo(flag,state):
        if state.get("enabled"):
            a.append(flag)

    gps=cfg.get("gps",{})
    aprs=cfg.get("aprs",{})
    beacon=cfg.get("beacon",{})
    outputs=cfg.get("outputs",{})
    system=cfg.get("system",{})

    val("-t",gps.get("tty",{}))
    boo("-u",gps.get("usb_abort",{}))
    boo("-U",gps.get("ublox_raw",{}))

    fx=gps.get("fixed_altitude",{})
    if fx.get("enabled"):
        a.extend([
            "-A",
            str(fx.get("altitude_cm","")),
            str(fx.get("fix_mode","4"))
        ])

    val("-M",gps.get("dynamic_model",{}))

    tp=gps.get("timepulse",{})
    if tp.get("enabled"):
        a.extend([
            "-T",
            str(tp.get("period_us","")),
            str(tp.get("duration_us",""))
        ])

    for v in gps.get("config_strings",[]):
        if str(v).strip():
            a.extend(["-C",str(v).strip()])

    val("-I",aprs.get("callsign",{}))
    val("-w",aprs.get("via",{}))
    val("-c",aprs.get("comment",{}))
    val("-i",aprs.get("symbol",{}))
    val("-f",aprs.get("format",{}))
    val("-d",aprs.get("destination_ssid",{}))
    boo("-D",aprs.get("dao",{}))
    boo("-a",aprs.get("altitude_off",{}))
    boo("-k",aprs.get("speed_course_off",{}))
    boo("-e",aprs.get("climb_off",{}))
    boo("-s",aprs.get("checksum_off",{}))

    val("-0",beacon.get("standing_time",{}))
    val("-b",beacon.get("driving_time",{}))
    val("-n",beacon.get("navigation_time",{}))
    val("-g",beacon.get("drive_speed",{}))
    val("-l",beacon.get("comment_interval",{}))
    boo("-p",beacon.get("double_drive_time",{}))
    boo("-B",beacon.get("balloon",{}))
    val("-4",beacon.get("meshcom4",{}))

    for v in outputs.get("monitor",[]):
        if str(v).strip():
            a.extend(["-m",str(v).strip()])

    for v in outputs.get("axudp",[]):
        if str(v).strip():
            a.extend(["-r",str(v).strip()])

    for v in outputs.get("navigation_axudp",[]):
        if str(v).strip():
            a.extend(["-N",str(v).strip()])

    val("-L",system.get("gps_log",{}))

    ts=system.get("time_set",{})
    if ts.get("enabled"):
        flag="-Z" if ts.get("mode")=="terminate" else "-z"
        a.extend([flag,str(ts.get("offset","0"))])

    if system.get("verbose_satellites",{}).get("enabled"):
        a.append("-V")
    elif system.get("verbose",{}).get("enabled"):
        a.append("-v")

    return " ".join(shlex.quote(str(x)) for x in a)


def gps2aprs_validate(cfg):

    try:
        gps=cfg.get("gps",{})
        aprs=cfg.get("aprs",{})
        beacon=cfg.get("beacon",{})
        system=cfg.get("system",{})

        comment=aprs.get("comment",{})

        if comment.get("enabled"):
            if len(str(comment.get("value","")).encode()) > 60:
                return False,"Commento APRS massimo 60 byte"

        symbol=aprs.get("symbol",{})

        if symbol.get("enabled"):
            if len(str(symbol.get("value",""))) != 2:
                return False,"Il simbolo APRS deve contenere esattamente 2 caratteri"

        fmt=aprs.get("format",{})

        if fmt.get("enabled"):
            if int(fmt.get("value","0")) not in (0,1,2):
                return False,"Formato APRS deve essere 0, 1 oppure 2"

        if (
            fmt.get("enabled")
            and int(fmt.get("value","0"))==1
            and aprs.get("dao",{}).get("enabled")
        ):
            return False,"DAO -D non è compatibile con formato compresso -f 1"

        ssid=aprs.get("destination_ssid",{})

        if ssid.get("enabled"):
            if not 0 <= int(ssid.get("value","0")) <= 7:
                return False,"Destination SSID deve essere 0..7"

        mesh=beacon.get("meshcom4",{})

        if mesh.get("enabled"):
            if not 0 <= int(mesh.get("value","0")) <= 7:
                return False,"MeshCom4 max hops deve essere 0..7"

        fx=gps.get("fixed_altitude",{})

        if fx.get("enabled"):
            if not str(fx.get("altitude_cm","")).strip():
                return False,"Quota fissa mancante"

            if str(fx.get("fix_mode","")) not in ("1","2","4"):
                return False,"Fix mode deve essere 1, 2 oppure 4"

        tp=gps.get("timepulse",{})

        if tp.get("enabled"):
            int(tp.get("period_us",""))
            n=int(tp.get("duration_us",""))

            if n < 0:
                return False,"Durata Timepulse non può essere negativa"

        ts=system.get("time_set",{})

        if ts.get("enabled"):
            if ts.get("mode") not in ("continue","terminate"):
                return False,"Modalità time set non valida"

            int(ts.get("offset","0"))

        return True,""

    except Exception as e:
        return False,str(e)


def update_gps2aprs_from_form(cfg):

    f=request.form

    gps=cfg["gps"]
    aprs=cfg["aprs"]
    beacon=cfg["beacon"]
    outputs=cfg["outputs"]
    system=cfg["system"]

    def value(section,key,name):
        section[key]["enabled"]=name+"_enabled" in f
        section[key]["value"]=f.get(name,"").strip()

    def boo(section,key,name):
        section[key]["enabled"]=name in f

    value(gps,"tty","gps_tty")
    boo(gps,"usb_abort","gps_usb_abort")
    boo(gps,"ublox_raw","gps_ublox")
    value(gps,"dynamic_model","gps_dynamic")

    gps["fixed_altitude"]["enabled"]="gps_fixed_enabled" in f
    gps["fixed_altitude"]["altitude_cm"]=f.get(
        "gps_fixed_altitude",""
    ).strip()
    gps["fixed_altitude"]["fix_mode"]=f.get(
        "gps_fix_mode","4"
    ).strip()

    gps["timepulse"]["enabled"]="gps_timepulse_enabled" in f
    gps["timepulse"]["period_us"]=f.get(
        "gps_timepulse_period",""
    ).strip()
    gps["timepulse"]["duration_us"]=f.get(
        "gps_timepulse_duration",""
    ).strip()

    gps["config_strings"]=[
        x.strip()
        for x in f.getlist("gps_config_string")
        if x.strip()
    ]

    value(aprs,"callsign","aprs_callsign")
    value(aprs,"via","aprs_via")
    value(aprs,"comment","aprs_comment")
    value(aprs,"symbol","aprs_symbol")
    value(aprs,"destination_ssid","aprs_ssid")

    aprs["format"]["enabled"]="aprs_format_enabled" in f
    aprs["format"]["value"]=f.get("aprs_format","0")

    boo(aprs,"dao","aprs_dao")
    boo(aprs,"altitude_off","aprs_no_alt")
    boo(aprs,"speed_course_off","aprs_no_speed")
    boo(aprs,"climb_off","aprs_no_climb")
    boo(aprs,"checksum_off","aprs_no_checksum")

    value(beacon,"standing_time","beacon_standing")
    value(beacon,"driving_time","beacon_driving")
    value(beacon,"navigation_time","beacon_navigation")
    value(beacon,"drive_speed","beacon_speed")
    value(beacon,"comment_interval","beacon_comment_interval")
    value(beacon,"meshcom4","beacon_mesh")

    boo(beacon,"double_drive_time","beacon_double")
    boo(beacon,"balloon","beacon_balloon")

    outputs["monitor"]=[
        x.strip()
        for x in f.getlist("output_monitor")
        if x.strip()
    ]

    outputs["axudp"]=[
        x.strip()
        for x in f.getlist("output_axudp")
        if x.strip()
    ]

    outputs["navigation_axudp"]=[
        x.strip()
        for x in f.getlist("output_nav")
        if x.strip()
    ]

    value(system,"gps_log","sys_log")

    system["time_set"]["enabled"]="sys_time_enabled" in f
    system["time_set"]["mode"]=f.get(
        "sys_time_mode","continue"
    )
    system["time_set"]["offset"]=f.get(
        "sys_time_offset","0"
    ).strip()

    boo(system,"verbose","sys_verbose")
    boo(system,"verbose_satellites","sys_verbose2")

    return cfg


def apply_gps2aprs_config():
    import shutil,subprocess,time,os

    was_running=gps2aprs_service_running()

    old=None

    if os.path.exists(GPS2APRS_ACTIVE_CONFIG):
        with open(GPS2APRS_ACTIVE_CONFIG,"rb") as f:
            old=f.read()

    try:
        shutil.copy2(
            GPS2APRS_CONFIG,
            GPS2APRS_ACTIVE_CONFIG
        )

        if was_running:

            ok,error=restart_gps2aprs_service()

            if not ok:
                raise RuntimeError(error)

            time.sleep(1)

            if not gps2aprs_service_running():

                p=subprocess.run(
                    [
                        "systemctl",
                        "show",
                        GPS2APRS_SERVICE,
                        "-p",
                        "ExecMainStatus",
                        "--value"
                    ],
                    text=True,
                    capture_output=True
                )

                raise RuntimeError(
                    "gps2aprs non rimane attivo; ExecMainStatus="
                    + p.stdout.strip()
                )

        return True,""

    except Exception as e:

        if old is not None:

            with open(GPS2APRS_ACTIVE_CONFIG,"wb") as f:
                f.write(old)

            if was_running:
                restart_gps2aprs_service()

        return False,str(e)


@app.route(
    "/config/gps2aprs",
    methods=["GET","POST"]
)
def config_gps2aprs():

    cfg=load_gps2aprs_config()

    if request.method=="POST":

        action=request.form.get(
            "action",
            "save"
        )

        if action=="start":

            ok,error=start_gps2aprs_service()

            flash(
                "GPS2APRS_START_OK"
                if ok
                else "GPS2APRS_ERROR: "+error
            )

            return redirect(
                "/config/gps2aprs"
            )

        if action=="stop":

            ok,error=stop_gps2aprs_service()

            flash(
                "GPS2APRS_STOP_OK"
                if ok
                else "GPS2APRS_ERROR: "+error
            )

            return redirect(
                "/config/gps2aprs"
            )

        if action=="restart":

            ok,error=restart_gps2aprs_service()

            flash(
                "GPS2APRS_RESTART_OK"
                if ok
                else "GPS2APRS_ERROR: "+error
            )

            return redirect(
                "/config/gps2aprs"
            )

        cfg=update_gps2aprs_from_form(cfg)

        ok,error=gps2aprs_validate(cfg)

        if not ok:

            flash(
                "GPS2APRS_ERROR: "+error
            )

            return redirect(
                "/config/gps2aprs"
            )

        gps2aprs_write(
            GPS2APRS_CONFIG,
            cfg
        )

        if action=="apply":

            ok,error=apply_gps2aprs_config()

            flash(
                "GPS2APRS_APPLY_OK"
                if ok
                else "GPS2APRS_ERROR: "+error
            )

        else:

            flash(
                "GPS2APRS_SAVE_OK"
            )

        return redirect(
            "/config/gps2aprs"
        )


    active=load_gps2aprs_active_config()

    return render_template(
        "config_gps2aprs.html",
        cfg=cfg,
        GPS=cfg.get("gps",{}),
        APRS=cfg.get("aprs",{}),
        BEACON=cfg.get("beacon",{}),
        OUTPUTS=cfg.get("outputs",{}),
        SYSTEM=cfg.get("system",{}),
        running=gps2aprs_service_running(),
        enabled=gps2aprs_service_enabled(),
        command=gps2aprs_build_command(
            cfg,
            load_config()
        ),
        active_command=gps2aprs_build_command(
            active,
            load_active_config()
        ),
        journal=gps2aprs_journal()
    )




# ============================================================
# HOSTINT
# ============================================================

HOSTINT_SERVICE = "dxlaprs-hostint.service"

HOSTINT_CONFIG = (
    "/opt/dxlaprs-manager/data/hostint_config.json"
)

HOSTINT_ACTIVE_CONFIG = (
    "/opt/dxlaprs-manager/data/hostint_active_config.json"
)


def hostint_load(path):

    import json

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


def hostint_write(path, cfg):

    import json
    import os
    import tempfile

    directory = os.path.dirname(path)

    fd, tmp = tempfile.mkstemp(
        prefix=".hostint-",
        dir=directory
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                indent=2
            )

            f.write("\n")

        os.replace(
            tmp,
            path
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def load_hostint_config():

    return hostint_load(
        HOSTINT_CONFIG
    )


def load_hostint_active_config():

    return hostint_load(
        HOSTINT_ACTIVE_CONFIG
    )


def hostint_service_running():

    import subprocess

    return subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            HOSTINT_SERVICE
        ]
    ).returncode == 0


def hostint_service_enabled():

    import subprocess

    return subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            HOSTINT_SERVICE
        ]
    ).returncode == 0


def hostint_systemctl(action):

    import subprocess

    p = subprocess.run(
        [
            "systemctl",
            action,
            HOSTINT_SERVICE
        ],
        text=True,
        capture_output=True
    )

    return (
        p.returncode == 0,
        (p.stderr or p.stdout).strip()
    )


def start_hostint_service():

    return hostint_systemctl(
        "start"
    )


def stop_hostint_service():

    return hostint_systemctl(
        "stop"
    )


def restart_hostint_service():

    return hostint_systemctl(
        "restart"
    )


def hostint_journal():

    import subprocess

    p = subprocess.run(
        [
            "journalctl",
            "-u",
            HOSTINT_SERVICE,
            "-n",
            "40",
            "--no-pager"
        ],
        text=True,
        capture_output=True
    )

    return p.stdout


def hostint_build_command(
    cfg,
    manager_cfg
):

    import shlex

    bin_dir = str(
        manager_cfg
        .get("dxlaprs", {})
        .get("bin_dir", "")
    ).strip()

    binary = (
        bin_dir.rstrip("/") + "/hostint"
        if bin_dir
        else "hostint"
    )

    argv = [binary]

    general = cfg.get(
        "general",
        {}
    )


    def add_value(
        flag,
        state
    ):

        if state.get("enabled"):

            value = str(
                state.get(
                    "value",
                    ""
                )
            ).strip()

            if value:
                argv.extend([
                    flag,
                    value
                ])


    def add_bool(
        flag,
        state
    ):

        if state.get("enabled"):
            argv.append(flag)


    # Il parser reale usa -i minuscola.
    add_value(
        "-i",
        general.get(
            "callsign",
            {}
        )
    )

    add_value(
        "-t",
        general.get(
            "tty",
            {}
        )
    )


    for value in cfg.get(
        "axudp",
        []
    ):

        value = str(
            value
        ).strip()

        if value:

            argv.extend([
                "-U",
                value
            ])


    add_bool(
        "-v",
        general.get(
            "verbose",
            {}
        )
    )


    return " ".join(
        shlex.quote(
            str(x)
        )
        for x in argv
    )


def hostint_validate(cfg):

    try:

        general = cfg.get(
            "general",
            {}
        )


        callsign = general.get(
            "callsign",
            {}
        )

        if callsign.get("enabled"):

            value = str(
                callsign.get(
                    "value",
                    ""
                )
            ).strip()

            if not value:
                return (
                    False,
                    "Nominativo mancante"
                )

            if any(
                c.isspace()
                for c in value
            ):
                return (
                    False,
                    "Il nominativo non può contenere spazi"
                )


        tty = general.get(
            "tty",
            {}
        )

        if tty.get("enabled"):

            value = str(
                tty.get(
                    "value",
                    ""
                )
            ).strip()

            if not value:
                return (
                    False,
                    "TTY/pipe mancante"
                )

            if ":" in value:

                dev, baud = value.rsplit(
                    ":",
                    1
                )

                if not dev:
                    return (
                        False,
                        "Nome TTY mancante"
                    )

                if not baud.isdigit():
                    return (
                        False,
                        "Baud TTY non valido"
                    )


        for value in cfg.get(
            "axudp",
            []
        ):

            value = str(
                value
            ).strip()

            if not value:
                continue

            parts = value.rsplit(
                ":",
                2
            )

            if len(parts) != 3:
                return (
                    False,
                    "AXUDP deve avere formato host:destport:listenport"
                )

            host, dest, listen = parts

            if not host:
                return (
                    False,
                    "Host AXUDP mancante"
                )

            try:

                dp = int(dest)
                lp = int(listen)

            except ValueError:

                return (
                    False,
                    "Porte AXUDP non valide"
                )

            if not (
                1 <= dp <= 65535
                and
                1 <= lp <= 65535
            ):

                return (
                    False,
                    "Porte AXUDP devono essere 1..65535"
                )


        return True, ""


    except Exception as e:

        return False, str(e)


def update_hostint_from_form(
    cfg
):

    f = request.form

    general = cfg[
        "general"
    ]


    general["callsign"]["enabled"] = (
        "general_callsign_enabled"
        in f
    )

    general["callsign"]["value"] = (
        f.get(
            "general_callsign",
            ""
        ).strip()
    )


    general["tty"]["enabled"] = (
        "general_tty_enabled"
        in f
    )

    general["tty"]["value"] = (
        f.get(
            "general_tty",
            ""
        ).strip()
    )


    general["verbose"]["enabled"] = (
        "general_verbose"
        in f
    )


    cfg["axudp"] = [
        x.strip()
        for x
        in f.getlist("axudp")
        if x.strip()
    ]


    return cfg


def apply_hostint_config():

    import shutil
    import subprocess
    import time
    import os


    was_running = (
        hostint_service_running()
    )

    old = None


    if os.path.exists(
        HOSTINT_ACTIVE_CONFIG
    ):

        with open(
            HOSTINT_ACTIVE_CONFIG,
            "rb"
        ) as f:

            old = f.read()


    try:

        shutil.copy2(
            HOSTINT_CONFIG,
            HOSTINT_ACTIVE_CONFIG
        )


        if was_running:

            ok, error = (
                restart_hostint_service()
            )

            if not ok:
                raise RuntimeError(
                    error
                )


            time.sleep(1)


            if not hostint_service_running():

                p = subprocess.run(
                    [
                        "systemctl",
                        "show",
                        HOSTINT_SERVICE,
                        "-p",
                        "ExecMainStatus",
                        "--value"
                    ],
                    text=True,
                    capture_output=True
                )

                raise RuntimeError(
                    "hostint non rimane attivo; "
                    "ExecMainStatus="
                    + p.stdout.strip()
                )


        return True, ""


    except Exception as e:

        if old is not None:

            with open(
                HOSTINT_ACTIVE_CONFIG,
                "wb"
            ) as f:

                f.write(old)


            if was_running:

                restart_hostint_service()


        return False, str(e)


@app.route(
    "/config/hostint",
    methods=[
        "GET",
        "POST"
    ]
)
def config_hostint():

    cfg = load_hostint_config()


    if request.method == "POST":

        action = request.form.get(
            "action",
            "save"
        )


        if action == "start":

            ok, error = (
                start_hostint_service()
            )

            flash(
                "HOSTINT_START_OK"
                if ok
                else
                "HOSTINT_ERROR: "
                + error
            )

            return redirect(
                "/config/hostint"
            )


        if action == "stop":

            ok, error = (
                stop_hostint_service()
            )

            flash(
                "HOSTINT_STOP_OK"
                if ok
                else
                "HOSTINT_ERROR: "
                + error
            )

            return redirect(
                "/config/hostint"
            )


        if action == "restart":

            ok, error = (
                restart_hostint_service()
            )

            flash(
                "HOSTINT_RESTART_OK"
                if ok
                else
                "HOSTINT_ERROR: "
                + error
            )

            return redirect(
                "/config/hostint"
            )


        cfg = (
            update_hostint_from_form(
                cfg
            )
        )


        ok, error = (
            hostint_validate(
                cfg
            )
        )


        if not ok:

            flash(
                "HOSTINT_ERROR: "
                + error
            )

            return redirect(
                "/config/hostint"
            )


        hostint_write(
            HOSTINT_CONFIG,
            cfg
        )


        if action == "apply":

            ok, error = (
                apply_hostint_config()
            )

            flash(
                "HOSTINT_APPLY_OK"
                if ok
                else
                "HOSTINT_ERROR: "
                + error
            )

        else:

            flash(
                "HOSTINT_SAVE_OK"
            )


        return redirect(
            "/config/hostint"
        )


    active = (
        load_hostint_active_config()
    )


    return render_template(
        "config_hostint.html",

        cfg=cfg,

        GENERAL=cfg.get(
            "general",
            {}
        ),

        AXUDP=cfg.get(
            "axudp",
            []
        ),

        running=(
            hostint_service_running()
        ),

        enabled=(
            hostint_service_enabled()
        ),

        command=hostint_build_command(
            cfg,
            load_config()
        ),

        active_command=hostint_build_command(
            active,
            load_active_config()
        ),

        journal=hostint_journal()
    )




# ============================================================
# L2CAT
# ============================================================

L2CAT_SERVICE="dxlaprs-l2cat.service"
L2CAT_CONFIG="/opt/dxlaprs-manager/data/l2cat_config.json"
L2CAT_ACTIVE_CONFIG="/opt/dxlaprs-manager/data/l2cat_active_config.json"


def l2cat_load(path):
    import json
    with open(path,"r",encoding="utf-8") as f:
        return json.load(f)


def l2cat_write(path,cfg):
    import json,os,tempfile

    directory=os.path.dirname(path)
    fd,tmp=tempfile.mkstemp(prefix=".l2cat-",dir=directory)

    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(cfg,f,indent=2)
            f.write("\n")
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_l2cat_config():
    return l2cat_load(L2CAT_CONFIG)


def load_l2cat_active_config():
    return l2cat_load(L2CAT_ACTIVE_CONFIG)


def l2cat_service_running():
    import subprocess
    return subprocess.run(
        ["systemctl","is-active","--quiet",L2CAT_SERVICE]
    ).returncode==0


def l2cat_service_enabled():
    import subprocess
    return subprocess.run(
        ["systemctl","is-enabled","--quiet",L2CAT_SERVICE]
    ).returncode==0


def l2cat_systemctl(action):
    import subprocess
    p=subprocess.run(
        ["systemctl",action,L2CAT_SERVICE],
        text=True,
        capture_output=True
    )
    return p.returncode==0,(p.stderr or p.stdout).strip()


def start_l2cat_service():
    return l2cat_systemctl("start")


def stop_l2cat_service():
    return l2cat_systemctl("stop")


def restart_l2cat_service():
    return l2cat_systemctl("restart")


def l2cat_journal():
    import subprocess
    p=subprocess.run(
        ["journalctl","-u",L2CAT_SERVICE,"-n","40","--no-pager"],
        text=True,
        capture_output=True
    )
    return p.stdout


def l2cat_build_command(cfg,manager_cfg):
    import shlex

    bin_dir=str(
        manager_cfg.get("dxlaprs",{}).get("bin_dir","")
    ).strip()

    binary=bin_dir.rstrip("/")+"/l2cat" if bin_dir else "l2cat"
    a=[binary]

    conn=cfg.get("connection",{})
    stream=cfg.get("stream",{})
    logging=cfg.get("logging",{})

    def val(flag,state):
        if state.get("enabled"):
            value=str(state.get("value","")).strip()
            if value:
                a.extend([flag,value])

    def boo(flag,state):
        if state.get("enabled"):
            a.append(flag)

    val("-C",conn.get("destination",{}))
    val("-c",conn.get("command",{}))
    val("-p",conn.get("pipe",{}))
    val("-i",conn.get("callsigns",{}))
    val("-j",stream.get("convert_from_pr",{}))
    val("-m",stream.get("monitor",{}))
    val("-w",stream.get("dupe_check",{}))
    val("-D",stream.get("discard",{}))
    val("-r",conn.get("reconnect_min",{}))
    val("-R",conn.get("reconnect_max",{}))

    for item in cfg.get("l2_parameters",[]):
        port=str(item.get("port","")).strip()
        parm=str(item.get("parameter","")).strip()
        value=str(item.get("value","")).strip()
        if port and parm and value:
            a.extend(["-n",port,parm,value])

    for dest in cfg.get("axudp",[]):
        dest=str(dest).strip()
        if dest:
            a.extend(["-U",dest])

    boo("-a",stream.get("autodetect",{}))
    boo("-P",stream.get("ppp_deflate",{}))
    boo("-d",stream.get("deflate",{}))

    if stream.get("strip_lf",{}).get("enabled"):
        a.append("-L")
    elif stream.get("convert_lf_cr",{}).get("enabled"):
        a.append("-l")

    if logging.get("very_verbose"):
        a.append("-V")
    elif logging.get("verbose"):
        a.append("-v")

    return " ".join(shlex.quote(str(x)) for x in a)


def l2cat_validate(cfg):

    try:
        conn=cfg.get("connection",{})
        stream=cfg.get("stream",{})

        if not cfg.get("axudp"):
            return False,"l2cat richiede almeno una porta AXUDP -U"

        if conn.get("destination",{}).get("enabled"):
            if not conn.get("callsigns",{}).get("enabled"):
                return False,"-C richiede un nominativo configurato con -i"

            if not str(conn.get("callsigns",{}).get("value","")).strip():
                return False,"-C richiede un nominativo valido con -i"

        for key in ("reconnect_min","reconnect_max"):
            st=conn.get(key,{})
            if st.get("enabled"):
                n=int(st.get("value",""))
                if not 0 <= n <= 4000000:
                    return False,"Ritardo riconnessione deve essere 0..4000000 ms"

        st=stream.get("convert_from_pr",{})
        if st.get("enabled"):
            n=int(st.get("value",""))
            if not 0 <= n <= 6:
                return False,"-j deve essere 0..6"

        st=stream.get("monitor",{})
        if st.get("enabled"):
            n=int(st.get("value",""))
            if not 0 <= n <= 2:
                return False,"-m deve essere 0..2"

        st=stream.get("dupe_check",{})
        if st.get("enabled"):
            n=int(st.get("value",""))
            if not 0 <= n <= 31:
                return False,"-w deve essere 0..31"

        st=stream.get("discard",{})
        if st.get("enabled"):
            n=int(st.get("value",""))
            if not 0 <= n <= 1500:
                return False,"-D deve essere 0..1500 byte"

        if (
            stream.get("convert_lf_cr",{}).get("enabled")
            and
            stream.get("strip_lf",{}).get("enabled")
        ):
            return False,"-l e -L sono modalità alternative"

        axudp=cfg.get("axudp",[])

        if len(axudp)>15:
            return False,"l2cat supporta al massimo 15 porte AXUDP"

        for dest in axudp:
            parts=str(dest).strip().rsplit(":",2)

            if len(parts)!=3:
                return False,"AXUDP deve avere formato host:destport:listenport"

            host,destport,listenport=parts

            if not host:
                return False,"Host AXUDP mancante"

            dp=int(destport)
            lp=int(listenport)

            if not 1 <= dp <= 65535:
                return False,"Porta destinazione AXUDP deve essere 1..65535"

            # Il parser consente listenport=0 per una porta libera.
            if not 0 <= lp <= 65535:
                return False,"Listen port AXUDP deve essere 0..65535"

        l2params=cfg.get("l2_parameters",[])

        if len(l2params)>256:
            return False,"Tabella parametri Layer 2 troppo grande"

        allowed={"t","d","o","f","F","I","n","h"}

        for item in l2params:
            port=str(item.get("port","")).strip()
            parm=str(item.get("parameter","")).strip()
            value=str(item.get("value","")).strip()

            if port!="a":
                p=int(port)
                if not 0 <= p <= 15:
                    return False,"Porta Layer 2 deve essere 0..15 oppure a"

            if parm not in allowed:
                return False,"Parametro Layer 2 non valido"

            if not value:
                return False,"Valore parametro Layer 2 mancante"

            n=int(value)
            if n < 0:
                return False,"Valore parametro Layer 2 non può essere negativo"

        return True,""

    except Exception as e:
        return False,str(e)


def update_l2cat_from_form(cfg):

    f=request.form
    conn=cfg["connection"]
    stream=cfg["stream"]
    logging=cfg["logging"]

    def value(section,key,name):
        section[key]["enabled"]=name+"_enabled" in f
        section[key]["value"]=f.get(name,"").strip()

    def boo(section,key,name):
        section[key]["enabled"]=name in f

    value(conn,"destination","conn_destination")
    value(conn,"callsigns","conn_callsigns")
    value(conn,"command","conn_command")
    value(conn,"pipe","conn_pipe")
    value(conn,"reconnect_min","conn_reconnect_min")
    value(conn,"reconnect_max","conn_reconnect_max")

    value(stream,"convert_from_pr","stream_convert")
    value(stream,"monitor","stream_monitor")
    value(stream,"dupe_check","stream_dupe")
    value(stream,"discard","stream_discard")

    boo(stream,"convert_lf_cr","stream_lfcr")
    boo(stream,"strip_lf","stream_striplf")
    boo(stream,"autodetect","stream_autodetect")
    boo(stream,"ppp_deflate","stream_ppp")
    boo(stream,"deflate","stream_deflate")

    cfg["axudp"]=[
        x.strip()
        for x in f.getlist("axudp")
        if x.strip()
    ]

    ports=f.getlist("l2_port")
    parms=f.getlist("l2_parameter")
    values=f.getlist("l2_value")

    cfg["l2_parameters"]=[]

    for port,parm,value in zip(ports,parms,values):
        port=port.strip()
        parm=parm.strip()
        value=value.strip()

        if port or value:
            cfg["l2_parameters"].append({
                "port":port,
                "parameter":parm,
                "value":value
            })

    logging["verbose"]="log_verbose" in f
    logging["very_verbose"]="log_very_verbose" in f

    return cfg


def apply_l2cat_config():
    import shutil,subprocess,time,os

    was_running=l2cat_service_running()
    old=None

    if os.path.exists(L2CAT_ACTIVE_CONFIG):
        with open(L2CAT_ACTIVE_CONFIG,"rb") as f:
            old=f.read()

    try:
        shutil.copy2(L2CAT_CONFIG,L2CAT_ACTIVE_CONFIG)

        if was_running:
            ok,error=restart_l2cat_service()

            if not ok:
                raise RuntimeError(error)

            time.sleep(1)

            if not l2cat_service_running():
                p=subprocess.run(
                    [
                        "systemctl","show",L2CAT_SERVICE,
                        "-p","ExecMainStatus","--value"
                    ],
                    text=True,
                    capture_output=True
                )

                raise RuntimeError(
                    "l2cat non rimane attivo; ExecMainStatus="
                    +p.stdout.strip()
                )

        return True,""

    except Exception as e:
        if old is not None:
            with open(L2CAT_ACTIVE_CONFIG,"wb") as f:
                f.write(old)

            if was_running:
                restart_l2cat_service()

        return False,str(e)


@app.route("/config/l2cat",methods=["GET","POST"])
def config_l2cat():

    cfg=load_l2cat_config()

    if request.method=="POST":

        action=request.form.get("action","save")

        if action=="start":
            ok,error=start_l2cat_service()
            flash("L2CAT_START_OK" if ok else "L2CAT_ERROR: "+error)
            return redirect("/config/l2cat")

        if action=="stop":
            ok,error=stop_l2cat_service()
            flash("L2CAT_STOP_OK" if ok else "L2CAT_ERROR: "+error)
            return redirect("/config/l2cat")

        if action=="restart":
            ok,error=restart_l2cat_service()
            flash("L2CAT_RESTART_OK" if ok else "L2CAT_ERROR: "+error)
            return redirect("/config/l2cat")

        cfg=update_l2cat_from_form(cfg)

        ok,error=l2cat_validate(cfg)

        if not ok:
            flash("L2CAT_ERROR: "+error)
            return redirect("/config/l2cat")

        l2cat_write(L2CAT_CONFIG,cfg)

        if action=="apply":
            ok,error=apply_l2cat_config()
            flash("L2CAT_APPLY_OK" if ok else "L2CAT_ERROR: "+error)
        else:
            flash("L2CAT_SAVE_OK")

        return redirect("/config/l2cat")

    active=load_l2cat_active_config()

    return render_template(
        "config_l2cat.html",
        CONNECTION=cfg.get("connection",{}),
        STREAM=cfg.get("stream",{}),
        AXUDP=cfg.get("axudp",[]),
        L2PARAMS=cfg.get("l2_parameters",[]),
        LOGGING=cfg.get("logging",{}),
        running=l2cat_service_running(),
        enabled=l2cat_service_enabled(),
        command=l2cat_build_command(cfg,load_config()),
        active_command=l2cat_build_command(active,load_active_config()),
        journal=l2cat_journal()
    )




# ============================================================
# SONDEUDP
# ============================================================

SONDEUDP_SERVICE="dxlaprs-sondeudp.service"
SONDEUDP_CONFIG="/opt/dxlaprs-manager/data/sondeudp_config.json"
SONDEUDP_ACTIVE_CONFIG="/opt/dxlaprs-manager/data/sondeudp_active_config.json"


def sondeudp_load(path):
    import json
    with open(path,"r",encoding="utf-8") as f:
        return json.load(f)


def sondeudp_write(path,cfg):
    import json,os,tempfile

    directory=os.path.dirname(path)
    fd,tmp=tempfile.mkstemp(prefix=".sondeudp-",dir=directory)

    try:
        with os.fdopen(fd,"w",encoding="utf-8") as f:
            json.dump(cfg,f,indent=2)
            f.write("\n")
        os.replace(tmp,path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_sondeudp_config():
    return sondeudp_load(SONDEUDP_CONFIG)


def load_sondeudp_active_config():
    return sondeudp_load(SONDEUDP_ACTIVE_CONFIG)


def sondeudp_running():
    import subprocess
    return subprocess.run(
        ["systemctl","is-active","--quiet",SONDEUDP_SERVICE]
    ).returncode==0


def sondeudp_enabled():
    import subprocess
    return subprocess.run(
        ["systemctl","is-enabled","--quiet",SONDEUDP_SERVICE]
    ).returncode==0


def sondeudp_ctl(action):
    import subprocess

    p=subprocess.run(
        ["systemctl",action,SONDEUDP_SERVICE],
        text=True,
        capture_output=True
    )

    return p.returncode==0,(p.stderr or p.stdout).strip()


def sondeudp_journal():
    import subprocess

    p=subprocess.run(
        ["journalctl","-u",SONDEUDP_SERVICE,"-n","40","--no-pager"],
        text=True,
        capture_output=True
    )

    return p.stdout


def sondeudp_build_command(cfg,manager_cfg):
    import shlex

    bin_dir=str(
        manager_cfg.get("dxlaprs",{}).get("bin_dir","")
    ).strip()

    binary=bin_dir.rstrip("/")+"/sondeudp" if bin_dir else "sondeudp"
    a=[binary]

    g=cfg.get("global",{})

    def val(flag,state):
        if state.get("enabled"):
            v=str(state.get("value","")).strip()
            if v:
                a.extend([flag,v])

    def boo(flag,state):
        if state.get("enabled"):
            a.append(flag)

    boo("-a",g.get("abort_sound_error",{}))
    val("-c",g.get("maxchannels",{}))
    val("-D",g.get("debug_output",{}))
    val("-f",g.get("sample_rate",{}))
    val("-g",g.get("dfm_old_threshold",{}))
    val("-G",g.get("dfm_change_threshold",{}))
    val("-S",g.get("dfm_id_threshold",{}))
    val("-W",g.get("sleep_seconds",{}))
    val("-l",g.get("sound_buffer",{}))
    val("-o",g.get("sound_device",{}))
    val("-L",g.get("receiver_label",{}))

    nm=g.get("dfm_name_mode",{})
    if nm.get("enabled"):
        a.extend([
            "-"+str(nm.get("mode","N")),
            str(nm.get("value","")).strip()
        ])

    boo("-s",g.get("disable_sdr_data",{}))
    boo("-J",g.get("dfm_swap",{}))
    boo("-O",g.get("dfm_old_name",{}))

    for dest in g.get("monitor_udp",[]):
        dest=str(dest).strip()
        if dest:
            a.extend(["-M",dest])

    flags={
        "m10_m20":"1",
        "mrz_meisei":"2",
        "c34_c50":"3",
        "rs41":"4",
        "dfm":"6",
        "imet":"8",
        "rs92":"9"
    }

    for ch in cfg.get("channels",[]):

        if not ch.get("enabled"):
            continue

        num=int(ch.get("channel",0))
        a.extend(["-C",str(num)])

        val("-e",ch.get("equalizer",{}))
        val("-I",ch.get("callsign",{}))
        val("-F",ch.get("afsk_mid",{}))

        for dest in ch.get("udp",[]):
            dest=str(dest).strip()
            if dest:
                a.extend(["-u",dest])

        dec=ch.get("decoders",{})

        for key,flag in flags.items():
            mode=dec.get(key,"default")
            if mode=="off":
                a.append("-"+flag)
            elif mode=="always":
                a.append("+"+flag)

    if g.get("very_verbose"):
        a.append("-V")
    elif g.get("verbose"):
        a.append("-v")

    return " ".join(shlex.quote(str(x)) for x in a)


def sondeudp_validate(cfg):

    try:
        g=cfg.get("global",{})

        def number(key,lo=None,hi=None):
            st=g.get(key,{})
            if not st.get("enabled"):
                return None

            n=int(st.get("value",""))

            if lo is not None and n<lo:
                raise ValueError(key+" sotto il minimo")

            if hi is not None and n>hi:
                raise ValueError(key+" sopra il massimo")

            return n

        number("maxchannels",0,62)
        number("sample_rate",8000,96000)
        number("sound_buffer",16,4096)

        label=g.get("receiver_label",{})
        if label.get("enabled"):
            if len(str(label.get("value",""))) > 4:
                return False,"Etichetta ricevitore: massimo 4 caratteri"

        nm=g.get("dfm_name_mode",{})
        if nm.get("enabled"):
            if nm.get("mode") not in ("N","n"):
                return False,"Modalità nome DFM non valida"

            n=int(nm.get("value",""))
            if not 0 <= n <= 255:
                return False,"Valore DFM deve essere 0..255"

        for ch in cfg.get("channels",[]):

            num=int(ch.get("channel",0))

            if num not in (0,1):
                return False,"Il parser sondeudp accetta -C solo 0 o 1"

            if not ch.get("enabled"):
                continue

            eq=ch.get("equalizer",{})
            if eq.get("enabled"):
                n=int(eq.get("value",""))
                if not -999 <= n <= 999:
                    return False,"Equalizzatore deve essere -999..999"

            call=ch.get("callsign",{})
            if call.get("enabled") and not str(call.get("value","")).strip():
                return False,"Nominativo canale mancante"

            for dest in ch.get("udp",[]):
                if ":" not in str(dest):
                    return False,"Destinazione UDP non valida"

            for mode in ch.get("decoders",{}).values():
                if mode not in ("default","off","always"):
                    return False,"Modalità decoder non valida"

        for dest in g.get("monitor_udp",[]):
            if ":" not in str(dest):
                return False,"Destinazione monitor UDP non valida"

        return True,""

    except Exception as e:
        return False,str(e)


def update_sondeudp_from_form(cfg):

    f=request.form
    g=cfg["global"]

    def val(key,name):
        g[key]["enabled"]=name+"_enabled" in f
        g[key]["value"]=f.get(name,"").strip()

    def boo(key,name):
        g[key]["enabled"]=name in f

    boo("abort_sound_error","g_abort")
    val("maxchannels","g_maxchannels")
    val("debug_output","g_debug")
    val("sample_rate","g_samplerate")
    val("dfm_old_threshold","g_dfmold")
    val("dfm_change_threshold","g_dfmchg")
    val("dfm_id_threshold","g_dfmid")
    val("sleep_seconds","g_sleep")
    val("sound_buffer","g_buffer")
    val("sound_device","g_sound")
    val("receiver_label","g_label")

    boo("disable_sdr_data","g_nosdr")
    boo("dfm_swap","g_dfmswap")
    boo("dfm_old_name","g_dfmoldname")

    g["dfm_name_mode"]["enabled"]="g_dfmname_enabled" in f
    g["dfm_name_mode"]["mode"]=f.get("g_dfmname_mode","N")
    g["dfm_name_mode"]["value"]=f.get("g_dfmname_value","").strip()

    g["monitor_udp"]=[
        x.strip()
        for x in f.getlist("monitor_udp")
        if x.strip()
    ]

    g["verbose"]="g_verbose" in f
    g["very_verbose"]="g_very_verbose" in f

    for ch in cfg["channels"]:

        n=int(ch["channel"])
        prefix="ch"+str(n)+"_"

        ch["enabled"]=prefix+"enabled" in f

        for key,field in (
            ("equalizer","equalizer"),
            ("callsign","callsign"),
            ("afsk_mid","afskmid")
        ):
            name=prefix+field
            ch[key]["enabled"]=name+"_enabled" in f
            ch[key]["value"]=f.get(name,"").strip()

        ch["udp"]=[
            x.strip()
            for x in f.getlist(prefix+"udp")
            if x.strip()
        ]

        for key in ch["decoders"]:
            ch["decoders"][key]=f.get(
                prefix+"decoder_"+key,
                "default"
            )

    return cfg


def apply_sondeudp_config():

    import shutil,subprocess,time,os

    was_running=sondeudp_running()
    old=None

    if os.path.exists(SONDEUDP_ACTIVE_CONFIG):
        with open(SONDEUDP_ACTIVE_CONFIG,"rb") as f:
            old=f.read()

    try:
        shutil.copy2(SONDEUDP_CONFIG,SONDEUDP_ACTIVE_CONFIG)

        if was_running:
            ok,error=sondeudp_ctl("restart")

            if not ok:
                raise RuntimeError(error)

            time.sleep(1)

            if not sondeudp_running():
                p=subprocess.run(
                    [
                        "systemctl","show",SONDEUDP_SERVICE,
                        "-p","ExecMainStatus","--value"
                    ],
                    text=True,
                    capture_output=True
                )

                raise RuntimeError(
                    "sondeudp non rimane attivo; ExecMainStatus="
                    +p.stdout.strip()
                )

        return True,""

    except Exception as e:

        if old is not None:
            with open(SONDEUDP_ACTIVE_CONFIG,"wb") as f:
                f.write(old)

            if was_running:
                sondeudp_ctl("restart")

        return False,str(e)


@app.route("/config/sondeudp",methods=["GET","POST"])
def config_sondeudp():

    cfg=load_sondeudp_config()

    if request.method=="POST":

        action=request.form.get("action","save")

        if action in ("start","stop","restart"):
            ok,error=sondeudp_ctl(action)

            flash(
                "SONDEUDP_"+action.upper()+"_OK"
                if ok else
                "SONDEUDP_ERROR: "+error
            )

            return redirect("/config/sondeudp")

        cfg=update_sondeudp_from_form(cfg)

        ok,error=sondeudp_validate(cfg)

        if not ok:
            flash("SONDEUDP_ERROR: "+error)
            return redirect("/config/sondeudp")

        sondeudp_write(SONDEUDP_CONFIG,cfg)

        if action=="apply":
            ok,error=apply_sondeudp_config()
            flash(
                "SONDEUDP_APPLY_OK"
                if ok else
                "SONDEUDP_ERROR: "+error
            )
        else:
            flash("SONDEUDP_SAVE_OK")

        return redirect("/config/sondeudp")

    active=load_sondeudp_active_config()

    return render_template(
        "config_sondeudp.html",
        G=cfg.get("global",{}),
        CHANNELS=cfg.get("channels",[]),
        running=sondeudp_running(),
        enabled=sondeudp_enabled(),
        command=sondeudp_build_command(cfg,load_config()),
        active_command=sondeudp_build_command(active,load_active_config()),
        journal=sondeudp_journal()
    )




# ============================================================
# SONDEMOD
# ============================================================

SONDEMOD_SERVICE="dxlaprs-sondemod.service"
SONDEMOD_CONFIG="/opt/dxlaprs-manager/data/sondemod_config.json"
SONDEMOD_ACTIVE_CONFIG="/opt/dxlaprs-manager/data/sondemod_active_config.json"


def sondemod_load(path):
    import json

    with open(path,"r",encoding="utf-8") as f:
        return json.load(f)


def sondemod_write(path,cfg):
    import json
    import os
    import tempfile

    directory=os.path.dirname(path)

    fd,tmp=tempfile.mkstemp(
        prefix=".sondemod-",
        dir=directory
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                indent=2
            )

            f.write("\n")

        os.replace(tmp,path)

    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_sondemod_config():
    return sondemod_load(
        SONDEMOD_CONFIG
    )


def load_sondemod_active_config():
    return sondemod_load(
        SONDEMOD_ACTIVE_CONFIG
    )


def sondemod_running():
    import subprocess

    return subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            SONDEMOD_SERVICE
        ]
    ).returncode==0


def sondemod_enabled():
    import subprocess

    return subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            SONDEMOD_SERVICE
        ]
    ).returncode==0


def sondemod_ctl(action):
    import subprocess

    p=subprocess.run(
        [
            "systemctl",
            action,
            SONDEMOD_SERVICE
        ],
        text=True,
        capture_output=True
    )

    return (
        p.returncode==0,
        (p.stderr or p.stdout).strip()
    )


def sondemod_journal():
    import subprocess

    p=subprocess.run(
        [
            "journalctl",
            "-u",
            SONDEMOD_SERVICE,
            "-n",
            "40",
            "--no-pager"
        ],
        text=True,
        capture_output=True
    )

    return p.stdout


def sondemod_build_command(cfg,manager_cfg):
    import shlex

    bin_dir=str(
        manager_cfg
        .get("dxlaprs",{})
        .get("bin_dir","")
    ).strip()

    binary=(
        bin_dir.rstrip("/")+"/sondemod"
        if bin_dir
        else "sondemod"
    )

    a=[binary]

    inp=cfg.get("input",{})
    aprs=cfg.get("aprs",{})
    files=cfg.get("files",{})
    alm=cfg.get("almanac",{})
    outputs=cfg.get("outputs",{})
    logging=cfg.get("logging",{})

    def val(flag,state):
        if state.get("enabled"):
            value=str(
                state.get("value","")
            ).strip()

            if value:
                a.extend([flag,value])

    def raw(flag,state):
        if state.get("enabled"):
            value=str(
                state.get("value","")
            ).strip()

            if value:
                args=shlex.split(value)

                if args:
                    a.append(flag)
                    a.extend(args)

    def boo(flag,state):
        if state.get("enabled"):
            a.append(flag)

    val("-o",inp.get("source",{}))

    boo("-d",aprs.get("dao",{}))
    raw("-a",aprs.get("fence",{}))
    boo("-F",aprs.get("track_filter_off",{}))
    val("-g",aprs.get("leap_seconds",{}))
    val("-p",aprs.get("send_quick",{}))
    val("-E",aprs.get("expire",{}))
    val("-b",aprs.get("beacon_times",{}))
    val("-G",aprs.get("max_distance",{}))
    val("-A",aprs.get("altitude_table",{}))
    val("-I",aprs.get("callsign",{}))
    val("-w",aprs.get("via",{}))
    raw("-P",aprs.get("position",{}))
    val("-N",aprs.get("my_altitude",{}))
    boo("-M",aprs.get("send_mhz",{}))

    val("-T",alm.get("max_age",{}))
    val("-R",alm.get("request_after",{}))

    val("-t",files.get("comment",{}))
    val("-S",files.get("srtm",{}))
    val("-s",files.get("sem",{}))
    val("-x",files.get("rinex",{}))
    val("-y",files.get("yuma",{}))
    val("-X",files.get("encrypted",{}))

    decoded=files.get("decoded",{})

    if decoded.get("enabled"):
        value=str(
            decoded.get("value","")
        ).strip()

        if value:
            mode=decoded.get(
                "mode",
                "csv"
            )

            a.extend([
                "-j" if mode=="json" else "-C",
                value
            ])

    radio=outputs.get("radio",{})

    if radio.get("enabled"):

        mode=radio.get(
            "mode",
            "r"
        )

        for dest in radio.get(
            "destinations",
            []
        ):
            dest=str(dest).strip()

            if dest:
                a.extend([
                    "-"+mode,
                    dest
                ])

    for dest in outputs.get(
        "json_udp",
        []
    ):
        dest=str(dest).strip()

        if dest:
            a.extend([
                "-J",
                dest
            ])

    val("-L",outputs.get("dfm_types",{}))

    if logging.get("very_verbose"):
        a.append("-V")

    elif logging.get("verbose"):
        a.append("-v")

    return " ".join(
        shlex.quote(str(x))
        for x in a
    )


def sondemod_validate(cfg):
    import shlex

    try:

        inp=cfg.get("input",{})
        aprs=cfg.get("aprs",{})
        files=cfg.get("files",{})
        alm=cfg.get("almanac",{})
        outputs=cfg.get("outputs",{})

        source=inp.get("source",{})

        if source.get("enabled"):
            if not str(
                source.get("value","")
            ).strip():
                return False,"Ingresso -o mancante"

        def gint(section,key,lo=None,hi=None):

            state=section.get(
                key,
                {}
            )

            if not state.get("enabled"):
                return None

            n=int(
                state.get("value","")
            )

            if lo is not None and n<lo:
                raise ValueError(
                    key+" sotto il minimo"
                )

            if hi is not None and n>hi:
                raise ValueError(
                    key+" sopra il massimo"
                )

            return n

        gint(aprs,"send_quick",0,2)
        gint(aprs,"expire",0,None)
        gint(aprs,"max_distance",0,None)

        gint(
            alm,
            "max_age",
            0,
            None
        )

        gint(
            alm,
            "request_after",
            0,
            None
        )

        leap=aprs.get(
            "leap_seconds",
            {}
        )

        if leap.get("enabled"):
            int(
                leap.get("value","")
            )

        alt=aprs.get(
            "my_altitude",
            {}
        )

        if alt.get("enabled"):
            float(
                alt.get("value","")
            )

        beacon=aprs.get(
            "beacon_times",
            {}
        )

        if beacon.get("enabled"):

            values=[
                x
                for x in str(
                    beacon.get(
                        "value",
                        ""
                    )
                ).split(":")
                if x!=""
            ]

            if not values:
                return False,"Tabella beacon vuota"

            if len(values)>20:
                return False,"La tabella -b supporta massimo 20 valori"

            for x in values:
                if int(x)<0:
                    return False,"I tempi beacon non possono essere negativi"

        ath=aprs.get(
            "altitude_table",
            {}
        )

        if ath.get("enabled"):

            values=[
                x
                for x in str(
                    ath.get(
                        "value",
                        ""
                    )
                ).split(":")
                if x!=""
            ]

            if not values:
                return False,"Tabella quote vuota"

            if len(values)>19:
                return False,"La tabella -A supporta massimo 19 valori"

            for x in values:
                if int(x)<0:
                    return False,"Le quote non possono essere negative"

        pos=aprs.get(
            "position",
            {}
        )

        if pos.get("enabled"):

            args=shlex.split(
                str(
                    pos.get(
                        "value",
                        ""
                    )
                )
            )

            if len(args) not in (1,2):
                return False,"-P richiede un locator oppure latitudine e longitudine"

        fence=aprs.get(
            "fence",
            {}
        )

        if fence.get("enabled"):

            args=shlex.split(
                str(
                    fence.get(
                        "value",
                        ""
                    )
                )
            )

            if len(args) not in (2,3,4):
                return False,"-a richiede due punti: locator e/o coordinate"

        call=aprs.get(
            "callsign",
            {}
        )

        if call.get("enabled"):
            if not str(
                call.get("value","")
            ).strip():
                return False,"Nominativo APRS mancante"

        decoded=files.get(
            "decoded",
            {}
        )

        if decoded.get("enabled"):

            if decoded.get("mode") not in (
                "csv",
                "json"
            ):
                return False,"Formato file dati non valido"

            if not str(
                decoded.get(
                    "value",
                    ""
                )
            ).strip():
                return False,"Nome file dati decodificati mancante"

        radio=outputs.get(
            "radio",
            {}
        )

        if radio.get("enabled"):

            if radio.get("mode") not in (
                "r",
                "m"
            ):
                return False,"Modalità uscita APRS non valida"

            if not radio.get(
                "destinations",
                []
            ):
                return False,"Uscita APRS attiva ma senza destinazioni"

            for dest in radio.get(
                "destinations",
                []
            ):
                if ":" not in str(dest):
                    return False,"Destinazione APRS non valida"

        for dest in outputs.get(
            "json_udp",
            []
        ):
            if ":" not in str(dest):
                return False,"Destinazione JSON UDP non valida"

        dfm=outputs.get(
            "dfm_types",
            {}
        )

        if dfm.get("enabled"):
            if not str(
                dfm.get(
                    "value",
                    ""
                )
            ).strip():
                return False,"Mappatura DFM vuota"

        return True,""

    except Exception as e:
        return False,str(e)


def update_sondemod_from_form(cfg):

    f=request.form

    inp=cfg["input"]
    aprs=cfg["aprs"]
    files=cfg["files"]
    alm=cfg["almanac"]
    outputs=cfg["outputs"]
    logging=cfg["logging"]

    def value(
        section,
        key,
        name
    ):
        section[key]["enabled"] = (
            name+"_enabled" in f
        )

        section[key]["value"] = (
            f.get(
                name,
                ""
            ).strip()
        )

    def boo(
        section,
        key,
        name
    ):
        section[key]["enabled"] = (
            name in f
        )

    value(
        inp,
        "source",
        "input_source"
    )

    value(
        aprs,
        "callsign",
        "aprs_callsign"
    )

    value(
        aprs,
        "via",
        "aprs_via"
    )

    boo(
        aprs,
        "dao",
        "aprs_dao"
    )

    boo(
        aprs,
        "track_filter_off",
        "aprs_nofilter"
    )

    value(
        aprs,
        "send_quick",
        "aprs_sendquick"
    )

    value(
        aprs,
        "beacon_times",
        "aprs_beacons"
    )

    value(
        aprs,
        "altitude_table",
        "aprs_altitudes"
    )

    value(
        aprs,
        "max_distance",
        "aprs_maxdistance"
    )

    value(
        aprs,
        "position",
        "aprs_position"
    )

    value(
        aprs,
        "my_altitude",
        "aprs_altitude"
    )

    value(
        aprs,
        "fence",
        "aprs_fence"
    )

    value(
        aprs,
        "expire",
        "aprs_expire"
    )

    value(
        aprs,
        "leap_seconds",
        "aprs_leap"
    )

    boo(
        aprs,
        "send_mhz",
        "aprs_mhz"
    )

    value(
        files,
        "comment",
        "file_comment"
    )

    value(
        files,
        "srtm",
        "file_srtm"
    )

    value(
        files,
        "sem",
        "file_sem"
    )

    value(
        files,
        "rinex",
        "file_rinex"
    )

    value(
        files,
        "yuma",
        "file_yuma"
    )

    value(
        files,
        "encrypted",
        "file_encrypted"
    )

    value(
        alm,
        "max_age",
        "alm_maxage"
    )

    value(
        alm,
        "request_after",
        "alm_request"
    )

    files["decoded"]["enabled"] = (
        "decoded_enabled" in f
    )

    files["decoded"]["mode"] = (
        f.get(
            "decoded_mode",
            "csv"
        )
    )

    files["decoded"]["value"] = (
        f.get(
            "decoded_value",
            ""
        ).strip()
    )

    outputs["radio"]["enabled"] = (
        "radio_enabled" in f
    )

    outputs["radio"]["mode"] = (
        f.get(
            "radio_mode",
            "r"
        )
    )

    outputs["radio"]["destinations"] = [
        x.strip()
        for x in f.getlist(
            "radio_destination"
        )
        if x.strip()
    ]

    outputs["json_udp"] = [
        x.strip()
        for x in f.getlist(
            "json_destination"
        )
        if x.strip()
    ]

    value(
        outputs,
        "dfm_types",
        "dfm_types"
    )

    logging["verbose"] = (
        "log_verbose" in f
    )

    logging["very_verbose"] = (
        "log_very_verbose" in f
    )

    return cfg


def apply_sondemod_config():

    import os
    import shutil
    import subprocess
    import time

    was_running=sondemod_running()
    old=None

    if os.path.exists(
        SONDEMOD_ACTIVE_CONFIG
    ):
        with open(
            SONDEMOD_ACTIVE_CONFIG,
            "rb"
        ) as f:
            old=f.read()

    try:

        shutil.copy2(
            SONDEMOD_CONFIG,
            SONDEMOD_ACTIVE_CONFIG
        )

        if was_running:

            ok,error=sondemod_ctl(
                "restart"
            )

            if not ok:
                raise RuntimeError(
                    error
                )

            time.sleep(1)

            if not sondemod_running():

                p=subprocess.run(
                    [
                        "systemctl",
                        "show",
                        SONDEMOD_SERVICE,
                        "-p",
                        "ExecMainStatus",
                        "--value"
                    ],
                    text=True,
                    capture_output=True
                )

                raise RuntimeError(
                    "sondemod non rimane attivo; ExecMainStatus="
                    +p.stdout.strip()
                )

        return True,""

    except Exception as e:

        if old is not None:

            with open(
                SONDEMOD_ACTIVE_CONFIG,
                "wb"
            ) as f:
                f.write(old)

            if was_running:
                sondemod_ctl(
                    "restart"
                )

        return False,str(e)


@app.route(
    "/config/sondemod",
    methods=["GET","POST"]
)
def config_sondemod():

    cfg=load_sondemod_config()

    if request.method=="POST":

        action=request.form.get(
            "action",
            "save"
        )

        if action in (
            "start",
            "stop",
            "restart"
        ):

            ok,error=sondemod_ctl(
                action
            )

            flash(
                "SONDEMOD_"+action.upper()+"_OK"
                if ok
                else
                "SONDEMOD_ERROR: "+error
            )

            return redirect(
                "/config/sondemod"
            )

        cfg=update_sondemod_from_form(
            cfg
        )

        ok,error=sondemod_validate(
            cfg
        )

        if not ok:
            flash(
                "SONDEMOD_ERROR: "+error
            )

            return redirect(
                "/config/sondemod"
            )

        sondemod_write(
            SONDEMOD_CONFIG,
            cfg
        )

        if action=="apply":

            ok,error=apply_sondemod_config()

            flash(
                "SONDEMOD_APPLY_OK"
                if ok
                else
                "SONDEMOD_ERROR: "+error
            )

        else:
            flash(
                "SONDEMOD_SAVE_OK"
            )

        return redirect(
            "/config/sondemod"
        )

    active=load_sondemod_active_config()

    return render_template(
        "config_sondemod.html",

        INPUT=cfg.get(
            "input",
            {}
        ),

        APRS=cfg.get(
            "aprs",
            {}
        ),

        FILES=cfg.get(
            "files",
            {}
        ),

        ALMANAC=cfg.get(
            "almanac",
            {}
        ),

        OUTPUTS=cfg.get(
            "outputs",
            {}
        ),

        LOGGING=cfg.get(
            "logging",
            {}
        ),

        running=sondemod_running(),
        enabled=sondemod_enabled(),

        command=sondemod_build_command(
            cfg,
            load_config()
        ),

        active_command=sondemod_build_command(
            active,
            load_active_config()
        ),

        journal=sondemod_journal()
    )




# ============================================================
# TTYTEE
# ============================================================

TTYTEE_SERVICE="dxlaprs-ttytee.service"
TTYTEE_CONFIG="/opt/dxlaprs-manager/data/ttytee_config.json"
TTYTEE_ACTIVE_CONFIG="/opt/dxlaprs-manager/data/ttytee_active_config.json"


def ttytee_load(path):

    import json

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def ttytee_write(path,cfg):

    import json
    import os
    import tempfile

    directory=os.path.dirname(
        path
    )

    fd,tmp=tempfile.mkstemp(
        prefix=".ttytee-",
        dir=directory
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                indent=2
            )

            f.write("\n")

        os.replace(
            tmp,
            path
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def load_ttytee_config():
    return ttytee_load(
        TTYTEE_CONFIG
    )


def load_ttytee_active_config():
    return ttytee_load(
        TTYTEE_ACTIVE_CONFIG
    )


def ttytee_running():

    import subprocess

    return subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            TTYTEE_SERVICE
        ]
    ).returncode==0


def ttytee_enabled():

    import subprocess

    return subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            TTYTEE_SERVICE
        ]
    ).returncode==0


def ttytee_ctl(action):

    import subprocess

    p=subprocess.run(
        [
            "systemctl",
            action,
            TTYTEE_SERVICE
        ],
        text=True,
        capture_output=True
    )

    return (
        p.returncode==0,
        (p.stderr or p.stdout).strip()
    )


def ttytee_journal():

    import subprocess

    p=subprocess.run(
        [
            "journalctl",
            "-u",
            TTYTEE_SERVICE,
            "-n",
            "40",
            "--no-pager"
        ],
        text=True,
        capture_output=True
    )

    return p.stdout


def ttytee_build_command(
    cfg,
    manager_cfg
):

    import shlex

    bin_dir=str(
        manager_cfg
        .get("dxlaprs",{})
        .get("bin_dir","")
    ).strip()

    binary=(
        bin_dir.rstrip("/")+"/ttytee"
        if bin_dir
        else "ttytee"
    )

    a=[binary]

    serial=cfg.get(
        "serial",
        {}
    )

    if serial.get("enabled"):

        device=str(
            serial.get(
                "device",
                ""
            )
        ).strip()

        baud=str(
            serial.get(
                "baud",
                ""
            )
        ).strip()

        if device and baud:
            a.extend([
                "-t",
                device+":"+baud
            ])

    for pipe in cfg.get(
        "outputs",
        []
    ):

        pipe=str(
            pipe
        ).strip()

        if pipe:
            a.extend([
                "-p",
                pipe
            ])

    if serial.get(
        "abort_on_usb_error"
    ):
        a.append("-u")

    if cfg.get(
        "logging",
        {}
    ).get(
        "verbose"
    ):
        a.append("-v")

    return " ".join(
        shlex.quote(
            str(x)
        )
        for x in a
    )


def ttytee_validate(cfg):

    try:

        serial=cfg.get(
            "serial",
            {}
        )

        if serial.get("enabled"):

            device=str(
                serial.get(
                    "device",
                    ""
                )
            ).strip()

            if not device:
                return (
                    False,
                    "Dispositivo seriale mancante"
                )

            baud=int(
                serial.get(
                    "baud",
                    ""
                )
            )

            if baud<=0:
                return (
                    False,
                    "Baud rate deve essere maggiore di zero"
                )

        outputs=[
            str(x).strip()
            for x in cfg.get(
                "outputs",
                []
            )
            if str(x).strip()
        ]

        for pipe in outputs:

            if "\n" in pipe:
                return (
                    False,
                    "Nome pipe non valido"
                )

        return True,""

    except Exception as e:
        return False,str(e)


def update_ttytee_from_form(cfg):

    f=request.form

    serial=cfg["serial"]

    serial["enabled"] = (
        "serial_enabled"
        in f
    )

    serial["device"] = (
        f.get(
            "serial_device",
            ""
        ).strip()
    )

    serial["baud"] = (
        f.get(
            "serial_baud",
            ""
        ).strip()
    )

    serial["abort_on_usb_error"] = (
        "serial_abort"
        in f
    )

    cfg["outputs"] = [
        x.strip()
        for x in f.getlist(
            "pipe_destination"
        )
        if x.strip()
    ]

    cfg["logging"]["verbose"] = (
        "log_verbose"
        in f
    )

    return cfg


def apply_ttytee_config():

    import os
    import shutil
    import subprocess
    import time

    was_running=ttytee_running()
    old=None

    if os.path.exists(
        TTYTEE_ACTIVE_CONFIG
    ):

        with open(
            TTYTEE_ACTIVE_CONFIG,
            "rb"
        ) as f:
            old=f.read()

    try:

        shutil.copy2(
            TTYTEE_CONFIG,
            TTYTEE_ACTIVE_CONFIG
        )

        if was_running:

            ok,error=ttytee_ctl(
                "restart"
            )

            if not ok:
                raise RuntimeError(
                    error
                )

            time.sleep(1)

            if not ttytee_running():

                p=subprocess.run(
                    [
                        "systemctl",
                        "show",
                        TTYTEE_SERVICE,
                        "-p",
                        "ExecMainStatus",
                        "--value"
                    ],
                    text=True,
                    capture_output=True
                )

                raise RuntimeError(
                    "ttytee non rimane attivo; ExecMainStatus="
                    +p.stdout.strip()
                )

        return True,""

    except Exception as e:

        if old is not None:

            with open(
                TTYTEE_ACTIVE_CONFIG,
                "wb"
            ) as f:
                f.write(old)

            if was_running:

                ttytee_ctl(
                    "restart"
                )

        return False,str(e)


@app.route(
    "/config/ttytee",
    methods=["GET","POST"]
)
def config_ttytee():

    cfg=load_ttytee_config()

    if request.method=="POST":

        action=request.form.get(
            "action",
            "save"
        )

        if action in (
            "start",
            "stop",
            "restart"
        ):

            ok,error=ttytee_ctl(
                action
            )

            flash(
                "TTYTEE_"+action.upper()+"_OK"
                if ok
                else
                "TTYTEE_ERROR: "+error
            )

            return redirect(
                "/config/ttytee"
            )

        cfg=update_ttytee_from_form(
            cfg
        )

        ok,error=ttytee_validate(
            cfg
        )

        if not ok:

            flash(
                "TTYTEE_ERROR: "+error
            )

            return redirect(
                "/config/ttytee"
            )

        ttytee_write(
            TTYTEE_CONFIG,
            cfg
        )

        if action=="apply":

            ok,error=apply_ttytee_config()

            flash(
                "TTYTEE_APPLY_OK"
                if ok
                else
                "TTYTEE_ERROR: "+error
            )

        else:

            flash(
                "TTYTEE_SAVE_OK"
            )

        return redirect(
            "/config/ttytee"
        )

    active=load_ttytee_active_config()

    return render_template(
        "config_ttytee.html",

        SERIAL=cfg.get(
            "serial",
            {}
        ),

        OUTPUTS=cfg.get(
            "outputs",
            []
        ),

        LOGGING=cfg.get(
            "logging",
            {}
        ),

        running=ttytee_running(),
        enabled=ttytee_enabled(),

        command=ttytee_build_command(
            cfg,
            load_config()
        ),

        active_command=ttytee_build_command(
            active,
            load_active_config()
        ),

        journal=ttytee_journal()
    )




# ============================================================
# ADSB2APRS
# ============================================================

ADSB2APRS_SERVICE="dxlaprs-adsb2aprs.service"
ADSB2APRS_CONFIG="/opt/dxlaprs-manager/data/adsb2aprs_config.json"
ADSB2APRS_ACTIVE_CONFIG="/opt/dxlaprs-manager/data/adsb2aprs_active_config.json"


def adsb2aprs_load(path):
    import json

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def adsb2aprs_write(path,cfg):
    import json
    import os
    import tempfile

    directory=os.path.dirname(path)

    fd,tmp=tempfile.mkstemp(
        prefix=".adsb2aprs-",
        dir=directory
    )

    try:
        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                cfg,
                f,
                indent=2
            )

            f.write("\n")

        os.replace(
            tmp,
            path
        )

    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def load_adsb2aprs_config():
    return adsb2aprs_load(
        ADSB2APRS_CONFIG
    )


def load_adsb2aprs_active_config():
    return adsb2aprs_load(
        ADSB2APRS_ACTIVE_CONFIG
    )


def adsb2aprs_running():
    import subprocess

    return subprocess.run(
        [
            "systemctl",
            "is-active",
            "--quiet",
            ADSB2APRS_SERVICE
        ]
    ).returncode==0


def adsb2aprs_enabled():
    import subprocess

    return subprocess.run(
        [
            "systemctl",
            "is-enabled",
            "--quiet",
            ADSB2APRS_SERVICE
        ]
    ).returncode==0


def adsb2aprs_ctl(action):
    import subprocess

    p=subprocess.run(
        [
            "systemctl",
            action,
            ADSB2APRS_SERVICE
        ],
        text=True,
        capture_output=True
    )

    return (
        p.returncode==0,
        (p.stderr or p.stdout).strip()
    )


def adsb2aprs_journal():
    import subprocess

    p=subprocess.run(
        [
            "journalctl",
            "-u",
            ADSB2APRS_SERVICE,
            "-n",
            "40",
            "--no-pager"
        ],
        text=True,
        capture_output=True
    )

    return p.stdout


def adsb2aprs_build_command(
    cfg,
    manager_cfg
):

    import shlex

    bin_dir=str(
        manager_cfg
        .get("dxlaprs",{})
        .get("bin_dir","")
    ).strip()

    binary=(
        bin_dir.rstrip("/")+"/adsb2aprs"
        if bin_dir
        else "adsb2aprs"
    )

    a=[binary]

    dump1090=cfg.get(
        "dump1090",
        {}
    )

    aprs=cfg.get(
        "aprs",
        {}
    )

    position=cfg.get(
        "position",
        {}
    )

    database=cfg.get(
        "aircraft_database",
        {}
    )

    logging=cfg.get(
        "logging",
        {}
    )


    def val(flag,state):

        if state.get("enabled"):

            value=str(
                state.get(
                    "value",
                    ""
                )
            ).strip()

            if value:
                a.extend([
                    flag,
                    value
                ])


    def raw(flag,state):

        if state.get("enabled"):

            value=str(
                state.get(
                    "value",
                    ""
                )
            ).strip()

            if value:

                args=shlex.split(
                    value
                )

                if args:
                    a.append(flag)
                    a.extend(args)


    def boo(flag,state):

        if state.get("enabled"):
            a.append(flag)


    val(
        "-t",
        dump1090.get(
            "server",
            {}
        )
    )

    boo(
        "-k",
        dump1090.get(
            "keep_connection",
            {}
        )
    )


    val(
        "-I",
        aprs.get(
            "callsign",
            {}
        )
    )

    val(
        "-u",
        aprs.get(
            "destination",
            {}
        )
    )

    val(
        "-b",
        aprs.get(
            "beacon_time",
            {}
        )
    )

    val(
        "-s",
        aprs.get(
            "symbol",
            {}
        )
    )

    val(
        "-c",
        aprs.get(
            "comment",
            {}
        )
    )


    raw(
        "-P",
        position.get(
            "home",
            {}
        )
    )

    val(
        "-A",
        position.get(
            "home_altitude",
            {}
        )
    )

    val(
        "-a",
        position.get(
            "altitude_correction",
            {}
        )
    )

    val(
        "-S",
        position.get(
            "srtm",
            {}
        )
    )


    val(
        "-D",
        database.get(
            "file",
            {}
        )
    )

    val(
        "-f",
        database.get(
            "titles",
            {}
        )
    )


    if logging.get(
        "very_verbose"
    ):
        a.append("-V")

    elif logging.get(
        "verbose"
    ):
        a.append("-v")


    return " ".join(
        shlex.quote(
            str(x)
        )
        for x in a
    )


def adsb2aprs_validate(cfg):

    import shlex

    try:

        dump1090=cfg.get(
            "dump1090",
            {}
        )

        aprs=cfg.get(
            "aprs",
            {}
        )

        position=cfg.get(
            "position",
            {}
        )

        database=cfg.get(
            "aircraft_database",
            {}
        )


        server=dump1090.get(
            "server",
            {}
        )

        if server.get("enabled"):

            value=str(
                server.get(
                    "value",
                    ""
                )
            ).strip()

            if not value:
                return False,"Server dump1090 mancante"

            if ":" not in value:
                return False,"Server dump1090 deve essere host:port"


        call=aprs.get(
            "callsign",
            {}
        )

        if call.get("enabled"):

            value=str(
                call.get(
                    "value",
                    ""
                )
            ).strip()

            if not 3 <= len(value) <= 9:
                return False,"Il nominativo deve essere lungo 3..9 caratteri"


        dest=aprs.get(
            "destination",
            {}
        )

        if dest.get("enabled"):

            value=str(
                dest.get(
                    "value",
                    ""
                )
            ).strip()

            if ":" not in value:
                return False,"Destinazione AXUDP deve essere host:port"


        bt=aprs.get(
            "beacon_time",
            {}
        )

        if bt.get("enabled"):

            n=int(
                bt.get(
                    "value",
                    ""
                )
            )

            if n<0:
                return False,"Intervallo beacon non valido"


        symbol=aprs.get(
            "symbol",
            {}
        )

        if symbol.get("enabled"):

            value=str(
                symbol.get(
                    "value",
                    ""
                )
            )

            if len(value)!=2:
                return False,"Il simbolo APRS deve avere esattamente 2 caratteri"

            if value[0]=="-":
                return False,"Il primo carattere del simbolo APRS non può essere '-'"


        pos=position.get(
            "home",
            {}
        )

        if pos.get("enabled"):

            args=shlex.split(
                str(
                    pos.get(
                        "value",
                        ""
                    )
                )
            )

            if len(args) not in (
                1,
                2
            ):
                return False,"-P richiede locator oppure latitudine e longitudine"


        for key in (
            "home_altitude",
            "altitude_correction"
        ):

            state=position.get(
                key,
                {}
            )

            if state.get("enabled"):
                float(
                    state.get(
                        "value",
                        ""
                    )
                )


        titles=database.get(
            "titles",
            {}
        )

        if titles.get("enabled"):

            value=str(
                titles.get(
                    "value",
                    ""
                )
            )

            if not value:
                return False,"Lista campi database vuota"

            if len(
                value.split(",")
            ) > 40:
                return False,"adsb2aprs supporta massimo 40 campi database"


        db=database.get(
            "file",
            {}
        )

        if db.get("enabled"):

            if not str(
                db.get(
                    "value",
                    ""
                )
            ).strip():
                return False,"Nome database CSV mancante"


        return True,""


    except Exception as e:
        return False,str(e)


def update_adsb2aprs_from_form(cfg):

    f=request.form

    dump1090=cfg["dump1090"]
    aprs=cfg["aprs"]
    position=cfg["position"]
    database=cfg["aircraft_database"]
    logging=cfg["logging"]


    def value(
        section,
        key,
        name
    ):

        section[key]["enabled"] = (
            name+"_enabled"
            in f
        )

        section[key]["value"] = (
            f.get(
                name,
                ""
            ).strip()
        )


    def boo(
        section,
        key,
        name
    ):

        section[key]["enabled"] = (
            name
            in f
        )


    value(
        dump1090,
        "server",
        "dump_server"
    )

    boo(
        dump1090,
        "keep_connection",
        "dump_keep"
    )


    value(
        aprs,
        "callsign",
        "aprs_callsign"
    )

    value(
        aprs,
        "destination",
        "aprs_destination"
    )

    value(
        aprs,
        "beacon_time",
        "aprs_beacon"
    )

    value(
        aprs,
        "symbol",
        "aprs_symbol"
    )

    value(
        aprs,
        "comment",
        "aprs_comment"
    )


    value(
        position,
        "home",
        "pos_home"
    )

    value(
        position,
        "home_altitude",
        "pos_alt"
    )

    value(
        position,
        "altitude_correction",
        "pos_corr"
    )

    value(
        position,
        "srtm",
        "pos_srtm"
    )


    value(
        database,
        "file",
        "db_file"
    )

    value(
        database,
        "titles",
        "db_titles"
    )


    logging["verbose"] = (
        "log_verbose"
        in f
    )

    logging["very_verbose"] = (
        "log_very_verbose"
        in f
    )


    return cfg


def apply_adsb2aprs_config():

    import os
    import shutil
    import subprocess
    import time

    was_running=adsb2aprs_running()
    old=None

    if os.path.exists(
        ADSB2APRS_ACTIVE_CONFIG
    ):

        with open(
            ADSB2APRS_ACTIVE_CONFIG,
            "rb"
        ) as f:
            old=f.read()


    try:

        shutil.copy2(
            ADSB2APRS_CONFIG,
            ADSB2APRS_ACTIVE_CONFIG
        )


        if was_running:

            ok,error=adsb2aprs_ctl(
                "restart"
            )

            if not ok:
                raise RuntimeError(
                    error
                )


            time.sleep(1)


            if not adsb2aprs_running():

                p=subprocess.run(
                    [
                        "systemctl",
                        "show",
                        ADSB2APRS_SERVICE,
                        "-p",
                        "ExecMainStatus",
                        "--value"
                    ],
                    text=True,
                    capture_output=True
                )

                raise RuntimeError(
                    "adsb2aprs non rimane attivo; ExecMainStatus="
                    +p.stdout.strip()
                )


        return True,""


    except Exception as e:

        if old is not None:

            with open(
                ADSB2APRS_ACTIVE_CONFIG,
                "wb"
            ) as f:
                f.write(old)


            if was_running:

                adsb2aprs_ctl(
                    "restart"
                )


        return False,str(e)


@app.route(
    "/config/adsb2aprs",
    methods=["GET","POST"]
)
def config_adsb2aprs():

    cfg=load_adsb2aprs_config()


    if request.method=="POST":

        action=request.form.get(
            "action",
            "save"
        )


        if action in (
            "start",
            "stop",
            "restart"
        ):

            ok,error=adsb2aprs_ctl(
                action
            )

            flash(
                "ADSB2APRS_"+action.upper()+"_OK"
                if ok
                else
                "ADSB2APRS_ERROR: "+error
            )

            return redirect(
                "/config/adsb2aprs"
            )


        cfg=update_adsb2aprs_from_form(
            cfg
        )

        ok,error=adsb2aprs_validate(
            cfg
        )

        if not ok:

            flash(
                "ADSB2APRS_ERROR: "+error
            )

            return redirect(
                "/config/adsb2aprs"
            )


        adsb2aprs_write(
            ADSB2APRS_CONFIG,
            cfg
        )


        if action=="apply":

            ok,error=apply_adsb2aprs_config()

            flash(
                "ADSB2APRS_APPLY_OK"
                if ok
                else
                "ADSB2APRS_ERROR: "+error
            )

        else:

            flash(
                "ADSB2APRS_SAVE_OK"
            )


        return redirect(
            "/config/adsb2aprs"
        )


    active=load_adsb2aprs_active_config()


    return render_template(
        "config_adsb2aprs.html",

        DUMP=cfg.get(
            "dump1090",
            {}
        ),

        APRS=cfg.get(
            "aprs",
            {}
        ),

        POSITION=cfg.get(
            "position",
            {}
        ),

        DATABASE=cfg.get(
            "aircraft_database",
            {}
        ),

        LOGGING=cfg.get(
            "logging",
            {}
        ),

        running=adsb2aprs_running(),
        enabled=adsb2aprs_enabled(),

        command=adsb2aprs_build_command(
            cfg,
            load_config()
        ),

        active_command=adsb2aprs_build_command(
            active,
            load_active_config()
        ),

        journal=adsb2aprs_journal()
    )



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
