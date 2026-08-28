#!/usr/bin/env python3

import json
import os
import re
import signal
import socket
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone


BASE_DIR = "/opt/dxlaprs-manager"
DB_FILE = os.path.join(BASE_DIR, "data", "monitor.db")

SERVICE = "dxlaprs-udpgate.service"

running = True


# ============================================================
# DATABASE
# ============================================================

def get_db():

    conn = sqlite3.connect(
        DB_FILE,
        timeout=10
    )

    conn.execute(
        "PRAGMA journal_mode=WAL"
    )

    conn.execute(
        "PRAGMA synchronous=NORMAL"
    )

    return conn


def init_db():

    os.makedirs(
        os.path.dirname(DB_FILE),
        exist_ok=True
    )

    conn = get_db()

    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp);

        CREATE INDEX IF NOT EXISTS idx_events_type
        ON events(event_type);


        CREATE TABLE IF NOT EXISTS connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            connected_at TEXT NOT NULL,
            disconnected_at TEXT,

            ip TEXT,
            remote_port INTEGER,

            callsign TEXT,
            verified INTEGER DEFAULT 0,
            software TEXT,
            filter TEXT,

            tx_frames INTEGER,
            rx_frames INTEGER,
            tx_bytes INTEGER,
            rx_bytes INTEGER,

            uptime TEXT,

            active INTEGER DEFAULT 1
        );

        CREATE INDEX IF NOT EXISTS idx_connections_active
        ON connections(active);

        CREATE INDEX IF NOT EXISTS idx_connections_callsign
        ON connections(callsign);

        CREATE INDEX IF NOT EXISTS idx_connections_ip
        ON connections(ip);


        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT NOT NULL,

            receiver TEXT,
            source TEXT,

            packet TEXT NOT NULL,

            duplicate INTEGER DEFAULT 0,

            raw_verbose TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_packets_timestamp
        ON packets(timestamp);

        CREATE INDEX IF NOT EXISTS idx_packets_receiver
        ON packets(receiver);

        CREATE INDEX IF NOT EXISTS idx_packets_source
        ON packets(source);
        """
    )

    conn.commit()
    conn.close()


def reset_active_connections():

    """
    Il collector non può sapere se una connessione registrata
    prima del proprio avvio è ancora realmente attiva.

    All'avvio chiudiamo quindi tutte le vecchie sessioni.
    Le connessioni reali verranno ricreate dai nuovi eventi
    T:connect to: / logresp di udpgate4.
    """

    conn = get_db()

    conn.execute(
        """
        UPDATE connections
        SET
            active = 0,
            disconnected_at =
                COALESCE(
                    disconnected_at,
                    ?
                )
        WHERE active = 1
        """,
        (
            datetime.now(
                timezone.utc
            ).isoformat(),
        )
    )

    conn.commit()
    conn.close()



def split_socket_address(value):

    """
    Divide indirizzo:porta prodotto da ss.

    Gestisce IPv4 e, per quanto possibile, IPv6.
    """

    value = str(value).strip()

    if not value:
        return None, None


    # IPv6 tra parentesi quadre.
    m = re.match(
        r"^\[(.+)\]:(\d+)$",
        value
    )

    if m:

        return (
            m.group(1),
            int(m.group(2))
        )


    # IPv4 / hostname.
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


def current_udpgate_sockets():

    """
    Restituisce le connessioni TCP ESTABLISHED
    realmente appartenenti a udpgate4.

    Ogni elemento:
        {
            direction: in/out,
            ip: peer ip,
            remote_port: porta peer
        }
    """

    try:

        output = subprocess.check_output(
            [
                "ss",
                "-tnp"
            ],
            text=True,
            errors="replace",
            timeout=3
        )

    except Exception:

        return []


    result = []


    for line in output.splitlines():

        if "udpgate4" not in line:
            continue

        if "ESTAB" not in line:
            continue


        parts = line.split()

        if len(parts) < 5:
            continue


        local = parts[3]
        peer = parts[4]


        local_ip, local_port = split_socket_address(
            local
        )

        peer_ip, peer_port = split_socket_address(
            peer
        )


        if (
            local_port is None
            or peer_port is None
        ):
            continue


        # ----------------------------------------------------
        # INBOUND:
        # udpgate4 ascolta localmente sulla 14580.
        # ----------------------------------------------------

        if local_port == 14580:

            result.append(
                {
                    "direction": "in",
                    "ip": peer_ip,
                    "remote_port": peer_port
                }
            )

            continue


        # ----------------------------------------------------
        # OUTBOUND APRS-IS:
        # peer porta 14580.
        # ----------------------------------------------------

        if peer_port == 14580:

            result.append(
                {
                    "direction": "out",
                    "ip": peer_ip,
                    "remote_port": peer_port
                }
            )


    return result


def hostname_addresses(host, port):

    addresses = set()

    try:

        info = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM
        )

        for item in info:

            addr = item[4][0]

            if addr:
                addresses.add(
                    addr
                )

    except Exception:
        pass


    return addresses


def connection_matches_socket(row, sock):

    if row["direction"] != sock["direction"]:
        return False


    # --------------------------------------------------------
    # INBOUND
    # --------------------------------------------------------

    if row["direction"] == "in":

        return (
            row["ip"] == sock["ip"]
            and int(
                row["remote_port"] or 0
            ) == int(
                sock["remote_port"] or 0
            )
        )


    # --------------------------------------------------------
    # OUTBOUND APRS-IS
    #
    # Nel DB possiamo avere:
    #     example.aprs.server
    #
    # mentre ss mostra:
    #     44.31.102.59
    # --------------------------------------------------------

    db_host = row["ip"]
    db_port = int(
        row["remote_port"] or 0
    )

    socket_ip = sock["ip"]
    socket_port = int(
        sock["remote_port"] or 0
    )


    if db_port != socket_port:
        return False


    if db_host == socket_ip:
        return True


    return (
        socket_ip
        in hostname_addresses(
            db_host,
            db_port
        )
    )


def reconcile_active_connections():

    """
    Riallinea monitor.db con i socket TCP REALI di udpgate4.

    Principi:

    - il kernel stabilisce se una sessione è realmente attiva;
    - le righe esistenti vengono riutilizzate quando possibile;
    - un socket reale senza riga DB viene creato;
    - un client nuovo privo di logresp eredita temporaneamente
      callsign/software/filter dall'ultima sessione dello stesso IP;
    - APRS-IS viene riconosciuto confrontando il socket reale
      con gli host configurati nell'opzione -g;
    - il successivo logresp rimane comunque autoritativo.
    """

    sockets = current_udpgate_sockets()

    conn = get_db()
    conn.row_factory = sqlite3.Row

    now = datetime.now(
        timezone.utc
    ).isoformat()


    # --------------------------------------------------------
    # COLONNE REALMENTE DISPONIBILI
    # --------------------------------------------------------

    columns = {
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(connections)"
        ).fetchall()
    }


    # --------------------------------------------------------
    # TARGET APRS-IS CONFIGURATI
    # --------------------------------------------------------

    aprsis_targets = []

    try:

        with open(
            "/opt/dxlaprs-manager/data/active_config.json",
            "r",
            encoding="utf-8"
        ) as f:

            cfg = json.load(f)

        values = (
            cfg
            .get("udpgate4_options", {})
            .get("-g", {})
            .get("values", [])
        )

        for value in values:

            value = str(value).strip()

            if not value:
                continue

            # Modalità file: non abbiamo qui un singolo
            # host da associare.
            if value.startswith(":"):
                continue

            hostport = value.split(
                "#",
                1
            )[0]

            try:

                host, port_text = hostport.rsplit(
                    ":",
                    1
                )

                port = int(
                    port_text
                )

            except Exception:
                continue

            host = host.strip()

            addresses = hostname_addresses(
                host,
                port
            )

            # Anche un IP configurato direttamente deve
            # essere considerato valido.
            addresses.add(
                host
            )

            aprsis_targets.append(
                {
                    "host": host,
                    "port": port,
                    "addresses": addresses
                }
            )

    except Exception:
        aprsis_targets = []


    def aprsis_name_for_socket(sock):

        if sock["direction"] != "out":
            return None

        for target in aprsis_targets:

            if int(
                target["port"]
            ) != int(
                sock["remote_port"]
            ):
                continue

            if sock["ip"] in target["addresses"]:

                return target["host"]

        return None


    # --------------------------------------------------------
    # RIGHE STORICHE
    # --------------------------------------------------------

    rows = conn.execute(
        """
        SELECT *
        FROM connections
        ORDER BY id DESC
        """
    ).fetchall()


    def historical_client(ip, exclude_id=None):

        """
        Ultima identità conosciuta per lo stesso IP.
        """

        for old in rows:

            if (
                old["direction"] != "in"
                or old["ip"] != ip
            ):
                continue

            if (
                exclude_id is not None
                and old["id"] == exclude_id
            ):
                continue

            callsign = (
                old["callsign"]
                if "callsign" in old.keys()
                else None
            )

            if not callsign:
                continue

            if str(callsign).upper() == "DXLMON":
                continue

            return old

        return None


    def historical_aprsis(
        host,
        port,
        socket_ip=None,
        exclude_id=None
    ):

        for old in rows:

            if old["direction"] != "out":
                continue

            if (
                exclude_id is not None
                and old["id"] == exclude_id
            ):
                continue

            if int(
                old["remote_port"] or 0
            ) != int(port):
                continue

            old_host = old["ip"]

            if old_host == host:
                return old

            if socket_ip:

                if old_host == socket_ip:
                    return old

                if socket_ip in hostname_addresses(
                    old_host,
                    port
                ):
                    return old

        return None


    def inherit_metadata(
        row_id,
        template
    ):

        if template is None:
            return

        assignments = []
        params = []

        for field in (
            "callsign",
            "verified",
            "software",
            "filter",
            "tcp_tx_frame_offset",
            "tcp_rx_frame_offset"
        ):

            if field not in columns:
                continue

            try:
                value = template[field]
            except Exception:
                continue

            if value is None:
                continue

            assignments.append(
                f"{field} = COALESCE({field}, ?)"
            )

            params.append(
                value
            )

        if not assignments:
            return

        params.append(
            row_id
        )

        conn.execute(
            f"""
            UPDATE connections
            SET {", ".join(assignments)}
            WHERE id = ?
            """,
            tuple(params)
        )


    def insert_socket(
        sock,
        template=None
    ):

        direction = sock["direction"]

        if direction == "out":

            canonical_host = aprsis_name_for_socket(
                sock
            )

            db_ip = (
                canonical_host
                or sock["ip"]
            )

            local_port = None

        else:

            db_ip = sock["ip"]
            local_port = 14580


        data = {
            "connected_at": now,
            "disconnected_at": None,
            "ip": db_ip,
            "remote_port": sock["remote_port"],
            "callsign": None,
            "verified": 0,
            "software": None,
            "filter": None,
            "active": 1,
            "direction": direction,
            "local_port": local_port
        }


        # Recupero dell'identità storica.
        if template is not None:

            for field in (
                "callsign",
                "verified",
                "software",
                "filter",
                "tcp_tx_frame_offset",
                "tcp_rx_frame_offset"
            ):

                if field not in columns:
                    continue

                try:
                    value = template[field]
                except Exception:
                    continue

                if value is not None:
                    data[field] = value


        # Campi live di una sessione appena ricostruita.
        defaults = {
            "rx_frames_live": 0,
            "rx_bytes_live": 0,
            "rx_bps_live": 0.0,
            "last_rx_at": None,
            "rx_window_bytes": 0,
            "rx_window_start": None
        }

        for field, value in defaults.items():

            if field in columns:
                data[field] = value


        usable = {
            key: value
            for key, value in data.items()
            if key in columns
        }

        names = list(
            usable.keys()
        )

        placeholders = ",".join(
            "?"
            for _ in names
        )

        cur = conn.execute(
            f"""
            INSERT INTO connections (
                {", ".join(names)}
            )
            VALUES (
                {placeholders}
            )
            """,
            tuple(
                usable[name]
                for name in names
            )
        )

        return cur.lastrowid


    matched_ids = set()
    matched_sockets = set()


    # --------------------------------------------------------
    # 1. ABBINO LE RIGHE ESISTENTI AI SOCKET REALI
    # --------------------------------------------------------

    for row in rows:

        for idx, sock in enumerate(
            sockets
        ):

            if idx in matched_sockets:
                continue

            if not connection_matches_socket(
                row,
                sock
            ):
                continue


            conn.execute(
                """
                UPDATE connections
                SET
                    active = 1,
                    disconnected_at = NULL
                WHERE id = ?
                """,
                (
                    row["id"],
                )
            )


            # Una connessione inbound può essere stata creata
            # prima che arrivasse il logresp.
            if (
                row["direction"] == "in"
                and not row["callsign"]
            ):

                template = historical_client(
                    row["ip"],
                    exclude_id=row["id"]
                )

                inherit_metadata(
                    row["id"],
                    template
                )


            # Anche una riga outbound molto vecchia può avere
            # hostname/IP non normalizzato.
            if row["direction"] == "out":

                canonical = aprsis_name_for_socket(
                    sock
                )

                if canonical:

                    conn.execute(
                        """
                        UPDATE connections
                        SET ip = ?
                        WHERE id = ?
                        """,
                        (
                            canonical,
                            row["id"]
                        )
                    )


            matched_ids.add(
                row["id"]
            )

            matched_sockets.add(
                idx
            )

            break


    # --------------------------------------------------------
    # 2. CREO LE SESSIONI REALI CHE NON ESISTONO NEL DB
    # --------------------------------------------------------

    for idx, sock in enumerate(
        sockets
    ):

        if idx in matched_sockets:
            continue


        if sock["direction"] == "in":

            template = historical_client(
                sock["ip"]
            )

        else:

            host = aprsis_name_for_socket(
                sock
            )

            template = historical_aprsis(
                host or sock["ip"],
                sock["remote_port"],
                socket_ip=sock["ip"]
            )


        new_id = insert_socket(
            sock,
            template
        )

        matched_ids.add(
            new_id
        )

        matched_sockets.add(
            idx
        )


    # --------------------------------------------------------
    # 3. CHIUDO SOLO CIÒ CHE NON HA PIÙ UN SOCKET REALE
    # --------------------------------------------------------

    conn.execute(
        """
        UPDATE connections
        SET
            active = 0,
            disconnected_at =
                COALESCE(
                    disconnected_at,
                    ?
                )
        WHERE active = 1
        """,
        (
            now,
        )
    )


    if matched_ids:

        placeholders = ",".join(
            "?"
            for _ in matched_ids
        )

        conn.execute(
            f"""
            UPDATE connections
            SET
                active = 1,
                disconnected_at = NULL
            WHERE id IN (
                {placeholders}
            )
            """,
            tuple(
                matched_ids
            )
        )


    conn.commit()
    conn.close()


# ============================================================
# UTILITY
# ============================================================

def iso_timestamp(us):

    try:

        dt = datetime.fromtimestamp(
            int(us) / 1_000_000,
            tz=timezone.utc
        )

    except Exception:

        dt = datetime.now(
            timezone.utc
        )

    return dt.isoformat()


def save_event(
    conn,
    timestamp,
    event_type,
    message
):

    conn.execute(
        """
        INSERT INTO events (
            timestamp,
            event_type,
            message
        )
        VALUES (?, ?, ?)
        """,
        (
            timestamp,
            event_type,
            message
        )
    )


# ============================================================
# CONNECTION PARSING
# ============================================================

RE_CONNECT = re.compile(
    r"^T:connect to:\s+"
    r"(\S+)\s+"
    r"(\d+)\s*$"
)


RE_LOGRESP_CLIENT = re.compile(
    r"^# logresp\s+"
    r"(\S+)\s+"
    r"(verified|unverified|server)"
    r"(?:,\s*server\s+\S+|\s+\S+)?"
    r"(?:\s+filter\s+(.+?))?"
    r"(?:\s+vers:\s*(.+))?$",
    re.I
)



RE_CLOSE = re.compile(
    r"^T:connection closed\s+"
    r"(\S+)"
    r"(?:\s+t=(\S+))?"
    r"(?:\s+txf=(\d+))?"
    r"(?:\s+rxf=(\d+))?"
    r"(?:\s+txB=(\d+))?"
    r"(?:\s+rxB=(\d+))?"
)


def connection_open(
    conn,
    timestamp,
    ip,
    port
):

    # --------------------------------------------------------
    # T:connect to: viene usato sia per:
    #
    # - client TCP in ingresso
    # - connessione APRS-IS in uscita
    #
    # Le connessioni APRS-IS configurate con -g hanno
    # normalmente porta destinazione 14580 e hostname/server.
    # I client LAN arrivano invece con una porta sorgente
    # effimera.
    # --------------------------------------------------------

    direction = "in"
    local_port = 14580

    active_cfg = "/opt/dxlaprs-manager/data/active_config.json"

    aprsis_targets = set()

    try:

        with open(
            active_cfg,
            "r",
            encoding="utf-8"
        ) as f:

            cfg = json.load(f)

        g = (
            cfg
            .get("udpgate4_options", {})
            .get("-g", {})
            .get("values", [])
        )

        for value in g:

            value = str(value)

            if value.startswith(":"):
                continue

            hostport = value.split("#", 1)[0]

            host = hostport.rsplit(":", 1)[0]

            if host:
                aprsis_targets.add(
                    host.lower()
                )

    except Exception:
        pass


    if ip.lower() in aprsis_targets:

        direction = "out"
        local_port = None


    conn.execute(
        """
        INSERT INTO connections (
            connected_at,
            ip,
            remote_port,
            local_port,
            direction,
            active
        )
        VALUES (?, ?, ?, ?, ?, 1)
        """,
        (
            timestamp,
            ip,
            int(port),
            local_port,
            direction
        )
    )


def latest_unidentified_connection(conn):

    return conn.execute(
        """
        SELECT id
        FROM connections
        WHERE active = 1
          AND callsign IS NULL
          AND direction = 'in'
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()


def connection_login(
    conn,
    callsign,
    state,
    filt,
    software
):

    row = latest_unidentified_connection(
        conn
    )

    if not row:
        return

    conn.execute(
        """
        UPDATE connections

        SET
            callsign = ?,
            verified = ?,
            filter = ?,
            software = ?

        WHERE id = ?
        """,
        (
            callsign,
            1 if state.lower() == "verified" else 0,
            filt,
            software,
            row[0]
        )
    )


def connection_close(
    conn,
    timestamp,
    ip,
    uptime,
    txf,
    rxf,
    txb,
    rxb
):

    row = conn.execute(
        """
        SELECT id
        FROM connections

        WHERE active = 1
          AND ip = ?

        ORDER BY id DESC
        LIMIT 1
        """,
        (ip,)
    ).fetchone()

    if not row:
        return

    conn.execute(
        """
        UPDATE connections

        SET
            disconnected_at = ?,
            active = 0,
            uptime = ?,
            tx_frames = ?,
            rx_frames = ?,
            tx_bytes = ?,
            rx_bytes = ?

        WHERE id = ?
        """,
        (
            timestamp,
            uptime,
            int(txf) if txf else None,
            int(rxf) if rxf else None,
            int(txb) if txb else None,
            int(rxb) if rxb else None,
            row[0]
        )
    )


# ============================================================
# PACKET PARSING
# ============================================================

def extract_source(packet):

    m = re.match(
        r"^([A-Z0-9]{1,10}(?:-[0-9]{1,2})?)>",
        packet,
        re.I
    )

    if not m:
        return None

    return m.group(1).upper()


def parse_verbose_packet(line):

    if not line.startswith("S:"):
        return None

    body = line[2:]

    duplicate = 0
    receiver = None


    # ========================================================
    # DUPLICATO SENZA PREFISSO RICEVITORE
    #
    # udpgate4 può produrre anche:
    #
    #     S:dup:CALL>...
    #
    # In questo caso "dup" NON è un callsign.
    # Il ricevitore verrà eventualmente ricavato più avanti
    # dal qAx contenuto nel pacchetto.
    # ========================================================

    if body.startswith("dup:"):

        duplicate = 1
        body = body[4:]


    # ========================================================
    # 1. EVENTUALE PREFISSO RICEVITORE TCP
    #
    # Esempi:
    #
    # CALL1-12: 47>S55YNA-12>...
    # CALL2-10:134>S55YZA-10>...
    # CALL2-10:dup:S55YNA-12>...
    # ========================================================

    m = re.match(
        r"^([A-Z0-9]{1,10}(?:-[0-9]{1,2})?):(.*)$",
        body,
        re.I
    )

    if m:

        receiver = m.group(1).upper()
        body = m.group(2)


        # ----------------------------------------------------
        # DUPLICATO
        # ----------------------------------------------------

        if body.startswith("dup:"):

            duplicate = 1
            body = body[4:]


    # ========================================================
    # 2. RIMUOVO CONTATORE DIAGNOSTICO UDPGATE
    #
    # Esempi:
    #
    # " 47>S55YNA-12>..."
    # "134>S55YZA-10>..."
    # " 44>IV3IHD-10>..."
    #
    # Quel numero NON appartiene al pacchetto APRS.
    # ========================================================

    body = re.sub(
        r"^\s*\d+\s*>",
        "",
        body,
        count=1
    )


    # ========================================================
    # 3. TROVO L'INIZIO REALE DEL PACCHETTO APRS
    # ========================================================

    m = re.search(
        r"([A-Z0-9]{1,10}(?:-[0-9]{1,2})?"
        r">[A-Z0-9][^:\s]*:.*)$",
        body,
        re.I
    )

    if not m:
        return None


    packet = m.group(1).strip()


    # ========================================================
    # 4. <0D>/<0A> SONO RAPPRESENTAZIONI VERBOSE DEI CR/LF
    #    E NON FANNO PARTE DEL PACCHETTO APRS.
    # ========================================================

    packet = re.sub(
        r"(?:<0D>|<0A>)+$",
        "",
        packet,
        flags=re.I
    )


    # ========================================================
    # 5. SOURCE = CALL PRIMA DEL PRIMO ">"
    # ========================================================

    source = extract_source(
        packet
    )


    # ========================================================
    # 6. SE IL PREFISSO NON INDICAVA IL RICEVITORE,
    #    LO RICAVIAMO DAL qAx DEL PACCHETTO.
    #
    # Esempio:
    #
    # IV3IHD-10>...,qAR,CALL1-12:...
    #                         ^^^^^^^^
    # ========================================================

    if receiver is None:

        q = re.search(
            r",qA[A-Z],"
            r"([A-Z0-9]{1,10}(?:-[0-9]{1,2})?)"
            r"(?=[:,])",
            packet,
            re.I
        )

        if q:
            receiver = q.group(1).upper()


    return {
        "receiver": receiver,
        "source": source,
        "packet": packet,
        "duplicate": duplicate
    }



def update_connection_rx(
    conn,
    timestamp,
    receiver,
    packet
):

    if not receiver:
        return

    row = conn.execute(
        """
        SELECT
            id,
            rx_frames_live,
            rx_bytes_live,
            rx_window_bytes,
            rx_window_start

        FROM connections

        WHERE active = 1
          AND direction = 'in'
          AND callsign = ?

        ORDER BY id DESC
        LIMIT 1
        """,
        (
            receiver,
        )
    ).fetchone()

    if not row:
        return


    conn_id = row[0]

    rx_frames = int(
        row[1] or 0
    )

    rx_bytes = int(
        row[2] or 0
    )

    window_bytes = int(
        row[3] or 0
    )

    window_start = row[4]


    packet_bytes = len(
        packet.encode(
            "utf-8",
            errors="replace"
        )
    )


    rx_frames += 1
    rx_bytes += packet_bytes
    window_bytes += packet_bytes


    now_dt = datetime.fromisoformat(
        timestamp
    )

    if window_start:

        try:
            start_dt = datetime.fromisoformat(
                window_start
            )

        except Exception:
            start_dt = now_dt

    else:
        start_dt = now_dt


    elapsed = (
        now_dt -
        start_dt
    ).total_seconds()


    # Finestra di circa 10 secondi.
    #
    # Se sono passati almeno 10 secondi,
    # calcoliamo il rate e ripartiamo.
    if elapsed >= 10:

        rx_bps = (
            window_bytes * 8.0
        ) / elapsed

        window_bytes = 0
        window_start = timestamp

    else:

        # Manteniamo l'ultimo valore.
        old = conn.execute(
            """
            SELECT rx_bps_live
            FROM connections
            WHERE id = ?
            """,
            (
                conn_id,
            )
        ).fetchone()

        rx_bps = float(
            old[0] or 0
        ) if old else 0


    conn.execute(
        """
        UPDATE connections

        SET
            rx_frames_live = ?,
            rx_bytes_live = ?,
            rx_bps_live = ?,
            last_rx_at = ?,
            rx_window_bytes = ?,
            rx_window_start = ?

        WHERE id = ?
        """,
        (
            rx_frames,
            rx_bytes,
            rx_bps,
            timestamp,
            window_bytes,
            window_start,
            conn_id
        )
    )



def save_packet(
    conn,
    timestamp,
    line
):

    parsed = parse_verbose_packet(
        line
    )

    if not parsed:
        return False


    conn.execute(
        """
        INSERT INTO packets (
            timestamp,
            receiver,
            source,
            packet,
            duplicate,
            raw_verbose
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            timestamp,
            parsed["receiver"],
            parsed["source"],
            parsed["packet"],
            parsed["duplicate"],
            line
        )
    )


    # --------------------------------------------------------
    # METRICHE RX DEL CLIENT
    #
    # Contiamo solo i frame effettivamente ricevuti
    # dal client TCP.
    #
    # I duplicati vengono comunque ricevuti dal client
    # e quindi contano come RX Frames/Bytes.
    # --------------------------------------------------------

    update_connection_rx(
        conn,
        timestamp,
        parsed["receiver"],
        parsed["packet"]
    )

    return True


# ============================================================
# PROCESS LINE
# ============================================================


def update_aprsis_rx(
    conn,
    timestamp,
    message
):

    """
    Aggiorna RX Frames / Bytes / bit/s della connessione
    APRS-IS outbound usando i frame verbose G:.

    NON conta G:flt:, che sono righe di stato/keepalive.
    """

    if not message.startswith("G:"):
        return False

    if message.startswith("G:flt:"):
        return False


    # --------------------------------------------------------
    # Formati osservati:
    #
    # G: 66>S59DEM-11>...
    # G:128>IQ3FL-10>...
    # G:  0>CALL3-7>...
    #
    # Il numero iniziale è diagnostico di udpgate4 e NON
    # appartiene al pacchetto APRS.
    # --------------------------------------------------------

    body = message[2:]

    body = re.sub(
        r"^\s*\d+\s*>",
        "",
        body,
        count=1
    )

    body = re.sub(
        r"(?:<0D>|<0A>)+$",
        "",
        body,
        flags=re.I
    )

    packet = body.strip()

    if not packet:
        return False


    # --------------------------------------------------------
    # Trova la connessione APRS-IS attiva.
    # --------------------------------------------------------

    row = conn.execute(
        """
        SELECT
            id,
            rx_frames_live,
            rx_bytes_live,
            rx_bps_live,
            rx_window_bytes,
            rx_window_start

        FROM connections

        WHERE active = 1
          AND direction = 'out'

        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()

    if not row:
        return False


    conn_id = row[0]

    rx_frames = int(
        row[1] or 0
    )

    rx_bytes = int(
        row[2] or 0
    )

    old_bps = float(
        row[3] or 0
    )

    window_bytes = int(
        row[4] or 0
    )

    window_start = row[5]


    packet_bytes = len(
        packet.encode(
            "utf-8",
            errors="replace"
        )
    )


    rx_frames += 1
    rx_bytes += packet_bytes
    window_bytes += packet_bytes


    now_dt = datetime.fromisoformat(
        timestamp
    )


    if window_start:

        try:

            start_dt = datetime.fromisoformat(
                window_start
            )

        except Exception:

            start_dt = now_dt

    else:

        start_dt = now_dt


    elapsed = (
        now_dt -
        start_dt
    ).total_seconds()


    # --------------------------------------------------------
    # Rate su finestra di almeno 10 secondi.
    # --------------------------------------------------------

    if elapsed >= 10:

        rx_bps = (
            window_bytes * 8.0
        ) / elapsed

        window_bytes = 0
        window_start = timestamp

    else:

        rx_bps = old_bps


    conn.execute(
        """
        UPDATE connections

        SET
            rx_frames_live = ?,
            rx_bytes_live = ?,
            rx_bps_live = ?,
            last_rx_at = ?,
            rx_window_bytes = ?,
            rx_window_start = ?

        WHERE id = ?
        """,
        (
            rx_frames,
            rx_bytes,
            rx_bps,
            timestamp,
            window_bytes,
            window_start,
            conn_id
        )
    )


    return True



def process_line(
    conn,
    timestamp,
    message
):

    event_type = "other"


    # --------------------------------------------------------
    # TCP CONNECT
    # --------------------------------------------------------

    m = RE_CONNECT.match(
        message
    )

    if m:

        ip, port = m.groups()

        connection_open(
            conn,
            timestamp,
            ip,
            port
        )

        event_type = "connect"


    # --------------------------------------------------------
    # LOGIN CLIENT
    # --------------------------------------------------------

    else:

        m = RE_LOGRESP_CLIENT.match(
            message
        )

        if m:

            callsign, state, filt, software = (
                m.groups()
            )

            connection_login(
                conn,
                callsign,
                state,
                filt,
                software
            )

            event_type = "login"


        else:

            # ------------------------------------------------
            # CLOSE
            # ------------------------------------------------

            m = RE_CLOSE.match(
                message
            )

            if m:

                (
                    ip,
                    uptime,
                    txf,
                    rxf,
                    txb,
                    rxb
                ) = m.groups()

                connection_close(
                    conn,
                    timestamp,
                    ip,
                    uptime,
                    txf,
                    rxf,
                    txb,
                    rxb
                )

                event_type = "disconnect"


            # ------------------------------------------------
            # APRS-IS RX PACKET
            # ------------------------------------------------

            elif update_aprsis_rx(
                conn,
                timestamp,
                message
            ):

                event_type = "aprsis_packet"


            # ------------------------------------------------
            # PACKET DA CLIENT TCP
            # ------------------------------------------------

            elif save_packet(
                conn,
                timestamp,
                message
            ):

                event_type = "packet"


            # ------------------------------------------------
            # APRS-IS KEEPALIVE / STATUS
            # ------------------------------------------------

            elif message.startswith(
                "G:flt:"
            ):

                event_type = "aprsis"


            elif message.startswith(
                "cant bind"
            ):

                event_type = "bind"


    save_event(
        conn,
        timestamp,
        event_type,
        message
    )


# ============================================================
# JOURNAL FOLLOW
# ============================================================

def follow_journal():

    global running


    cmd = [
        "journalctl",

        "-u",
        SERVICE,

        "-f",

        "-n",
        "0",

        "-o",
        "json",

        "--no-pager"
    ]


    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1
    )


    conn = get_db()


    try:

        for raw in process.stdout:

            if not running:
                break


            raw = raw.strip()

            if not raw:
                continue


            try:

                item = json.loads(
                    raw
                )

            except json.JSONDecodeError:
                continue


            message = item.get(
                "MESSAGE",
                ""
            )


            if not isinstance(
                message,
                str
            ):
                continue


            timestamp = iso_timestamp(
                item.get(
                    "__REALTIME_TIMESTAMP",
                    0
                )
            )


            try:

                process_line(
                    conn,
                    timestamp,
                    message
                )

                conn.commit()


            except Exception as exc:

                conn.rollback()

                print(
                    "collector parse error:",
                    repr(exc),
                    "line:",
                    message,
                    file=sys.stderr,
                    flush=True
                )


    finally:

        try:
            process.terminate()
        except Exception:
            pass

        conn.close()


# ============================================================
# SIGNALS
# ============================================================

def stop_handler(signum, frame):

    global running
    running = False


signal.signal(
    signal.SIGTERM,
    stop_handler
)

signal.signal(
    signal.SIGINT,
    stop_handler
)


# ============================================================
# MAIN
# ============================================================

def main():

    init_db()

    # Riallinea il database con le connessioni TCP
    # realmente esistenti di udpgate4.
    reconcile_active_connections()

    print(
        "DxlAprs native collector started",
        flush=True
    )

    follow_journal()


if __name__ == "__main__":
    main()
