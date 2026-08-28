#!/usr/bin/env python3

import re
import sqlite3
import json
from datetime import datetime, timezone, timedelta
import urllib.request
from html.parser import HTMLParser


UDPGATE_BASE = "http://127.0.0.1:14501"


class MhParser(HTMLParser):

    def __init__(self):
        super().__init__(convert_charrefs=True)

        self.tables = []

        self.in_table = False
        self.in_row = False
        self.in_cell = False

        self.current_table = None
        self.current_row = None
        self.current_cell = None


    def handle_starttag(self, tag, attrs):

        tag = tag.lower()
        attrs = dict(attrs)

        if tag == "table" and attrs.get("id") == "mheard":

            self.in_table = True

            self.current_table = {
                "rows": []
            }

            return


        if not self.in_table:
            return


        if tag == "tr":

            self.in_row = True
            self.current_row = []

            return


        if tag in ("td", "th") and self.in_row:

            self.in_cell = True

            style = attrs.get("style", "")

            icon = ""

            m = re.search(
                r'background-image\s*:\s*url\(([^)]+)\)',
                style,
                re.I
            )

            if m:
                icon = m.group(1).strip(
                    '"\' '
                )

            self.current_cell = {
                "tag": tag,
                "text": [],
                "icon": icon
            }


    def handle_data(self, data):

        if self.in_cell and self.current_cell is not None:
            self.current_cell["text"].append(data)


    def handle_endtag(self, tag):

        tag = tag.lower()

        if not self.in_table:
            return


        if tag in ("td", "th") and self.in_cell:

            text = "".join(
                self.current_cell["text"]
            )

            text = " ".join(
                text.replace("\xa0", " ").split()
            )

            self.current_cell["text"] = text

            self.current_row.append(
                self.current_cell
            )

            self.current_cell = None
            self.in_cell = False

            return


        if tag == "tr" and self.in_row:

            if self.current_row:
                self.current_table["rows"].append(
                    self.current_row
                )

            self.current_row = None
            self.in_row = False

            return


        if tag == "table":

            if self.current_table is not None:

                self.tables.append(
                    self.current_table
                )

            self.current_table = None
            self.in_table = False


def _download(path):

    url = UDPGATE_BASE + path

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent":
                "DxlAprs-Manager/0.5"
        }
    )

    with urllib.request.urlopen(
        req,
        timeout=3
    ) as response:

        return response.read()


def _cell_text(row, index):

    if index >= len(row):
        return ""

    return row[index].get(
        "text",
        ""
    )


def _cell_icon(row, index):

    if index >= len(row):
        return ""

    icon = row[index].get(
        "icon",
        ""
    )

    if not icon:
        return ""

    # udpgate restituisce per esempio icon/262.gif
    name = icon.rsplit("/", 1)[-1]

    if not re.fullmatch(
        r'[0-9]+\.gif',
        name,
        re.I
    ):
        return ""

    return name


def _table_title(table):

    rows = table.get(
        "rows",
        []
    )

    if not rows:
        return ""

    return _cell_text(
        rows[0],
        0
    )


def _data_rows(table):

    rows = table.get(
        "rows",
        []
    )

    if len(rows) <= 2:
        return []

    return rows[2:]


def _count_from_title(title):

    m = re.match(
        r'\s*(\d+)',
        title
    )

    if not m:
        return 0

    return int(
        m.group(1)
    )


def fetch_heard():

    """
    Heard nativo del DxlAprs Manager.

    Non legge più /mh dalla vecchia interfaccia web
    di udpgate4.

    Sorgenti:
        connections -> client TCP attivi
        packets     -> stazioni APRS ricevute / objects
    """

    db_file = (
        "/opt/dxlaprs-manager/"
        "data/monitor.db"
    )

    result = {
        "ok": True,

        "radio": {
            "count": 0,
            "title": "Heard Stations",
            "rows": []
        },

        "tcp": {
            "count": 0,
            "title": "Via TCP Connected Stations",
            "rows": []
        },

        "objects": {
            "count": 0,
            "title": "Heard Objects",
            "rows": []
        }
    }


    # --------------------------------------------------------
    # UTILITY
    # --------------------------------------------------------

    def parse_dt(value):

        if not value:
            return None

        try:

            dt = datetime.fromisoformat(
                value
            )

            if dt.tzinfo is None:

                dt = dt.replace(
                    tzinfo=timezone.utc
                )

            return dt.astimezone(
                timezone.utc
            )

        except Exception:
            return None


    def ago(value):

        dt = parse_dt(
            value
        )

        if dt is None:
            return "—"

        seconds = max(
            0,
            int(
                (
                    datetime.now(
                        timezone.utc
                    ) - dt
                ).total_seconds()
            )
        )

        if seconds < 60:
            return f"{seconds}s"

        minutes = seconds // 60

        if minutes < 60:
            return f"{minutes}m"

        hours = minutes // 60

        if hours < 24:
            return f"{hours}h"

        days = hours // 24

        return f"{days}d"


    def packet_path(packet):

        if not packet:
            return "—"

        try:

            header = packet.split(
                ":",
                1
            )[0]

            if ">" not in header:
                return "—"

            right = header.split(
                ">",
                1
            )[1]

            parts = right.split(",")

            # Il primo elemento è la destination APRS.
            path = parts[1:]

            clean = []

            skip_next = False

            for part in path:

                if skip_next:

                    skip_next = False
                    continue

                upper = part.upper()

                if upper.startswith(
                    (
                        "QAR",
                        "QAO",
                        "QAC",
                        "QAS",
                        "QAI",
                        "QAX"
                    )
                ):

                    skip_next = True
                    continue

                clean.append(
                    part
                )

            return (
                ",".join(clean)
                if clean
                else "direct"
            )

        except Exception:
            return "—"


    def object_name(packet):

        if not packet or ":" not in packet:
            return None

        info = packet.split(
            ":",
            1
        )[1]

        # APRS Object:
        # ;OBJECTNAM*...
        if not info.startswith(";"):
            return None

        if len(info) < 10:
            return None

        name = info[1:10].strip()

        return name or None


    # --------------------------------------------------------
    # HEARD WINDOW
    #
    # Usa -H della configurazione attiva.
    # Default = 10080 minuti = 168 ore.
    # --------------------------------------------------------

    heard_minutes = 10080

    try:

        with open(
            "/opt/dxlaprs-manager/"
            "data/active_config.json",
            "r",
            encoding="utf-8"
        ) as f:

            cfg = json.load(f)

        value = (
            cfg
            .get("udpgate4_options", {})
            .get("-H", {})
            .get("value")
        )

        if value is not None:

            heard_minutes = max(
                1,
                int(value)
            )

    except Exception:
        pass


    cutoff = (
        datetime.now(
            timezone.utc
        )
        -
        timedelta(
            minutes=heard_minutes
        )
    ).isoformat()


    try:

        conn = sqlite3.connect(
            db_file,
            timeout=3
        )

        conn.row_factory = sqlite3.Row


        # ====================================================
        # 1. CLIENT TCP ATTUALMENTE CONNESSI
        # ====================================================

        tcp_rows = conn.execute(
            """
            SELECT
                callsign,
                ip,
                remote_port,
                software,
                filter,
                connected_at,
                last_rx_at,
                rx_frames_live,
                rx_bytes_live

            FROM connections

            WHERE active = 1
              AND direction = 'in'
              AND callsign IS NOT NULL
              AND callsign != ''
              AND UPPER(callsign) != 'DXLMON'

            ORDER BY
                callsign COLLATE NOCASE
            """
        ).fetchall()


        for row in tcp_rows:

            last_seen = (
                row["last_rx_at"]
                or row["connected_at"]
            )

            software = (
                row["software"]
                or "—"
            )

            filt = (
                row["filter"]
                or ""
            )

            if filt:

                data = (
                    f"{software} · "
                    f"filter {filt}"
                )

            else:

                data = software


            endpoint = (
                row["ip"]
                or "—"
            )

            if row["remote_port"]:

                endpoint += (
                    ":"
                    + str(
                        row["remote_port"]
                    )
                )


            result["tcp"]["rows"].append(
                {
                    "call":
                        row["callsign"],

                    "icon":
                        "",

                    "overlay":
                        "—",

                    "ago":
                        ago(last_seen),

                    "position":
                        "—",

                    "pack":
                        int(
                            row["rx_frames_live"]
                            or 0
                        ),

                    "junk":
                        "0",

                    "qrb":
                        "—",

                    "alt":
                        "—",

                    "data":
                        data,

                    "path":
                        endpoint
                }
            )


        result["tcp"]["count"] = len(
            result["tcp"]["rows"]
        )


        # ====================================================
        # 2. STAZIONI APRS OSSERVATE
        # ====================================================

        heard = conn.execute(
            """
            SELECT
                source,
                COUNT(*) AS packets,
                SUM(
                    CASE
                        WHEN duplicate = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS duplicates,
                MAX(timestamp) AS last_seen

            FROM packets

            WHERE source IS NOT NULL
              AND source != ''
              AND timestamp >= ?

            GROUP BY source

            ORDER BY
                last_seen DESC,
                source COLLATE NOCASE
            """,
            (
                cutoff,
            )
        ).fetchall()


        for station in heard:

            latest = conn.execute(
                """
                SELECT
                    timestamp,
                    receiver,
                    packet,
                    duplicate

                FROM packets

                WHERE source = ?

                ORDER BY id DESC
                LIMIT 1
                """,
                (
                    station["source"],
                )
            ).fetchone()


            if not latest:
                continue


            # Gli APRS Objects vengono presentati nella
            # sezione dedicata e non duplicati qui.
            obj = object_name(
                latest["packet"]
            )

            if obj:
                continue


            receiver = (
                latest["receiver"]
                or "—"
            )


            result["radio"]["rows"].append(
                {
                    "call":
                        station["source"],

                    "icon":
                        "",

                    "overlay":
                        "—",

                    "ago":
                        ago(
                            station["last_seen"]
                        ),

                    "pack":
                        int(
                            station["packets"]
                            or 0
                        ),

                    "junk":
                        int(
                            station["duplicates"]
                            or 0
                        ),

                    "qrb":
                        "—",

                    "az":
                        "—",

                    "alt":
                        "—",

                    "data":
                        "via " + receiver,

                    "path":
                        packet_path(
                            latest["packet"]
                        )
                }
            )


        result["radio"]["count"] = len(
            result["radio"]["rows"]
        )


        # ====================================================
        # 3. APRS OBJECTS
        # ====================================================

        object_packets = conn.execute(
            """
            SELECT
                id,
                timestamp,
                receiver,
                source,
                packet

            FROM packets

            WHERE timestamp >= ?
              AND packet LIKE '%:;%'

            ORDER BY id DESC
            """,
            (
                cutoff,
            )
        ).fetchall()


        objects = {}

        for row in object_packets:

            name = object_name(
                row["packet"]
            )

            if not name:
                continue

            if name in objects:
                continue

            objects[name] = row


        for name, row in objects.items():

            packet = row["packet"]

            count = conn.execute(
                """
                SELECT COUNT(*)
                FROM packets
                WHERE timestamp >= ?
                  AND packet LIKE ?
                """,
                (
                    cutoff,
                    "%:;" + name + "%"
                )
            ).fetchone()[0]


            result["objects"]["rows"].append(
                {
                    "object":
                        name,

                    "icon":
                        "",

                    "overlay":
                        "—",

                    "port":
                        row["receiver"]
                        or "—",

                    "ago":
                        ago(
                            row["timestamp"]
                        ),

                    "pack":
                        int(count or 0),

                    "qrb":
                        "—",

                    "az":
                        "—",

                    "lat":
                        "—",

                    "long":
                        "—",

                    "alt":
                        "—",

                    "clb":
                        "—",

                    "dir":
                        "—",

                    "mhz":
                        "—",

                    "dt":
                        "—",

                    "data":
                        row["source"]
                        or "—",

                    "path":
                        packet_path(
                            packet
                        )
                }
            )


        result["objects"]["count"] = len(
            result["objects"]["rows"]
        )


        conn.close()

        return result


    except Exception as exc:

        return {
            "ok": False,
            "error": str(exc),

            "radio": {
                "count": 0,
                "title": "",
                "rows": []
            },

            "tcp": {
                "count": 0,
                "title": "",
                "rows": []
            },

            "objects": {
                "count": 0,
                "title": "",
                "rows": []
            }
        }


def fetch_icon(name):

    if not re.fullmatch(
        r'[0-9]+\.gif',
        name,
        re.I
    ):
        raise ValueError(
            "invalid icon name"
        )

    return _download(
        "/icon/" + name
    )
