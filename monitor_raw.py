#!/usr/bin/env python3

import os
import re
import sqlite3
from datetime import datetime


BASE_DIR = "/opt/dxlaprs-manager"
DB_FILE = os.path.join(
    BASE_DIR,
    "data",
    "monitor.db"
)


def valid_callsign(callsign):

    return bool(
        re.fullmatch(
            r"[A-Z0-9]{1,10}(?:-[0-9]{1,2})?",
            callsign
        )
    )


def format_timestamp(value):

    if not value:
        return ""

    value = str(value).strip()

    try:

        dt = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )

        return dt.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    except Exception:

        return value



# ============================================================
# POSIZIONE APRS
# ============================================================

def _base91(value):

    result = 0

    for char in value:

        n = ord(char) - 33

        if n < 0 or n > 90:
            raise ValueError(
                "invalid base91"
            )

        result = (
            result * 91
            + n
        )

    return result


def _parse_uncompressed_position(info):

    """
    APRS posizione non compressa:

        !DDMM.mmN/DDDMM.mmE>
        =DDMM.mmN/DDDMM.mmE>
        /timestampDDMM.mmN/DDDMM.mmE>
        @timestampDDMM.mmN/DDDMM.mmE>
    """

    if not info:
        return None


    # ! e =
    if info[0] in ("!", "="):

        pos = info[1:]


    # / e @ includono timestamp APRS di 7 caratteri
    elif info[0] in ("/", "@"):

        if len(info) < 9:
            return None

        pos = info[8:]


    else:
        return None


    m = re.match(
        r"^"
        r"(\d{2})(\d{2}\.\d{2})([NS])"
        r"."
        r"(\d{3})(\d{2}\.\d{2})([EW])",
        pos,
        re.I
    )

    if not m:
        return None


    lat_deg = int(
        m.group(1)
    )

    lat_min = float(
        m.group(2)
    )

    lat = (
        lat_deg
        + lat_min / 60.0
    )

    if m.group(3).upper() == "S":
        lat = -lat


    lon_deg = int(
        m.group(4)
    )

    lon_min = float(
        m.group(5)
    )

    lon = (
        lon_deg
        + lon_min / 60.0
    )

    if m.group(6).upper() == "W":
        lon = -lon


    if not (
        -90 <= lat <= 90
        and
        -180 <= lon <= 180
    ):
        return None


    return lat, lon


def _parse_compressed_position(info):

    """
    APRS posizione compressa.

    Dopo il data type troviamo:

        table + 4 lat + 4 lon + symbol

    Formula APRS standard:

        lat = 90 - Y / 380926
        lon = -180 + X / 190463
    """

    if not info:
        return None


    if info[0] in ("!", "="):

        pos = info[1:]


    elif info[0] in ("/", "@"):

        if len(info) < 9:
            return None

        pos = info[8:]


    else:
        return None


    if len(pos) < 10:
        return None


    # Primo carattere = symbol table.
    lat_chars = pos[1:5]
    lon_chars = pos[5:9]


    try:

        lat_raw = _base91(
            lat_chars
        )

        lon_raw = _base91(
            lon_chars
        )

    except Exception:
        return None


    lat = (
        90.0
        -
        lat_raw / 380926.0
    )

    lon = (
        -180.0
        +
        lon_raw / 190463.0
    )


    if not (
        -90 <= lat <= 90
        and
        -180 <= lon <= 180
    ):
        return None


    return lat, lon


def parse_aprs_position(packet):

    if not packet:
        return None


    packet = str(
        packet
    ).strip()


    # --------------------------------------------------------
    # THIRD PARTY
    #
    # CALL>DEST:}INNER>DEST:...
    # --------------------------------------------------------

    try:

        if ":" not in packet:
            return None

        info = packet.split(
            ":",
            1
        )[1]

    except Exception:
        return None


    if info.startswith("}"):

        inner = info[1:]

        if ">" in inner and ":" in inner:

            return parse_aprs_position(
                inner
            )


    # Prima proviamo non compressa.
    result = _parse_uncompressed_position(
        info
    )

    if result:
        return result


    # Poi compressa.
    return _parse_compressed_position(
        info
    )


def raw_position_fields(packet):

    coords = parse_aprs_position(
        packet
    )

    if not coords:

        return "", ""


    lat, lon = coords


    position = (
        f"{lat:.5f}, {lon:.5f}"
    )


    map_url = (
        "https://www.openstreetmap.org/"
        f"?mlat={lat:.6f}"
        f"&mlon={lon:.6f}"
        f"#map=13/{lat:.6f}/{lon:.6f}"
    )


    return position, map_url


def fetch_raw(callsign):

    callsign = callsign.upper().strip()

    if not valid_callsign(callsign):

        return {
            "ok": False,
            "error": "invalid callsign",
            "callsign": callsign,
            "count": 0,
            "rows": []
        }


    try:

        conn = sqlite3.connect(
            DB_FILE
        )

        conn.row_factory = sqlite3.Row


        rows = conn.execute(
            """
            SELECT
                timestamp,
                receiver,
                source,
                packet,
                duplicate
            FROM packets
            WHERE UPPER(source) = ?
            ORDER BY id DESC
            """,
            (
                callsign,
            )
        ).fetchall()


        conn.close()


    except Exception as exc:

        return {
            "ok": False,
            "error": str(exc),
            "callsign": callsign,
            "count": 0,
            "rows": []
        }


    result_rows = []


    for row in rows:

        packet = (
            row["packet"]
            if row["packet"] is not None
            else ""
        )

        result_rows.append({
            "timestamp":
                format_timestamp(
                    row["timestamp"]
                ),

            "packet":
                packet,

            # Questi campi vengono mantenuti
            # per compatibilità con raw_packets.html.
            #
            # In futuro potranno essere calcolati
            # nativamente dal packet APRS.
            "distance":
                "",

            "position":
                raw_position_fields(
                    packet
                )[0],

            "map_url":
                raw_position_fields(
                    packet
                )[1],

            "receiver":
                row["receiver"] or "",

            "duplicate":
                bool(row["duplicate"])
        })


    return {
        "ok": True,
        "callsign": callsign,
        "count": len(result_rows),
        "rows": result_rows
    }
