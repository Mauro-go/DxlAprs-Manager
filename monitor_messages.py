#!/usr/bin/env python3

import re
import sqlite3


DB_FILE = "/opt/dxlaprs-manager/data/monitor.db"


MESSAGE_RE = re.compile(
    r"^:([A-Z0-9\- ]{9}):(.*)$",
    re.I
)


def _empty_section(title):

    return {
        "title": title,
        "headers": [],
        "rows": []
    }


def fetch_messages():

    result = {
        "ok": True,

        "heard": _empty_section(
            "Heard Messages"
        ),

        "digi": _empty_section(
            "Via Digi Heard Messages"
        ),

        "net": _empty_section(
            "Via Net Heard Messages"
        )
    }


    try:

        conn = sqlite3.connect(
            DB_FILE
        )

        conn.row_factory = sqlite3.Row


        rows = conn.execute(
            """
            SELECT
                id,
                timestamp,
                receiver,
                source,
                packet,
                duplicate

            FROM packets

            ORDER BY id DESC
            """
        ).fetchall()


        conn.close()


    except Exception as exc:

        return {
            "ok": False,
            "error": str(exc),

            "heard":
                _empty_section(
                    "Heard Messages"
                ),

            "digi":
                _empty_section(
                    "Via Digi Heard Messages"
                ),

            "net":
                _empty_section(
                    "Via Net Heard Messages"
                )
        }


    # ========================================================
    # PARSING MESSAGGI APRS
    #
    # Per ora classifichiamo tutti i messaggi trovati
    # nella sezione Heard.
    #
    # Quando avremo traffico reale potremo distinguere
    # in modo affidabile Heard / Digi / Net.
    # ========================================================

    parsed_rows = []


    for row in rows:

        packet = row["packet"] or ""

        if ":" not in packet:
            continue


        info = packet.split(
            ":",
            1
        )[1]


        m = MESSAGE_RE.match(
            info
        )

        if not m:
            continue


        destination = (
            m.group(1)
            .strip()
        )

        text = m.group(2)


        parsed_rows.append([
            row["timestamp"] or "",
            row["source"] or "",
            destination,
            row["receiver"] or "",
            text
        ])


    if parsed_rows:

        result["heard"]["headers"] = [
            "Timestamp",
            "From",
            "To",
            "Receiver",
            "Message"
        ]

        result["heard"]["rows"] = (
            parsed_rows
        )


    return result
