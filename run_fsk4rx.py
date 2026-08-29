#!/usr/bin/env python3

import json
import os

BASE = "/opt/dxlaprs-manager"

with open(
    os.path.join(BASE, "data", "active_config.json"),
    encoding="utf-8"
) as f:
    manager = json.load(f)

with open(
    os.path.join(BASE, "data", "fsk4rx_active_config.json"),
    encoding="utf-8"
) as f:
    cfg = json.load(f)

bin_dir = str(
    manager.get("dxlaprs", {}).get("bin_dir", "")
).strip()

binary = os.path.join(bin_dir, "fsk4rx") if bin_dir else "fsk4rx"

g = cfg.get("global", {})

argv = [binary]


def add(flag, item):
    if item.get("enabled"):
        value = str(item.get("value", "")).strip()
        if value:
            argv.extend([flag, value])


add("-i", g.get("input", {}))
add("-f", g.get("format", {}))
add("-r", g.get("sample_rate", {}))
add("-I", g.get("callsign", {}))
add("-J", g.get("json_udp", {}))

axudp = g.get("axudp", {})

if axudp.get("enabled"):
    for row in axudp.get("values", []):
        row = str(row).strip()
        if not row:
            continue

        if row.startswith("L "):
            argv.extend(["-L", row[2:].strip()])
        elif row.startswith("U "):
            argv.extend(["-U", row[2:].strip()])
        else:
            argv.extend(["-U", row])

add("-A", g.get("ais_file", {}))
add("-C", g.get("callbook", {}))
add("-Y", g.get("country_db", {}))
add("-T", g.get("ship_beacon", {}))
add("-q", g.get("squelch", {}))

if g.get("verbose", {}).get("enabled"):
    argv.append("-v")

if g.get("very_verbose", {}).get("enabled"):
    argv.append("-V")


for d in cfg.get("demodulators", []):

    if not d.get("enabled"):
        continue

    mode = str(d.get("mode", "4")).strip()

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
        raise SystemExit("Modo demodulatore non valido: " + mode)

    argv.extend(["-m", mvalue])

    # Valori espliciti per evitare ereditarietà fra modem.
    argv.extend([
        "-M", str(d.get("frequency_mhz", "0")),
        "-n", str(d.get("bfo", "1500"))
    ])

    if mode == "4":
        argv.extend([
            "-b", str(d.get("baud", "100")),
            "-D", str(d.get("spacing", "270")),
            "-W", str(d.get("if_width", "3240"))
        ])

    audio_mode = str(d.get("audio_mode", "")).strip()
    audio_file = str(d.get("audio_file", "")).strip()

    if audio_mode and audio_file:
        if audio_mode == "FM":
            argv.extend(["-F", audio_file])
        elif audio_mode == "USB":
            argv.extend(["-S", audio_file])

    tune = str(d.get("tune", "0")).strip() or "0"
    afc = str(d.get("afc", "0")).strip() or "0"

    argv.extend([
        "-t",
        tune + "," + afc
    ])


os.execv(binary, argv)
