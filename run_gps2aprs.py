#!/usr/bin/env python3

import json
import os
import sys

BASE = "/opt/dxlaprs-manager"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


manager_cfg = load_json(
    os.path.join(BASE, "data", "active_config.json")
)

cfg = load_json(
    os.path.join(BASE, "data", "gps2aprs_active_config.json")
)

bin_dir = str(
    manager_cfg.get("dxlaprs", {}).get("bin_dir", "")
).strip()

binary = (
    os.path.join(bin_dir, "gps2aprs")
    if bin_dir
    else "gps2aprs"
)

argv = [binary]


def add_value(flag, state):
    if not state.get("enabled"):
        return

    v = str(state.get("value", "")).strip()

    if not v:
        raise SystemExit(f"{flag}: valore mancante")

    argv.extend([flag, v])


def add_bool(flag, state):
    if state.get("enabled"):
        argv.append(flag)


gps = cfg.get("gps", {})
aprs = cfg.get("aprs", {})
beacon = cfg.get("beacon", {})
outputs = cfg.get("outputs", {})
system = cfg.get("system", {})


# ============================================================
# GPS / SERIALE
# ============================================================

add_value("-t", gps.get("tty", {}))
add_bool("-u", gps.get("usb_abort", {}))
add_bool("-U", gps.get("ublox_raw", {}))

fix = gps.get("fixed_altitude", {})

if fix.get("enabled"):
    altitude = str(fix.get("altitude_cm", "")).strip()
    mode = str(fix.get("fix_mode", "")).strip()

    if not altitude or not mode:
        raise SystemExit("-A: quota o fixmode mancante")

    argv.extend(["-A", altitude, mode])


add_value("-M", gps.get("dynamic_model", {}))

tp = gps.get("timepulse", {})

if tp.get("enabled"):
    period = str(tp.get("period_us", "")).strip()
    duration = str(tp.get("duration_us", "")).strip()

    if not period or not duration:
        raise SystemExit("-T: periodo o durata mancante")

    argv.extend(["-T", period, duration])


for item in gps.get("config_strings", []):
    v = str(item).strip()
    if v:
        argv.extend(["-C", v])


# ============================================================
# APRS
# ============================================================

add_value("-I", aprs.get("callsign", {}))
add_value("-w", aprs.get("via", {}))
add_value("-c", aprs.get("comment", {}))
add_value("-i", aprs.get("symbol", {}))
add_value("-f", aprs.get("format", {}))
add_value("-d", aprs.get("destination_ssid", {}))

add_bool("-D", aprs.get("dao", {}))
add_bool("-a", aprs.get("altitude_off", {}))
add_bool("-k", aprs.get("speed_course_off", {}))
add_bool("-e", aprs.get("climb_off", {}))
add_bool("-s", aprs.get("checksum_off", {}))


# ============================================================
# BEACON
# ============================================================

add_value("-0", beacon.get("standing_time", {}))
add_value("-b", beacon.get("driving_time", {}))
add_value("-n", beacon.get("navigation_time", {}))
add_value("-g", beacon.get("drive_speed", {}))
add_value("-l", beacon.get("comment_interval", {}))

add_bool("-p", beacon.get("double_drive_time", {}))
add_bool("-B", beacon.get("balloon", {}))
add_value("-4", beacon.get("meshcom4", {}))


# ============================================================
# DESTINAZIONI
# ============================================================

for v in outputs.get("monitor", []):
    v = str(v).strip()
    if v:
        argv.extend(["-m", v])

for v in outputs.get("axudp", []):
    v = str(v).strip()
    if v:
        argv.extend(["-r", v])

for v in outputs.get("navigation_axudp", []):
    v = str(v).strip()
    if v:
        argv.extend(["-N", v])


# ============================================================
# SISTEMA / LOG
# ============================================================

add_value("-L", system.get("gps_log", {}))

ts = system.get("time_set", {})

if ts.get("enabled"):
    offset = str(ts.get("offset", "")).strip()

    if not offset:
        raise SystemExit("Time set: offset mancante")

    mode = str(ts.get("mode", "continue")).strip()

    if mode == "terminate":
        argv.extend(["-Z", offset])

    elif mode == "continue":
        argv.extend(["-z", offset])

    else:
        raise SystemExit("Modalità sincronizzazione ora non valida")


if system.get("verbose_satellites", {}).get("enabled"):
    argv.append("-V")

elif system.get("verbose", {}).get("enabled"):
    argv.append("-v")


if len(argv) == 1:
    raise SystemExit("Nessun parametro gps2aprs configurato")


if "--check" in sys.argv:
    print(" ".join(argv))
    raise SystemExit(0)


os.execv(binary, argv)
