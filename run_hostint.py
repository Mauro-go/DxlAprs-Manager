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
    os.path.join(BASE, "data", "hostint_active_config.json")
)

bin_dir = str(
    manager_cfg.get("dxlaprs", {}).get("bin_dir", "")
).strip()

binary = (
    os.path.join(bin_dir, "hostint")
    if bin_dir
    else "hostint"
)

argv = [binary]

general = cfg.get("general", {})


def add_value(flag, state):
    if not state.get("enabled"):
        return

    value = str(state.get("value", "")).strip()

    if not value:
        raise SystemExit(f"{flag}: valore mancante")

    argv.extend([flag, value])


def add_bool(flag, state):
    if state.get("enabled"):
        argv.append(flag)


# Il parser reale usa -i minuscola.
add_value("-i", general.get("callsign", {}))

add_value("-t", general.get("tty", {}))


for value in cfg.get("axudp", []):
    value = str(value).strip()

    if value:
        argv.extend(["-U", value])


add_bool("-v", general.get("verbose", {}))


if len(argv) == 1:
    raise SystemExit("Nessun parametro hostint configurato")


if "--check" in sys.argv:
    print(" ".join(argv))
    raise SystemExit(0)


os.execv(binary, argv)
