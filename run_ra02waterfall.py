#!/usr/bin/env python3

import json
import os

BASE = "/opt/dxlaprs-manager"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


manager_cfg = load_json(
    os.path.join(BASE, "data", "active_config.json")
)

cfg = load_json(
    os.path.join(BASE, "data", "ra02waterfall_active_config.json")
)

bin_dir = str(
    manager_cfg.get("dxlaprs", {}).get("bin_dir", "")
).strip()

binary = os.path.join(bin_dir, "ra02waterfall") if bin_dir else "ra02waterfall"

argv = [binary]


def add_value(flag, state):
    if not state.get("enabled"):
        return

    value = str(state.get("value", "")).strip()

    if value:
        argv.extend([flag, value])


def add_bool(flag, state):
    if state.get("enabled"):
        argv.append(flag)


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

add_bool("-l", radio.get("lna_boost", {}))
add_value("-P", radio.get("ppm", {}))


frequency = cfg.get("frequency", {})

if frequency.get("enabled"):

    mode = str(frequency.get("mode", "range")).strip()

    if mode == "range":

        argv.extend([
            "-f",
            str(frequency.get("start_mhz", "")).strip(),
            str(frequency.get("end_mhz", "")).strip()
        ])

    elif mode == "table":

        table = str(frequency.get("table", "")).strip()

        if not table:
            raise SystemExit("Tabella frequenze vuota")

        argv.extend(["-f", table])

    else:
        raise SystemExit("Modalità frequenza non valida")


image = cfg.get("image", {})

add_value("-w", image.get("filename", {}))
add_value("-x", image.get("xsize", {}))
add_value("-y", image.get("ysize", {}))
add_value("-r", image.get("roll", {}))
add_value("-s", image.get("spectrum", {}))
add_value("-d", image.get("delay", {}))

add_bool("-R", image.get("scale", {}))
add_bool("-T", image.get("timestamps", {}))
add_bool("-t", image.get("transparent", {}))
add_bool("-m", image.get("mirror", {}))


external = cfg.get("external", {})

add_value("-c", external.get("colour_file", {}))
add_value("-g", external.get("gps", {}))
add_value("-j", external.get("level_file", {}))


debug = cfg.get("debug", {})

add_bool("-v", debug.get("verbose", {}))
add_bool("-V", debug.get("very_verbose", {}))


if len(argv) == 1:
    raise SystemExit("Nessun parametro ra02waterfall configurato")

os.execv(binary, argv)
