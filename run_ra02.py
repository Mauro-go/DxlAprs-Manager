#!/usr/bin/env python3

import json
import os
import sys

BASE = "/opt/dxlaprs-manager"


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


manager_cfg = load_json(
    os.path.join(
        BASE,
        "data",
        "active_config.json"
    )
)

cfg = load_json(
    os.path.join(
        BASE,
        "data",
        "ra02_active_config.json"
    )
)

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
    os.path.join(bin_dir, "ra02")
    if bin_dir
    else "ra02"
)

argv = [binary]

g = cfg.get("global", {})

poll = g.get("poll", {})

if poll.get("enabled"):
    argv.extend([
        "-u",
        str(poll.get("rx_us", "30000")),
        str(poll.get("tx_us", "10000"))
    ])


def add_value(target, flag, state):
    if not state.get("enabled"):
        return

    value = str(
        state.get("value", "")
    ).strip()

    if value:
        target.extend([flag, value])


def add_bool(target, flag, state):
    if state.get("enabled"):
        target.append(flag)


for chip in cfg.get("chips", []):

    if not chip.get("enabled"):
        continue

    gpio = chip.get("gpio", {})

    argv.extend([
        "-p",
        str(gpio.get("nss", "")).strip(),
        str(gpio.get("mosi", "")).strip(),
        str(gpio.get("miso", "")).strip(),
        str(gpio.get("sck", "")).strip()
    ])

    rx = chip.get("rx", {})

    add_value(argv, "-f", rx.get("frequency", {}))
    add_value(argv, "-s", rx.get("sf", {}))
    add_value(argv, "-b", rx.get("bandwidth", {}))
    add_value(argv, "-c", rx.get("coding_rate", {}))
    add_value(argv, "-n", rx.get("network_id", {}))
    add_value(argv, "-g", rx.get("gfsk_baud", {}))

    add_value(argv, "-e", rx.get("lna_gain", {}))
    add_value(argv, "-l", rx.get("lna_boost", {}))
    add_value(argv, "-r", rx.get("rssi_correction", {}))

    add_value(argv, "-o", rx.get("optimize", {}))
    add_value(argv, "-P", rx.get("ppm", {}))
    add_value(argv, "-X", rx.get("datarate", {}))
    add_value(argv, "-W", rx.get("preamble_limit", {}))

    # Nel sorgente corrente -R e -Z appartengono al CHIP.
    add_value(argv, "-R", rx.get("pa_ramp", {}))
    add_value(argv, "-Z", rx.get("ocp", {}))

    add_bool(argv, "-a", rx.get("agc", {}))
    add_bool(argv, "-i", rx.get("implicit", {}))
    add_bool(argv, "-q", rx.get("invert_iq", {}))

    # -J usa una destinazione globale, ma il parser abilita rxon
    # sul chip corrente. Lo ripetiamo quindi per ogni chip.
    json_udp = g.get("json_udp", {})

    if json_udp.get("enabled"):
        value = str(
            json_udp.get("value", "")
        ).strip()

        if value:
            argv.extend(["-J", value])

    for tx in chip.get("tx_contexts", []):

        if not tx.get("enabled"):
            continue

        transport = str(
            tx.get("transport", "L")
        ).strip().upper()

        endpoint = str(
            tx.get("endpoint", "")
        ).strip()

        if transport not in {"L", "U"}:
            raise SystemExit(
                "Trasporto TX non valido: "
                + transport
            )

        if not endpoint:
            raise SystemExit(
                "Endpoint AXUDP mancante"
            )

        argv.extend([
            "-" + transport,
            endpoint
        ])

        add_value(argv, "-F", tx.get("frequency", {}))
        add_value(argv, "-S", tx.get("sf", {}))
        add_value(argv, "-B", tx.get("bandwidth", {}))
        add_value(argv, "-C", tx.get("coding_rate", {}))
        add_value(argv, "-N", tx.get("network_id", {}))
        add_value(argv, "-w", tx.get("power", {}))
        add_value(argv, "-H", tx.get("preamble", {}))
        add_value(argv, "-T", tx.get("tx_delay", {}))
        add_value(argv, "-D", tx.get("deviation", {}))
        add_value(argv, "-G", tx.get("gfsk_baud", {}))
        add_value(argv, "-O", tx.get("optimize", {}))

        add_bool(argv, "-A", tx.get("afsk", {}))
        add_bool(argv, "-E", tx.get("raw_fsk", {}))
        add_bool(argv, "-K", tx.get("raw_lora", {}))
        add_bool(argv, "-I", tx.get("implicit", {}))
        add_bool(argv, "-d", tx.get("dcd", {}))
        add_bool(argv, "-Q", tx.get("invert_iq", {}))


if g.get("verbose", {}).get("enabled"):
    argv.append("-v")

if g.get("very_verbose", {}).get("enabled"):
    argv.append("-V")


if len(argv) == 1:
    raise SystemExit(
        "Nessun chip ra02 attivo"
    )


os.execv(binary, argv)
