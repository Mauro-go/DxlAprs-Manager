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
    os.path.join(BASE, "data", "sdrtst_active_config.json")
)

bin_dir = str(
    manager_cfg.get("dxlaprs", {}).get("bin_dir", "")
).strip()

binary = (
    os.path.join(bin_dir, "sdrtst")
    if bin_dir
    else "sdrtst"
)

argv = [binary]


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


# ============================================================
# INGRESSO IQ
# ============================================================

inp = cfg.get("input", {})

add_value("-t", inp.get("source", {}))
add_value("-f", inp.get("format", {}))
add_value("-i", inp.get("iq_rate", {}))
add_value("-T", inp.get("manual_tune", {}))
add_value("-O", inp.get("center_offset", {}))
add_value("-o", inp.get("converter_offset", {}))
add_bool("-k", inp.get("reconnect", {}))


# ============================================================
# CONFIGURAZIONE CANALI
# ============================================================

channels = cfg.get("channels", {})

add_value(
    "-c",
    channels.get("config_source", {})
)


# ============================================================
# AUDIO
# ============================================================

audio = cfg.get("audio", {})

out = audio.get("output", {})

if out.get("enabled"):

    mode = str(out.get("mode", "s16")).strip()
    value = str(out.get("value", "")).strip()

    if not value:
        raise SystemExit("Uscita audio: valore mancante")

    flags = {
        "s16": "-s",
        "u8": "-S",
        "alaw": "-A"
    }

    if mode not in flags:
        raise SystemExit("Modalità uscita audio non valida")

    argv.extend([
        flags[mode],
        value
    ])


add_value(
    "-r",
    audio.get("sample_rate", {})
)

add_value(
    "-d",
    audio.get("downsample", {})
)

add_value(
    "-m",
    audio.get("mix_channels", {})
)

add_value(
    "-B",
    audio.get("buffer_samples", {})
)

add_bool(
    "-q",
    audio.get("stop_when_squelched", {})
)

add_bool(
    "-e",
    audio.get("watermark", {})
)


# ============================================================
# RICEVITORE / CPU
# ============================================================

rx = cfg.get("receiver", {})

add_value(
    "-a",
    rx.get("max_active", {})
)

add_value(
    "-w",
    rx.get("max_awake", {})
)

powersave = rx.get("powersave", {})

if powersave.get("enabled"):

    value = str(
        powersave.get("value", "")
    ).strip()

    if not value:
        raise SystemExit(
            "Powersave: valore mancante"
        )

    mode = str(
        powersave.get("mode", "normal")
    ).strip()

    if mode == "normal":
        argv.extend(["-z", value])

    elif mode == "fast":
        argv.extend(["-Z", value])

    else:
        raise SystemExit(
            "Modalità powersave non valida"
        )


add_value(
    "-F",
    rx.get("afc_speed", {})
)


# ============================================================
# TELEMETRIA UDP
# ============================================================

telemetry = cfg.get("telemetry", {})

for value in telemetry.get(
    "level_destinations", []
):

    value = str(value).strip()

    if value:
        argv.extend(["-L", value])


for value in telemetry.get(
    "noise_destinations", []
):

    value = str(value).strip()

    if value:
        argv.extend(["-N", value])


# ============================================================
# PARAMETRI RTL_TCP
# ============================================================

rtl = cfg.get("rtl_tcp", {})

for item in rtl.get("parameters", []):

    if not item.get("enabled", True):
        continue

    cmd = str(
        item.get("cmd", "")
    ).strip()

    value = str(
        item.get("value", "")
    ).strip()

    if cmd and value:
        argv.extend([
            "-p",
            cmd,
            value
        ])


# ============================================================
# DEBUG
# ============================================================

debug = cfg.get("debug", {})

add_value(
    "-D",
    debug.get("iq_dump", {})
)

add_bool(
    "-v",
    debug.get("verbose", {})
)


if len(argv) == 1:
    raise SystemExit(
        "Nessun parametro sdrtst configurato"
    )


if "--check" in sys.argv:
    print(" ".join(argv))
    raise SystemExit(0)


os.execv(binary, argv)
