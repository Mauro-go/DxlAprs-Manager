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
    os.path.join(BASE, "data", "afskmodem_active_config.json")
)

bin_dir = str(
    manager_cfg.get("dxlaprs", {}).get("bin_dir", "")
).strip()

binary = os.path.join(bin_dir, "afskmodem") if bin_dir else "afskmodem"

argv = [binary]


def value(flag, state):
    if not state.get("enabled"):
        return
    v = str(state.get("value", "")).strip()
    if not v:
        raise SystemExit(f"{flag}: valore mancante")
    argv.extend([flag, v])


def boolean(flag, state):
    if state.get("enabled"):
        argv.append(flag)


# ------------------------------------------------------------
# GLOBALI
# ------------------------------------------------------------

g = cfg.get("global", {})

boolean("-a", g.get("abort_sound_error", {}))
value("-b", g.get("tx_dac_buffers", {}))
boolean("-B", g.get("bad_sound_driver", {}))
value("-c", g.get("max_channels", {}))
value("-D", g.get("debug_file", {}))
value("-e", g.get("ptt_hold_buffers", {}))
value("-f", g.get("sample_rate", {}))
value("-i", g.get("kiss_pipe", {}))
value("-k", g.get("kiss_buffers", {}))
value("-l", g.get("adc_buffer_length", {}))
value("-m", g.get("mixer", {}))
value("-o", g.get("sound_device", {}))
value("-s", g.get("fragment_size", {}))


# ------------------------------------------------------------
# CANALI
# ------------------------------------------------------------

channels = {}

for ch in cfg.get("channels", []):
    if not ch.get("enabled"):
        continue

    n = int(ch.get("number", 0))

    if n not in (0, 1):
        raise SystemExit("Canale -C deve essere 0 oppure 1")

    if n in channels:
        raise SystemExit(f"Canale -C {n} duplicato")

    channels[n] = ch

    argv.extend(["-C", str(n)])

    ptt = ch.get("ptt", {})
    if ptt.get("enabled"):
        dev = str(ptt.get("device", "")).strip()
        bit = str(ptt.get("bit", "")).strip()
        if not dev or not bit:
            raise SystemExit(f"Canale {n}: PTT incompleto")
        argv.extend(["-p", dev, bit])

    if ch.get("close_ptt_tty", {}).get("enabled"):
        argv.append("-u")

    value("-f", ch.get("duplex", {}))
    value("-g", ch.get("gm900_delay", {}))
    value("-r", ch.get("random_wait", {}))


# ------------------------------------------------------------
# MODEM
# ------------------------------------------------------------

seen_modems = set()

for m in cfg.get("modems", []):
    if not m.get("enabled"):
        continue

    n = int(m.get("number", 0))

    if n < 0 or n > 7:
        raise SystemExit("Modem -M deve essere compreso tra 0 e 7")

    if n in seen_modems:
        raise SystemExit(f"Modem -M {n} duplicato")

    seen_modems.add(n)

    argv.extend(["-M", str(n)])

    boolean("-a", m.get("fsk", {}))
    value("-b", m.get("baud", {}))
    value("-B", m.get("bert", {}))
    value("-c", m.get("audio_channel", {}))
    value("-d", m.get("dcd_level", {}))
    value("-e", m.get("equalizer", {}))
    value("-f", m.get("afsk_mid", {}))
    boolean("-g", m.get("scrambler", {}))
    value("-H", m.get("tx_highpass", {}))
    boolean("-i", m.get("ignore_kiss_parameters", {}))
    value("-k", m.get("kiss_port", {}))
    value("-m", m.get("monitor", {}))
    value("-n", m.get("nyquist", {}))
    value("-p", m.get("pll_speed", {}))
    value("-q", m.get("quiet_level", {}))
    value("-s", m.get("afsk_shift", {}))
    value("-t", m.get("txdelay", {}))
    value("-T", m.get("tx_timeout", {}))

    ax = m.get("axudp", {})
    if ax.get("enabled"):
        mode = str(ax.get("mode", "U"))
        dest = str(ax.get("value", "")).strip()

        if not dest:
            raise SystemExit(f"Modem {n}: destinazione AXUDP mancante")

        flags = {
            "U": "-U",
            "L": "-L",
            "P": "-P"
        }

        if mode not in flags:
            raise SystemExit(f"Modem {n}: modalità AXUDP non valida")

        argv.extend([flags[mode], dest])

    value("-v", m.get("tx_volume", {}))
    value("-w", m.get("txdelay_pattern", {}))

    tail = m.get("txtail", {})
    if tail.get("enabled"):
        chnum = int(m.get("audio_channel", {}).get("value", 0))
        if chnum not in channels:
            raise SystemExit(
                f"Modem {n}: -x richiede il canale -C {chnum} configurato"
            )
        value("-x", tail)

    value("-z", m.get("dc_clamp", {}))


if len(argv) == 1:
    raise SystemExit("Nessun parametro afskmodem configurato")


if "--check" in sys.argv:
    print(" ".join(argv))
    raise SystemExit(0)


os.execv(binary, argv)
