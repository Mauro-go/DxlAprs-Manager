#!/usr/bin/env python3

import json
import os
import shlex
import sys

BASE = "/opt/dxlaprs-manager"
DATA = os.path.join(BASE, "data")

MANAGER_ACTIVE = os.path.join(DATA, "active_config.json")
MANAGER_DRAFT = os.path.join(DATA, "config.json")

LORARX_ACTIVE = os.path.join(DATA, "lorarx_active_config.json")
LORARX_DRAFT = os.path.join(DATA, "lorarx_config.json")


def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_manager():
    path = MANAGER_ACTIVE if os.path.exists(MANAGER_ACTIVE) else MANAGER_DRAFT
    return load_json(path)


def load_lorarx():
    path = LORARX_ACTIVE if os.path.exists(LORARX_ACTIVE) else LORARX_DRAFT
    return load_json(path)


def value(item, flag):
    v = str(item.get("value", "")).strip()

    if not v:
        raise ValueError(f"{flag}: valore mancante")

    return v


def build_argv(cfg, manager_cfg):
    bin_dir = str(
        manager_cfg.get("dxlaprs", {}).get("bin_dir", "")
    ).strip()

    binary = os.path.join(bin_dir, "lorarx") if bin_dir else "lorarx"

    argv = [binary]
    g = cfg.get("global", {})

    globals_with_value = (
        ("input_file", "-i"),
        ("format", "-f"),
        ("bandwidth", "-b"),
        ("gain_correction", "-g"),
        ("sample_rate", "-r"),
        ("fir_length", "-w"),
        ("offset", "-o"),
        ("frequency_mhz", "-M"),
        ("autonotch", "-W"),
    )

    for key, flag in globals_with_value:
        item = g.get(key, {})

        if item.get("enabled"):
            argv.extend([flag, value(item, flag)])

    notch = g.get("notch", {})

    if notch.get("enabled"):
        for row in notch.get("values", []):
            parts = str(row).split()

            if len(parts) != 2:
                raise ValueError(
                    "-n: ogni filtro richiede due frequenze"
                )

            argv.extend(["-n", parts[0], parts[1]])

    z = g.get("noise_blanker", {})

    if z.get("enabled"):
        up = str(z.get("up", "")).strip()
        down = str(z.get("down", "")).strip()

        if not up or not down:
            raise ValueError(
                "-Z: upspeed e downspeed sono obbligatori"
            )

        argv.extend(["-Z", up, down])

    global_bools = (
        ("no_multipath", "-R"),
        ("no_crc_repair", "-E"),
        ("no_max_block_fec", "-F"),
        ("ascii", "-H"),
        ("newline", "-N"),
        ("crc_only", "-Q"),
        ("verbose", "-v"),
        ("very_verbose", "-V"),
    )

    for key, flag in global_bools:
        if g.get(key, {}).get("enabled"):
            argv.append(flag)

    y = g.get("debug_iq", {})

    if y.get("enabled"):
        mode = str(y.get("mode", "")).strip()
        val = str(y.get("value", "")).strip()

        if mode not in ("d", "f", "b"):
            raise ValueError("-Y: modo valido d, f oppure b")

        if not val:
            raise ValueError("-Y: valore mancante")

        argv.extend(["-Y", mode, val])

    for nr, dem in enumerate(cfg.get("demodulators", []), 1):

        if not dem.get("enabled"):
            continue

        sf = str(dem.get("sf", "")).strip()

        try:
            sf_num = int(sf)
        except ValueError:
            raise ValueError(
                f"Demodulatore {nr}: spread factor non valido"
            )

        if abs(sf_num) < 5 or abs(sf_num) > 12:
            raise ValueError(
                f"Demodulatore {nr}: -s deve essere ±5..±12"
            )

        # IMPORTANTE:
        # -s deve essere la prima opzione del nuovo demodulatore.
        argv.extend(["-s", sf])

        dem_values = (
            ("afc", "-a"),
            ("coding_rate", "-c"),
            ("data_length", "-l"),
            ("squelch", "-S"),
            ("network_id", "-X"),
            ("optimize", "-O"),
            ("ppm", "-P"),
        )

        for key, flag in dem_values:
            item = dem.get(key, {})

            if not item.get("enabled"):
                continue

            v = value(item, f"Demodulatore {nr} {flag}")

            if flag == "-c":
                try:
                    n = int(v)
                except ValueError:
                    raise ValueError(
                        f"Demodulatore {nr}: -c deve essere 4..8"
                    )

                if n < 4 or n > 8:
                    raise ValueError(
                        f"Demodulatore {nr}: -c deve essere 4..8"
                    )

            if flag == "-l":
                try:
                    n = int(v)
                except ValueError:
                    raise ValueError(
                        f"Demodulatore {nr}: -l deve essere 2..255"
                    )

                if n < 2 or n > 255:
                    raise ValueError(
                        f"Demodulatore {nr}: -l deve essere 2..255"
                    )

            if flag == "-O" and v not in ("0", "1"):
                raise ValueError(
                    f"Demodulatore {nr}: -O deve essere 0 oppure 1"
                )

            argv.extend([flag, v])

        dem_bools = (
            ("frame_chaining", "-A"),
            ("implicit_crc", "-C"),
            ("continue_dcd", "-D"),
            ("disable_collision", "-d"),
            ("invert_iq", "-q"),
        )

        for key, flag in dem_bools:
            if dem.get(key):
                argv.append(flag)

        ax = dem.get("axudp", {})
        mode = str(ax.get("mode", "")).strip()
        val = str(ax.get("value", "")).strip()

        if mode:
            if mode not in ("U", "L"):
                raise ValueError(
                    f"Demodulatore {nr}: output AXUDP non valido"
                )

            if not val:
                raise ValueError(
                    f"Demodulatore {nr}: indirizzo AXUDP mancante"
                )

            argv.extend(["-" + mode, val])

        raw = dem.get("raw_udp", {})
        mode = str(raw.get("mode", "")).strip()
        val = str(raw.get("value", "")).strip()

        if mode:
            if mode not in ("u", "t"):
                raise ValueError(
                    f"Demodulatore {nr}: output UDP raw non valido"
                )

            if not val:
                raise ValueError(
                    f"Demodulatore {nr}: indirizzo UDP raw mancante"
                )

            argv.extend(["-" + mode, val])

    # -J è globale. Lo lasciamo dopo i demodulatori per evitare
    # di alterare l'ereditarietà interna legata a hasudp.
    j = g.get("json_udp", {})

    if j.get("enabled"):
        argv.extend(["-J", value(j, "-J")])

    if len(argv) == 1:
        raise ValueError("Nessuna opzione lorarx abilitata")

    return argv


def main():
    argv = build_argv(
        load_lorarx(),
        load_manager()
    )

    if "--check" in sys.argv:
        print(" ".join(shlex.quote(x) for x in argv))
        return

    binary = argv[0]

    if "/" in binary:
        if not os.path.isfile(binary):
            raise RuntimeError(
                f"Eseguibile lorarx non trovato: {binary}"
            )

        if not os.access(binary, os.X_OK):
            raise RuntimeError(
                f"Eseguibile lorarx non eseguibile: {binary}"
            )

    print(
        "Exec:",
        " ".join(shlex.quote(x) for x in argv),
        flush=True
    )

    os.execv(binary, argv)


if __name__ == "__main__":
    try:
        main()

    except Exception as exc:
        print(f"ERRORE: {exc}", file=sys.stderr)
        raise SystemExit(1)
