#!/usr/bin/env python3

import os
import json
import sys

BASE_DIR = "/opt/dxlaprs-manager"

CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "config.json"
)

ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "active_config.json"
)

sys.path.insert(0, BASE_DIR)



def load_runtime_config():

    path = (
        ACTIVE_CONFIG_FILE
        if os.path.isfile(ACTIVE_CONFIG_FILE)
        else CONFIG_FILE
    )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


def build_argv(cfg):

    binary = cfg["dxlaprs"]["binary"]
    options = cfg.get("udpgate4_options", {})

    argv = [binary]

    order = [
        "-s", "-S",
        "-R", "-M",
        "-H", "-I", "-C", "-B", "-u", "-F",
        "-A", "-a", "-Y",
        "-d", "-E", "-K", "-O", "-o", "-q", "-V", "-X", "-x",
        "-g", "-f", "-e", "-k", "-T", "-0", "-c",
        "-p", "-Q",
        "-t", "-m",
        "-w", "-D", "-W",
        "-l", "-r", "-v",
        "-n"
    ]

    web_mode = cfg.get("web", {}).get("mode", "original")

    for flag in order:

        item = options.get(flag)

        # -v è obbligatorio per il collector nativo.
        # Deve essere sempre passato a udpgate4.
        if flag == "-v":
            argv.append("-v")
            continue

        if not item or not item.get("enabled"):
            continue

        if web_mode == "manager" and flag in ("-D", "-W", "-w"):
            continue

        if "values" in item:

            for value in item.get("values", []):

                value = str(value).strip()

                if value:
                    argv.extend([flag, value])

        elif "value" in item:

            value = str(item.get("value", "")).strip()

            if value:
                argv.extend([flag, value])

        else:
            argv.append(flag)

    return argv


def main():

    cfg = load_runtime_config()
    argv = build_argv(cfg)

    if not argv:
        raise RuntimeError("Comando udpgate4 vuoto")

    binary = argv[0]

    if not os.path.isfile(binary):
        raise RuntimeError(
            f"Binary udpgate4 non trovato: {binary}"
        )

    if not os.access(binary, os.X_OK):
        raise RuntimeError(
            f"Binary udpgate4 non eseguibile: {binary}"
        )

    print(
        "DxlAprs Manager: avvio:",
        " ".join(argv),
        flush=True
    )

    os.execv(binary, argv)


if __name__ == "__main__":
    main()
