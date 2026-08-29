#!/usr/bin/env python3

import json
import os
import shlex
import sys


BASE_DIR = "/opt/dxlaprs-manager"

CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udpbox_config.json"
)

ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udpbox_active_config.json"
)

MANAGER_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "config.json"
)

MANAGER_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "active_config.json"
)


ORDER = [
    "-a",
    "-b",
    "-c",
    "-D",
    "-d",
    "-e",
    "-f",
    "-k",
    "-L",
    "-l",
    "-M",
    "-m",
    "-n",
    "-p",
    "-P",
    "-R",
    "-r",
    "-S",
    "-s",
    "-t",
    "-u",
    "-v",
    "-X",
    "-x"
]


BOOLEAN_FLAGS = {
    "-D",
    "-e",
    "-S",
    "-s",
    "-v"
}


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


def load_manager_runtime_config():

    path = (
        MANAGER_ACTIVE_CONFIG_FILE
        if os.path.isfile(MANAGER_ACTIVE_CONFIG_FILE)
        else MANAGER_CONFIG_FILE
    )

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def get_udpbox_binary():

    manager_cfg = load_manager_runtime_config()

    bin_dir = str(
        manager_cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    if not bin_dir:
        raise RuntimeError(
            "Directory binari dxlAPRS non configurata"
        )

    return os.path.join(
        bin_dir,
        "udpbox"
    )


def build_argv(cfg):

    binary = get_udpbox_binary()

    options = cfg.get(
        "options",
        {}
    )

    argv = [binary]

    for flag in ORDER:

        item = options.get(flag)

        if not item:
            continue

        if not item.get("enabled"):
            continue

        if flag in BOOLEAN_FLAGS:
            argv.append(flag)
            continue

        if "values" in item:

            for value in item.get(
                "values",
                []
            ):

                value = str(
                    value
                ).strip()

                if value:
                    argv.extend(
                        [
                            flag,
                            value
                        ]
                    )

            continue

        value = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if value:
            argv.extend(
                [
                    flag,
                    value
                ]
            )

    return argv


def validate_argv(argv):

    if not argv:
        raise RuntimeError(
            "Comando udpbox vuoto"
        )

    binary = argv[0]

    if not os.path.isfile(binary):
        raise RuntimeError(
            f"Binary udpbox non trovato: {binary}"
        )

    if not os.access(
        binary,
        os.X_OK
    ):
        raise RuntimeError(
            f"Binary udpbox non eseguibile: {binary}"
        )

    if len(argv) == 1:
        raise RuntimeError(
            "Nessuna opzione udpbox abilitata"
        )


def command_text(argv):

    return " ".join(
        shlex.quote(
            str(x)
        )
        for x in argv
    )


def main():

    cfg = load_runtime_config()

    argv = build_argv(cfg)

    validate_argv(argv)

    if "--check" in sys.argv:

        print(
            command_text(argv)
        )

        return

    print(
        "DxlAprs Manager: avvio udpbox:",
        command_text(argv),
        flush=True
    )

    os.execv(
        argv[0],
        argv
    )


if __name__ == "__main__":
    main()
