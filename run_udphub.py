#!/usr/bin/env python3

import json
import os
import shlex
import sys


BASE_DIR = "/opt/dxlaprs-manager"

CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "config.json"
)

ACTIVE_MANAGER_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "active_config.json"
)

UDPHUB_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udphub_config.json"
)

UDPHUB_ACTIVE_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "udphub_active_config.json"
)


def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def load_manager_config():

    if os.path.isfile(
        ACTIVE_MANAGER_CONFIG_FILE
    ):
        return load_json(
            ACTIVE_MANAGER_CONFIG_FILE
        )

    return load_json(
        CONFIG_FILE
    )


def load_udphub_config():

    if os.path.isfile(
        UDPHUB_ACTIVE_CONFIG_FILE
    ):
        return load_json(
            UDPHUB_ACTIVE_CONFIG_FILE
        )

    return load_json(
        UDPHUB_CONFIG_FILE
    )


def build_argv():

    manager_cfg = load_manager_config()
    cfg = load_udphub_config()

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
        binary = "udphub"
    else:
        binary = os.path.join(
            bin_dir,
            "udphub"
        )

    options = cfg.get(
        "options",
        {}
    )

    order = [
        "-a",
        "-b",
        "-d",
        "-I",
        "-i",
        "-l",
        "-m",
        "-O",
        "-p",
        "-u",
        "-v",
        "-V",
        "-w"
    ]

    boolean_flags = {
        "-a",
        "-I",
        "-O",
        "-v",
        "-V"
    }

    argv = [binary]

    for flag in order:

        item = options.get(
            flag,
            {}
        )

        if not item.get(
            "enabled"
        ):
            continue

        if flag in boolean_flags:

            argv.append(
                flag
            )

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


def main():

    argv = build_argv()

    if len(argv) <= 1:

        print(
            "DxlAprs Manager: nessuna opzione udphub attiva",
            file=sys.stderr,
            flush=True
        )

        return 2

    binary = argv[0]

    if os.path.sep in binary:

        if not os.path.isfile(binary):

            print(
                "DxlAprs Manager: binario udphub non trovato: "
                + binary,
                file=sys.stderr,
                flush=True
            )

            return 2

        if not os.access(
            binary,
            os.X_OK
        ):

            print(
                "DxlAprs Manager: binario udphub non eseguibile: "
                + binary,
                file=sys.stderr,
                flush=True
            )

            return 2

    print(
        "DxlAprs Manager: avvio udphub: "
        + " ".join(
            shlex.quote(str(x))
            for x in argv
        ),
        flush=True
    )

    if "--check" in sys.argv:

        return 0

    os.execv(
        binary,
        argv
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
