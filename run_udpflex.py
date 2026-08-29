#!/usr/bin/env python3

import json
import os
import shlex
import sys


BASE_DIR = "/opt/dxlaprs-manager"

MANAGER_CONFIG = os.path.join(
    BASE_DIR,
    "data",
    "config.json"
)

MANAGER_ACTIVE_CONFIG = os.path.join(
    BASE_DIR,
    "data",
    "active_config.json"
)

UDPFLEX_CONFIG = os.path.join(
    BASE_DIR,
    "data",
    "udpflex_config.json"
)

UDPFLEX_ACTIVE_CONFIG = os.path.join(
    BASE_DIR,
    "data",
    "udpflex_active_config.json"
)


def load_json(path):
    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:
        return json.load(f)


def load_manager_config():

    if os.path.exists(
        MANAGER_ACTIVE_CONFIG
    ):
        return load_json(
            MANAGER_ACTIVE_CONFIG
        )

    return load_json(
        MANAGER_CONFIG
    )


def load_udpflex_config():

    if os.path.exists(
        UDPFLEX_ACTIVE_CONFIG
    ):
        return load_json(
            UDPFLEX_ACTIVE_CONFIG
        )

    return load_json(
        UDPFLEX_CONFIG
    )


def build_argv(
    cfg,
    manager_cfg
):

    dxlaprs = manager_cfg.get(
        "dxlaprs",
        {}
    )

    bin_dir = str(
        dxlaprs.get(
            "bin_dir",
            ""
        )
    ).strip()

    if bin_dir:
        binary = os.path.join(
            bin_dir,
            "udpflex"
        )
    else:
        binary = "udpflex"

    options = cfg.get(
        "options",
        {}
    )

    order = [
        "-A",
        "-a",
        "-d",
        "-i",
        "-K",
        "-k",
        "-p",
        "-r",
        "-s",
        "-t",
        "-T",
        "-U",
        "-u",
        "-v",
        "-V"
    ]

    boolean_flags = {
        "-A",
        "-a",
        "-k",
        "-r",
        "-s",
        "-u",
        "-v",
        "-V"
    }

    argv = [
        binary
    ]

    enabled_count = 0

    for flag in order:

        item = options.get(
            flag,
            {}
        )

        if not item.get(
            "enabled",
            False
        ):
            continue

        enabled_count += 1

        if flag in boolean_flags:

            argv.append(
                flag
            )

            continue

        if "values" in item:

            values = item.get(
                "values",
                []
            )

            for value in values:

                value = str(
                    value
                ).strip()

                if not value:
                    continue

                argv.extend([
                    flag,
                    value
                ])

            continue

        value = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if value:

            argv.extend([
                flag,
                value
            ])

    if enabled_count == 0:
        raise RuntimeError(
            "udpflex: nessuna opzione abilitata"
        )

    return argv


def main():

    manager_cfg = load_manager_config()
    cfg = load_udpflex_config()

    argv = build_argv(
        cfg,
        manager_cfg
    )

    binary = argv[0]

    if os.path.sep in binary:

        if not os.path.isfile(
            binary
        ):
            raise RuntimeError(
                f"Binary non trovato: {binary}"
            )

        if not os.access(
            binary,
            os.X_OK
        ):
            raise RuntimeError(
                f"Binary non eseguibile: {binary}"
            )

    print(
        "udpflex command:",
        shlex.join(argv),
        flush=True
    )

    if "--check" in sys.argv:
        return 0

    os.execv(
        binary,
        argv
    )


if __name__ == "__main__":

    try:
        raise SystemExit(
            main()
        )

    except Exception as e:

        print(
            f"udpflex wrapper error: {e}",
            file=sys.stderr,
            flush=True
        )

        raise SystemExit(1)
