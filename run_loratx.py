#!/usr/bin/env python3

import json
import os
import shlex
import sys


BASE_DIR = "/opt/dxlaprs-manager"

CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "active_config.json"
)

LORATX_CONFIG_FILE = os.path.join(
    BASE_DIR,
    "data",
    "loratx_active_config.json"
)


BOOLEAN_FLAGS = {
    "-C",
    "-H",
    "-I",
    "-j",
    "-q",
    "-v",
    "-V"
}


ORDER = [
    "-i",
    "-o",
    "-f",
    "-r",

    "-b",
    "-s",
    "-c",
    "-C",
    "-I",
    "-N",
    "-O",
    "-p",
    "-q",
    "-j",

    "-g",
    "-S",

    "-B",
    "-E",
    "-P",
    "-R",
    "-T",
    "-w",
    "-Z",
    "-z",

    "-H",
    "-v",
    "-V"
]


ARITY = {
    "-B": 2,
    "-E": 2,
    "-P": 3,
    "-T": 2
}


def load_json(path):

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as f:

        return json.load(f)


def binary_path():

    cfg = load_json(
        CONFIG_FILE
    )

    bin_dir = str(
        cfg.get(
            "dxlaprs",
            {}
        ).get(
            "bin_dir",
            ""
        )
    ).strip()

    if not bin_dir:
        return "loratx"

    return os.path.join(
        bin_dir,
        "loratx"
    )


def parse_multi(flag, value):

    try:
        parts = shlex.split(
            str(value)
        )
    except ValueError as exc:
        raise ValueError(
            f"{flag}: {exc}"
        )

    expected = ARITY[flag]

    if len(parts) != expected:
        raise ValueError(
            f"{flag} richiede {expected} valori"
        )

    return parts


def build_argv():

    cfg = load_json(
        LORATX_CONFIG_FILE
    )

    options = cfg.get(
        "options",
        {}
    )

    argv = [
        binary_path()
    ]

    for flag in ORDER:

        item = options.get(
            flag,
            {}
        )

        if not item.get(
            "enabled"
        ):
            continue

        if flag in BOOLEAN_FLAGS:

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

                if not value:
                    continue

                argv.append(
                    flag
                )

                argv.extend(
                    parse_multi(
                        flag,
                        value
                    )
                )

            continue

        value = str(
            item.get(
                "value",
                ""
            )
        ).strip()

        if not value:
            continue

        argv.append(
            flag
        )

        if flag in ARITY:

            argv.extend(
                parse_multi(
                    flag,
                    value
                )
            )

        else:

            argv.append(
                value
            )

    return argv


def validate(argv):

    if "-i" not in argv:
        raise ValueError(
            "opzione -i file input non configurata"
        )

    if "-o" not in argv:
        raise ValueError(
            "opzione -o file output non configurata"
        )

    if "-f" in argv:

        i = argv.index("-f")

        if i + 1 >= len(argv) or argv[i + 1] not in {
            "u8",
            "i16",
            "f32"
        }:

            raise ValueError(
                "-f deve essere u8, i16 oppure f32"
            )

    if "-c" in argv:

        i = argv.index("-c")

        value = int(
            argv[i + 1]
        )

        if value < 4 or value > 8:

            raise ValueError(
                "-c deve essere compreso tra 4 e 8"
            )

    if "-s" in argv:

        i = argv.index("-s")

        value = int(
            argv[i + 1]
        )

        if abs(value) < 5 or abs(value) > 12:

            raise ValueError(
                "-s deve essere 5..12 oppure -5..-12"
            )

    if "-O" in argv:

        i = argv.index("-O")

        if argv[i + 1] not in {
            "0",
            "1"
        }:

            raise ValueError(
                "-O deve essere 0 oppure 1"
            )

    if "-r" in argv:

        i = argv.index("-r")

        if float(
            argv[i + 1]
        ) <= 0:

            raise ValueError(
                "-r deve essere maggiore di zero"
            )


def main():

    try:

        argv = build_argv()

        validate(
            argv
        )

    except Exception as exc:

        print(
            "loratx configuration error:",
            exc,
            file=sys.stderr
        )

        return 2

    if len(
        sys.argv
    ) > 1 and sys.argv[1] == "--check":

        print(
            " ".join(
                shlex.quote(
                    x
                )
                for x in argv
            )
        )

        return 0

    os.execv(
        argv[0],
        argv
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )
