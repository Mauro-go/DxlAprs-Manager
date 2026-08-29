#!/usr/bin/env python3

import json
import os
import shlex
import sys

BASE="/opt/dxlaprs-manager"


def load(path):
    with open(path,"r",encoding="utf-8") as f:
        return json.load(f)


manager=load(BASE+"/data/active_config.json")
cfg=load(BASE+"/data/ttytee_active_config.json")

bin_dir=str(
    manager.get("dxlaprs",{}).get("bin_dir","")
).strip()

binary=os.path.join(bin_dir,"ttytee") if bin_dir else "ttytee"

a=[binary]

serial=cfg.get("serial",{})
outputs=cfg.get("outputs",[])
logging=cfg.get("logging",{})


if serial.get("enabled"):

    device=str(
        serial.get("device","")
    ).strip()

    baud=str(
        serial.get("baud","")
    ).strip()

    if not device:
        raise SystemExit(
            "ttytee: dispositivo seriale mancante"
        )

    if not baud:
        raise SystemExit(
            "ttytee: baud rate mancante"
        )

    a.extend([
        "-t",
        device+":"+baud
    ])


for pipe in outputs:

    pipe=str(pipe).strip()

    if pipe:
        a.extend([
            "-p",
            pipe
        ])


if serial.get("abort_on_usb_error"):
    a.append("-u")


if logging.get("verbose"):
    a.append("-v")


if "--check" in sys.argv:
    print(
        " ".join(
            shlex.quote(str(x))
            for x in a
        )
    )
    raise SystemExit(0)


if not serial.get("enabled"):
    raise SystemExit(
        "ttytee: configurare -t <tty>:<baud>"
    )


if not [
    x for x in outputs
    if str(x).strip()
]:
    raise SystemExit(
        "ttytee: configurare almeno una uscita -p"
    )


os.execv(binary,a)
