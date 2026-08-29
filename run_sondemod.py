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
cfg=load(BASE+"/data/sondemod_active_config.json")

bin_dir=str(
    manager.get("dxlaprs",{}).get("bin_dir","")
).strip()

binary=os.path.join(bin_dir,"sondemod") if bin_dir else "sondemod"

a=[binary]

inp=cfg.get("input",{})
aprs=cfg.get("aprs",{})
files=cfg.get("files",{})
alm=cfg.get("almanac",{})
outputs=cfg.get("outputs",{})
logging=cfg.get("logging",{})


def val(flag,state):
    if state.get("enabled"):
        value=str(state.get("value","")).strip()

        if not value:
            raise SystemExit(f"{flag}: valore mancante")

        a.extend([flag,value])


def raw(flag,state):
    if state.get("enabled"):
        value=str(state.get("value","")).strip()

        if not value:
            raise SystemExit(f"{flag}: valore mancante")

        args=shlex.split(value)

        if not args:
            raise SystemExit(f"{flag}: valore mancante")

        a.append(flag)
        a.extend(args)


def boo(flag,state):
    if state.get("enabled"):
        a.append(flag)


# Ingresso
val("-o",inp.get("source",{}))

# APRS / posizione
boo("-d",aprs.get("dao",{}))
raw("-a",aprs.get("fence",{}))
boo("-F",aprs.get("track_filter_off",{}))
val("-g",aprs.get("leap_seconds",{}))
val("-p",aprs.get("send_quick",{}))
val("-E",aprs.get("expire",{}))
val("-b",aprs.get("beacon_times",{}))
val("-G",aprs.get("max_distance",{}))
val("-A",aprs.get("altitude_table",{}))
val("-I",aprs.get("callsign",{}))
val("-w",aprs.get("via",{}))
raw("-P",aprs.get("position",{}))
val("-N",aprs.get("my_altitude",{}))
boo("-M",aprs.get("send_mhz",{}))

# Almanacco
val("-T",alm.get("max_age",{}))
val("-R",alm.get("request_after",{}))

# File / directory
val("-t",files.get("comment",{}))
val("-S",files.get("srtm",{}))
val("-s",files.get("sem",{}))
val("-x",files.get("rinex",{}))
val("-y",files.get("yuma",{}))
val("-X",files.get("encrypted",{}))

decoded=files.get("decoded",{})

if decoded.get("enabled"):
    value=str(decoded.get("value","")).strip()

    if not value:
        raise SystemExit("File dati decodificati: valore mancante")

    mode=decoded.get("mode","csv")

    if mode=="json":
        a.extend(["-j",value])
    else:
        a.extend(["-C",value])

# AXUDP / testo
radio=outputs.get("radio",{})

if radio.get("enabled"):
    mode=radio.get("mode","r")

    if mode not in ("r","m"):
        raise SystemExit("Modalità uscita radio non valida")

    for dest in radio.get("destinations",[]):
        dest=str(dest).strip()

        if dest:
            a.extend(["-"+mode,dest])

# JSON UDP
for dest in outputs.get("json_udp",[]):
    dest=str(dest).strip()

    if dest:
        a.extend(["-J",dest])

val("-L",outputs.get("dfm_types",{}))

if logging.get("very_verbose"):
    a.append("-V")
elif logging.get("verbose"):
    a.append("-v")


if "--check" in sys.argv:
    print(" ".join(shlex.quote(str(x)) for x in a))
    raise SystemExit(0)


os.execv(binary,a)
