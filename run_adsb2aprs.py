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
cfg=load(BASE+"/data/adsb2aprs_active_config.json")

bin_dir=str(
    manager.get("dxlaprs",{}).get("bin_dir","")
).strip()

binary=os.path.join(bin_dir,"adsb2aprs") if bin_dir else "adsb2aprs"

a=[binary]

dump1090=cfg.get("dump1090",{})
aprs=cfg.get("aprs",{})
position=cfg.get("position",{})
database=cfg.get("aircraft_database",{})
logging=cfg.get("logging",{})


def val(flag,state):
    if state.get("enabled"):
        value=str(state.get("value","")).strip()

        if not value:
            raise SystemExit(
                f"{flag}: valore mancante"
            )

        a.extend([flag,value])


def raw(flag,state):
    if state.get("enabled"):
        value=str(state.get("value","")).strip()

        if not value:
            raise SystemExit(
                f"{flag}: valore mancante"
            )

        args=shlex.split(value)

        if not args:
            raise SystemExit(
                f"{flag}: valore mancante"
            )

        a.append(flag)
        a.extend(args)


def boo(flag,state):
    if state.get("enabled"):
        a.append(flag)


# dump1090
val("-t",dump1090.get("server",{}))
boo("-k",dump1090.get("keep_connection",{}))

# APRS
val("-I",aprs.get("callsign",{}))
val("-u",aprs.get("destination",{}))
val("-b",aprs.get("beacon_time",{}))
val("-s",aprs.get("symbol",{}))
val("-c",aprs.get("comment",{}))

# Posizione / quota
raw("-P",position.get("home",{}))
val("-A",position.get("home_altitude",{}))
val("-a",position.get("altitude_correction",{}))
val("-S",position.get("srtm",{}))

# Database aeromobili
val("-D",database.get("file",{}))
val("-f",database.get("titles",{}))

# Log
if logging.get("very_verbose"):
    a.append("-V")
elif logging.get("verbose"):
    a.append("-v")


if "--check" in sys.argv:
    print(
        " ".join(
            shlex.quote(str(x))
            for x in a
        )
    )
    raise SystemExit(0)


# Per un avvio reale richiediamo almeno dump1090 e uscita APRS.
if not dump1090.get("server",{}).get("enabled"):
    raise SystemExit(
        "adsb2aprs: configurare il server dump1090 -t"
    )

if not aprs.get("destination",{}).get("enabled"):
    raise SystemExit(
        "adsb2aprs: configurare la destinazione AXUDP -u"
    )


os.execv(binary,a)
