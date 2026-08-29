#!/usr/bin/env python3

import json
import os
import sys

BASE="/opt/dxlaprs-manager"

def load(path):
    with open(path,"r",encoding="utf-8") as f:
        return json.load(f)

manager=load(BASE+"/data/active_config.json")
cfg=load(BASE+"/data/l2cat_active_config.json")

bin_dir=str(manager.get("dxlaprs",{}).get("bin_dir","")).strip()
binary=os.path.join(bin_dir,"l2cat") if bin_dir else "l2cat"

argv=[binary]

conn=cfg.get("connection",{})
stream=cfg.get("stream",{})
logging=cfg.get("logging",{})

def val(flag,state):
    if state.get("enabled"):
        value=str(state.get("value","")).strip()
        if not value:
            raise SystemExit(f"{flag}: valore mancante")
        argv.extend([flag,value])

def boo(flag,state):
    if state.get("enabled"):
        argv.append(flag)

val("-C",conn.get("destination",{}))
val("-c",conn.get("command",{}))
val("-p",conn.get("pipe",{}))
val("-i",conn.get("callsigns",{}))
val("-j",stream.get("convert_from_pr",{}))
val("-m",stream.get("monitor",{}))
val("-w",stream.get("dupe_check",{}))
val("-D",stream.get("discard",{}))
val("-r",conn.get("reconnect_min",{}))
val("-R",conn.get("reconnect_max",{}))

for item in cfg.get("l2_parameters",[]):
    port=str(item.get("port","")).strip()
    parm=str(item.get("parameter","")).strip()
    value=str(item.get("value","")).strip()

    if port and parm and value:
        argv.extend(["-n",port,parm,value])

for dest in cfg.get("axudp",[]):
    dest=str(dest).strip()
    if dest:
        argv.extend(["-U",dest])

boo("-a",stream.get("autodetect",{}))
boo("-P",stream.get("ppp_deflate",{}))
boo("-d",stream.get("deflate",{}))

# -l e -L sono modalità alternative.
if stream.get("strip_lf",{}).get("enabled"):
    argv.append("-L")
elif stream.get("convert_lf_cr",{}).get("enabled"):
    argv.append("-l")

if logging.get("very_verbose"):
    argv.append("-V")
elif logging.get("verbose"):
    argv.append("-v")

if "--check" in sys.argv:
    print(" ".join(argv))
    raise SystemExit(0)

if not cfg.get("axudp"):
    raise SystemExit("l2cat richiede almeno una porta -U")

os.execv(binary,argv)
