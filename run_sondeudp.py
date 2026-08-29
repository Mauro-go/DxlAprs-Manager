#!/usr/bin/env python3

import json
import os
import sys

BASE="/opt/dxlaprs-manager"

def load(path):
    with open(path,"r",encoding="utf-8") as f:
        return json.load(f)

manager=load(BASE+"/data/active_config.json")
cfg=load(BASE+"/data/sondeudp_active_config.json")

bin_dir=str(
    manager.get("dxlaprs",{}).get("bin_dir","")
).strip()

binary=os.path.join(bin_dir,"sondeudp") if bin_dir else "sondeudp"
a=[binary]

g=cfg.get("global",{})

def val(flag,state):
    if state.get("enabled"):
        v=str(state.get("value","")).strip()
        if not v:
            raise SystemExit(f"{flag}: valore mancante")
        a.extend([flag,v])

def boo(flag,state):
    if state.get("enabled"):
        a.append(flag)

boo("-a",g.get("abort_sound_error",{}))
val("-c",g.get("maxchannels",{}))
val("-D",g.get("debug_output",{}))
val("-f",g.get("sample_rate",{}))
val("-g",g.get("dfm_old_threshold",{}))
val("-G",g.get("dfm_change_threshold",{}))
val("-S",g.get("dfm_id_threshold",{}))
val("-W",g.get("sleep_seconds",{}))
val("-l",g.get("sound_buffer",{}))
val("-o",g.get("sound_device",{}))
val("-L",g.get("receiver_label",{}))

name=g.get("dfm_name_mode",{})
if name.get("enabled"):
    mode=str(name.get("mode","N"))
    value=str(name.get("value","")).strip()
    if not value:
        raise SystemExit("DFM name mode: valore mancante")
    a.extend(["-"+mode,value])

boo("-s",g.get("disable_sdr_data",{}))
boo("-J",g.get("dfm_swap",{}))
boo("-O",g.get("dfm_old_name",{}))

for dest in g.get("monitor_udp",[]):
    dest=str(dest).strip()
    if dest:
        a.extend(["-M",dest])

decoder_flags={
    "m10_m20":"1",
    "mrz_meisei":"2",
    "c34_c50":"3",
    "rs41":"4",
    "dfm":"6",
    "imet":"8",
    "rs92":"9"
}

for ch in cfg.get("channels",[]):

    if not ch.get("enabled"):
        continue

    num=int(ch.get("channel",0))
    a.extend(["-C",str(num)])

    val("-e",ch.get("equalizer",{}))
    val("-I",ch.get("callsign",{}))
    val("-F",ch.get("afsk_mid",{}))

    for dest in ch.get("udp",[]):
        dest=str(dest).strip()
        if dest:
            a.extend(["-u",dest])

    dec=ch.get("decoders",{})

    for key,flag in decoder_flags.items():
        mode=dec.get(key,"default")

        if mode=="off":
            a.append("-"+flag)
        elif mode=="always":
            a.append("+"+flag)

if g.get("very_verbose"):
    a.append("-V")
elif g.get("verbose"):
    a.append("-v")

if "--check" in sys.argv:
    print(" ".join(a))
    raise SystemExit(0)

os.execv(binary,a)
