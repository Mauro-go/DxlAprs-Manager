#!/usr/bin/env python3

import json
import os
import socket
import subprocess
import sys
import tempfile
import time


CONFIG = (
    "/opt/dxlaprs-manager/"
    "data/active_config.json"
)

ROUTE = (
    "/etc/apache2/"
    "dxlaprs-active-route.conf"
)


def load_mode():

    with open(
        CONFIG,
        "r",
        encoding="utf-8"
    ) as f:

        cfg = json.load(f)

    mode = (
        cfg.get(
            "web",
            {}
        ).get(
            "mode",
            "manager"
        )
    )

    if mode not in (
        "manager",
        "original"
    ):
        mode = "manager"

    return mode


def port_open(port):

    try:

        s = socket.create_connection(
            (
                "127.0.0.1",
                port
            ),
            timeout=1
        )

        s.close()

        return True

    except Exception:

        return False


def manager_routes():

    return r'''
# DxlAprs Manager selezionato.

# /manager è sempre il punto di ingresso amministrativo.
# Lo escludiamo dal catch-all ProxyPass /.
ProxyPass /manager !

RedirectMatch 302 ^/manager/?$ /config/general

ProxyPass        / http://127.0.0.1:8085/ nocanon
ProxyPassReverse / http://127.0.0.1:8085/
'''


def original_routes():

    return r'''
# ============================================================
# DxlAprs Manager - amministrazione sempre disponibile
# ============================================================

# IMPORTANTISSIMO:
# impedisce al ProxyPass catch-all verso udpgate4 di
# intercettare /manager.
ProxyPass /manager !

RedirectMatch 302 ^/manager/?$ /config/general

# SSE prima della regola /api/
ProxyPass        /api/monitor/traffic/stream http://127.0.0.1:8085/api/monitor/traffic/stream nocanon flushpackets=on timeout=600
ProxyPassReverse /api/monitor/traffic/stream http://127.0.0.1:8085/api/monitor/traffic/stream

ProxyPass        /config/ http://127.0.0.1:8085/config/ nocanon
ProxyPassReverse /config/ http://127.0.0.1:8085/config/

ProxyPass        /admin http://127.0.0.1:8085/admin nocanon
ProxyPassReverse /admin http://127.0.0.1:8085/admin

ProxyPass        /api/ http://127.0.0.1:8085/api/ nocanon
ProxyPassReverse /api/ http://127.0.0.1:8085/api/

ProxyPass        /traffic http://127.0.0.1:8085/traffic nocanon
ProxyPassReverse /traffic http://127.0.0.1:8085/traffic

ProxyPass        /messages http://127.0.0.1:8085/messages nocanon
ProxyPassReverse /messages http://127.0.0.1:8085/messages

ProxyPass        /heard http://127.0.0.1:8085/heard nocanon
ProxyPassReverse /heard http://127.0.0.1:8085/heard

ProxyPass        /raw/ http://127.0.0.1:8085/raw/ nocanon
ProxyPassReverse /raw/ http://127.0.0.1:8085/raw/

ProxyPass        /dxl-icon/ http://127.0.0.1:8085/dxl-icon/ nocanon
ProxyPassReverse /dxl-icon/ http://127.0.0.1:8085/dxl-icon/

# ============================================================
# Web originale udpgate4
# ============================================================

ProxyPass        / http://127.0.0.1:14502/ nocanon
ProxyPassReverse / http://127.0.0.1:14502/
'''


def write_route(content):

    directory = os.path.dirname(
        ROUTE
    )

    fd, tmp = tempfile.mkstemp(
        prefix="dxlaprs-route-",
        suffix=".conf",
        dir=directory
    )

    try:

        with os.fdopen(
            fd,
            "w",
            encoding="utf-8"
        ) as f:

            f.write(content)

        os.replace(
            tmp,
            ROUTE
        )

    finally:

        if os.path.exists(tmp):
            os.unlink(tmp)


def main():

    mode = load_mode()

    print(
        "DxlAprs web router mode:",
        mode,
        flush=True
    )

    if mode == "original":

        # Durante Applica configurazione active_config.json
        # può cambiare pochi istanti prima del restart udpgate4.
        # Attendiamo il backend originale.
        for _ in range(20):

            if port_open(14502):
                break

            time.sleep(1)

        content = original_routes()

    else:

        content = manager_routes()

    write_route(content)

    test = subprocess.run(
        [
            "/usr/sbin/apache2ctl",
            "configtest"
        ]
    )

    if test.returncode != 0:
        raise SystemExit(
            "Apache configtest fallito"
        )

    subprocess.run(
        [
            "systemctl",
            "reload",
            "apache2"
        ],
        check=True
    )


if __name__ == "__main__":
    main()
