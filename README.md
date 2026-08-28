# DxlAprs Manager

DxlAprs Manager is a web-based management and monitoring interface for the
dxlAPRS toolchain, initially focused on `udpgate4`.

The project provides a modern bilingual (Italian/English) interface for
configuration, service management and native monitoring without depending
on the original udpgate4 monitoring pages.

## Current features

- Web configuration of udpgate4 0.80
- Italian / English interface
- Public monitoring pages
- Password-protected administration area
- Save / Apply configuration workflow
- Automatic rollback when a new udpgate4 configuration fails to start
- Native monitoring based on udpgate4 verbose output
- SQLite monitoring database
- Heard stations monitoring
- APRS messages monitoring
- Raw packet monitoring
- TCP/APRS-IS connection monitoring
- Live traffic view
- Original dxlAPRS web interface selectable as an alternative frontend
- systemd service management
- Apache reverse-proxy frontend

## Installation

A Debian-based system is currently recommended.

Clone or download this repository, then run the installer as root:

    chmod +x install.sh
    sudo ./install.sh

The installer automatically installs the required Debian packages,
downloads the official dxlAPRS source code, builds the complete dxlAPRS
toolchain and installs DxlAprs Manager.

The tested dxlAPRS source revision is pinned to:

    86803526d2670fd800388036a0c6b78deae8f4af

The installer verifies that the resulting `udpgate4` version is 0.80.

## First access

After installation:

    http://SERVER-IP:14501/

Configuration:

    http://SERVER-IP:14501/config/general

Initial administrator credentials:

    Username: admin
    Password: admin

Change the administrator password immediately after the first login.

## First configuration

udpgate4 is intentionally not enabled or started immediately after a fresh
installation.

Open the configuration interface and configure at least the required
udpgate4 parameters, including the server callsign.

Then use:

    Save / Apply

DxlAprs Manager validates the new configuration by starting udpgate4 and
checking the configured TCP services.

After the first successful Apply, the udpgate4 service, native monitoring
collector and reconciliation timer are enabled for subsequent system boots.

## Network ports

DxlAprs Manager uses the following fixed infrastructure ports:

- `14501/tcp` - public Apache frontend
- `8085/tcp` - internal DxlAprs Manager service, bound to localhost
- `14502/tcp` - internal port reserved for the original udpgate4 web interface

Additional ports used by udpgate4 depend on the user's configuration.

## Installation directories

DxlAprs Manager:

    /opt/dxlaprs-manager

dxlAPRS:

    /opt/dxlaprs

Compiled dxlAPRS binaries:

    /opt/dxlaprs/bin

dxlAPRS source tree:

    /opt/dxlaprs/source

Original dxlAPRS web files:

    /opt/dxlaprs/www

## Services

The installation provides these systemd units:

- `dxlaprs-manager.service`
- `dxlaprs-udpgate.service`
- `dxlaprs-collector.service`
- `dxlaprs-reconcile.service`
- `dxlaprs-reconcile.timer`
- `dxlaprs-web-router.service`
- `dxlaprs-web-router.path`

The Manager and web router are enabled during installation.

udpgate4 and its monitoring services are enabled only after a valid
configuration has been successfully applied.

## Monitoring architecture

DxlAprs Manager does not depend on scraping the original dxlAPRS web pages
for its monitoring data.

`udpgate4` runs with verbose output enabled. The native collector reads the
systemd journal and stores monitoring information in a local SQLite
database.

Linux TCP socket information is also used to maintain connection state and
traffic statistics.

## dxlAPRS

DxlAprs Manager uses the original dxlAPRS toolchain developed by
Christian Rabler (OE5DXL).

dxlAPRS is a separate project and is not part of DxlAprs Manager.

Official upstream repository:

    https://github.com/oe5hpm/dxlAPRS

The source revision currently tested and used by this release is:

    86803526d2670fd800388036a0c6b78deae8f4af

The dxlAPRS source identifies itself as:

    SPDX-License-Identifier: GPL-2.0+

and contains:

    Copyright (C) Christian Rabler <oe5dxl@oevsv.at>

Please refer to the upstream dxlAPRS project for its complete licensing
terms, documentation and source code.

## Project status

DxlAprs Manager is under active development.

The current release concentrates on `udpgate4`. The architecture is
intended to allow additional dxlAPRS programs to be integrated as separate
management modules in future versions.

Possible future modules include other components of the dxlAPRS toolchain
such as afskmodem, udpbox, udpflex, udphub, udprfnet, gps2aprs and aprsmap.

## Important note

DxlAprs Manager is an independent management interface.

It is not the official dxlAPRS user interface and is not affiliated with
or endorsed by the original dxlAPRS project unless explicitly stated
otherwise.
