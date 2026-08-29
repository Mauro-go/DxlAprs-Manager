# DxlAprs Manager

DxlAprs Manager is a web-based management, configuration and monitoring
interface for the dxlAPRS toolchain.

It provides a modern bilingual (Italian/English) interface for managing
`udpgate4` and additional dxlAPRS programs from a single web application.

DxlAprs Manager is an independent project and is not part of the official
dxlAPRS distribution.

## Current features

- Web configuration of udpgate4 0.80
- Italian / English interface
- Public monitoring pages
- Password-protected administration area
- Save / Apply configuration workflow
- Separate saved (draft) and active configurations
- Automatic rollback when an applied configuration fails
- Start / Stop / Restart controls for managed programs
- Saved and active command preview
- systemd journal viewer
- Native monitoring based on udpgate4 verbose output
- SQLite monitoring database
- Heard stations monitoring
- APRS messages monitoring
- Raw packet monitoring
- TCP/APRS-IS connection monitoring
- Live traffic view
- Services monitor
- Runtime and automatic boot state displayed separately
- Original dxlAPRS web interface selectable as an alternative frontend
- Apache reverse-proxy frontend

## Managed dxlAPRS programs

In addition to `udpgate4`, DxlAprs Manager currently provides dedicated
configuration and service management for:

- `udpbox`
- `udphub`
- `udpflex`
- `lorarx`
- `loratx`
- `fsk4rx`
- `ra02`
- `ra02waterfall`
- `sdrtst`
- `afskmodem`
- `gps2aprs`
- `hostint`
- `l2cat`
- `sondeudp`
- `sondemod`
- `ttytee`
- `adsb2aprs`

Each additional program has its own configuration page, Python launcher
and systemd service.

## Save / Apply configuration

DxlAprs Manager separates the configuration being edited from the last
configuration successfully applied to a program.

`Save configuration` stores the draft configuration without restarting
the program.

`Apply configuration` promotes the saved configuration to active,
restarts the program when required and verifies the result.

When verification fails, the Manager restores the previous active
configuration.

This prevents an invalid configuration change from unnecessarily
replacing the last known working configuration.

## Services monitor

The `Monitor -> Services` page provides a central view of dxlAPRS services.

Services are grouped into:

1. DxlAprs Manager infrastructure
2. Base service (`udpgate4`)
3. Additional dxlAPRS programs

Runtime state and automatic boot state are intentionally displayed
separately.

A service can therefore be running now but disabled at boot, or stopped
now while still enabled for the next system boot.

Managed program services can be started, stopped, restarted, enabled or
disabled from the interface.

Internal infrastructure services are protected from inappropriate actions.

## Installation

A Debian-based system is currently recommended.

Clone or download this repository, then run the installer as root:

    git clone https://github.com/Mauro-go/DxlAprs-Manager.git
    cd DxlAprs-Manager
    chmod +x install.sh
    sudo ./install.sh

The installer automatically installs the required Debian packages,
downloads the official dxlAPRS source code, builds the dxlAPRS toolchain
and installs DxlAprs Manager.

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

Open the configuration interface and configure the required parameters,
including the server callsign.

Then use:

    Save / Apply

DxlAprs Manager validates the new configuration by starting udpgate4 and
checking the configured services.

Additional dxlAPRS programs can then be configured independently from
their dedicated pages.

## Configuration files

The main Manager configuration uses separate saved and active files.

Additional programs follow the same model:

    PROGRAM_config.json
    PROGRAM_active_config.json

The public repository does not contain installation-specific runtime
configurations.

Instead it contains neutral templates:

    PROGRAM_config.default.json

During a new installation, the installer creates the local saved and
active configuration files from these defaults.

During upgrades, existing runtime configurations are preserved.

This keeps callsigns, addresses, ports, paths and other installation-
specific values out of the public repository.

## dxlAPRS binary directory

The common dxlAPRS binary directory is stored in the global Manager
configuration as:

    dxlaprs.bin_dir

The default installer sets it to:

    /opt/dxlaprs/bin

All additional program launchers use this setting instead of containing
installation-specific dxlAPRS paths.

## Network ports

DxlAprs Manager uses the following fixed infrastructure ports:

- `14501/tcp` - public Apache frontend
- `8085/tcp` - internal DxlAprs Manager service, bound to localhost
- `14502/tcp` - internal port reserved for the original udpgate4 web interface

Additional ports depend on the programs and configuration selected by the
user.

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

## systemd integration

DxlAprs Manager installs its infrastructure systemd units together with
dedicated units for the supported dxlAPRS programs.

The installer automatically installs all service units distributed in the
repository.

Program configuration and program boot state remain independent: enabling
a service controls automatic startup, while Start / Stop controls its
current runtime state.

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

The original udpgate4 management architecture has been extended to
additional dxlAPRS programs while keeping each component independent.

The project is designed so that additional dxlAPRS components can be
integrated without changing the configuration of already working
components.

## Important note

DxlAprs Manager is an independent management interface.

It is not the official dxlAPRS user interface and is not affiliated with
or endorsed by the original dxlAPRS project unless explicitly stated
otherwise.

## License

DxlAprs Manager is free software licensed under the
GNU General Public License version 2 or, at your option, any later version
(GPL-2.0-or-later).

See the `LICENSE` file for the complete license text.

The dxlAPRS toolchain is a separate upstream project and retains its own
copyright and licensing terms.

<img width="1917" height="856" alt="immagine" src="https://github.com/user-attachments/assets/1af5ea96-c749-4f89-835d-0c5e45e65265" />
<img width="1902" height="1056" alt="immagine" src="https://github.com/user-attachments/assets/d09619f0-e706-4bf9-ae73-937ea6f21c13" />
