#!/bin/bash

set -u
set -o pipefail

# ============================================================
# DxlAprs Manager Installer
# Compatible with udpgate4 0.80
# ============================================================

MANAGER_DIR="/opt/dxlaprs-manager"
DXL_DIR="/opt/dxlaprs"
DXL_SRC="/opt/dxlaprs/source"
DXL_BIN="/opt/dxlaprs/bin"

REPO_URL="https://github.com/oe5hpm/dxlAPRS.git"
EXPECTED_DXL_COMMIT="86803526d2670fd800388036a0c6b78deae8f4af"

EXPECTED_UDPGATE_VERSION="0.80"

APACHE_PUBLIC_PORT="14501"
MANAGER_PORT="8085"
ORIGINAL_WEB_PORT="14502"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FAILED=0


banner()
{
    echo
    echo "============================================================"
    echo " $1"
    echo "============================================================"
}


fail()
{
    echo
    echo "ERRORE: $1"
    FAILED=1
}


banner "DXLAPRS MANAGER - INSTALLAZIONE"


# ============================================================
# VERIFICA ROOT
# ============================================================

if [ "$(id -u)" -ne 0 ]; then
    echo
    echo "Questo installer deve essere eseguito come root."
    echo
    echo "Usare:"
    echo "sudo ./install.sh"
    echo
    FAILED=1
fi


# ============================================================
# INFORMAZIONI SISTEMA
# ============================================================

if [ -r /etc/os-release ]; then
    . /etc/os-release
    echo "Sistema: ${PRETTY_NAME:-Linux}"
else
    echo "Sistema: Linux"
fi

echo "Architettura: $(uname -m)"


# ============================================================
# DIPENDENZE DEBIAN
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "INSTALLAZIONE DIPENDENZE"

    export DEBIAN_FRONTEND=noninteractive

    apt-get update

    if [ $? -ne 0 ]; then
        fail "apt-get update fallito."
    fi
fi


if [ "$FAILED" -eq 0 ]; then

    apt-get install -y \
        ca-certificates \
        curl \
        git \
        build-essential \
        gcc \
        g++ \
        make \
        binutils \
        pkg-config \
        libpng-dev \
        libjpeg-dev \
        libx11-dev \
        libxext-dev \
        libxcb1-dev \
        libxau-dev \
        libxdmcp-dev \
        zlib1g-dev \
        python3 \
        python3-flask \
        python3-requests \
        apache2 \
        iproute2 \
        netcat-openbsd

    if [ $? -ne 0 ]; then
        fail "Installazione dipendenze fallita."
    fi
fi


# ============================================================
# PREPARAZIONE DIRECTORY
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "PREPARAZIONE DIRECTORY"

    mkdir -p \
        "$DXL_DIR" \
        "$DXL_BIN" \
        "$MANAGER_DIR" \
        "$MANAGER_DIR/data" \
        "$MANAGER_DIR/backup"

    if [ $? -ne 0 ]; then
        fail "Creazione directory fallita."
    fi
fi


# ============================================================
# DOWNLOAD SORGENTI DXLAPRS
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "DOWNLOAD SORGENTI DXLAPRS"

    rm -rf "$DXL_SRC"

    git clone "$REPO_URL" "$DXL_SRC"

    if [ $? -ne 0 ]; then
        fail "Clone repository dxlAPRS fallito."
    fi
fi


# ============================================================
# COMMIT DXLAPRS TESTATO
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    if ! git -C "$DXL_SRC" checkout --detach "$EXPECTED_DXL_COMMIT"; then
        fail "Checkout del commit dxlAPRS testato fallito."
    fi
fi


if [ "$FAILED" -eq 0 ]; then

    DXL_COMMIT="$(git -C "$DXL_SRC" rev-parse HEAD 2>/dev/null)"

    if [ "$DXL_COMMIT" != "$EXPECTED_DXL_COMMIT" ]; then
        fail "Il commit dxlAPRS installato non corrisponde a quello previsto."
    else
        echo
        echo "Commit dxlAPRS:"
        echo "$DXL_COMMIT"
    fi
fi


# ============================================================
# COMPILAZIONE COMPLETA DXLAPRS
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "COMPILAZIONE DXLAPRS"

    cd "$DXL_SRC/src" || fail "Directory sorgenti dxlAPRS non trovata."
fi


if [ "$FAILED" -eq 0 ]; then

    rm -rf "$DXL_SRC/out-manager"

    mkdir -p "$DXL_SRC/out-manager"

    make \
        -j1 \
        OUT="$DXL_SRC/out-manager/" \
        LFLAGS="-Wl,--gc-sections -no-pie"

    if [ $? -ne 0 ]; then
        fail "Compilazione completa dxlAPRS fallita."
    fi
fi


# ============================================================
# VERIFICA UDPGATE4
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "VERIFICA UDPGATE4"

    BUILT_UDPGATE="$DXL_SRC/out-manager/udpgate4"

    if [ ! -x "$BUILT_UDPGATE" ]; then

        fail "udpgate4 non è stato compilato."

    else

        UDPGATE_HELP="$("$BUILT_UDPGATE" -h 2>&1 | head -20)"

        echo "$UDPGATE_HELP"

        if echo "$UDPGATE_HELP" | grep -q "udpgate 0.80"; then

            echo
            echo "udpgate4 0.80 verificato."

        else

            echo
            echo "Versione attesa: $EXPECTED_UDPGATE_VERSION"
            fail "Versione udpgate4 incompatibile con DxlAprs Manager."

        fi
    fi
fi


# ============================================================
# COPIA BINARI DXLAPRS
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "INSTALLAZIONE BINARI DXLAPRS"

    rm -rf "$DXL_BIN"

    mkdir -p "$DXL_BIN"

    find "$DXL_SRC/out-manager" \
        -maxdepth 1 \
        -type f \
        -perm -111 \
        -exec cp -a {} "$DXL_BIN/" \;

    if [ ! -x "$DXL_BIN/udpgate4" ]; then

        fail "Copia dei binari dxlAPRS fallita."

    else

        chmod 755 "$DXL_BIN"/*

        echo
        echo "Binari installati in:"
        echo "$DXL_BIN"

        echo
        echo "Numero binari:"
        find "$DXL_BIN" \
            -maxdepth 1 \
            -type f \
            -perm -111 \
            | wc -l

    fi
fi


# ============================================================
# INSTALLAZIONE WEB ORIGINALE DXLAPRS
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "INSTALLAZIONE WEB ORIGINALE DXLAPRS"

    if [ -d "$DXL_SRC/dxlAPRS_common/www" ]; then

        rm -rf "$DXL_DIR/www"
        mkdir -p "$DXL_DIR/www"

        cp -a "$DXL_SRC/dxlAPRS_common/www/." "$DXL_DIR/www/"

        if [ $? -ne 0 ]; then
            fail "Copia della web originale dxlAPRS fallita."
        else
            echo "Web originale installata in:"
            echo "$DXL_DIR/www"
        fi

    else

        fail "Directory dxlAPRS_common/www non trovata nei sorgenti."

    fi
fi


# ============================================================
# INSTALLAZIONE DXLAPRS MANAGER
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "INSTALLAZIONE DXLAPRS MANAGER"

    # Se esiste già un'installazione, ne conserviamo una copia.
    if [ -d "$MANAGER_DIR" ] &&
       [ -f "$MANAGER_DIR/manager.py" ]; then

        BACKUP_DIR="/opt/dxlaprs-manager-backup-$(date +%Y%m%d-%H%M%S)"

        echo
        echo "Installazione precedente rilevata."
        echo "Backup:"
        echo "$BACKUP_DIR"

        cp -a "$MANAGER_DIR" "$BACKUP_DIR"

        if [ $? -ne 0 ]; then
            fail "Backup della precedente installazione fallito."
        fi
    fi
fi


if [ "$FAILED" -eq 0 ]; then

    # Puliamo solo i file applicativi.
    # La directory backup viene ricreata sotto.
    rm -rf \
        "$MANAGER_DIR/templates" \
        "$MANAGER_DIR/static"

    mkdir -p \
        "$MANAGER_DIR/templates" \
        "$MANAGER_DIR/static" \
        "$MANAGER_DIR/data" \
        "$MANAGER_DIR/backup"

    # Moduli Python principali.
    cp -a \
        "$SCRIPT_DIR/manager.py" \
        "$SCRIPT_DIR/monitor_heard.py" \
        "$SCRIPT_DIR/monitor_messages.py" \
        "$SCRIPT_DIR/monitor_raw.py" \
        "$SCRIPT_DIR/monitor_traffic.py" \
        "$SCRIPT_DIR/native_collector.py" \
        "$SCRIPT_DIR/run_udpgate.py" \
        "$SCRIPT_DIR/web_router.py" \
        "$MANAGER_DIR/"

    if [ $? -ne 0 ]; then
        fail "Copia dei moduli DxlAprs Manager fallita."
    fi
fi


if [ "$FAILED" -eq 0 ]; then

    cp -a \
        "$SCRIPT_DIR/templates/." \
        "$MANAGER_DIR/templates/"

    if [ $? -ne 0 ]; then
        fail "Copia dei template fallita."
    fi
fi


if [ "$FAILED" -eq 0 ]; then

    # static/ può essere vuota o assente nella release.
    if [ -d "$SCRIPT_DIR/static" ]; then
        cp -a \
            "$SCRIPT_DIR/static/." \
            "$MANAGER_DIR/static/"
    fi

    cp -a \
        "$SCRIPT_DIR/data/options.json" \
        "$MANAGER_DIR/data/options.json"

    cp -a \
        "$SCRIPT_DIR/data/config.default.json" \
        "$MANAGER_DIR/data/config.default.json"

    if [ $? -ne 0 ]; then
        fail "Copia dei file di configurazione base fallita."
    fi
fi


# ============================================================
# CONFIGURAZIONE INIZIALE
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "CONFIGURAZIONE INIZIALE"

    python3 - "$MANAGER_DIR" "$DXL_BIN" <<'PY'
import json
import sys
from pathlib import Path

manager_dir = Path(sys.argv[1])
dxl_bin = Path(sys.argv[2])

default_file = manager_dir / "data" / "config.default.json"
config_file = manager_dir / "data" / "config.json"
active_file = manager_dir / "data" / "active_config.json"

with default_file.open("r", encoding="utf-8") as f:
    cfg = json.load(f)

# ------------------------------------------------------------
# Percorsi installati
# ------------------------------------------------------------

dx = cfg.setdefault("dxlaprs", {})

dx["binary"] = str(dxl_bin / "udpgate4")
dx["web_interface"] = "manager"

# ------------------------------------------------------------
# Manager
# ------------------------------------------------------------

manager = cfg.setdefault("manager", {})

manager["listen_address"] = "127.0.0.1"
manager["port"] = 8085
manager["apply_changes"] = False

# ------------------------------------------------------------
# Frontend web
# ------------------------------------------------------------

web = cfg.setdefault("web", {})

web["mode"] = "manager"
web["manager_path"] = "/"
web["manager_port"] = 8085
web["public_port"] = 14501
web["original_backend_port"] = 14502

# ------------------------------------------------------------
# Admin iniziale
# manager.py creerà l'hash della password "admin"
# al primo avvio se password_hash è vuoto.
# ------------------------------------------------------------

admin = cfg.setdefault("admin", {})

admin["username"] = "admin"
admin["password_hash"] = ""

# ------------------------------------------------------------
# udpgate4
# ------------------------------------------------------------

opts = cfg.setdefault("udpgate4_options", {})

# Verbose obbligatorio per il collector.
opts.setdefault("-v", {})
opts["-v"]["enabled"] = True

# Web originale disponibile ma non attivo all'installazione.
opts.setdefault("-D", {})
opts["-D"]["enabled"] = False
opts["-D"]["value"] = "/opt/dxlaprs/www"

opts.setdefault("-W", {})
opts["-W"]["enabled"] = False
opts["-W"]["value"] = "4000"

opts.setdefault("-w", {})
opts["-w"]["enabled"] = False
opts["-w"]["value"] = "14502"

# ------------------------------------------------------------
# Scrittura runtime
# ------------------------------------------------------------

for destination in (config_file, active_file):

    with destination.open("w", encoding="utf-8") as f:
        json.dump(
            cfg,
            f,
            indent=2,
            ensure_ascii=False
        )
        f.write("\n")

print("Creato:", config_file)
print("Creato:", active_file)
print("Binario:", dx["binary"])
PY

    if [ $? -ne 0 ]; then
        fail "Generazione configurazione iniziale fallita."
    fi
fi


# ============================================================
# PERMESSI MANAGER
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    chmod 755 \
        "$MANAGER_DIR/manager.py" \
        "$MANAGER_DIR/native_collector.py" \
        "$MANAGER_DIR/run_udpgate.py" \
        "$MANAGER_DIR/web_router.py"

    chmod 644 \
        "$MANAGER_DIR/data/options.json" \
        "$MANAGER_DIR/data/config.default.json" \
        "$MANAGER_DIR/data/config.json" \
        "$MANAGER_DIR/data/active_config.json"

    echo
    echo "DxlAprs Manager installato in:"
    echo "$MANAGER_DIR"

    echo
    echo "udpgate4:"
    echo "$DXL_BIN/udpgate4"
fi


# ============================================================
# INSTALLAZIONE SYSTEMD
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "INSTALLAZIONE SYSTEMD"

    cp -a \
        "$SCRIPT_DIR/systemd/dxlaprs-collector.service" \
        "$SCRIPT_DIR/systemd/dxlaprs-manager.service" \
        "$SCRIPT_DIR/systemd/dxlaprs-reconcile.service" \
        "$SCRIPT_DIR/systemd/dxlaprs-reconcile.timer" \
        "$SCRIPT_DIR/systemd/dxlaprs-udpgate.service" \
        "$SCRIPT_DIR/systemd/dxlaprs-web-router.path" \
        "$SCRIPT_DIR/systemd/dxlaprs-web-router.service" \
        /etc/systemd/system/

    if [ $? -ne 0 ]; then
        fail "Installazione unit systemd fallita."
    fi
fi





# ============================================================
# INSTALLAZIONE APACHE
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "CONFIGURAZIONE APACHE"

    cp -a \
        "$SCRIPT_DIR/apache/dxlaprs-manager.conf" \
        /etc/apache2/sites-available/dxlaprs-manager.conf

    cp -a \
        "$SCRIPT_DIR/apache/dxlaprs-active-route.conf" \
        /etc/apache2/dxlaprs-active-route.conf

    if [ $? -ne 0 ]; then
        fail "Copia configurazione Apache fallita."
    fi
fi


if [ "$FAILED" -eq 0 ]; then

    if ! grep -Eq '^[[:space:]]*Listen[[:space:]]+14501([[:space:]]|$)' \
        /etc/apache2/ports.conf; then

        echo >> /etc/apache2/ports.conf
        echo "# DxlAprs Manager" >> /etc/apache2/ports.conf
        echo "Listen 14501" >> /etc/apache2/ports.conf
    fi
fi


if [ "$FAILED" -eq 0 ]; then

    a2enmod proxy
    a2enmod proxy_http
    a2enmod headers
    a2enmod rewrite

    a2ensite dxlaprs-manager.conf

    apache2ctl configtest

    if [ $? -ne 0 ]; then
        fail "Configurazione Apache non valida."
    fi
fi


# ============================================================
# ATTIVAZIONE SERVIZI
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "ATTIVAZIONE SERVIZI"

    systemctl daemon-reload

    if ! systemctl enable dxlaprs-manager.service; then
        fail "Abilitazione DxlAprs Manager fallita."
    fi

    if [ "$FAILED" -eq 0 ]; then
        if ! systemctl enable dxlaprs-web-router.path; then
            fail "Abilitazione web router fallita."
        fi
    fi

    # udpgate4, collector e reconcile non vengono abilitati
    # finché udpgate4 non dispone di una configurazione valida.

    if [ "$FAILED" -eq 0 ]; then
        if ! systemctl restart apache2; then
            fail "Riavvio Apache fallito."
        fi
    fi
fi


# ============================================================
# AVVIO MANAGER
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    systemctl restart dxlaprs-manager.service

    sleep 2

    if ! systemctl is-active --quiet dxlaprs-manager.service; then
        fail "DxlAprs Manager non è attivo."
    fi
fi


# ============================================================
# WEB ROUTER
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    systemctl restart dxlaprs-web-router.service

    if [ $? -ne 0 ]; then
        fail "Configurazione routing web fallita."
    fi

    systemctl start dxlaprs-web-router.path
fi


# ============================================================
# NOTA UDPGATE4
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    echo
    echo "udpgate4 non viene avviato finché non viene"
    echo "configurato almeno il nominativo/server call."
    echo
    echo "Configurarlo da DxlAprs Manager e usare"
    echo "Salva / Applica."
fi


# ============================================================
# VERIFICA WEB
# ============================================================

if [ "$FAILED" -eq 0 ]; then

    banner "VERIFICA INSTALLAZIONE"

    sleep 2

    if curl -fsS \
        "http://127.0.0.1:${MANAGER_PORT}/" \
        >/dev/null; then

        echo "Manager interno ${MANAGER_PORT}: OK"

    else

        fail "Manager non raggiungibile sulla porta ${MANAGER_PORT}."
    fi
fi


if [ "$FAILED" -eq 0 ]; then

    if curl -fsS \
        "http://127.0.0.1:${APACHE_PUBLIC_PORT}/" \
        >/dev/null; then

        echo "Apache pubblico ${APACHE_PUBLIC_PORT}: OK"

    else

        fail "Frontend Apache non raggiungibile sulla porta ${APACHE_PUBLIC_PORT}."
    fi
fi


# ============================================================
# RISULTATO
# ============================================================

echo

if [ "$FAILED" -eq 0 ]; then

    banner "INSTALLAZIONE COMPLETATA"

    echo "DxlAprs Manager:"
    echo "  http://IP-SERVER:${APACHE_PUBLIC_PORT}/"
    echo

    echo "Configurazione:"
    echo "  http://IP-SERVER:${APACHE_PUBLIC_PORT}/config/general"
    echo

    echo "Login iniziale:"
    echo "  User:     admin"
    echo "  Password: admin"
    echo

    echo "Directory Manager:"
    echo "  $MANAGER_DIR"
    echo

    echo "Directory dxlAPRS:"
    echo "  $DXL_DIR"
    echo

    echo "Binari:"
    echo "  $DXL_BIN"
    echo

    echo "IMPORTANTE:"
    echo "Cambiare la password admin dopo il primo accesso."

else

    banner "INSTALLAZIONE NON COMPLETATA"

    echo "Si sono verificati uno o più errori."
    echo
    echo "Controllare i messaggi precedenti prima di procedere."
fi

# ============================================================
# CODICE DI USCITA
# ============================================================

if [ "$FAILED" -ne 0 ]; then
    false
else
    true
fi
