#!/bin/bash

set -euo pipefail
umask 077

# check für root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Aborting!" >&2
    exit 1
fi

# $USER_HOME erstellen 
if [ -n "${SUDO_USER:-}" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -z "$USER_HOME" ]; then
        echo "Failed to determine the home directory of $SUDO_USER. Aborting!" >&2
        exit 1
    fi
    export USER_HOME
else
    export USER_HOME=$HOME
fi

# global variables
export LOG_DIR="/var/log/kernel-upgrade"
export LOG_FILE="$LOG_DIR/kernel-upgrade.log"

# erstellen des log verzeichnisses
mkdir -p "$LOG_DIR"

# simple log funktion
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# komplette updates/upgrades
update() {
    log "updating and upgrading the system..."
    apt update && \
    apt upgrade -y && \
    apt autoremove -y && \
    apt autoclean \
    || { log "Error while updating and upgrading the system. Aborting!"; exit 1; }
}

# apt source list update with backports
list_update() {
    log "updating apt-sources.list ..."
    cat << EOF > /etc/apt/sources.list
# Debian 12 (Bookworm) Official Repositories

deb http://deb.debian.org/debian/ bookworm main
deb-src http://deb.debian.org/debian/ bookworm main

deb http://deb.debian.org/debian/ bookworm-updates main
deb-src http://deb.debian.org/debian/ bookworm-updates main

deb http://security.debian.org/debian-security bookworm-security main
deb-src http://security.debian.org/debian-security bookworm-security main

deb http://deb.debian.org/debian bookworm-backports main
EOF

    if ! sudo chown root:root /etc/apt/sources.list; then
        echo "Fehler beim Setzen des Eigentümers!" >&2
        exit 1
    fi

    chmod 644 /etc/apt/sources.list
}

kernel() {
    log "upgrading kernel ..."
    apt install -y -t bookworm-backports linux-image-amd64 \
    || { log "Error while updating and upgrading the system. Aborting!"; exit 1; }
}

main() {
    log "Main script execution started..."

    # Ausführen der Funktionen mit Fehlerbehandlung
    update || { log "Error while updating and upgrading the system. Aborting!"; exit 1; }
    list_update || { log "Error while updating and upgrading the apt sources.list. Aborting!"; exit 1; }
    apt update 
    kernel || { log "Error while updating and upgrading the kernel. Aborting!"; exit 1; }
    apt autoremove -y

    log "Main script execution completed successfully."
}

# Aufruf der main-Funktion
main && { log "System will reboot now..."; sudo reboot; }
