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

deb http://deb.debian.org/debian sid main
EOF

    if ! sudo chown root:root /etc/apt/sources.list; then
        echo "Fehler beim Setzen des Eigentümers!" >&2
        exit 1
    fi

    chmod 644 /etc/apt/sources.list
}

kernel_backports() {
    log "upgrading bookworm-backports kernel ..."
    apt install -y -t bookworm-backports linux-image-amd64
}

kernel_sid() {
    log "upgrading sid kernel ..."
    apt install -t sid linux-image-amd64
    sed -i '/sid main/d' /etc/apt/sources.list #remove sid list for better upgrade protection
}

kernel_ubuntu(){
    # Set the base URL of the Ubuntu Mainline Kernel PPA
    MAINLINE_URL="https://kernel.ubuntu.com/~kernel-ppa/mainline/"

    # Get the latest kernel version directory
    LATEST_KERNEL=$(curl -s $MAINLINE_URL | grep -oP 'v[0-9]+\.[0-9]+(\.[0-9]+)?/' | tail -n 1 | sed 's:/$::')

    # Exit if no kernel version is found
    if [ -z "$LATEST_KERNEL" ]; then
      log "Could not find the latest kernel version."
      exit 1
    fi

    log "Found latest kernel version: $LATEST_KERNEL"

    # Create a directory to store the downloaded files
    DOWNLOAD_DIR="kernel-$LATEST_KERNEL"
    mkdir -p $DOWNLOAD_DIR
    cd $DOWNLOAD_DIR

    # Get the download links for the required .deb files
    KERNEL_FILES=$(curl -s "${MAINLINE_URL}${LATEST_KERNEL}/" | grep -oP 'href=".*amd64\.deb"' | cut -d'"' -f2)

    # Exit if no files are found
    if [ -z "$KERNEL_FILES" ]; then
      log "No .deb files found for the latest kernel."
      exit 1
    fi

    # Download the .deb files
    for FILE in $KERNEL_FILES; do
      log "Downloading $FILE ..."
      wget -q "${MAINLINE_URL}${LATEST_KERNEL}/${FILE}"
    done

    log "All files downloaded successfully."

    # Install the downloaded .deb files
    log "Installing the kernel..."
    sudo dpkg -i *.deb

    # Update grub
    log "Updating GRUB..."
    sudo update-grub

    # Notify completion
    log "Kernel $LATEST_KERNEL installed successfully. Please reboot your system."
}

main() {
    log "Main script execution started..."

    # Ausführen der Funktionen mit Fehlerbehandlung
    update || { log "Error while updating and upgrading the system. Aborting!"; exit 1; }
    list_update || { log "Error while updating and upgrading the apt sources.list. Aborting!"; exit 1; }
    apt update 
    kernel_backports || { log "Error while updating and upgrading the kernel. Aborting!"; exit 1; }
    #kernel_sid || { log "Error while updating and upgrading the kernel. Aborting!"; exit 1; }
    #kernel_ubuntu || { log "Error while updating and upgrading the kernel. Aborting!"; exit 1; }
    apt autoremove -y

    log "Main script execution completed successfully."
}

# Aufruf der main-Funktion
main && { log "System will reboot now..."; sudo reboot; }

