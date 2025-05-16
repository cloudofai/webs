#!/bin/bash

# start execution timer
script_start_time=$(date +%s)

# check if script is running root
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Aborting!" >&2
    exit 1
fi

# set variables for log-dir/file
export LOG_DIR="/var/log/postin"
export LOG_FILE="$LOG_DIR/postin.log"

# create log-dir
mkdir -p "$LOG_DIR" || { echo "Fehler beim Erstellen des Log-Verzeichnisses. Abbruch!"; exit 1; }

# Log function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# install: UPDATEs & UPGRADEs
update() {
    log "making the system up2date..."
    sudo apt update || { log "Fehler beim Installieren der Abhängigkeiten. Abbruch!"; exit 1; }
}

# install: TOOLS
tools() {
    log "installing tools..."
    sudo apt install -y \
         git \
         gzip \
         unzip \
         iproute2 \
         shellcheck \
         neofetch \
         openssl \
         libssl-dev \
         nmap \
         jq \
         wget \
         curl \
         gpg \
         lynx \
         || { log "Fehler beim Installieren der Tools. Abbruch!"; exit 1; }
}

# ausführen
update
tools

# Endzeit des Skripts berechnen
script_end_time=$(date +%s)
script_duration=$((script_end_time - script_start_time))
duration_formatted=$(printf '%02d:%02d:%02d' $((script_duration/3600)) $((script_duration%3600/60)) $((script_duration%60)))
log "Script execution completed! Total runtime: $duration_formatted (hh:mm:ss)"
