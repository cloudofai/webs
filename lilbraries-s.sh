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
libraries() {
    log "installing libraries..."
    sudo apt install -y \
         zstd \
         libzstd-dev \
         libssl-dev \
         liblzma5 \
         liblzma-dev \
         zlib1g \
         zlib1g-dev \
         libevent-2.1-7t64 \
         libevent-dev \
         libtool \
         libfuzzer-dev \
         libmysqlclient-dev \
         sqlite3 \
         libsqlite3-dev \
         build-essential \
         libpq-dev \
         libcurl4-openssl-dev \
         libsasl2-dev \
         libjpeg-dev \
         libpng-dev \
         libwebp-dev \
         libtiff-dev \
         ffmpeg \
         libavcodec-dev \
         libgmp-dev \
         libmpfr-dev \
         libblas-dev \
         liblapack-dev \
         libbz2-dev \
         liblz4-dev \
         libxml2-dev \
         libexpat1-dev \
         libjson-c-dev \
         automake \
         pkg-config \
         autoconf \
         python3 \
         ninja-build \
         gcc \
         g++ \
         make \
         cmake \
         llvm-dev \
         clang \
         || { log "Fehler beim Installieren der Tools. Abbruch!"; exit 1; }
}

# ausführen
update
libraries

# Endzeit des Skripts berechnen
script_end_time=$(date +%s)
script_duration=$((script_end_time - script_start_time))
duration_formatted=$(printf '%02d:%02d:%02d' $((script_duration/3600)) $((script_duration%3600/60)) $((script_duration%60)))
log "Script execution completed! Total runtime: $duration_formatted (hh:mm:ss)"
