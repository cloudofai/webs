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
export LOG_DIR="/var/log/apache2"
export LOG_FILE="$LOG_DIR/apache2.log"

# erstellen des log verzeichnisses
mkdir -p "$LOG_DIR"

# simple log funktion
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

tools() {
    # Tools, die installiert werden sollen
    local packages=(
        apache2
        openssh-server
        certbot
        python3-certbot-apache
    )

    # Installieren der Tools
    apt update && apt install -y "${packages[@]}" || {
        log "Fehler: Fehler beim Installieren der Tools. Abbruch!" >&2
        exit 1
    }
}

start_stop() {
    # Apache starten
    systemctl start apache2
    if [[ $? -ne 0 ]]; then
        log "Fehler: Apache konnte nicht gestartet werden." >&2
        return 1
    fi

    # Apache aktivieren
    systemctl enable apache2
    if [[ $? -ne 0 ]]; then
        log "Fehler: Apache konnte nicht aktiviert werden." >&2
        return 1
    fi

    # Überprüfen, ob Apache aktiv ist
    systemctl is-active --quiet apache2
    if [[ $? -eq 0 ]]; then
        log "Apache läuft erfolgreich."
    else
        log "Fehler: Apache läuft nicht." >&2
        return 1
    fi

    # Apache stoppen
    systemctl stop apache2
    if [[ $? -ne 0 ]]; then
        log "Fehler: Apache konnte nicht gestoppt werden." >&2
        return 1
    fi

    log "Apache wurde erfolgreich gestartet und danach gestoppt."
}

load_modules() {
    a2enmod headers
    a2enmod ssl
    a2enmod rewrite
    a2enmod security2
}

apache_conf() {
    cat << EOF > /etc/apache2/sites-available/onion-site.conf
    <VirtualHost 127.0.0.1:80>
    ServerName example.onion
    DocumentRoot /var/www/onion-site
    <Directory /var/www/onion-site>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    ErrorLog ${APACHE_LOG_DIR}/onion-site-error.log
    CustomLog ${APACHE_LOG_DIR}/onion-site-access.log combined

    # Sicherheits-Header
    Header always set Content-Security-Policy "default-src 'self';"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set Referrer-Policy "no-referrer"
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</VirtualHost>
EOF

    mkdir -p /var/www/onion-site
    log "<h1>Willkommen auf meiner Onion-Seite!</h1>" | sudo tee /var/www/onion-site/index.html

    a2ensite onion-site || {
        log "Fehler: Konnte die Apache-Site nicht aktivieren." >&2
        return 1
    }

    systemctl reload apache2 || {
        log "Fehler: Konnte den Apache-Dienst nicht neu laden." >&2
        return 1
    }
}

stop() {
    # Apache stoppen
    systemctl stop apache2
    if [[ $? -ne 0 ]]; then
        log "Fehler: Apache konnte nicht gestoppt werden." >&2
        return 1
    fi
}

# Funktion, um die .onion-Domain auszulesen und als Variable zu speichern
get_onion_domain() {
    local onion_file
    onion_file="/var/lib/tor/hidden_service/hostname"

    # Prüfen, ob die Datei existiert
    if [[ -f "$onion_file" ]]; then
        # Die .onion-Domain aus der Datei auslesen
        local onion_domain=$(< "$onion_file")
        
        # Prüfen, ob die Datei einen Inhalt hat
        if [[ -n "$onion_domain" ]]; then
        echo "$onion_domain"
        else
            log "Fehler: Datei $onion_file ist leer." >&2
            return 1
        fi
    else
        log "Fehler: Datei $onion_file existiert nicht." >&2
        return 1
    fi
}

# Die Funktion aufrufen und die .onion-Domain in einer Variablen speichern
onion_domain=$(get_onion_domain)

update_config() {
    local config_file
    config_file="/etc/apache2/sites-available/onion-site.conf"
    local new_server_name
    new_server_name="$onion_domain"

    if [[ -f "$config_file" ]]; then
        # Ersetze die Zeile, die mit "ServerName" beginnt, durch die neue Onion-Domain
        sed -i "s|ServerName .*|ServerName ${new_server_name}|g" "$config_file"

        log "Die Apache-Konfiguration wurde erfolgreich aktualisiert mit der neuen Onion-Domain: $new_server_name"
    else
        log "Fehler: Die Apache-Konfigurationsdatei $config_file existiert nicht." >&2
        return 1
    fi

    systemctl reload apache2
}

tools
start_stop
load_modules
apache_conf
stop
get_onion_domain
update_config