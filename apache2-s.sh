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

# Logs initialisieren und Berechtigungen setzen
log "LOG_DIR=$LOG_DIR"
log "LOG_FILE=$LOG_FILE"

touch "$LOG_DIR"
chmod 644 "$LOG_DIR"
chown root:adm "$LOG_DIR"

touch "$LOG_FILE"
chmod 644 "$LOG_FILE"
chown root:adm "$LOG_FILE"

tools() {
    # Tools, die installiert werden sollen
    local packages=(
        apache2
        openssh-server
        certbot
        python3-certbot-apache
        install libapache2-mod-security2
        libapache2-mod-evasive
        brotli
        libapache2-mod-geoip
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

modules() {
    # Liste der zu ladenden Module
    local modules=(
        headers
        ssl
        rewrite
        security2
        deflate
        expires
        proxy
        proxy_http
        status
        remoteip
        evasive
        brotli
        geoip
    )

    # Module iterativ aktivieren
    for module in "${modules[@]}"; do
        if ! a2enmod "$module" >/dev/null 2>&1; then
            echo "Fehler: Modul $module konnte nicht aktiviert werden." >&2
            return 1
        fi
    done
}

apache2_conf() {
    cat << EOF > /etc/apache2/sites-available/onion-site.conf
<VirtualHost 127.0.0.1:80>
    ServerName example.onion
    DocumentRoot /var/www/onion-site
    
    # Verzeichniszugriffsregeln
    <Directory /var/www/onion-site>
        Options -Indexes +FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>

    # Fehler- und Zugriffsprotokollierung
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

    # Deflate-Komprimierung
    <IfModule mod_deflate.c>
        AddOutputFilterByType DEFLATE text/html text/plain text/xml
        AddOutputFilterByType DEFLATE application/javascript application/json
        AddOutputFilterByType DEFLATE text/css
    </IfModule>

    # Expires-Modul für Caching
    <IfModule mod_expires.c>
        ExpiresActive On
        ExpiresByType image/jpg "access plus 1 month"
        ExpiresByType image/png "access plus 1 month"
        ExpiresByType text/css "access plus 1 week"
        ExpiresByType application/javascript "access plus 1 week"
    </IfModule>

    # Proxy-Einstellungen (für Tor)
    <IfModule mod_proxy.c>
        ProxyPreserveHost On
        ProxyRequests Off
        <Proxy *>
            Require all granted
        </Proxy>
        ProxyPass / http://127.0.0.1:8080/
        ProxyPassReverse / http://127.0.0.1:8080/
    </IfModule>

    # RemoteIP-Modul-Konfiguration (falls hinter einem Proxy)
    <IfModule mod_remoteip.c>
        RemoteIPHeader X-Forwarded-For
        RemoteIPTrustedProxy 127.0.0.1
    </IfModule>

    # Brotli-Komprimierung
    <IfModule mod_brotli.c>
        AddOutputFilterByType BROTLI_COMPRESS text/html text/plain text/xml
        AddOutputFilterByType BROTLI_COMPRESS application/javascript application/json
        AddOutputFilterByType BROTLI_COMPRESS text/css
    </IfModule>

    # ModSecurity (Security2)
    <IfModule security2_module>
        SecRuleEngine On
        IncludeOptional /usr/share/modsecurity-crs/*.conf
        IncludeOptional /usr/share/modsecurity-crs/rules/*.conf
    </IfModule>

    # Status-Modul (nur für Debugging und lokal zugänglich)
    <Location "/server-status">
        SetHandler server-status
        Require local
    </Location>
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

tools
start_stop
modules
apache2_conf
stop
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

update_config