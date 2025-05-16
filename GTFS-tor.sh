#!/bin/bash

# Dieses Programm steht unter der GNU General Public License Version 3 (GPLv3).
# Copyright (C) [Jahr] [Dein Name oder GitHub-Benutzername]
#
# Dieses Programm ist freie Software: Sie können es unter den Bedingungen der
# GNU General Public License, wie von der Free Software Foundation veröffentlicht,
# weiterverbreiten und/oder ändern, entweder gemäß Version 3 der Lizenz oder
# (nach Ihrer Option) jeder späteren Version.
#
# Dieses Programm wird in der Hoffnung verbreitet, dass es nützlich sein wird,
# aber OHNE JEDE GEWÄHRLEISTUNG; sogar ohne die implizite Gewährleistung der
# MARKTFÄHIGKEIT oder EIGNUNG FÜR EINEN BESTIMMTEN ZWECK. Siehe die GNU General
# Public License für weitere Details.
#
# Eine Kopie der GNU General Public License sollte zusammen mit diesem
# Programm bereitgestellt werden. Wenn nicht, siehe <https://www.gnu.org/licenses/>.

# start execution timer
script_start_time=$(date +%s)

# Verwende ein eindeutigeres Lockfile, um Konflikte zu vermeiden
lockfile=${lockfile:-"/tmp/$(basename "$0").lock"}

# Überprüfen, ob Lockfile bereits existiert
if [ -e "$lockfile" ]; then
    echo "Script is already running or lockfile exists: $lockfile" >&2
    exit 1
fi
touch "$lockfile"

# Füge eine Cleanup-Funktion hinzu, um temporäre Dateien sicher zu entfernen
trap 'cleanup_function' EXIT

cleanup_function() {
    # Bereinigung temporärer Dateien (falls erforderlich)
    if [ -n "${TEMP_FILE:-}" ] && [ -f "$TEMP_FILE" ]; then
        rm -f "$TEMP_FILE"
    fi

    # Überprüfen, ob das Lockfile existiert, bevor es entfernt wird
    if [ -f "$lockfile" ]; then
        rm -f "$lockfile"
    fi
}

# Aktivieren eines sicheren Fehlerverhaltens
set -euo pipefail

# etze eine sichere Umask, um sensible Dateien vor unbefugtem Zugriff zu schützen
umask 077 || {
    echo "Failed to set umask. Aborting." >&2
    exit 1
}

# Überprüfen, ob das Skript mit Root-Rechten ausgeführt wird
if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root. Aborting." >&2
    exit 1
fi

# Setze USER_HOME sicher und verwende "getent" für mehr Sicherheit
if [ -n "${SUDO_USER:-}" ]; then
    USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
    if [ -z "$USER_HOME" ]; then
        echo "Failed to determine the home directory of $SUDO_USER. Aborting." >&2
        exit 1
    fi
    export USER_HOME
else
    export USER_HOME=$HOME
fi

log_dir="/var/log/oO"

# Überprüfen, ob log_dir existiert und ein Verzeichnis ist
if [ -e "$log_dir" ] && [ ! -d "$log_dir" ]; then
    echo "$log_dir existiert, ist aber kein Verzeichnis. Abbruch!" >&2
    exit 1
fi

# Verzeichnis erstellen, falls es nicht existiert
if [ ! -d "$log_dir" ]; then
    mkdir -p "$log_dir" || { echo "Fehler beim Erstellen von $log_dir. Abbruch!" >&2; exit 1; }
fi

# Setze die Berechtigungen
chmod 755 "$log_dir"
chown root:adm "$log_dir"


# Einheitlicher Log-Pfad
log_dir="/var/log/oO"

# Abgeleitete Variablen
export oO_LOG_PATH="$log_dir"
export oO_LOG_FILE="$log_dir/oO.log"
export oO_LOG_RESOLV="$log_dir/resolv.log"
export oO_LOG_PROXYFETCH="$log_dir/proxiefetch.log"
export oO_LOG_PROXYCHAINS="$log_dir/proxychains.log"
export oO_LOG_NFTABLES="$log_dir/nftables.log"

# Log-Level sicher definieren
LOG_LEVEL_DEBUG=0
LOG_LEVEL_INFO=1
LOG_LEVEL_WARNING=2
LOG_LEVEL_ERROR=3
LOG_LEVEL_CRITICAL=4

# Aktuelles Log-Level setzen (Standard: DEBUG)
CURRENT_LOG_LEVEL=${CURRENT_LOG_LEVEL:-$LOG_LEVEL_DEBUG}

# Verbesserte Logging-Funktion mit Sicherheitsaspekten
log() {
    local level="$1"
    local message="$2"
    local log_file="${3:-/var/log/oO/default.log}"
    local log_level_name

    # Mapping der Log-Level-Namen
    case "$level" in
        "$LOG_LEVEL_DEBUG") log_level_name="DEBUG" ;;
        "$LOG_LEVEL_INFO") log_level_name="INFO" ;;
        "$LOG_LEVEL_WARNING") log_level_name="WARNING" ;;
        "$LOG_LEVEL_ERROR") log_level_name="ERROR" ;;
        "$LOG_LEVEL_CRITICAL") log_level_name="CRITICAL" ;;
        *) log_level_name="UNKNOWN" ;;
    esac

    # Überprüfung der Log-Level-Werte
    if [ -z "$level" ] || [ -z "$CURRENT_LOG_LEVEL" ] || ! [[ "$level" =~ ^[0-9]+$ ]] || ! [[ "$CURRENT_LOG_LEVEL" =~ ^[0-9]+$ ]]; then
        echo "$(date +'%Y-%m-%d %H:%M:%S.%3N') [ERROR] Invalid log level configuration." >&2
        return 1
    fi
    if [ "$level" -lt "$CURRENT_LOG_LEVEL" ]; then
        return 0
    fi

    # Überprüfen, ob das Logfile sicher ist
    if [ -z "$log_file" ] || [ ! -d "$(dirname "$log_file")" ]; then
        echo "$(date +'%Y-%m-%d %H:%M:%S.%3N') [ERROR] Log file path is invalid or not writable." >&2
        return 1
    fi

    # Lockfile erstellen, um Race Conditions zu vermeiden
    local lockfile="${log_file}.lock"
    exec 200>"$lockfile"
    flock -n 200 || {
        echo "$(date +'%Y-%m-%d %H:%M:%S.%3N') [ERROR] Could not acquire lock for log file. Another process might be writing." >&2
        return 1
    }

    # Logrotation mit Fehlerbehandlung
    if [ -f "$log_file" ] && [ "$(stat -c%s "$log_file")" -gt 1048576 ]; then
        if ! /usr/bin/gzip -c "$log_file" > "$log_file.$(date +'%Y%m%d%H%M%S').gz"; then
            echo "$(date +'%Y-%m-%d %H:%M:%S.%3N') [ERROR] Failed to compress log file. Skipping rotation." >&2
        else
            true > "$log_file"
            find "$(dirname "$log_file")" -name "$(basename "$log_file").*.gz" -type f | sort -r | tail -n +11 | xargs rm -f
        fi
    fi

    # Erzeugen der Metadaten für Log-Einträge
    local timestamp
    timestamp=$(date +'%Y-%m-%d %H:%M:%S.%3N')
    local script_name
    script_name=$(basename "$0")
    local user
    user=$(whoami)
    local hostname
    hostname=$(hostname)
    
    # Log-Eintrag schreiben
    if ! echo "$timestamp [$log_level_name] [$script_name] [$user@$hostname] - $message" >> "$log_file"; then
        echo "$(date +'%Y-%m-%d %H:%M:%S.%3N') [ERROR] Failed to write to log file." >&2
        return 1
    fi

    # Lockfile entfernen
    flock -u 200
    rm -f "$lockfile"
}

# Logs initialisieren und Berechtigungen setzen
log "$LOG_LEVEL_INFO" "oO_LOG_FILE=$oO_LOG_FILE" "$oO_LOG_FILE"
log "$LOG_LEVEL_INFO" "oO_LOG_PATH=$oO_LOG_PATH" "$oO_LOG_FILE"
log "$LOG_LEVEL_INFO" "oO_LOG_RESOLV=$oO_LOG_RESOLV" "$oO_LOG_FILE"
log "$LOG_LEVEL_INFO" "oO_LOG_PROXYFETCH=$oO_LOG_PROXYFETCH" "$oO_LOG_FILE"
log "$LOG_LEVEL_INFO" "oO_LOG_PROXYCHAINS=$oO_LOG_PROXYCHAINS" "$oO_LOG_FILE"
log "$LOG_LEVEL_INFO" "oO_LOG_NFTABLES=$oO_LOG_NFTABLES" "$oO_LOG_FILE"

touch "$oO_LOG_FILE"
chmod 644 "$oO_LOG_FILE"
chown root:adm "$oO_LOG_FILE"

touch /var/log/oO/default.log
chmod 644 /var/log/oO/default.log
chown root:adm /var/log/oO/default.log

echo ""
echo "============================================================================="
echo "                             remove/install                                  "
echo "============================================================================="
echo ""

remover() {
    log "$LOG_LEVEL_INFO" "Checking if libcurl4 is installed..." "$oO_LOG_FILE"

    # Überprüfen, ob das Skript mit Root-Rechten ausgeführt wird
    if [ "$EUID" -ne 0 ]; then
        log "$LOG_LEVEL_CRITICAL" "This function must be run as root. Aborting." "$oO_LOG_FILE"
        exit 1
    fi

    # Sicherstellen, dass alle erforderlichen Befehle vorhanden sind
    required_commands=("dpkg" "apt" "grep")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log "$LOG_LEVEL_CRITICAL" "Required command $cmd not found. Aborting." "$oO_LOG_FILE"
            exit 1
        fi
    done

    # Lockfile, um Race Conditions zu vermeiden
    local lockfile
    lockfile="/tmp/remover.lock.$(basename "$0").$$"
    if [ -e "$lockfile" ]; then
        log "$LOG_LEVEL_CRITICAL" "Another instance of the remover function is already running. Aborting." "$oO_LOG_FILE"
        exit 1
    fi
    touch "$lockfile"
    trap 'rm -f "$lockfile"' EXIT

    # APT-Sperre behandeln
    local lock_wait_time=0
    local max_lock_wait_time=60  # Timeout: 60 Sekunden
    while fuser /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [ $lock_wait_time -ge $max_lock_wait_time ]; then
            log "$LOG_LEVEL_CRITICAL" "APT is locked for more than $max_lock_wait_time seconds. Aborting." "$oO_LOG_FILE"
            exit 1
        fi
        log "$LOG_LEVEL_WARNING" "APT is locked by another process. Retrying in 5 seconds..." "$oO_LOG_FILE"
        sleep 5
        lock_wait_time=$((lock_wait_time + 5))
    done

    # Überprüfen, ob libcurl4 installiert ist
    if dpkg -l | grep -q "^ii.*libcurl4"; then
        log "$LOG_LEVEL_INFO" "libcurl4 is installed. Attempting to remove it for better compatibility with curl install..." "$oO_LOG_FILE"

        local attempts=0
        local max_attempts=3
        while [ $attempts -lt $max_attempts ]; do
            if timeout 180 /usr/bin/apt remove --purge -y curl libcurl4; then
                log "$LOG_LEVEL_INFO" "libcurl4 was successfully removed. curl will now be installed with the oO-Package." "$oO_LOG_FILE"
                return 0
            else
                attempts=$((attempts + 1))
                log "$LOG_LEVEL_INFO"  "Failed to remove libcurl4. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$oO_LOG_FILE"
                sleep $((attempts * 5))
            fi
        done

        log "$LOG_LEVEL_CRITICAL" "Failed to remove libcurl4 after $max_attempts attempts. Please check for errors in the package manager logs." "$oO_LOG_FILE"
        return 1
    else
        log "$LOG_LEVEL_INFO" "libcurl4 is not installed. Skipping removal." "$oO_LOG_FILE"
    fi
}

installer() {
    log "$LOG_LEVEL_INFO" "Starting package installation..." "$oO_LOG_FILE"

    local attempts=0
    local max_attempts=3
    local critical_packages=("curl" "tor" "nmap" "resolvconf" "nftables" "proxychains" "apt-transport-https" "jq" "git" "gzip" "iproute2" "nginx" "coreutils" "certbot" "python3-certbot-nginx" "ca-certificates")

    # APT-Sperre behandeln
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        log "$LOG_LEVEL_WARNING" "APT is locked by another process. Retrying in 5 seconds..." "$oO_LOG_FILE"
        sleep 5
    done

    while [ $attempts -lt $max_attempts ]; do
        log "$LOG_LEVEL_INFO" "Updating package lists..." "$oO_LOG_FILE"
        if ! apt update -y; then
            log "Failed to update package lists. Attempt $((attempts + 1)) of $max_attempts." "$oO_LOG_FILE"
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
            continue
        fi

        log "$LOG_LEVEL_INFO" "Installing packages: ${critical_packages[*]}..." "$oO_LOG_FILE"
        if apt install -y "${critical_packages[@]}"; then
            log "$LOG_LEVEL_INFO" "Packages installed successfully." "$oO_LOG_FILE"

            # Überprüfen, ob alle kritischen Pakete installiert sind
            for pkg in "${critical_packages[@]}"; do
                if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "installed"; then
                    log "Critical package $pkg is missing or not fully installed. Aborting." "$oO_LOG_FILE"
                    return 1
                fi
            done

            log "$LOG_LEVEL_INFO" "All critical packages verified." "$oO_LOG_FILE"

            # Bereinige temporäre Dateien
            log "$LOG_LEVEL_INFO" "Cleaning up temporary apt files..." "$oO_LOG_FILE"
            if ! apt clean; then
                log "$LOG_LEVEL_WARNING" "Failed to clean up temporary apt files." "$oO_LOG_FILE"
            fi

            return 0
        else
            attempts=$((attempts + 1))
            log "$LOG_LEVEL_ERROR" "Failed to install packages. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$oO_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log "$LOG_LEVEL_ERROR" "Failed to install packages after $max_attempts attempts. Please check your network connection and try again." "$oO_LOG_FILE"
    return 1
}

remover
installer
update-ca-certificates

echo ""
echo "============================================================================="
echo "                               network setup                                 "
echo "============================================================================="
echo ""

# Funktion zur Erkennung des lokalen Netzwerk-IP-Bereichs
net_setup() {
    log "$LOG_LEVEL_INFO" "Starting network setup..." "$oO_LOG_FILE"

    # Erkennen und Festlegen der primären Netzwerkschnittstelle
    log "$LOG_LEVEL_INFO" "Detecting primary network interface..." "$oO_LOG_FILE"
    local primary_interface
    local fallback_interfaces=("eth0" "wlan0")
    
    # Versuchen, die primäre Schnittstelle aus der Standardroute zu erhalten
    primary_interface=$(ip route | grep default | awk '{print $5}')
    if [ -z "$primary_interface" ]; then
        log "$LOG_LEVEL_WARNING" "PRIMARY_INTERFACE is not set. Attempting to use fallback interfaces." "$oO_LOG_FILE"
        for fallback in "${fallback_interfaces[@]}"; do
            if ip link show "$fallback" > /dev/null 2>&1; then
                primary_interface="$fallback"
                log "$LOG_LEVEL_INFO" "Fallback to $fallback as PRIMARY_INTERFACE." "$oO_LOG_FILE"
                break
            fi
        done

        if [ -z "$primary_interface" ]; then
            log "$LOG_LEVEL_CRITICAL" "No valid network interface found. Please check your network settings." "$oO_LOG_FILE"
            exit 1
        fi
    fi
    log "$LOG_LEVEL_INFO" "Detected primary interface: $primary_interface" "$oO_LOG_FILE"

    # Erkennen und Festlegen des lokalen IP-Bereichs
    log "$LOG_LEVEL_INFO" "Detecting local IP range..." "$oO_LOG_FILE"
    local local_ip
    local ip_prefix
    local allowed_ip_range

    local_ip=$(ip -o -4 addr show "$primary_interface" | awk '{print $4}' | cut -d/ -f1)
    if [ -z "$local_ip" ]; then
        log "$LOG_LEVEL_CRITICAL" "Unable to determine local IP address for interface $primary_interface." "$oO_LOG_FILE"
        exit 1
    fi

    if [[ ! "$local_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log "$LOG_LEVEL_CRITICAL" "Invalid IP address detected: $local_ip" "$oO_LOG_FILE"
        exit 1
    fi

    ip_prefix=$(echo "$local_ip" | cut -d. -f1-3)
    allowed_ip_range="$ip_prefix.0/24"
    log "$LOG_LEVEL_INFO" "Detected IP range: $allowed_ip_range (Interface: $primary_interface, IP: $local_ip)" "$oO_LOG_FILE"

    # Exportieren der primären Schnittstelle und des IP-Bereichs
    export PRIMARY_INTERFACE="$primary_interface"
    export ALLOWED_IP_RANGE="$allowed_ip_range"

    # IPv6 systemweit deaktivieren
    log "$LOG_LEVEL_INFO" "Disabling IPv6 system-wide..." "$oO_LOG_FILE"
    local ipv6_conf="/etc/sysctl.d/99-disable-ipv6.conf"

    # Überprüfen, ob das Skript mit Root-Rechten ausgeführt wird
    if [ "$EUID" -ne 0 ]; then
        log "$LOG_LEVEL_CRITICAL" "This function must be run as root." "$oO_LOG_FILE"
        exit 1
    fi

    # Sicherstellen, dass der Befehl sysctl verfügbar ist
    if ! command -v sysctl &> /dev/null; then
        log "$LOG_LEVEL_CRITICAL" "sysctl command not found." "$oO_LOG_FILE"
        exit 1
    fi

    # Überprüfen, ob die Konfigurationsdatei sicher ist
    if [ -e "$ipv6_conf" ] && [ ! -f "$ipv6_conf" ]; then
        log "$LOG_LEVEL_CRITICAL" "$ipv6_conf exists but is not a regular file." "$oO_LOG_FILE"
        exit 1
    fi

    # Schreiben der IPv6-Konfiguration
    {
        echo "net.ipv6.conf.all.disable_ipv6 = 1"
        echo "net.ipv6.conf.default.disable_ipv6 = 1"
        echo "net.ipv6.conf.lo.disable_ipv6 = 1"
    } > "$ipv6_conf"

    # Anwenden der Änderungen
    if sysctl --system; then
        log "$LOG_LEVEL_INFO" "IPv6 successfully disabled system-wide." "$oO_LOG_FILE"
    else
        log "$LOG_LEVEL_CRITICAL" "Failed to apply sysctl configurations." "$oO_LOG_FILE"
        exit 1
    fi

    # Überprüfung, ob IPv6 deaktiviert wurde
    if sysctl net.ipv6.conf.all.disable_ipv6 | grep -q "1" && \
        sysctl net.ipv6.conf.default.disable_ipv6 | grep -q "1" && \
        sysctl net.ipv6.conf.lo.disable_ipv6 | grep -q "1"; then
        log "$LOG_LEVEL_INFO" "IPv6 successfully disabled and verified." "$oO_LOG_FILE"
    else
        log "$LOG_LEVEL_WARNING" "IPv6 might still be active. Verification failed." "$oO_LOG_FILE"
        echo "Warnung: IPv6 ist noch aktiv!"
    fi
}

preconf_nft() {
    log "$LOG_LEVEL_INFO" "Prüfe, ob nftables installiert ist..." "$oO_LOG_FILE"
    if ! command -v nft &> /dev/null; then
        echo "nftables ist nicht installiert. Installiere nftables..."
        sudo apt update && sudo apt install -y nftables
        if [ $? -ne 0 ]; then
            echo "Fehler: nftables konnte nicht installiert werden!" >&2
            exit 1
        fi
    else
        echo "nftables ist installiert."
    fi

    log "$LOG_LEVEL_INFO" "Prüfe, ob das nf_tables-Modul geladen ist..." "$oO_LOG_FILE"
    if [ ! -d "/sys/module/nf_tables" ]; then
        echo "Das Kernel-Modul nf_tables ist nicht geladen. Lade das Modul..."
        sudo modprobe nf_tables
        if [ $? -ne 0 ]; then
            echo "Fehler: Das Kernel-Modul nf_tables konnte nicht geladen werden!" >&2
            exit 1
        fi
    else
        echo "Das Kernel-Modul nf_tables ist geladen."
    fi

    log "$LOG_LEVEL_INFO" "Prüfe, ob das xt_owner-Modul geladen ist..." "$oO_LOG_FILE"
    if ! lsmod | grep -q "xt_owner"; then
        echo "Das Kernel-Modul xt_owner ist nicht geladen. Lade das Modul..."
        sudo modprobe xt_owner
        if [ $? -ne 0 ]; then
            echo "Fehler: Das Kernel-Modul xt_owner konnte nicht geladen werden!" >&2
            exit 1
        fi
        echo "Füge xt_owner zum Autostart hinzu..."
        echo "xt_owner" | sudo tee -a /etc/modules
    else
        echo "Das Kernel-Modul xt_owner ist geladen."
    fi

    log "$LOG_LEVEL_INFO" "Verifiziere, ob nftables korrekt funktioniert..." "$oO_LOG_FILE"
    sudo nft add table ip test_table
    if [ $? -ne 0 ]; then
        echo "Fehler: nftables konnte keine Test-Tabelle hinzufügen!" >&2
        exit 1
    fi

    output=$(sudo nft list tables | grep "test_table")
    if [[ $output == *"test_table"* ]]; then
        echo "Test-Tabelle erfolgreich erstellt. Verifiziere Regeln..."
        sudo nft list ruleset
        echo "Entferne Test-Tabelle..."
        sudo nft delete table ip test_table
    else
        echo "Fehler: Test-Tabelle konnte nicht erstellt werden!" >&2
        exit 1
    fi

    echo "nftables ist korrekt installiert und funktioniert einwandfrei."
}

dis_cups_p631() {
    # Ausgabe und Logging starten
    log "$LOG_LEVEL_INFO" "[WARNING] Disabling CUPS on port 631!" "$oO_LOG_FILE"
    echo "[WARNING] Disabling CUPS on port 631!"

    # CUPS stoppen
    if sudo systemctl stop cups; then
        log "$LOG_LEVEL_INFO" "CUPS service has been stopped successfully." "$oO_LOG_FILE"
    else 
        log "$LOG_LEVEL_ERROR" "Error! CUPS service could not be stopped!" "$oO_LOG_FILE"
        return 1
    fi
    
    # CUPS deaktivieren
    if sudo systemctl disable cups; then
        log "$LOG_LEVEL_INFO" "CUPS service has been disabled. Port 631 is now closed." "$oO_LOG_FILE"
    else    
        log "$LOG_LEVEL_ERROR" "Error! CUPS service could not be disabled! Port 631 might still be open." "$oO_LOG_FILE"
        return 1
    fi    
}

net_setup
preconf_nft
dis_cups_p631

echo ""
echo "============================================================================="
echo "                           Creating  Configurations                          "
echo "============================================================================="
echo ""

tor_conf() {
    log "$LOG_LEVEL_INFO" "Configuring and enabling Tor..." "$oO_LOG_FILE"

    # Überprüfen, ob Root-Rechte vorhanden sind
    if [ "$EUID" -ne 0 ]; then
        log "$LOG_LEVEL_ERROR" "This script must be run as root." "$oO_LOG_FILE"
        return 1
    fi

    # Überprüfen, ob Tor installiert ist
    if ! command -v tor &> /dev/null; then
        log "$LOG_LEVEL_ERROR" "Tor is not installed. Please install Tor before running this script." "$oO_LOG_FILE"
        return 1
    fi

    # Stoppe den Tor-Dienst, falls aktiv
    if systemctl is-active --quiet tor; then
        log "$LOG_LEVEL_INFO" "Stopping Tor service before reconfiguration..." "$oO_LOG_FILE"
        if ! systemctl stop tor; then
            log "$LOG_LEVEL_ERROR" "Failed to stop Tor service." "$oO_LOG_FILE"
            return 1
        fi
    fi

    # Erstelle das Tor-Verzeichnis, falls nicht vorhanden
    if [ ! -d /etc/tor ]; then
        mkdir -p /etc/tor
        log "$LOG_LEVEL_INFO" "Created /etc/tor directory." "$oO_LOG_FILE"
    fi

    # Überprüfen, ob der Benutzer debian-tor existiert
    if ! id -u debian-tor &>/dev/null; then
        useradd -r -s /bin/false debian-tor
        log "$LOG_LEVEL_INFO" "Created user debian-tor." "$oO_LOG_FILE"
    fi

    # Setze sichere Berechtigungen für /var/lib/tor
    mkdir -p /var/lib/tor
    chmod 700 /var/lib/tor
    chown -R debian-tor:debian-tor /var/lib/tor
    log "$LOG_LEVEL_INFO" "Set permissions for /var/lib/tor." "$oO_LOG_FILE"

    # Setze sichere Berechtigungen für /var/run/tor
    mkdir -p /var/run/tor
    chmod 755 /var/run/tor
    chown debian-tor:debian-tor /var/run/tor
    log "$LOG_LEVEL_INFO" "Set permissions for /var/run/tor." "$oO_LOG_FILE"

    # Schreibe die torrc-Datei sicher
    log "$LOG_LEVEL_INFO" "Writing torrc file..." "$oO_LOG_FILE"
    temp_torrc=$(mktemp)
    cat <<EOF > "$temp_torrc"
# torrc  by GTFD ka5oeze ==================== #
#                                             #                
# 	torrc - tor configuration file        #
#                                             #
# =========================================== #                                                            
# Grundlegende Einstellungen
# ===========================================
User debian-tor
RunAsDaemon 1
PidFile /var/run/tor/tor.pid
DataDirectory /var/lib/tor
Log notice file /var/log/tor/log
SafeLogging 1

# ===========================================
# Netzwerk- und Proxy-Einstellungen
# ===========================================
SocksPort 127.0.0.1:9050 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
TransPort 127.0.0.1:9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
DNSPort 127.0.0.1:5353
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
ClientUseIPv6 0 
ClientDNSRejectInternalAddresses 1

# ===========================================
# ControlPort-Einstellungen
# ===========================================
ControlPort 9051
CookieAuthentication 1
CookieAuthFile /var/lib/tor/control_auth_cookie
# HashedControlPassword 16:ABCDEF1234567890

# ===========================================
# Sicherheits- und Datenschutzoptionen
# ===========================================
DisableDebuggerAttachment 1
AvoidDiskWrites 1
ConnectionPadding 1
ReducedConnectionPadding 1
UseEntryGuards 1
MaxClientCircuitsPending 128
NewCircuitPeriod 30
MaxCircuitDirtiness 600
NumEntryGuards 3
NumDirectoryGuards 3

# ===========================================
# Exit-Policy
# ===========================================
ExitPolicy reject *:*

# ===========================================
# Debugging und Fehlerbehebung
# ===========================================
LogTimeGranularity 1
DisableNetwork 0

# ===========================================
# Hidden Service Konfiguration
# ===========================================
HiddenServiceDir /var/lib/tor/hidden_service/
HiddenServicePort 80 127.0.0.1:80
# HiddenServiceAuthorizeClient stealth client1,client2

# ===========================================
# Reserviert für zukünftige Erweiterungen
# ===========================================
# Bridge-Relay-Konfigurationen können hier hinzugefügt werden, falls benötigt.
EOF

    # Überprüfen, ob die Datei sicher verschoben werden kann
    if ! mv "$temp_torrc" /etc/tor/torrc; then
        log "$LOG_LEVEL_ERROR" "Failed to move temporary torrc file to /etc/tor/torrc." "$oO_LOG_FILE"
        return 1
    fi
    chmod 600 /etc/tor/torrc
    chown debian-tor:adm /etc/tor/torrc
    log "$LOG_LEVEL_INFO" "Tor configuration written successfully." "$oO_LOG_FILE"

    # Überprüfen der Tor-Konfiguration
    if ! tor --verify-config &>> "$oO_LOG_FILE"; then
        log "$LOG_LEVEL_ERROR" "Invalid torrc configuration. Please check the log for details." "$oO_LOG_FILE"
        return 1
    fi

    # Systemd neu laden und Tor-Dienst aktivieren
    log "$LOG_LEVEL_INFO" "Reloading systemd manager configuration..." "$oO_LOG_FILE"
    if ! systemctl daemon-reload; then
        log "$LOG_LEVEL_ERROR" "Failed to reload systemd manager configuration." "$oO_LOG_FILE"
        return 1
    fi

    log "$LOG_LEVEL_INFO" "Enabling Tor service..." "$oO_LOG_FILE"
    if ! systemctl enable tor; then
        log "$LOG_LEVEL_ERROR" "Failed to enable Tor service." "$oO_LOG_FILE"
        return 1
    fi

    log "$LOG_LEVEL_INFO" "Starting Tor service..." "$oO_LOG_FILE"
    if ! systemctl start tor; then
        log "$LOG_LEVEL_ERROR" "Failed to start Tor service." "$oO_LOG_FILE"
        return 1
    fi

    log "$LOG_LEVEL_INFO" "Tor service is running successfully." "$oO_LOG_FILE"
    return 0
}

tor_conf

touch /var/log/tor/log
chmod 644 /var/log/tor/log
chown debian-tor:adm /var/log/tor/log

touch /var/log/tor/security.log
chmod 644 /var/log/tor/security.log
chown debian-tor:adm /var/log/tor/security.log

resolv_conf() {
    log "$LOG_LEVEL_INFO" "Configuring resolv.conf to prevent DNS leaks..." "$oO_LOG_RESOLV"

    # Überprüfen, ob Root-Rechte vorhanden sind
    if [ "$EUID" -ne 0 ]; then
        log "$LOG_LEVEL_ERROR" "This function must be run as root. Insufficient privileges." "$oO_LOG_RESOLV"
        return 1
    fi

    # Überprüfen, ob die Datei ein Symlink ist
    if [ -L /etc/resolv.conf ]; then
        log "$LOG_LEVEL_INFO" "/etc/resolv.conf is a symlink. Replacing it with a regular file." "$oO_LOG_RESOLV"
        target=$(readlink -f /etc/resolv.conf)
        if [ "$target" != "/etc/resolv.conf" ]; then
            log "$LOG_LEVEL_WARNING" "Symlink target of /etc/resolv.conf is $target. Removing it safely." "$oO_LOG_RESOLV"
        fi
        if ! rm -f /etc/resolv.conf; then
            log "$LOG_LEVEL_ERROR" "Failed to remove symlink /etc/resolv.conf. Check permissions." "$oO_LOG_RESOLV"
            return 1
        fi
    fi

    # Schreibe die neue resolv.conf
    local dns_server="127.0.0.1"
    if ! echo "nameserver $dns_server" > /etc/resolv.conf; then
        log "$LOG_LEVEL_ERROR" "Failed to write to /etc/resolv.conf. Check permissions." "$oO_LOG_RESOLV"
        return 1
    fi
    log "$LOG_LEVEL_INFO" "Successfully wrote to /etc/resolv.conf." "$oO_LOG_RESOLV"

    # Setze die Berechtigungen für /etc/resolv.conf
    if ! chmod 644 /etc/resolv.conf; then
        log "$LOG_LEVEL_ERROR" "Failed to set permissions on /etc/resolv.conf. Check permissions." "$oO_LOG_RESOLV"
        return 1
    fi
    if ! chown root:root /etc/resolv.conf; then
        log "$LOG_LEVEL_ERROR" "Failed to set ownership on /etc/resolv.conf. Check permissions." "$oO_LOG_RESOLV"
        return 1
    fi

    # Setze das Immutable-Flag
    if chattr +i /etc/resolv.conf &> /dev/null; then
        log "$LOG_LEVEL_INFO" "Immutable flag set successfully on /etc/resolv.conf." "$oO_LOG_RESOLV"
    else
        log "$LOG_LEVEL_WARNING" "Failed to set immutable flag. Ensure filesystem supports chattr." "$oO_LOG_RESOLV"
    fi

    log "$LOG_LEVEL_INFO" "Resolv configuration completed successfully." "$oO_LOG_RESOLV"
    return 0
}

resolv_conf

touch "$oO_LOG_RESOLV"
chmod 644 "$oO_LOG_RESOLV"
chown root:adm "$oO_LOG_RESOLV"

proxychains_conf() {
    log "$LOG_LEVEL_INFO" "Checking if ProxyChains is installed..." "$oO_LOG_PROXYCHAINS"
    
    # Überprüfen, ob Root-Rechte vorhanden sind
    if [ "$EUID" -ne 0 ]; then
        log "$LOG_LEVEL_ERROR" "This function must be run as root. Insufficient privileges." "$oO_LOG_PROXYCHAINS"
        return 1
    fi

    # Überprüfen, ob ProxyChains installiert ist
    if ! command -v proxychains &> /dev/null; then
        log "$LOG_LEVEL_ERROR" "ProxyChains is not installed. Please install ProxyChains before running this script." "$oO_LOG_PROXYCHAINS"
        return 1
    else
        log "$LOG_LEVEL_INFO" "ProxyChains is already installed." "$oO_LOG_PROXYCHAINS"
    fi

    # Sicherstellen, dass das Verzeichnis für Proxys existiert
    local proxychains_dir="/etc/proxychains"
    if [ -e "$proxychains_dir" ] && [ ! -d "$proxychains_dir" ]; then
        log "$LOG_LEVEL_ERROR" "$proxychains_dir exists but is not a directory. Aborting to prevent potential symlink attacks." "$oO_LOG_PROXYCHAINS"
        return 1
    fi

    if [ ! -d "$proxychains_dir" ]; then
        mkdir -p "$proxychains_dir"
        chmod 755 "$proxychains_dir"
        chown root:root "$proxychains_dir"
        log "$LOG_LEVEL_INFO" "Created directory $proxychains_dir." "$oO_LOG_PROXYCHAINS"
    fi

    # Sicherstellen, dass die ProxyChains-Konfigurationsdatei existiert und sicher ist
    local proxychains_conf="/etc/proxychains.conf"
    if [ -e "$proxychains_conf" ] && [ ! -f "$proxychains_conf" ]; then
        log "$LOG_LEVEL_ERROR" "$proxychains_conf exists but is not a regular file. Aborting to prevent potential symlink attacks." "$oO_LOG_PROXYCHAINS"
        return 1
    fi

    # Konfigurationsdatei immer erstellen oder aktualisieren
    log "$LOG_LEVEL_INFO" "Creating or updating $proxychains_conf file..." "$oO_LOG_PROXYCHAINS"
    cat << 'EOF' > "$proxychains_conf"
# proxychains.conf  by GTFD ka5oeze
#
#        HTTP, SOCKS4, SOCKS5 tunneling proxifier with DNS.
#	
# ###########################################################

# The option below identifies how the ProxyList is treated.
# only one option should be uncommented at time,
# otherwise the last appearing option will be accepted
#
#dynamic_chain
#
# Dynamic - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# at least one proxy must be online to play in chain
# (dead proxies are skipped)
# otherwise EINTR is returned to the app
#
strict_chain
#
# Strict - Each connection will be done via chained proxies
# all proxies chained in the order as they appear in the list
# all proxies must be online to play in chain
# otherwise EINTR is returned to the app
#
#random_chain
#
# Random - Each connection will be done via random proxy
# (or proxy chain, see  chain_len) from the list.
# this option is good to test your IDS :)

# Make sense only if random_chain
#chain_len = 2

# Quiet mode (no output from library)
#quiet_mode

# Proxy DNS requests - no leak for DNS data
proxy_dns 

# Some timeouts in milliseconds
tcp_read_time_out 15000
tcp_connect_time_out 8000

# Remote DNS Subnet
remote_dns_subnet 224

# ProxyList format
#       type  host  port [user pass]
#       (values separated by 'tab' or 'blank')
#        Examples:
#            	socks5	192.168.67.78	1080	lamer	secret
#		http	192.168.89.3	8080	justu	hidden
#	 	socks4	192.168.1.49	1080
#	        http	192.168.39.93	8080	
#		 proxy types: http, socks4, socks5
#        ( auth types supported: "basic"-http  "user/pass"-socks )
#

[ProxyList]

# defaults set to "tor"
socks5  127.0.0.1 9050
EOF

    # Berechtigungen setzen
    if [ ! -f "$proxychains_conf" ]; then
        chmod 644 "$proxychains_conf"
        chown root:root "$proxychains_conf"
        log "$LOG_LEVEL_INFO" "ProxyChains configuration file created and permissions set." "$oO_LOG_PROXYCHAINS"
    else
        log "$LOG_LEVEL_INFO" "ProxyChains configuration file already exists." "$oO_LOG_PROXYCHAINS"
    fi

    log "$LOG_LEVEL_INFO" "ProxyChains configured successfully." "$oO_LOG_PROXYCHAINS"
    return 0
}

proxychains_conf

touch "$oO_LOG_PROXYCHAINS"
chmod 644 "$oO_LOG_PROXYCHAINS"
chown root:adm "$oO_LOG_PROXYCHAINS"

nftables_conf() {
    log "$LOG_LEVEL_INFO" "Configuring nftables..." "$oO_LOG_NFTABLES"
    
    # Überprüfen, ob Root-Rechte vorhanden sind
    if [ "$EUID" -ne 0 ]; then
        log "$LOG_LEVEL_ERROR" "This function must be run as root. Insufficient privileges." "$oO_LOG_NFTABLES"
        return 1
    fi

    # Überprüfen, ob nftables installiert ist
    if ! command -v nft &> /dev/null; then
        log "$LOG_LEVEL_INFO" "nftables is not installed. Please install nftables before running this script." "$oO_LOG_NFTABLES"
        return 1
    fi

    # Bestehende Konfiguration löschen
    log "$LOG_LEVEL_INFO" "Flushing existing nftables rules..." "$oO_LOG_NFTABLES"
    nft flush ruleset

    # Konfiguration für Tor
    virtual_address="10.192.0.0/10"  # Anpassen an deine Netzwerkadresse
    trans_port=9040
    dns_port=5353
    tor_uid=$(id -u debian-tor 2>/dev/null)  # Dein Tor-Benutzer
    if [ -z "$tor_uid" ]; then
        log "The Tor user 'debian-tor' does not exist. Please configure Tor correctly before running this script." "$oO_LOG_NFTABLES"
        return 1
    fi
    non_tor="192.168.0.0/16"

    # nftables-Konfiguration erstellen
    local nftables_conf="/etc/nftables.conf"
    cat << EOF > "$nftables_conf"
#!/usr/sbin/nft -f
flush ruleset

define virtual_address = 10.192.0.0/10
define trans_port = 9040
define dns_port = 5353
define tor_uid = $(id -u debian-tor)
define non_tor = { 192.168.0.0/16 }

# Filter-Tabelle: Eingehender und ausgehender Traffic
table ip filter {
    chain input {
        type filter hook input priority 0; policy drop;     # Standard: Alles blockieren
        ct state established,related accept                 # Erlaube etablierte Verbindungen
        iif lo accept                                       # Erlaube lokalen Verkehr
        drop                                                # Alles andere blockieren
    }

    chain output {
        type filter hook output priority 0; policy drop;        # Standard: Alles blockieren
        ct state invalid drop                                   # Ungültige Verbindungen blockieren
        ct state established,related accept                     # Erlaube etablierte Verbindungen
        meta skuid $tor_uid tcp flags syn ct state new accept   # Erlaube neuen Verkehr für Tor
        ip daddr 127.0.0.1 oif lo accept                        # Erlaube Loopback-Verkehr
        ip daddr 127.0.0.1 tcp dport $trans_port accept     # Erlaube Verkehr zu Tor
        tcp dport 9050 accept                                   # Erlaube SOCKS5 (Port 9050 für Proxychains)
        drop                                                    # Alles andere blockieren
    }
}

# NAT-Tabelle: Weiterleitung und Umleitung
table ip nat {
    chain output {
        type nat hook output priority 0; policy accept; # Standard: Alles erlauben
        ip daddr $virtual_address tcp flags syn redirect to :$trans_port    # TCP-Verkehr zu Tor umleiten
        ip daddr 127.0.0.1 udp dport 53 redirect to :$dns_port              # DNS zu Tor umleiten
        meta skuid $tor_uid return                                          # Verkehr von Tor-Benutzer zurückgeben
        oif lo return                                                       # Lokalen Verkehr zurückgeben
        ip daddr $non_tor return                                            # Lokales Netzwerk erlauben
        ip protocol tcp redirect to :$trans_port                            # Weiterleitung aller anderen TCP-Verbindungen
    }
}
EOF

    chmod 600 "$nftables_conf"
    chown root:root "$nftables_conf"
    log "$LOG_LEVEL_INFO" "Successfully created nftables configuration at $nftables_conf." "$oO_LOG_NFTABLES"

    # Regeln laden
    log "$LOG_LEVEL_INFO" "Loading nftables configuration..." "$oO_LOG_NFTABLES"
    if ! nft -f "$nftables_conf"; then
        log "$LOG_LEVEL_ERROR" "Failed to load nftables configuration." "$oO_LOG_NFTABLES"
        return 1
    fi

    # nftables-Dienst aktivieren
    log "$LOG_LEVEL_INFO" "Enabling nftables service..." "$oO_LOG_NFTABLES"
    systemctl enable nftables
    if ! systemctl restart nftables; then
        log "$LOG_LEVEL_ERROR" "Failed to restart nftables service." "$oO_LOG_NFTABLES"
        return 1
    fi

    log "$LOG_LEVEL_INFO" "nftables configuration completed successfully." "$oO_LOG_NFTABLES"
}

nftables_conf

touch "$oO_LOG_NFTABLES"
chmod 644 "$oO_LOG_NFTABLES"
chown root:adm "$oO_LOG_NFTABLES"

status() {
    log "$LOG_LEVEL_INFO" "Statusabfrage der Dienste..." "$oO_LOG_FILE"

    log "$LOG_LEVEL_INFO" "Prüfe Tor-Dienst..."
    if ! systemctl status tor &>/dev/null; then
        log $LOG_LEVEL_ERROR "Tor service failed to start." "$oO_LOG_FILE"
        echo "Tor-Dienst konnte nicht gestartet werden. Siehe Log-Datei für Details."
    else
        log "$LOG_LEVEL_INFO" "Tor-Dienst läuft einwandfrei." "$oO_LOG_FILE"
    fi

    log "$LOG_LEVEL_INFO" "Prüfe nftables-Regeln..." "$oO_LOG_FILE"
    if ! nft list ruleset &>/dev/null; then
        log $LOG_LEVEL_ERROR "Failed to apply nftables rules." "$oO_LOG_NFTABLES"
        echo "nftables-Regeln konnten nicht angewendet werden. Siehe Log-Datei für Details."
    else
        log "$LOG_LEVEL_INFO" "nftables-Regeln erfolgreich angewendet." "$oO_LOG_FILE"
    fi
}

status

echo "============================================================================="
echo "                                 Setup Check                                 "
echo "============================================================================="

verifier() {
    echo "===================================="
    echo "#             nmap scan            #"
    echo "===================================="

    # Funktion zur Überprüfung offener Ports mit nmap
    nmap_check() {
        if ! command -v nmap &>/dev/null; then
            echo "nmap ist nicht installiert. Bitte installieren Sie nmap, um die Ports zu überprüfen."
            log $LOG_LEVEL_ERROR "nmap is not installed. Port scan cannot be performed." "$oO_LOG_FILE"
            return 1
        fi

        if nmap 127.0.0.1; then
            echo "nmap scan completed successfully."
        else
            echo "Error: nmap scan failed."
            return 1
        fi
    }

    nmap_check
    
    echo "===================================="
    echo "#            check IP              #"
    echo "===================================="
  
    # Funktion zum Überprüfen auf DNS-Lecks
    ip_check() {

        # Kostenlose IP-Details-API
        local test_url
        test_url="http://ip-api.com/json/"

        # Test durchführen und JSON-Daten abrufen
        result=$(curl -s $test_url)

        if [[ -n "$result" ]]; then
            # Mit jq JSON-Daten extrahieren
            ip=$(echo "$result" | jq -r '.query')
            isp=$(echo "$result" | jq -r '.isp')
            country=$(echo "$result" | jq -r '.country')
            timezone=$(echo "$result" | jq -r '.timezone')

            # Ergebnisse anzeigen
            echo "IP: $ip"
            echo "ISP: $isp"
            echo "Land: $country"
            echo "Zeitzone: $timezone"
            log "$LOG_LEVEL_INFO" "IP: $ip" "$oO_LOG_FILE"
            log "$LOG_LEVEL_INFO" "ISP: $isp" "$oO_LOG_FILE"
            log "$LOG_LEVEL_INFO" "Land: $country" "$oO_LOG_FILE"
            log "$LOG_LEVEL_INFO" "Zeitzone: $timezone" "$oO_LOG_FILE"
        else
            echo "Konnte keine Ergebnisse abrufen. Bitte überprüfen Sie Ihre Verbindung oder die Website."
        fi
    }

    ip_check
}

verifier

log "$LOG_LEVEL_INFO" "#############################################################################" "$oO_LOG_FILE"
log "$LOG_LEVEL_INFO" "=============================================================================" "$oO_LOG_FILE"

echo "#############################################################################"
echo "============================================================================="

# Endzeit des Skripts berechnen
script_end_time=$(date +%s)
script_duration=$((script_end_time - script_start_time))
duration_formatted=$(printf '%02d:%02d:%02d' $((script_duration/3600)) $((script_duration%3600/60)) $((script_duration%60)))

# Loggen der Abschlussnachricht
log "$LOG_LEVEL_INFO" "Script execution completed! Total runtime: $duration_formatted (hh:mm:ss)" "$oO_LOG_FILE"
echo  "Script execution completed! Total runtime: $duration_formatted (hh:mm:ss)"
