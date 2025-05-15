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
log "oO_LOG_FILE=$oO_LOG_FILE" "$oO_LOG_FILE"
log "oO_LOG_PATH=$oO_LOG_PATH" "$oO_LOG_FILE"
log "oO_LOG_RESOLV=$oO_LOG_RESOLV" "$oO_LOG_FILE"
log "oO_LOG_PROXYFETCH=$oO_LOG_PROXYFETCH" "$oO_LOG_FILE"
log "oO_LOG_PROXYCHAINS=$oO_LOG_PROXYCHAINS" "$oO_LOG_FILE"
log "oO_LOG_NFTABLES=$oO_LOG_NFTABLES" "$oO_LOG_FILE" 

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
    log "Checking if libcurl4 is installed..." "$oO_LOG_FILE"

    # Überprüfen, ob das Skript mit Root-Rechten ausgeführt wird
    if [ "$EUID" -ne 0 ]; then
        log $LOG_LEVEL_CRITICAL "This function must be run as root. Aborting." "$oO_LOG_FILE"
        exit 1
    fi

    # Sicherstellen, dass alle erforderlichen Befehle vorhanden sind
    required_commands=("dpkg" "apt" "grep")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log $LOG_LEVEL_CRITICAL "Required command $cmd not found. Aborting." "$oO_LOG_FILE"
            exit 1
        fi
    done

    # Lockfile, um Race Conditions zu vermeiden
    local lockfile
    lockfile="/tmp/remover.lock.$(basename "$0").$$"
    if [ -e "$lockfile" ]; then
        log $LOG_LEVEL_CRITICAL "Another instance of the remover function is already running. Aborting." "$oO_LOG_FILE"
        exit 1
    fi
    touch "$lockfile"
    trap 'rm -f "$lockfile"' EXIT

    # APT-Sperre behandeln
    local lock_wait_time=0
    local max_lock_wait_time=60  # Timeout: 60 Sekunden
    while fuser /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        if [ $lock_wait_time -ge $max_lock_wait_time ]; then
            log $LOG_LEVEL_CRITICAL "APT is locked for more than $max_lock_wait_time seconds. Aborting." "$oO_LOG_FILE"
            exit 1
        fi
        log "$LOG_LEVEL_WARNING" "APT is locked by another process. Retrying in 5 seconds..." "$oO_LOG_FILE"
        sleep 5
        lock_wait_time=$((lock_wait_time + 5))
    done

    # Überprüfen, ob libcurl4 installiert ist
    if dpkg -l | grep -q "^ii.*libcurl4"; then
        log "libcurl4 is installed. Attempting to remove it for better compatibility with curl install..." "$oO_LOG_FILE"

        local attempts=0
        local max_attempts=3
        while [ $attempts -lt $max_attempts ]; do
            if timeout 180 /usr/bin/apt remove --purge -y curl libcurl4; then
                log "libcurl4 was successfully removed. curl will now be installed with the oO-Package." "$oO_LOG_FILE"
                return 0
            else
                attempts=$((attempts + 1))
                log "Failed to remove libcurl4. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$oO_LOG_FILE"
                sleep $((attempts * 5))
            fi
        done

        log $LOG_LEVEL_CRITICAL "Failed to remove libcurl4 after $max_attempts attempts. Please check for errors in the package manager logs." "$oO_LOG_FILE"
        return 1
    else
        log "libcurl4 is not installed. Skipping removal." "$oO_LOG_FILE"
    fi
}

installer() {
    log "Starting package installation..." "$oO_LOG_FILE"

    local attempts=0
    local max_attempts=3
    local critical_packages=("curl" "tor" "nmap" "resolvconf" "nftables" "proxychains" "apt-transport-https" "jq" "git" "gzip" "iproute2" "nginx" "coreutils" "certbot" "python3-certbot-nginx" "ca-certificates")

    # APT-Sperre behandeln
    while fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        log "$LOG_LEVEL_WARNING" "APT is locked by another process. Retrying in 5 seconds..." "$oO_LOG_FILE"
        sleep 5
    done

    while [ $attempts -lt $max_attempts ]; do
        log "Updating package lists..." "$oO_LOG_FILE"
        if ! apt update -y; then
            log "Failed to update package lists. Attempt $((attempts + 1)) of $max_attempts." "$oO_LOG_FILE"
            attempts=$((attempts + 1))
            sleep $((attempts * 5))
            continue
        fi

        log "Installing packages: ${critical_packages[*]}..." "$oO_LOG_FILE"
        if apt install -y "${critical_packages[@]}"; then
            log "Packages installed successfully." "$oO_LOG_FILE"

            # Überprüfen, ob alle kritischen Pakete installiert sind
            for pkg in "${critical_packages[@]}"; do
                if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "installed"; then
                    log "Critical package $pkg is missing or not fully installed. Aborting." "$oO_LOG_FILE"
                    return 1
                fi
            done

            log "All critical packages verified." "$oO_LOG_FILE"

            # Bereinige temporäre Dateien
            log "Cleaning up temporary apt files..." "$oO_LOG_FILE"
            if ! apt clean; then
                log "$LOG_LEVEL_WARNING" "Failed to clean up temporary apt files." "$oO_LOG_FILE"
            fi

            return 0
        else
            attempts=$((attempts + 1))
            log "Failed to install packages. Attempt $attempts of $max_attempts. Retrying in $((attempts * 5)) seconds..." "$oO_LOG_FILE"
            sleep $((attempts * 5))
        fi
    done

    log "Failed to install packages after $max_attempts attempts. Please check your network connection and try again." "$oO_LOG_FILE"
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
    log "Starting network setup..." "$oO_LOG_FILE"

    # Erkennen und Festlegen der primären Netzwerkschnittstelle
    log "Detecting primary network interface..." "$oO_LOG_FILE"
    local primary_interface
    local fallback_interfaces=("eth0" "wlan0")
    
    # Versuchen, die primäre Schnittstelle aus der Standardroute zu erhalten
    primary_interface=$(ip route | grep default | awk '{print $5}')
    if [ -z "$primary_interface" ]; then
        log "$LOG_LEVEL_WARNING" "PRIMARY_INTERFACE is not set. Attempting to use fallback interfaces." "$oO_LOG_FILE"
        for fallback in "${fallback_interfaces[@]}"; do
            if ip link show "$fallback" > /dev/null 2>&1; then
                primary_interface="$fallback"
                log "Fallback to $fallback as PRIMARY_INTERFACE." "$oO_LOG_FILE"
                break
            fi
        done

        if [ -z "$primary_interface" ]; then
            log $LOG_LEVEL_CRITICAL "No valid network interface found. Please check your network settings." "$oO_LOG_FILE"
            exit 1
        fi
    fi
    log "Detected primary interface: $primary_interface" "$oO_LOG_FILE"

    # Erkennen und Festlegen des lokalen IP-Bereichs
    log "Detecting local IP range..." "$oO_LOG_FILE"
    local local_ip
    local ip_prefix
    local allowed_ip_range

    local_ip=$(ip -o -4 addr show "$primary_interface" | awk '{print $4}' | cut -d/ -f1)
    if [ -z "$local_ip" ]; then
        log $LOG_LEVEL_CRITICAL "Unable to determine local IP address for interface $primary_interface." "$oO_LOG_FILE"
        exit 1
    fi

    if [[ ! "$local_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log $LOG_LEVEL_CRITICAL "Invalid IP address detected: $local_ip" "$oO_LOG_FILE"
        exit 1
    fi

    ip_prefix=$(echo "$local_ip" | cut -d. -f1-3)
    allowed_ip_range="$ip_prefix.0/24"
    log "Detected IP range: $allowed_ip_range (Interface: $primary_interface, IP: $local_ip)" "$oO_LOG_FILE"

    # Exportieren der primären Schnittstelle und des IP-Bereichs
    export PRIMARY_INTERFACE="$primary_interface"
    export ALLOWED_IP_RANGE="$allowed_ip_range"

    # IPv6 systemweit deaktivieren
    log "Disabling IPv6 system-wide..." "$oO_LOG_FILE"
    local ipv6_conf="/etc/sysctl.d/99-disable-ipv6.conf"

    # Überprüfen, ob das Skript mit Root-Rechten ausgeführt wird
    if [ "$EUID" -ne 0 ]; then
        log $LOG_LEVEL_CRITICAL "This function must be run as root." "$oO_LOG_FILE"
        exit 1
    fi

    # Sicherstellen, dass der Befehl sysctl verfügbar ist
    if ! command -v sysctl &> /dev/null; then
        log $LOG_LEVEL_CRITICAL "sysctl command not found." "$oO_LOG_FILE"
        exit 1
    fi

    # Überprüfen, ob die Konfigurationsdatei sicher ist
    if [ -e "$ipv6_conf" ] && [ ! -f "$ipv6_conf" ]; then
        log $LOG_LEVEL_CRITICAL "$ipv6_conf exists but is not a regular file." "$oO_LOG_FILE"
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
        log "IPv6 successfully disabled system-wide." "$oO_LOG_FILE"
    else
        log $LOG_LEVEL_CRITICAL "Failed to apply sysctl configurations." "$oO_LOG_FILE"
        exit 1
    fi

    # Überprüfung, ob IPv6 deaktiviert wurde
    if sysctl net.ipv6.conf.all.disable_ipv6 | grep -q "1" && \
        sysctl net.ipv6.conf.default.disable_ipv6 | grep -q "1" && \
        sysctl net.ipv6.conf.lo.disable_ipv6 | grep -q "1"; then
        log "IPv6 successfully disabled and verified." "$oO_LOG_FILE"
    else
        log "$LOG_LEVEL_WARNING" "IPv6 might still be active. Verification failed." "$oO_LOG_FILE"
        echo "Warnung: IPv6 ist noch aktiv!"
    fi
}

preconf_nft() {
    log "Prüfe, ob nftables installiert ist..." "$oO_LOG_FILE"
    if ! command -v nft &> /dev/null; then
        echo "nftables ist nicht installiert. Installiere nftables..."
        sudo apt update && sudo apt install -y nftables
        if ! my_command; then
            echo "Fehler: nftables konnte nicht installiert werden!" >&2
            exit 1
        fi
    else
        echo "nftables ist installiert."
    fi

    log "Prüfe, ob das nf_tables-Modul geladen ist..." "$oO_LOG_FILE"
    if [ ! -d "/sys/module/nf_tables" ]; then
        echo "Das Kernel-Modul nf_tables ist nicht geladen. Lade das Modul..."
        sudo modprobe nf_tables
        if ! my_command; then
            echo "Fehler: Das Kernel-Modul nf_tables konnte nicht geladen werden!" >&2
            exit 1
        fi
    else
        echo "Das Kernel-Modul nf_tables ist geladen."
    fi

    log "Prüfe, ob das xt_owner-Modul geladen ist..." "$oO_LOG_FILE"
    if ! lsmod | grep -q "xt_owner"; then
        echo "Das Kernel-Modul xt_owner ist nicht geladen. Lade das Modul..."
        sudo modprobe xt_owner
        if ! my_command; then
            echo "Fehler: Das Kernel-Modul xt_owner konnte nicht geladen werden!" >&2
            exit 1
        fi
        echo "Füge xt_owner zum Autostart hinzu..."
        echo "xt_owner" | sudo tee -a /etc/modules
    else
        echo "Das Kernel-Modul xt_owner ist geladen."
    fi

    log "Verifiziere, ob nftables korrekt funktioniert..." "$oO_LOG_FILE"
    sudo nft add table ip test_table
    if ! my_command; then
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
    log "Configuring and enabling Tor..." "$oO_LOG_FILE"

    # Überprüfen, ob Root-Rechte vorhanden sind
    if [ "$EUID" -ne 0 ]; then
        log "This script must be run as root." "$oO_LOG_FILE"
        return 1
    fi

    # Überprüfen, ob Tor installiert ist
    if ! command -v tor &> /dev/null; then
        log "Tor is not installed. Please install Tor before running this script." "$oO_LOG_FILE"
        return 1
    fi

    # Stoppe den Tor-Dienst, falls aktiv
    if systemctl is-active --quiet tor; then
        log "Stopping Tor service before reconfiguration..." "$oO_LOG_FILE"
        if ! systemctl stop tor; then
            log "Failed to stop Tor service." "$oO_LOG_FILE"
            return 1
        fi
    fi

    # Erstelle das Tor-Verzeichnis, falls nicht vorhanden
    if [ ! -d /etc/tor ]; then
        mkdir -p /etc/tor
        log "Created /etc/tor directory." "$oO_LOG_FILE"
    fi

    # Überprüfen, ob der Benutzer debian-tor existiert
    if ! id -u debian-tor &>/dev/null; then
        useradd -r -s /bin/false debian-tor
        log "Created user debian-tor." "$oO_LOG_FILE"
    fi

    # Setze sichere Berechtigungen für /var/lib/tor
    mkdir -p /var/lib/tor
    chmod 700 /var/lib/tor
    chown -R debian-tor:debian-tor /var/lib/tor
    log "Set permissions for /var/lib/tor." "$oO_LOG_FILE"

    # Setze sichere Berechtigungen für /var/run/tor
    mkdir -p /var/run/tor
    chmod 755 /var/run/tor
    chown debian-tor:debian-tor /var/run/tor
    log "Set permissions for /var/run/tor." "$oO_LOG_FILE"

    # Schreibe die torrc-Datei sicher
    log "Writing torrc file..." "$oO_LOG_FILE"
    temp_torrc=$(mktemp)
    cat <<EOF > "$temp_torrc"
# torrc by GTFD ka5oeze ===================== #
#                                             #
#       torrc - tor configuration file        #
#                                             #
# =========================================== #
#
# Diese Datei enthält die Konfigurationseinstellungen für den Tor-Dienst, der aus dem Quellcode kompiliert wurde. 
# Sie wird verwendet, um das Verhalten und die Funktionalität des Tor-Dienstes zu steuern. 
# Eine Quellcode-kompilierte Installation bedeutet, dass der Tor-Dienst nicht über ein vorkompiliertes Paket 
# (wie z. B. über einen Paketmanager wie APT auf Debian-basierten Systemen) installiert wurde, sondern direkt aus dem Quellcode 
# kompiliert wurde. Dies bietet mehr Flexibilität und Kontrolle über die Version und die spezifischen Build-Optionen. 
# Der Vorteil dieses Ansatzes liegt darin, dass der Benutzer die Möglichkeit hat, Tor mit spezifischen Anpassungen 
# oder zusätzlichen Funktionen zu kompilieren, die in den Standardpaketen möglicherweise nicht enthalten sind. 
# Beispiele hierfür könnten experimentelle Funktionen, Debugging-Optionen oder spezielle Sicherheitsanpassungen sein.
# Diese Konfigurationsdatei ist das zentrale Steuerungsinstrument für den Dienst. Durch die Definition von Parametern 
# in dieser Datei können grundlegende Einstellungen (z. B. Benutzerrechte, Datenverzeichnisse und Logging), Netzwerk- 
# und Sicherheitsoptionen, Exit-Policies sowie Debugging-Parameter angepasst werden. 
# Es ist wichtig, die Datei korrekt zu konfigurieren, da fehlerhafte Einstellungen dazu führen können, dass der Tor-Dienst 
# nicht startet oder nicht wie gewünscht funktioniert. Administratoren sollten daher sicherstellen, dass die Datei sowohl 
# funktional korrekt als auch sicherheitsbewusst konfiguriert ist, insbesondere wenn der Dienst in sensiblen Umgebungen 
# oder für öffentliche Zwecke genutzt wird.
# Wenn der Dienst für spezielle Funktionen wie Hidden Services oder Bridge-Relays erweitert werden soll, können diese 
# Anpassungen ebenfalls in dieser Datei vorgenommen werden. Sie bietet somit eine zentrale und flexible Möglichkeit, 
# den Betrieb des Tor-Dienstes zu steuern und zu optimieren.
                                                            
# ===========================================
# #      Grundlegende Einstellungen
# ===========================================
#
# Dieser Abschnitt enthält die grundlegenden Konfigurationseinstellungen für den Tor-Dienst. 
# Diese Parameter legen fest, wie der Dienst ausgeführt wird, wo er Daten speichert und wie er sich verhält.
# Der Parameter "User" definiert den Benutzer, unter dem der Tor-Dienst ausgeführt wird. In diesem Fall ist es "debian-tor", 
# ein dediziertes Benutzerkonto, das in vielen Linux-Systemen speziell für den Tor-Dienst eingerichtet wird. 
# Dies ist eine Sicherheitsmaßnahme, da der Dienst nicht mit Administratorrechten laufen sollte, um das Risiko 
# von Sicherheitslücken zu minimieren.
# Mit "RunAsDaemon" wird festgelegt, ob Tor als Hintergrunddienst (Daemon) ausgeführt wird. Ein Wert von "1" bedeutet, 
# dass Tor im Hintergrund arbeitet, was ideal ist, wenn der Dienst kontinuierlich laufen soll, ohne dass er an eine 
# spezifische Benutzerkonsole gebunden ist.
# Die Option "PidFile" gibt den Speicherort der Datei an, in der die Prozess-ID (PID) des laufenden Tor-Dienstes gespeichert wird. 
# Diese Datei, in diesem Fall "/var/run/tor/tor.pid", ist nützlich, um den Prozess eindeutig zu identifizieren. 
# Sie wird häufig von Verwaltungstools verwendet, um den Dienst zu starten, zu stoppen oder neu zu starten.
# Der Parameter "DataDirectory" gibt das Verzeichnis an, in dem Tor seine Daten speichert, einschließlich seiner Schlüssel, 
# Caches und anderer statusbezogener Informationen. Hier wird "/var/lib/tor" verwendet, ein typisches Verzeichnis für 
# persistenten Speicher, das sicherstellen sollte, dass nur der "debian-tor"-Benutzer Zugriff darauf hat.
# Mit der Option "Log" wird die Protokollierung des Tor-Dienstes konfiguriert. Der Wert "notice" gibt an, dass 
# wichtige Ereignisse, aber keine zu detaillierten Debugging-Informationen geloggt werden. Die Protokolle werden in der Datei 
# "/var/log/tor/log" gespeichert. Dies ermöglicht es dem Administrator, die Aktivitäten des Dienstes zu überwachen 
# und potenzielle Probleme zu erkennen.
# Schließlich steuert "SafeLogging", ob sensible Informationen in den Logs verborgen werden. Ein Wert von "1" 
# sorgt dafür, dass sensible Daten wie IP-Adressen oder Verbindungsdetails nicht in den Logs auftauchen. 
# Dies ist besonders nützlich, um Datenschutzrichtlinien einzuhalten oder Tools wie Fail2Ban sicher zu verwenden, 
# ohne private Informationen preiszugeben.

User debian-tor
RunAsDaemon 1
PidFile /var/run/tor/tor.pid
DataDirectory /var/lib/tor
Log notice file /var/log/tor/log
Log warn file /var/log/tor/security.log
SafeLogging 1  # Logs enthalten vollständige Informationen für Debugging (z. B. Fail2Ban)

# ===========================================
# #    Netzwerk- und Proxy-Einstellungen
# ===========================================
#
# In dieser Sektion werden die Netzwerk- und Proxy-Einstellungen des Tor-Dienstes definiert. 
# Diese Optionen steuern, wie der Dienst Anfragen verarbeitet, weiterleitet und mit anderen Netzwerken interagiert.
# Der Parameter "SocksPort" legt die Adresse und den Port für den SOCKS-Proxy fest. In diesem Fall wird der SOCKS-Proxy
# auf der IP-Adresse "127.0.0.1" (localhost) und dem Port "9050" bereitgestellt. Der SOCKS-Proxy fungiert als 
# Schnittstelle zwischen Anwendungen, die das Tor-Netzwerk verwenden möchten, und dem Tor-Dienst. Zusätzlich werden 
# hier mehrere Isolierungsfunktionen aktiviert: 
# - "IsolateClientAddr" stellt sicher, dass Anfragen basierend auf der Absender-IP isoliert werden. 
# - "IsolateClientProtocol" isoliert Anfragen basierend auf dem verwendeten Protokoll (z. B. HTTP oder FTP). 
# - "IsolateDestAddr" sorgt dafür, dass Anfragen basierend auf der Zieladresse isoliert werden. 
# - "IsolateDestPort" isoliert Anfragen basierend auf dem Zielport. 
# Diese Isolierungsoptionen erhöhen die Privatsphäre, da sie verhindern, dass unterschiedliche Verbindungen miteinander verknüpft werden.
# Der "TransPort"-Parameter definiert einen transparenten Proxy, der ebenfalls auf der Adresse "127.0.0.1" und Port "9040"
# läuft. Ein transparenter Proxy ermöglicht es, den Datenverkehr automatisch über Tor zu leiten, ohne dass die Anwendung 
# explizit den SOCKS-Proxy verwenden muss. Auch hier werden die Isolierungsoptionen verwendet, um die Privatsphäre zu maximieren.
# Mit "DNSPort" wird ein lokaler DNS-Proxy auf "127.0.0.1" und Port "5353" eingerichtet. Dieser Proxy leitet DNS-Anfragen
# über das Tor-Netzwerk, wodurch die tatsächliche Quelle der DNS-Anfrage anonymisiert wird. Dies verhindert DNS-Leaks, 
# bei denen externe DNS-Server die echte IP-Adresse des Nutzers sehen könnten.
# Die Option "VirtualAddrNetworkIPv4" definiert einen virtuellen IPv4-Adressbereich, der für Hosts verwendet wird, 
# die über das Tor-Netzwerk aufgelöst werden. Der Bereich "10.192.0.0/10" wird hier spezifiziert und dient als Platzhalter 
# für Adressen, die über Tor aufgelöst werden.
# Mit "AutomapHostsOnResolve" wird festgelegt, dass Tor automatisch virtuelle Adressen für aufgelöste Hosts zuweist.
# Dies ist nützlich, wenn Anwendungen mit virtuellen Adressen arbeiten müssen, die über Tor aufgelöst wurden.
# Der Parameter "ClientUseIPv6" deaktiviert IPv6-Unterstützung (Wert "0"), was sinnvoll sein kann, wenn keine IPv6-Verbindungen benötigt werden
# oder um Kompatibilitätsprobleme zu vermeiden.
# Schließlich legt "ClientDNSRejectInternalAddresses" fest, dass DNS-Anfragen an interne Adressen (z. B. lokale Netzwerke 
# wie 192.168.x.x oder 10.x.x.x) abgelehnt werden. Diese Einstellung schützt vor potenziellen DNS-Leaks und stellt sicher,
# dass keine Anfragen an interne Netzwerke gesendet werden, die möglicherweise sensible Informationen preisgeben könnten.

SocksPort 127.0.0.1:9050 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
TransPort 127.0.0.1:9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
DNSPort 127.0.0.1:5353
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
ClientUseIPv6 0  # IPv6 deaktivieren, falls nicht verwendet
ClientDNSRejectInternalAddresses 1  # Schutz vor DNS-Leaks

# ===========================================
# #      ControlPort-Einstellungen
# ===========================================
#
# In dieser Sektion werden die Einstellungen für den ControlPort des Tor-Dienstes definiert. 
# Der ControlPort ist eine Schnittstelle, die es ermöglicht, Tor programmgesteuert zu steuern und zu überwachen. 
# Dies wird häufig von Anwendungen wie Tor-Controllern oder Skripten verwendet, die erweiterte Funktionen wie 
# das Erstellen neuer Verbindungen oder das Abfragen von Statusinformationen benötigen.
# Mit dem Parameter "ControlPort" wird der Port festgelegt, auf dem der ControlPort lauscht. In diesem Fall ist 
# es der Port "9051", der standardmäßig von vielen Anwendungen genutzt wird, um mit Tor zu kommunizieren.
# Die Option "CookieAuthentication" aktiviert die Cookie-basierte Authentifizierung für den Zugriff auf den ControlPort. 
# Wenn dieser Wert auf "1" gesetzt ist, wird ein Authentifizierungs-Cookie verwendet, das sicherstellt, dass nur Prozesse, 
# die Zugriff auf die Datei mit dem Cookie haben, mit dem ControlPort kommunizieren können. Dies ist eine sichere Methode, 
# da nur autorisierte Benutzer mit Zugriff auf die Cookie-Datei mit dem Tor-Dienst interagieren können.
# Der Parameter "CookieAuthFile" gibt den Speicherort der Datei an, die das Authentifizierungs-Cookie enthält. 
# In diesem Fall wird das Cookie in der Datei "/var/lib/tor/control_auth_cookie" gespeichert. 
# Diese Datei sollte mit eingeschränkten Berechtigungen versehen sein, um unbefugten Zugriff zu verhindern.
# Optional kann auch ein Passwort für die Authentifizierung am ControlPort verwendet werden. Dies wird durch den Parameter 
# "HashedControlPassword" ermöglicht, der einen gehashten Passwortwert enthält. Ein Beispielwert wird hier kommentiert angegeben 
# ("16:ABCDEF1234567890"). Falls diese Option verwendet wird, müssen sich Anwendungen mit dem entsprechenden Passwort 
# am ControlPort anmelden. Diese Methode kann als Alternative oder Ergänzung zur Cookie-Authentifizierung genutzt werden, 
# insbesondere in Szenarien, in denen mehrere Benutzer oder Systeme Zugriff auf den ControlPort benötigen.

ControlPort 9051
CookieAuthentication 1
CookieAuthFile /var/lib/tor/control_auth_cookie
# HashedControlPassword 16:ABCDEF1234567890  # Optional: Passwort-Authentifizierung für ControlPort

# ===========================================
# #  Sicherheits- und Datenschutzoptionen
# ===========================================
#
# Diese Sektion widmet sich den Einstellungen, die die Sicherheit und den Datenschutz bei der Nutzung des Tor-Dienstes verbessern sollen.
# Die Konfigurationen in diesem Abschnitt minimieren potenzielle Angriffsflächen, erhöhen die Anonymität und optimieren die Sicherheit
# der Verbindungen.
# Der Parameter "DisableDebuggerAttachment" legt fest, ob Debugger an den Tor-Prozess angehängt werden können. Mit dem Wert "1" 
# wird dies verhindert, was die Sicherheit erhöht, da Angreifer keine Debugger verwenden können, um Informationen über den laufenden 
# Prozess oder dessen Speicher zu erhalten.
# Mit "AvoidDiskWrites" wird festgelegt, dass Tor versuchen soll, keine Daten auf die Festplatte zu schreiben. Der Wert "1" minimiert 
# die Schreibvorgänge und sorgt dafür, dass sensible Daten nur im Arbeitsspeicher gehalten werden. Dies ist besonders wichtig, um 
# Spuren auf dem System zu vermeiden, falls es kompromittiert wird.
# Die Option "ConnectionPadding" aktiviert ein Verfahren, um das Traffic-Profiling zu erschweren. Mit dem Wert "1" fügt Tor sogenannte 
# "Padding-Daten" (also zusätzliche Datenpakete) zu Verbindungen hinzu, um es Dritten zu erschweren, die tatsächlichen Kommunikationsmuster 
# eines Nutzers zu analysieren. Dies schützt die Anonymität, kann jedoch die Bandbreite geringfügig erhöhen.
# "ReducedConnectionPadding" ist eine Ergänzung zu "ConnectionPadding". Wenn dieser Parameter auf "1" gesetzt ist, wird der Bandbreitenverbrauch 
# reduziert, während weiterhin Padding-Daten hinzugefügt werden. Dies ist nützlich, um ein Gleichgewicht zwischen Datenschutz und 
# Bandbreitennutzung zu schaffen.
# Der Parameter "UseEntryGuards" sorgt dafür, dass sogenannte "Entry Guards" verwendet werden. Dies sind vertrauenswürdige Einstiegsknoten, 
# die für eine gewisse Zeit konstant bleiben. Dadurch wird das Risiko verringert, dass ein Angreifer durch häufigen Wechsel der Einstiegsknoten 
# die Anonymität des Nutzers kompromittiert.
# Mit "MaxClientCircuitsPending" wird die maximale Anzahl von wartenden Verbindungsanfragen festgelegt, die auf die Erstellung eines neuen 
# Circuits (eines virtuellen Pfades durch das Tor-Netzwerk) warten. Der Wert "128" sorgt dafür, dass genügend Anfragen gleichzeitig verarbeitet 
# werden können, ohne die Leistung zu beeinträchtigen.
# Der Parameter "NewCircuitPeriod" gibt die Zeit in Sekunden an, nach der ein neuer Circuit erstellt wird. Der Wert "30" bedeutet, dass alle 
# 30 Sekunden ein neuer Circuit aufgebaut wird, um die Anonymität weiter zu erhöhen.
# "MaxCircuitDirtiness" legt fest, wie lange ein Circuit maximal für Datenverkehr genutzt werden darf, bevor er geschlossen wird. Der Wert "600" 
# Sekunden (10 Minuten) stellt sicher, dass Circuits nicht zu lange bestehen bleiben, was die Wahrscheinlichkeit verringert, dass sie deanonymisiert 
# werden können.
# Die Option "NumEntryGuards" gibt an, wie viele Entry Guards gleichzeitig verwendet werden. Der Wert "3" sorgt für eine Balance zwischen 
# Sicherheit und Redundanz, da mehrere Einstiegsknoten genutzt werden, aber nicht zu viele, um das Risiko zu minimieren.
# Schließlich definiert "NumDirectoryGuards" die Anzahl der Verzeichnisknoten, die für den Zugriff auf das Tor-Verzeichnis genutzt werden. 
# Auch hier wird der Wert "3" gewählt, um eine gute Balance zwischen Sicherheit und Verfügbarkeit zu gewährleisten.

DisableDebuggerAttachment 1  # Verhindert Debugger-Zugriff
AvoidDiskWrites 1  # Minimiert Schreibvorgänge auf die Festplatte
ConnectionPadding 1  # Schutz vor Traffic-Profiling
ReducedConnectionPadding 1  # Spart Bandbreite bei aktiviertem ConnectionPadding
UseEntryGuards 1  # Stellt sicher, dass Entry Guards verwendet werden
MaxClientCircuitsPending 128
NewCircuitPeriod 30
MaxCircuitDirtiness 600
NumEntryGuards 3
NumDirectoryGuards 3

# ===========================================
# Exit-Policy
# ===========================================
#
# Die Exit-Policy legt fest, welche Verbindungen ein Tor-Knoten zulässt oder ablehnt, wenn er als Exit-Knoten fungiert. 
# Exit-Knoten sind der letzte Punkt im Tor-Netzwerk, von dem aus der Datenverkehr an sein endgültiges Ziel weitergeleitet wird.
# Sie spielen eine entscheidende Rolle, da sie die Schnittstelle zwischen dem anonymen Tor-Netzwerk und dem offenen Internet bilden.
# In dieser Konfiguration ist die Exit-Policy so eingestellt, dass alle ausgehenden Verbindungen blockiert werden. 
# Dies wird durch den Wert "reject *:*" erreicht, was bedeutet, dass keine Verbindungen zu irgendeiner Adresse (durch das erste "*") 
# auf irgendeinem Port (durch das zweite "*") zugelassen werden. Mit dieser Einstellung übernimmt der Tor-Dienst die Rolle eines 
# "Client-only"-Knotens. Ein solcher Knoten nutzt das Tor-Netzwerk ausschließlich, um Verbindungen aufzubauen und Daten zu senden 
# oder zu empfangen, ohne selbst als Exit-Knoten zu agieren.
# Diese Einstellung hat mehrere Vorteile:
# - **Privatsphäre**: Da keine ausgehenden Verbindungen vom Tor-Knoten zugelassen werden, wird verhindert, dass der Knoten zum 
#   Ziel von Missbrauch oder illegalen Aktivitäten wird, die über das Tor-Netzwerk ausgeführt werden könnten.
# - **Sicherheit**: Durch die Deaktivierung der Exit-Funktion kann der Knotenbetreiber sicherstellen, dass er nicht für den 
#   durchgeleiteten Datenverkehr verantwortlich gemacht wird.
# - **Ressourcenschonung**: Exit-Knoten benötigen oft mehr Bandbreite und Ressourcen, da sie große Mengen an Datenverkehr verarbeiten. 
#   Ein Client-only-Knoten hat geringere Anforderungen an Bandbreite und Rechenleistung.
# Diese Konfiguration ist ideal für Benutzer, die das Tor-Netzwerk nutzen möchten, ohne selbst als Exit-Knoten zu fungieren. 
# Es ist jedoch wichtig zu beachten, dass eine Exit-Policy mit "reject *:*" bedeutet, dass der Knoten keinen öffentlichen Dienst 
# für das Tor-Netzwerk bereitstellt, sondern lediglich ein privater Tor-Client ist.

ExitPolicy reject *:*  # Blockiert alle ausgehenden Verbindungen (Client-Modus)

# ===========================================
# Debugging und Fehlerbehebung
# ===========================================
#
# Diese Sektion umfasst Einstellungen, die nützlich sind, um den Tor-Dienst zu debuggen oder Probleme zu beheben. 
# Mit diesen Optionen können Administratoren präzisere Informationen über den Status des Dienstes erhalten und 
# potenzielle Probleme effizienter identifizieren und beheben.
# Der Parameter "LogTimeGranularity" legt die Genauigkeit der Zeitstempel in den Log-Dateien fest. 
# Standardmäßig könnten Zeitstempel eine geringere Präzision haben, was das Debuggen erschwert. 
# Mit dem Wert "1" wird die Granularität der Zeitstempel erhöht, sodass Ereignisse präziser zeitlich zugeordnet werden können.
# Dies ist besonders nützlich, wenn mehrere Ereignisse in kurzer Zeitspanne auftreten und genau nachvollzogen werden soll, 
# in welcher Reihenfolge sie stattfanden.
# Die Option "DisableNetwork" steuert, ob der Netzwerkzugang für den Tor-Dienst aktiviert oder deaktiviert ist. 
# Wenn dieser Wert auf "0" gesetzt ist, bleibt der Netzwerkzugang aktiv, sodass der Tor-Dienst normal arbeiten kann. 
# Ein Wert von "1" hingegen schaltet Tor in den sogenannten Offline-Modus, in dem keine Netzwerkverbindungen aufgebaut werden.
# Dies kann nützlich sein, um Tor zu konfigurieren oder zu testen, ohne dabei das Netzwerk zu verwenden. 
# Im normalen Betrieb sollte dieser Wert jedoch auf "0" gesetzt sein, damit Tor seine Funktionalität als Anonymitätsnetzwerk 
# vollständig bereitstellen kann.

LogTimeGranularity 1  # Präzisere Zeitstempel in Logs
DisableNetwork 0  # Netzwerkzugang aktivieren (1 schaltet Tor in den Offline-Modus)

# ===========================================
# Reserviert für zukünftige Erweiterungen
# ===========================================
#
# Dieser Abschnitt ist als Platzhalter für zusätzliche Konfigurationen gedacht, die in Zukunft hinzugefügt werden könnten. 
# Insbesondere bietet er die Möglichkeit, erweiterte Funktionen des Tor-Dienstes zu konfigurieren, wie etwa Hidden Services 
# oder Bridge-Relay-Konfigurationen.
# **Hidden Services**: 
# Hidden Services ermöglichen es, Server oder Dienste zu betreiben, die vollständig innerhalb des Tor-Netzwerks erreichbar sind, 
# ohne dass ihre physische IP-Adresse offengelegt wird. Dies wird häufig genutzt, um anonyme Websites, APIs oder andere Dienste 
# bereitzustellen. Die Konfiguration eines Hidden Services würde in diesem Abschnitt vorgenommen werden, indem Parameter wie 
# "HiddenServiceDir" (das Verzeichnis, in dem die Hidden-Service-Dateien gespeichert werden) und "HiddenServicePort" (die Weiterleitung 
# von Ports zu einem internen Dienst) definiert werden.
# **Bridge-Relays**: 
# Bridge-Relays sind spezielle Tor-Knoten, die dabei helfen, das Tor-Netzwerk zugänglicher zu machen, insbesondere in Ländern oder 
# Regionen, in denen der Zugriff auf Tor durch staatliche Zensur blockiert wird. Bridges funktionieren als versteckte Einstiegspunkte 
# ins Tor-Netzwerk und können hier konfiguriert werden. Typische Parameter beinhalten "BridgeRelay 1", um den Knoten als Bridge zu 
# kennzeichnen, und die Angabe von Transport-Protokollen (z. B. obfs4), um die Verbindung zu verschleiern.
# Durch die Bereitstellung dieses Abschnitts bleibt die Konfigurationsdatei flexibel und erweiterbar. Falls in Zukunft die Notwendigkeit 
# besteht, zusätzliche Funktionen oder Dienste im Tor-Netzwerk zu implementieren, können die entsprechenden Parameter hier eingefügt 
# werden, ohne die bestehende Struktur der Konfigurationsdatei zu beeinträchtigen.

# Hidden Services oder Bridge-Relay-Konfigurationen können hier hinzugefügt werden, falls benötigt.
EOF

    # Überprüfen, ob die Datei sicher verschoben werden kann
    if ! mv "$temp_torrc" /etc/tor/torrc; then
        log "Failed to move temporary torrc file to /etc/tor/torrc." "$oO_LOG_FILE"
        return 1
    fi
    chmod 600 /etc/tor/torrc
    chown debian-tor:adm /etc/tor/torrc
    log "Tor configuration written successfully." "$oO_LOG_FILE"

    # Überprüfen der Tor-Konfiguration
    if ! tor --verify-config &>> "$oO_LOG_FILE"; then
        log "Invalid torrc configuration. Please check the log for details." "$oO_LOG_FILE"
        return 1
    fi

    # Systemd neu laden und Tor-Dienst aktivieren
    log "Reloading systemd manager configuration..." "$oO_LOG_FILE"
    if ! systemctl daemon-reload; then
        log "Failed to reload systemd manager configuration." "$oO_LOG_FILE"
        return 1
    fi

    log "Enabling Tor service..." "$oO_LOG_FILE"
    if ! systemctl enable tor; then
        log "Failed to enable Tor service." "$oO_LOG_FILE"
        return 1
    fi

    log "Starting Tor service..." "$oO_LOG_FILE"
    if ! systemctl start tor; then
        log "Failed to start Tor service." "$oO_LOG_FILE"
        return 1
    fi

    log "Tor service is running successfully." "$oO_LOG_FILE"
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
    log "Configuring resolv.conf to prevent DNS leaks..." "$oO_LOG_RESOLV"

    # Überprüfen, ob Root-Rechte vorhanden sind
    if [ "$EUID" -ne 0 ]; then
        log "This function must be run as root. Insufficient privileges." "$oO_LOG_RESOLV"
        return 1
    fi

    # Überprüfen, ob die Datei ein Symlink ist
    if [ -L /etc/resolv.conf ]; then
        log "$LOG_LEVEL_WARNING" "/etc/resolv.conf is a symlink. Replacing it with a regular file." "$oO_LOG_RESOLV"
        target=$(readlink -f /etc/resolv.conf)
        if [ "$target" != "/etc/resolv.conf" ]; then
            log "$LOG_LEVEL_WARNING" "Symlink target of /etc/resolv.conf is $target. Removing it safely." "$oO_LOG_RESOLV"
        fi
        if ! rm -f /etc/resolv.conf; then
            log "Failed to remove symlink /etc/resolv.conf. Check permissions." "$oO_LOG_RESOLV"
            return 1
        fi
    fi

    # Schreibe die neue resolv.conf
    local dns_server="127.0.0.1"
    if ! echo "nameserver $dns_server" > /etc/resolv.conf; then
        log "Failed to write to /etc/resolv.conf. Check permissions." "$oO_LOG_RESOLV"
        return 1
    fi
    log "Successfully wrote to /etc/resolv.conf." "$oO_LOG_RESOLV"

    # Setze die Berechtigungen für /etc/resolv.conf
    if ! chmod 644 /etc/resolv.conf; then
        log "Failed to set permissions on /etc/resolv.conf. Check permissions." "$oO_LOG_RESOLV"
        return 1
    fi
    if ! chown root:root /etc/resolv.conf; then
        log "Failed to set ownership on /etc/resolv.conf. Check permissions." "$oO_LOG_RESOLV"
        return 1
    fi

    # Setze das Immutable-Flag
    if chattr +i /etc/resolv.conf &> /dev/null; then
        log "Immutable flag set successfully on /etc/resolv.conf." "$oO_LOG_RESOLV"
    else
        log "$LOG_LEVEL_WARNING" "Failed to set immutable flag. Ensure filesystem supports chattr." "$oO_LOG_RESOLV"
    fi

    log "Resolv configuration completed successfully." "$oO_LOG_RESOLV"
    return 0
}

resolv_conf

touch "$oO_LOG_RESOLV"
chmod 644 "$oO_LOG_RESOLV"
chown root:adm "$oO_LOG_RESOLV"

proxychains_conf() {
    log "Checking if ProxyChains is installed..." "$oO_LOG_PROXYCHAINS"
    
    # Überprüfen, ob Root-Rechte vorhanden sind
    if [ "$EUID" -ne 0 ]; then
        log "This function must be run as root. Insufficient privileges." "$oO_LOG_PROXYCHAINS"
        return 1
    fi

    # Überprüfen, ob ProxyChains installiert ist
    if ! command -v proxychains &> /dev/null; then
        log "ProxyChains is not installed. Please install ProxyChains before running this script." "$oO_LOG_PROXYCHAINS"
        return 1
    else
        log "ProxyChains is already installed." "$oO_LOG_PROXYCHAINS"
    fi

    # Sicherstellen, dass das Verzeichnis für Proxys existiert
    local proxychains_dir="/etc/proxychains"
    if [ -e "$proxychains_dir" ] && [ ! -d "$proxychains_dir" ]; then
        log "$proxychains_dir exists but is not a directory. Aborting to prevent potential symlink attacks." "$oO_LOG_PROXYCHAINS"
        return 1
    fi

    if [ ! -d "$proxychains_dir" ]; then
        mkdir -p "$proxychains_dir"
        chmod 755 "$proxychains_dir"
        chown root:root "$proxychains_dir"
        log "Created directory $proxychains_dir." "$oO_LOG_PROXYCHAINS"
    fi

    # Sicherstellen, dass die ProxyChains-Konfigurationsdatei existiert und sicher ist
    local proxychains_conf="/etc/proxychains.conf"
    if [ -e "$proxychains_conf" ] && [ ! -f "$proxychains_conf" ]; then
        log "$proxychains_conf exists but is not a regular file. Aborting to prevent potential symlink attacks." "$oO_LOG_PROXYCHAINS"
        return 1
    fi

    # Konfigurationsdatei immer erstellen oder aktualisieren
    log "Creating or updating $proxychains_conf file..." "$oO_LOG_PROXYCHAINS"
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
socks5 67.201.33.10 25283
socks5 192.252.220.92 17328
socks5 51.210.111.216 60686
socks5 98.191.0.37 4145
socks5 199.58.184.97 4145
socks5 192.111.139.165 4145
socks5 72.211.46.124 4145
socks5 68.71.243.14 4145
socks5 68.71.249.153 48606
socks5 192.252.208.67 14287
socks5 24.249.199.4 4145
socks5 72.195.34.58 4145
socks5 98.181.137.80 4145
socks5 68.71.247.130 4145
socks5 98.170.57.231 4145
socks5 72.195.34.35 27360
socks5 72.195.34.60 27391
socks5 184.181.178.33 4145
socks5 184.181.217.201 4145

# defaults set to "tor"
socks5  127.0.0.1 9050
EOF

    # Berechtigungen setzen
    if [ ! -f "$proxychains_conf" ]; then
        chmod 644 "$proxychains_conf"
        chown root:root "$proxychains_conf"
        log "ProxyChains configuration file created and permissions set." "$oO_LOG_PROXYCHAINS"
    else
        log "ProxyChains configuration file already exists." "$oO_LOG_PROXYCHAINS"
    fi

    log "ProxyChains configured successfully." "$oO_LOG_PROXYCHAINS"
    return 0
}

proxychains_conf

touch "$oO_LOG_PROXYCHAINS"
chmod 644 "$oO_LOG_PROXYCHAINS"
chown root:adm "$oO_LOG_PROXYCHAINS"

nftables_conf() {
    log "Configuring nftables..." "$oO_LOG_NFTABLES"
    
    # Überprüfen, ob Root-Rechte vorhanden sind
    if [ "$EUID" -ne 0 ]; then
        log "This function must be run as root. Insufficient privileges." "$oO_LOG_NFTABLES"
        return 1
    fi

    # Überprüfen, ob nftables installiert ist
    if ! command -v nft &> /dev/null; then
        log "nftables is not installed. Please install nftables before running this script." "$oO_LOG_NFTABLES"
        return 1
    fi

    # Bestehende Konfiguration löschen
    log "Flushing existing nftables rules..." "$oO_LOG_NFTABLES"
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
    log "Successfully created nftables configuration at $nftables_conf." "$oO_LOG_NFTABLES"

    # Regeln laden
    log "Loading nftables configuration..." "$oO_LOG_NFTABLES"
    if ! nft -f "$nftables_conf"; then
        log "Failed to load nftables configuration." "$oO_LOG_NFTABLES"
        return 1
    fi

    # nftables-Dienst aktivieren
    log "Enabling nftables service..." "$oO_LOG_NFTABLES"
    systemctl enable nftables
    if ! systemctl restart nftables; then
        log "Failed to restart nftables service." "$oO_LOG_NFTABLES"
        return 1
    fi

    log "nftables configuration completed successfully." "$oO_LOG_NFTABLES"
}

nftables_conf

touch "$oO_LOG_NFTABLES"
chmod 644 "$oO_LOG_NFTABLES"
chown root:adm "$oO_LOG_NFTABLES"

configure_nginx_ssl() {
    log "Configuring Nginx SSL with strict HTTPS enforcement and SOCKS5 proxy..." "$oO_LOG_FILE"
    local default_site="/etc/nginx/sites-enabled/default"
    binary_remote_addr="\$binary_remote_addr"

    # Check if Nginx is installed
    if ! command -v nginx &> /dev/null; then
        log "$LOG_LEVEL_WARNING" "Nginx is not installed. Please install Nginx before running this script." "$oO_LOG_FILE"
        return 1
    fi

    # Check if OpenSSL is installed
    if ! command -v openssl &> /dev/null; then
        log "$LOG_LEVEL_WARNING" "OpenSSL is not installed. Please install OpenSSL before running this script." "$oO_LOG_FILE"
        return 1
    fi

    # Create required directories
    mkdir -p /etc/nginx/snippets
    mkdir -p /var/www/html

    # Check if the default site exists
    if [ -L "$default_site" ] || [ -f "$default_site" ]; then
        log  "Found default site at $default_site. Removing it..." "$oO_LOG_FILE"
        rm "$default_site"
        log "Default site removed successfully." "$oO_LOG_FILE"
    else
        log  "Default site not found at $default_site. No action needed." "$oO_LOG_FILE"
    fi

    # Ensure SSL certificates
    if [ ! -f /etc/ssl/private/nginx-selfsigned.key ] || [ ! -f /etc/ssl/certs/nginx-selfsigned.crt ] || [ ! -f /etc/ssl/certs/dhparam.pem ]; then
        log "Required SSL files missing. Generating SSL certificates..." "$oO_LOG_FILE"
        configure_openssl
        if ! my_command; then
            log "$LOG_LEVEL_WARNING" "Failed to generate SSL certificates. Skipping Nginx configuration." "$oO_LOG_FILE"
            return 1
        fi
    else
        log "SSL certificates already exist. Skipping generation." "$oO_LOG_FILE"
    fi

    # Configure global Nginx settings
    local nginx_global_conf="/etc/nginx/nginx.conf"
    if [ ! -f "$nginx_global_conf.bak" ]; then
        cp "$nginx_global_conf" "$nginx_global_conf.bak"
        log "Backup of nginx.conf created at $nginx_global_conf.bak" "$oO_LOG_FILE"
    fi

    # Ensure the limit_req_zone directive exists in the global http block
    if ! grep -q "limit_req_zone" "$nginx_global_conf"; then
        sed -i "/^http {/a \    limit_req_zone $binary_remote_addr zone=one:10m rate=10r/s;" "$nginx_global_conf"
        log "Added rate limiting directive to Nginx global http block." "$oO_LOG_FILE"
    else
        log "Rate limiting directive already exists in Nginx configuration, skipping." "$oO_LOG_FILE"
    fi

    # Ensure the log_format directive exists in the global http block
    if ! grep -q "log_format proxy_logs" "$nginx_global_conf"; then
        sed -i "/^http {/a \    log_format proxy_logs '\''[\$time_local] \$remote_addr: \$remote_port -> \$server_addr: \$server_port '\''\n                       '\"\$request" \$status \$body_bytes_sent'\\n                       '\"\$http_referer\" \"\$http_user_agent" SSL: \$ssl_cipher \$ssl_protocol';" "$nginx_global_conf"
        log "Added log_format directive to Nginx global http block." "$oO_LOG_FILE"
    else
        log "Log_format directive already exists in Nginx configuration, skipping." "$oO_LOG_FILE"
    fi

    # Configure Nginx SSL snippet 
    local NGX_SSL_CONF="/etc/nginx/snippets/self-signed.conf"
    cat << 'EOF' > "$NGX_SSL_CONF"
ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_session_timeout 1d;
ssl_session_cache shared:SSL:50m;
ssl_session_tickets off;
ssl_dhparam /etc/ssl/certs/dhparam.pem;

# OCSP-Stapling (optional)
# ssl_stapling on;
# ssl_stapling_verify on;
# resolver 8.8.8.8 1.1.1.1 valid=300s;
# resolver_timeout 5s;

# Add security headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Content-Type-Options nosniff;
add_header X-Frame-Options "DENY" always;
add_header X-XSS-Protection "1; mode=block";
add_header Referrer-Policy "strict-origin-when-cross-origin";
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
EOF

    # Create Nginx configuration for strict HTTPS and SOCKS5 proxy
    local NGX_CONF="/etc/nginx/sites-available/tor_proxy"
    cat << 'EOF' > "$NGX_CONF"
server {
    listen 80;
    server_name yourdomain.com;

    # Leite alle HTTP-Anfragen auf HTTPS um
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com; 

    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_dhparam /etc/ssl/certs/dhparam.pem;

    location / {
        proxy_pass http://127.0.0.1:8118; # Privoxy läuft auf Port 8118
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

server {
    listen 9060;
    server_name localhost;

    include /etc/nginx/snippets/self-signed.conf;

    location / {
        root /var/www/html;
        index index.html index.htm;

        # Rate Limiting
        limit_req zone=one burst=20;

        # Directory Listing deaktivieren
        autoindex off;

        # Traffic über den SOCKS5-Proxy (Tor) weiterleiten
        proxy_pass http://127.0.0.1:8118; # Privoxy läuft auf Port 8118
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;

        # Proxy Timeout und Pufferung
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
        proxy_buffering on;
        proxy_buffers 8 16k;
        proxy_buffer_size 4k;
    }

    # Logging
    access_log /var/log/nginx/https_proxy_access.log proxy_logs;
    error_log /var/log/nginx/https_proxy_error.log;

    # Maximale Upload-Größe
    client_max_body_size 1M;

    # HTTP-Methoden einschränken
    if ($request_method !~ ^(GET|POST|HEAD)$ ) {
        return 444;
    }

    # Server Tokens deaktivieren
    server_tokens off;
}
EOF

    # Enable the site by creating a symbolic link
    local NGX_SITES_ENABLED="/etc/nginx/sites-enabled/tor_proxy"
    if [ ! -f "$NGX_SITES_ENABLED" ]; then
        ln -s "$NGX_CONF" "$NGX_SITES_ENABLED"
        log "Linked $NGX_CONF to $NGX_SITES_ENABLED." "$oO_LOG_FILE"
    else
        log "Nginx site configuration already enabled, skipping." "$oO_LOG_FILE"
    fi

    # Test Nginx configuration
    if ! nginx -t; then
        log "$LOG_LEVEL_WARNING" "Nginx configuration test failed. Please check your configuration." "$oO_LOG_FILE"
        return 1
    fi

    # Start Nginx to apply changes
    if systemctl start nginx; then
        log "Nginx started successfully with updated configuration." "$oO_LOG_FILE"
    else
        log "$LOG_LEVEL_WARNING" "Failed to start Nginx. Check the service status." "$oO_LOG_FILE"
        return 1
    fi

    log "Nginx SSL with strict HTTPS and SOCKS5 proxy configured successfully." "$oO_LOG_FILE"
    return 0
}

# Create configure_privoxy for socks5 traffic
privoxy_conf() {
    local PRIVOXY_CONF="/etc/privoxy/config"
    log "Creating privoxy config..." "$oO_LOG_FILE"
    cat << 'EOF' > "$PRIVOXY_CONF"
# Weiterleitung an Tor (SOCKS5-Proxy)
forward-socks5t / 127.0.0.1:9050 .

# Log in file
logfile /var/log/privoxy/logfile
EOF

    # Set permissions for the configuration file
    chmod 644 "$PRIVOXY_CONF"
    chown root:root "$PRIVOXY_CONF"
    log "Creating privoxy config successful..." "$oO_LOG_FILE"
}

echo "============================================================================="
echo "                                 Setup Check                                 "
echo "============================================================================="

verifier() {
    echo "===================================="
    echo "#             nmap scan            #"
    echo "===================================="

    # Funktion zur Überprüfung offener Ports mit nmap
    nmap_check() {
        if ! command -v nmap &> /dev/null; then
            echo "Error: nmap is not installed. Please install nmap to perform this check." 
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
        local test_url="http://ip-api.com/json/"

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
        else
            echo "Konnte keine Ergebnisse abrufen. Bitte überprüfen Sie Ihre Verbindung oder die Website."
        fi
    }

    ip_check
}

verifier

log "#############################################################################" "$oO_LOG_FILE"
log "=============================================================================" "$oO_LOG_FILE"

echo "#############################################################################"
echo "============================================================================="

# Endzeit des Skripts berechnen
script_end_time=$(date +%s)
script_duration=$((script_end_time - script_start_time))
duration_formatted=$(printf '%02d:%02d:%02d' $((script_duration/3600)) $((script_duration%3600/60)) $((script_duration%60)))

# Loggen der Abschlussnachricht
log "Script execution completed! Total runtime: $duration_formatted (hh:mm:ss)" "$oO_LOG_FILE"
echo  "Script execution completed! Total runtime: $duration_formatted (hh:mm:ss)"