#!/bin/bash
# =====================================================
# Säkerhetsloggövervakning för Ubuntu Server
# Syfte: Övervaka och analysera säkerhetsloggar för att 
#        identifiera, rapportera och reagera på misstänkt aktivitet.
# Skapat av: Henriette Heikki, April 2025
# Version: 1.0
#Sammanfattning: Skriptet analyserar autentiseringsloggar, identifierar
# Det loggar även åtgärder och säkerhetsrelaterade händelser.
# högrisk-IP-adresser, blockerar dem och skickar en säkerhetsrapport via e-post.
# ----------------------------------------------------
# Input: Loggfiler och backup-katalog hanteras via variabler.
# Handling: Loggfiler analyseras, räknas och arkiveras.
# Kontroll: Antalet händelser jämförs mot tröskelvärden, och diskutrymme kan enkelt läggas till som en kontroll.
# Output: Rapport genereras, skickas via e-post och loggas.
# Säkerhet: Fel hanteras, temporära filer rensas, och variabler skyddas.

# =====================================================

# ------------------ 1. KONFIGURATION ------------------

# Definiera sökvägar till loggfilerna som ska analyseras
AUTH_LOG="${AUTH_LOG:-/var/log/auth.log}"            # Loggfil med autentiseringsförsök
SYS_LOG="${SYS_LOG:-/var/log/syslog}"               # Systemloggar
SECURITY_ACTION_LOG="${SECURITY_ACTION_LOG:-/var/log/security_actions.log}"  # Loggfil för skriptets åtgärder

# Definiera var backupfiler ska sparas
BACKUP_DIR="${BACKUP_DIR:-/var/backups}"               # Katalog där loggarkiv sparas

# Skapa unik rapportfil baserad på dagens datum
REPORT_FILE="${REPORT_FILE:-security_report_$(date +%Y%m%d).txt}"  # Filnamn för säkerhetsrapporten

# E-postadress dit rapporten ska skickas
ADMIN_EMAIL="${ADMIN_EMAIL:-henrietteheikki@hotmail.com}"         # Ändra till rätt e-postadress

# Definiera tröskelvärde för "hög risk" (antal misslyckade inloggningsförsök)
HIGH_RISK_THRESHOLD="${HIGH_RISK_THRESHOLD:-5}"                # IP:n med fler misslyckade försök än detta flaggas

# Temp-filer för analys
TEMP_FILE="/tmp/security_analysis_$(date +%Y%m%d).tmp"  # Temporär fil för analys

# Definiera hur gamla loggar ska vara innan de raderas (i dagar)
LOG_RETENTION_DAYS=${LOG_RETENTION_DAYS:-7}                    # Antal dagar att behålla loggar

# Få datum för 24 timmar sedan för att filtrera loggar
YESTERDAY=$(date -d "24 hours ago" "+%b %d")  # Gårdagens datum i loggfilformat
TODAY=$(date "+%b %d")                  # Dagens datum i loggfilformat

#    ------------------ 2. SÄKERHETSÅTGÄRDER ------------------

# Trap för att städa upp temporära filer vid avslut
trap 'rm -f "$TEMP_FILE" "$TEMP_FILE.failed" "$TEMP_FILE.invalid" "$TEMP_FILE.accepted" "$TEMP_FILE.session"' EXIT

# Aktivera strikt felhantering
set -euo pipefail  # Avsluta skriptet vid fel och odefinierade variabler

# Funktion för att logga meddelanden
log_message() {
    local message="$1"  # Tar emot ett meddelande som parameter
    [ -z "$SECURITY_ACTION_LOG" ] && echo "FEL: Loggfil inte definierad." >&2 && exit 1  # Kontrollera att loggfilen är definierad
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> "$SECURITY_ACTION_LOG"  # Skriv meddelandet till loggfilen med tidsstämpel
}

# Kontrollera att skriptet körs som root
if [ "$(id -u)" -ne 0 ]; then
    echo "Detta skript måste köras som root!" >&2  # Visa felmeddelande om ej root
    log_message "FEL: Skriptet körs inte som root"  # Logga felmeddelande
    exit 1                              # Avsluta med felkod
fi

# Kontrollera att nödvändiga verktyg är installerade
check_required_tools() {
    local required_tools=("mail" "ufw" "tar" "grep" "awk" "sort" "uniq")  # Lista över nödvändiga verktyg
    for cmd in "${required_tools[@]}"; do  # Iterera över varje verktyg
        if ! command -v "$cmd" &> /dev/null; then  # Kontrollera om verktyget är installerat
            local error_message="FEL: Verktyget $cmd är inte installerat. Installera det med: apt-get install $cmd"
            log_message "$error_message"  # Logga felmeddelande
            echo "$error_message" >&2  # Visa felmeddelande
            exit 1  # Avsluta om verktyget saknas
        fi
    done
}

# Anropa funktionen för att kontrollera verktyg
check_required_tools

# Skapa säkerhetsloggfil om den inte existerar
if [ ! -f "$SECURITY_ACTION_LOG" ]; then
    touch "$SECURITY_ACTION_LOG" || { echo "FEL: Kunde inte skapa loggfilen $SECURITY_ACTION_LOG" >&2; exit 1; }  # Skapa loggfilen
    chmod 600 "$SECURITY_ACTION_LOG"    # Sätt behörigheter (endast root kan läsa/skriva)
    log_message "Säkerhetsloggfil skapad: $SECURITY_ACTION_LOG"  # Logga skapandet av loggfilen
fi

# Skapa backup-katalog om den inte existerar
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"              # Skapa katalogstrukturen (-p = skapa även föräldrakataloger)
    chmod 700 "$BACKUP_DIR"             # Sätt behörigheter (endast root kan komma åt)
fi

# Logga början på skriptkörningen
log_message "Säkerhetsanalys påbörjad"

# ------------------ 3. FUNKTIONER ------------------

# Valideringsfunktion - kontrollerar att miljön är rätt inställd
validate_environment() {
    # Kontrollera att loggfilerna existerar och är läsbara
    if [ ! -r "$AUTH_LOG" ] || [ ! -r "$SYS_LOG" ]; then
        echo "Kan inte läsa en eller flera loggfiler. Kontrollera behörigheter." >&2
        log_message "FEL: Kan inte läsa loggfiler"
        exit 1                          # Avsluta om loggfiler saknas
    fi
    
    # Kontrollera att ufw är aktiverat
    if ! ufw status | grep -q "Status: active"; then
        echo "UFW är inte aktiverat. Aktiverar..."  # Informationsmeddelande
        ufw enable                      # Aktivera Ubuntu Firewall
        log_message "UFW aktiverat"
    fi
    
    # Kontrollera att vi kan skriva till backup-katalogen
    if [ ! -w "$BACKUP_DIR" ]; then
        echo "Kan inte skriva till backup-katalogen $BACKUP_DIR" >&2
        log_message "FEL: Kan inte skriva till backup-katalogen"
        exit 1                          # Avsluta om backup-katalogen inte är skrivbar
    fi
}

# Funktion för att analysera loggfiler
analyze_auth_log() {
    log_message "Analyserar auth.log för inloggningsförsök..."
    # Skapa temporära filer för analysen
    : > "$TEMP_FILE.failed"
    : > "$TEMP_FILE.invalid"
    : > "$TEMP_FILE.accepted"
    : > "$TEMP_FILE.session"

    # Analysera loggfiler
    grep -E "(${YESTERDAY}|${TODAY}).*Failed password" "$AUTH_LOG" > "$TEMP_FILE.failed"
    grep -E "(${YESTERDAY}|${TODAY}).*Invalid user" "$AUTH_LOG" > "$TEMP_FILE.invalid"
    grep -E "(${YESTERDAY}|${TODAY}).*Accepted password" "$AUTH_LOG" > "$TEMP_FILE.accepted"
    grep -E "(${YESTERDAY}|${TODAY}).*session opened" "$AUTH_LOG" > "$TEMP_FILE.session"
}

# Funktion för att identifiera högrisk-IP-adresser
identify_high_risk_ips() {
    log_message "Identifierar högrisk-IP-adresser..."
    grep "Failed password" "$TEMP_FILE.failed" | awk '{print $(NF-3)}' | sort | uniq -c | awk -v threshold="$HIGH_RISK_THRESHOLD" '$1 > threshold {print $2}'
}

# Funktion för att blockera högrisk-IP-adresser
block_high_risk_ips() {
    local high_risk_ips="$1"
    log_message "Blockerar högrisk-IP-adresser..."
    echo "$high_risk_ips" | while read -r ip; do
        if ! ufw status | grep -q "$ip"; then
            ufw deny from "$ip" to any
            log_message "Blockerat högrisk-IP: $ip"
        fi
    done
}

# Funktion för att generera säkerhetsrapport
generate_report() {
    log_message "Genererar säkerhetsrapport..."
    {
        echo "======================================================"
        echo "SÄKERHETSRAPPORT - $(date '+%Y-%m-%d %H:%M:%S')"
        echo "======================================================"
        cat "$TEMP_FILE"
    } > "$REPORT_FILE"
}

# Funktion för att skicka rapport via e-post
send_report() {
    log_message "Skickar rapport via e-post..."
    if [ -s "$REPORT_FILE" ]; then
        mail -s "Säkerhetsrapport $(date '+%Y-%m-%d')" "$ADMIN_EMAIL" < "$REPORT_FILE"
        log_message "Säkerhetsrapport skickad till $ADMIN_EMAIL"
    else
        log_message "VARNING: Rapporten är tom, inget e-postmeddelande skickat"
    fi
}

# Funktion för att arkivera loggar
archive_logs() {
    log_message "Arkiverar loggar..."
    local archive_name
    archive_name="security_logs_$(date +%Y%m%d_%H%M%S).tar.gz"
    tar -czf "$BACKUP_DIR/$archive_name" "$AUTH_LOG" "$SYS_LOG"
    log_message "Loggar arkiverade till $BACKUP_DIR/$archive_name"
    find "$BACKUP_DIR" -name "security_logs_*.tar.gz" -type f -mtime +"$LOG_RETENTION_DAYS" -delete
}

# ------------------ 4. HUVUDLOGIKEN ------------------

validate_environment # Validera miljön innan vi börjar
analyze_auth_log # Analysera auth.log för inloggningsförsök
ALL_HIGH_RISK_IPS=$(identify_high_risk_ips) # Identifiera högrisk-IP-adresser
block_high_risk_ips "$ALL_HIGH_RISK_IPS" # Blockera högrisk-IP-adresser
generate_report # Generera säkerhetsrapport
send_report # Skicka rapport via e-post
archive_logs # Arkivera loggar

# ------------------ 5. AVSLUTNING ------------------
# Städa upp temporära filer
rm -f "$TEMP_FILE" "$TEMP_FILE.failed" "$TEMP_FILE.invalid" "$TEMP_FILE.accepted" "$TEMP_FILE.session"
# Logga avslutning av skriptet
echo "$(date '+%Y-%m-%d %H:%M:%S') - Säkerhetsanalys slutförd" >> "$SECURITY_ACTION_LOG"
# Avsluta med lyckad statuskod 

log_message "Säkerhetsanalys slutförd"
exit 0

# Förklaring:
# - Skriptet övervakar och analyserar säkerhetsloggar för att identifiera misstänkt aktivitet.
# - Det loggar händelser, identifierar högrisk-IP-adresser, blockerar dem och skickar rapporter via e-post.
# - Skriptet är konfigurerbart med variabler för loggfiler, backup-kataloger och e-postadresser.
# - Det använder funktioner för att organisera koden och göra den mer läsbar.
# - Skriptet är skrivet för att köras som root och kontrollerar nödvändiga verktyg innan det körs.
# - Det använder trap för att städa upp temporära filer vid avslut och aktiverar strikt felhantering.
# - Skriptet är designat för att vara robust och hantera fel på ett kontrollerat sätt.
# - Det loggar alla åtgärder och felmeddelanden för att underlätta felsökning och övervakning.
# - Skriptet är användbart för systemadministratörer som vill övervaka och skydda sina servrar mot intrång och attacker.
# - Det kan enkelt anpassas för att passa specifika behov och miljöer.
# - Skriptet är skrivet med fokus på säkerhet och användarvänlighet.
# - Det är viktigt att testa skriptet i en säker miljö innan det används i produktion.
# - Skriptet kan köras automatiskt med cron-jobb för att schemalägga säkerhetsanalyser.
# - Det är viktigt att hålla skriptet och dess beroenden uppdaterade för att säkerställa bästa möjliga säkerhet.
# - Skriptet kan också utökas med fler funktioner för att förbättra säkerheten och övervakningen.
# - Det är viktigt att följa bästa praxis för säkerhet och systemadministration 