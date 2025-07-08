#!/usr/bin/env python3
"""
Dokumentation:
  Detta skript implementerar ett enkelt IDS (Intrusion Detection System) för realtidsdetektering
  och automatiserad respons mot nätverksattacker genom att läsa en löpande loggfil.
Skapat av: Henriette Heikki 
Datum: 10/05/2025
Version: 1.0    
Syftet:
  - Övervaka och analysera nätverkstrafik i realtid.
  - Identifiera misstänkt aktivitet baserat på anslutningsfrekvens, ovanliga portar och hög volym.
  - Generera rapporter, skicka varningar och automatiskt blockera hotfulla IP-adresser.

Krav:
  1. Läs en dynamisk loggfil (network_traffic.log) med formatet:
     tidpunkt, källa-IP, destination-IP, port, protokoll.
  2. Analysera trafiken i 5-minutersintervall.
  3. Flagga IP-adresser som:
       * har över 100 anslutningar under intervallet.
       * använder ovanliga portar (<1024 utanför 22, 80, 443).
       * skickar hög volym trafik mot en enskild destination.
  4. Skicka e-postvarningar via SMTP vid misstänkt aktivitet.
  5. Generera CSV-rapport (attack_report.csv) med detaljer och statistik.
  6. Blockera misstänkta IP-adresser med ufw via subprocess.

God praxis: modulär design, tydlig loggning, robust felhantering och enhetstester.
"""

# =======================================
# Modulimporteringen: externa bibliotek
# =======================================
import time                      # för sömn och intervallhantering
import datetime                  # för tidsstämplar i ISO-format
from datetime import timezone  # för tidszonhantering
import csv                       # för att generera CSV-rapporter
import os                        # för filhantering och miljövariabler
import smtplib                   # för e-post via SMTP
import subprocess                # för att köra externa kommandon (ufw)
import logging                   # för loggutskrifter
import sys                       # för systemavslut och argument
import unittest                  # för enhetstester
from collections import Counter  # enkel räknare för anslutningar
from email.mime.text import MIMEText      # för e-postinnehåll
from email.utils import formataddr       # för korrekt avsändaradress

# ==============
# Konfiguration
# ==============
LOG_FILE = 'network_traffic.log'           # loggfil att läsa från
REPORT_FILE = 'attack_report.csv'          # CSV-rapportfil
ANALYSIS_INTERVAL = 300                    # 5 minuter (i sekunder)
CONNECTION_THRESHOLD = 100                 # max anslutningar innan flaggning
UNUSUAL_PORTS = set(range(1, 1024)) - {22, 80, 443}  # avvikande portar
VOLUME_THRESHOLD = 100                    # max trafikvolym till en dst

# E-postserverns inställningar
SMTP_SERVER = 'localhost'
SMTP_PORT = 25

# We don’t need auth on localhost:25 but tests expect these names:
SMTP_USER = os.getenv('SMTP_USER', '')  # or None
SMTP_PASS = os.getenv('SMTP_PASS', '')  # or None

FROM_ADDR = 'root@agent-ifema'  # your new “From:” address
ADMIN_EMAIL = 'henrietteheikki@hotmail.com'  # recipient email

# =====================
# Loggkonfiguration
# =====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# =================================
# Säkerställ att loggfil finns
# =================================
def ensure_log_file_exists():
    """Skapar loggfilen om den saknas för första körning."""
    if not os.path.exists(LOG_FILE):
        # Skapa tom fil och logga varning
        open(LOG_FILE, 'a').close()
        logging.warning(f"Loggfil skapad: {LOG_FILE}")

# ==================
# Läs loggfil i realtid
# ==================
def tail_log(file_path):
    """
    Generator som följer loggfilen och returnerar nya rader.
    Väntar på fil om den inte finns, sedan seek till slut och yieldar.
    """
    # Vänta inledningsvis om filen inte existerar
    while not os.path.exists(file_path):
        logging.warning(f"Väntar på loggfil: {file_path}")
        time.sleep(5)
    try:
        with open(file_path, 'r') as f:
            # Hoppa till slutet för att bara läsa nya poster
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if not line:
                    # Inga nya rader, vänta en sekund
                    time.sleep(1)
                    continue
                # Returnera avradad rad utan ny rad-tecken
                yield line.strip()
    except Exception as e:
        # Fel vid filläsning, logga och avsluta generatorn
        logging.error(f"Fel vid läsning av loggfil: {e}")
        return

# ===========================
# Validering och parsning
# ===========================
def parse_line(line):
    """
    Validerar syntax för en loggrad och parsar till en tuple.
    Förväntat format:
        tidpunkt, källa-IP, destination-IP, port, protokoll
    Returnerar None om ogiltig.
    """
    parts = [p.strip() for p in line.split(',')]
    if len(parts) != 5:
        logging.warning(f"Ogiltigt format, hoppar över: {line}")
        return None
    try:
        # Tolka ISO-tidpunkt, IP och port
        ts = datetime.datetime.fromisoformat(parts[0])
        src, dst = parts[1], parts[2]
        port = int(parts[3])
        proto = parts[4]
        return ts, src, dst, port, proto
    except Exception as e:
        logging.warning(f"Parsingfel: {e} -- {line}")
        return None

# =========================================
# Analys- och åtgärdsfunktioner för IDS
# =========================================
def analyze_window(records):
    """
    Analyserar en samling loggposter över 5-minutersfönster.
    Returnerar lista med flaggade events för rapport/blockering.
    """
    src_count = Counter()   # räknar anslutningar per källa
    dst_count = Counter()   # räknar volym per källa->dest
    port_flags = []         # listor för portar att rapportera
    flagged = []            # listor för IP att blockera

    # Steg 1: Räkna poster och hitta ovanliga portar
    for ts, src, dst, port, proto in records:
        src_count[src] += 1
        dst_count[(src, dst)] += 1
        if port in UNUSUAL_PORTS:
            port_flags.append((ts, src, dst, port, proto, 'Unusual port'))

    # Steg 2: Kontrollera tröskelvärden
    for src, cnt in src_count.items():
        if cnt > CONNECTION_THRESHOLD:
            flagged.append((src, cnt, 'High connection count'))
    for (src, dst), cnt in dst_count.items():
        if cnt > VOLUME_THRESHOLD:
            flagged.append((src, cnt, f'High volume to {dst}'))

    # Steg 3: Bygg event-lista för rapporter och blockering
    events = []
    for ts, src, dst, port, proto, reason in port_flags:
        events.append((ts.isoformat(), src, dst, port, proto, 1, reason))
    for src, cnt, reason in flagged:
        events.append((datetime.datetime.now(datetime.timezone.utc).isoformat(), src, '', '', '', cnt, reason))
    return events

# ===================
# Huvudlogiken
# ===================
def main():
    """
    Huvudloopen: säkerställ loggfil, samla poster, analysera och agera.
    Kör kontinuerligt och hanterar analys i fasta tidsintervall.
    """
    # Se till att loggfilen finns innan vi börjar
    ensure_log_file_exists()

    # Starta realtidsläsning av loggen
    log_iter = tail_log(LOG_FILE)
    buffer = []
    start = time.time()

    # Loopa över nya loggrader
    for line in log_iter or []:
        rec = parse_line(line)
        if rec:
            buffer.append(rec)  # samla i buffert

        # Kolla om 5 minuter passerat
        if time.time() - start >= ANALYSIS_INTERVAL:
            try:
                events = analyze_window(buffer)
                if events:
                    # Skriv rapport, blockera IP och skicka mail
                    write_report(events)
                    unique_ips = {e[1] for e in events}
                    for ip in unique_ips:
                        block_ip(ip)
                    subject = f"IDS Alert: {len(unique_ips)} IPs flagged"
                    body = "Misstänkta IPs:\n" + "\n".join(unique_ips)
                    send_email(subject, body)
                else:
                    logging.info("Inga misstänkta aktiviteter.")
            except Exception as e:
                logging.error(f"Fel i analys/respons: {e}")
            # Återställ buffert och timer för nästa fönster
            buffer.clear()
            start = time.time()

# ============================
# Funktioner avslutning
# ============================
def send_email(subject, body):
    """
    Skickar e-post via den lokala MTA:n utan inloggning eller med autentisering om SMTP_USER och SMTP_PASS är satta.
    """
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = FROM_ADDR
        msg['To'] = ADMIN_EMAIL

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as smtp:
            # Only do TLS+login if both user+pass are non‐empty
            if SMTP_USER and SMTP_PASS:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)

            smtp.send_message(msg)

        logging.info(f"E-post skickad: {subject} → {ADMIN_EMAIL}")
    except Exception as e:
        logging.error(f"Misslyckades skicka mail: {e}")


def block_ip(ip):
    """
    Blockerar en IP-adress via ufw-kommandot.
    Ger loggutskrift vid framgång eller fel.
    """
    try:
        subprocess.run(['sudo', 'ufw', 'deny', 'from', ip], check=True)
        logging.info(f"Blockerad IP: {ip}")
    except Exception as e:
        logging.error(f"Blockeringsfel: {e}")


def write_report(events):
    """
    Lägger till flaggade event i CSV-rapporten.
    Skapar header om filen är ny.
    """
    new_file = not os.path.exists(REPORT_FILE)
    try:
        with open(REPORT_FILE, 'a', newline='') as f:
            w = csv.writer(f)
            if new_file:
                # Skriv kolumnrubriker första gången
                w.writerow(['timestamp', 'src_ip', 'dst_ip', 'port', 'protocol', 'count', 'reason'])
            # Skriv alla events
            w.writerows(events)
        logging.info(f"Rapport uppdaterad med {len(events)} events.")
    except Exception as e:
        logging.error(f"Rapportfel: {e}")

# ============
# Enhetstester
# ============
class TestIDS(unittest.TestCase):
    def test_parse_line_valid(self):
        # Testa giltig rad
        line = "2025-05-14T12:00:00,192.168.0.1,10.0.0.1,80,TCP"
        out = parse_line(line)
        self.assertEqual(out[1], '192.168.0.1')
        self.assertEqual(out[3], 80)

    def test_parse_line_invalid(self):
        # Testa ogiltig rad
        self.assertIsNone(parse_line("foo,bar"))

    def test_analyze_high_conn(self):
        # Skapa 101 poster för att trigga High connection count
        now = datetime.datetime.now(datetime.timezone.utc)
        recs = [(now,'1.1.1.1','2.2.2.2',22,'TCP')]*101
        ev = analyze_window(recs)
        self.assertTrue(any('High connection' in e[-1] for e in ev))

    def test_analyze_unusual_port(self):
        # Testa på en ovanlig port (23)
        now = datetime.datetime.now(datetime.timezone.utc)
        ev = analyze_window([(now,'1.1.1.1','2.2.2.2',23,'TCP')])
        self.assertTrue(any('Unusual port' in e[-1] for e in ev))

    def test_send_email_no_pass(self):
        # Testa att send_email inte kraschar utan SMTP_PASS
        global SMTP_PASS
        tmp = SMTP_PASS
        SMTP_PASS = None
        try:
            send_email("ämne","text")
        except Exception:
            self.fail("send_email kastade undantag utan lösenord")
        SMTP_PASS = tmp

if __name__ == '__main__':
    # Kör tester om --test är angivet, annars starta IDS
    if '--test' in sys.argv:
        unittest.main(argv=[sys.argv[0]])
    else:
        try:
            logging.info("Startar IDS...")
            main()
        except KeyboardInterrupt:
            logging.info("Avslutar på användaravbrott.")
        except Exception as e:
            logging.critical(f"Oväntat fel: {e}", exc_info=True)
            logging.info("Avslut utan SystemExit.")
