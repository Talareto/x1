#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Główny moduł honeynetu uruchamiający wszystkie symulowane usługi IoT.
"""

import argparse
import logging
import os
import sys
import threading
import time
import sqlite3
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

# Dodajemy katalog główny projektu do ścieżki, aby można było importować moduły
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeynet.db_handler import init_database
from honeynet.ip_camera_service import run_camera_service
from honeynet.logistics_service import run_logistics_service
from honeynet.production_machine_service import run_production_service
from honeynet.utils import setup_logging, create_directories

# Konfiguracja logowania
logger = logging.getLogger('honeynet')

# Globalne statystyki ataków
attack_stats = {
    'total_attacks': 0,
    'ddos_attacks': 0,
    'sql_injection_attacks': 0,
    'machine_takeover_attacks': 0,
    'unique_ips': set(),
    'last_attack_time': None,
    'attack_rates': [],
    'hourly_stats': {},
    'severity_counts': {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
}

# Blokada dla synchronizacji dostępu do statystyk
stats_lock = threading.Lock()


def parse_arguments():
    """Przetwarzanie argumentów wiersza poleceń."""
    parser = argparse.ArgumentParser(description='IoT Honeynet - symulator urządzeń IoT do monitorowania ataków')
    parser.add_argument('--ip', type=str, default='0.0.0.0', help='Adres IP do nasłuchiwania (domyślnie: 0.0.0.0)')
    parser.add_argument('--ports', type=str, default='8000,8001,8002',
                        help='Porty dla usług (domyślnie: 8000,8001,8002)')
    parser.add_argument('--db', type=str, default='database/honeynet.db',
                        help='Ścieżka do bazy danych (domyślnie: database/honeynet.db)')
    parser.add_argument('--log-level', type=str, default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Poziom logowania (domyślnie: INFO)')
    parser.add_argument('--log-file', type=str, default='logs/honeynet.log',
                        help='Plik logów (domyślnie: logs/honeynet.log)')
    parser.add_argument('--no-camera', action='store_true', help='Wyłącz symulację kamer IP')
    parser.add_argument('--no-logistics', action='store_true', help='Wyłącz symulację systemu logistycznego')
    parser.add_argument('--no-machines', action='store_true', help='Wyłącz symulację maszyn produkcyjnych')
    parser.add_argument('--monitor', action='store_true', help='Włącz monitor ataków w czasie rzeczywistym')
    parser.add_argument('--stats-interval', type=int, default=5, 
                        help='Interwał wyświetlania statystyk w sekundach (domyślnie: 5)')
    parser.add_argument('--generate-report', action='store_true', 
                        help='Automatycznie generuj raport co godzinę')

    return parser.parse_args()


def print_banner():
    """Wyświetlenie bannera aplikacji."""
    banner = """
    ██╗ ██████╗ ████████╗    ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗███╗   ██╗███████╗████████╗
    ██║██╔═══██╗╚══██╔══╝    ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝████╗  ██║██╔════╝╚══██╔══╝
    ██║██║   ██║   ██║       ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██╔██╗ ██║█████╗     ██║   
    ██║██║   ██║   ██║       ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██║╚██╗██║██╔══╝     ██║   
    ██║╚██████╔╝   ██║       ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║ ╚████║███████╗   ██║   
    ╚═╝ ╚═════╝    ╚═╝       ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝   
    """
    print(banner)
    print("\t\t\t   System symulacji i monitorowania ataków IoT")
    print("\t\t\t      v1.0.0 - Wszystkie prawa zastrzeżone")
    print("\n")


def clear_screen():
    """Czyści ekran konsoli."""
    os.system('cls' if os.name == 'nt' else 'clear')


def get_attack_stats(db_path, last_id=0):
    """
    Pobiera statystyki ataków z bazy danych.
    
    Args:
        db_path (str): Ścieżka do bazy danych
        last_id (int): Ostatni przetworzony ID ataku
        
    Returns:
        tuple: (nowe_ataki, ostatni_id)
    """
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Pobieranie nowych ataków
        cursor.execute("""
            SELECT * FROM attack_logs 
            WHERE id > ?
            ORDER BY id ASC
        """, (last_id,))
        
        new_attacks = [dict(row) for row in cursor.fetchall()]
        
        if new_attacks:
            last_id = new_attacks[-1]['id']
            
        return new_attacks, last_id
        
    except sqlite3.Error as e:
        logger.error(f"Błąd bazy danych podczas pobierania statystyk: {e}")
        return [], last_id
    finally:
        if conn:
            conn.close()


def update_statistics(new_attacks):
    """
    Aktualizuje globalne statystyki na podstawie nowych ataków.
    
    Args:
        new_attacks (list): Lista nowych ataków
    """
    with stats_lock:
        for attack in new_attacks:
            attack_stats['total_attacks'] += 1
            attack_type = attack.get('attack_type', '')
            
            if attack_type == 'ddos':
                attack_stats['ddos_attacks'] += 1
            elif attack_type == 'sql_injection':
                attack_stats['sql_injection_attacks'] += 1
            elif attack_type == 'machine_takeover':
                attack_stats['machine_takeover_attacks'] += 1
                
            source_ip = attack.get('source_ip', '')
            if source_ip:
                attack_stats['unique_ips'].add(source_ip)
                
            severity = attack.get('severity', 'medium').lower()
            if severity in attack_stats['severity_counts']:
                attack_stats['severity_counts'][severity] += 1
                
            # Aktualizacja czasu ostatniego ataku
            attack_stats['last_attack_time'] = datetime.now()
            
            # Aktualizacja statystyk godzinowych
            hour = datetime.now().strftime('%Y-%m-%d %H:00')
            if hour not in attack_stats['hourly_stats']:
                attack_stats['hourly_stats'][hour] = {
                    'total': 0,
                    'ddos': 0,
                    'sql_injection': 0,
                    'machine_takeover': 0
                }
            
            attack_stats['hourly_stats'][hour]['total'] += 1
            if attack_type in attack_stats['hourly_stats'][hour]:
                attack_stats['hourly_stats'][hour][attack_type] += 1
                
        # Obliczanie częstotliwości ataków (ostatnie 10 minut)
        current_time = datetime.now()
        ten_min_ago = current_time - timedelta(minutes=10)
        
        # Filtrowanie ataków tylko z ostatnich 10 minut
        recent_attacks = [a for a in new_attacks if a.get('timestamp') and datetime.fromisoformat(a.get('timestamp', current_time.isoformat())[:19]) > ten_min_ago]
        
        if recent_attacks:
            attack_stats['attack_rates'].append((current_time, len(recent_attacks)))
            
            # Ograniczenie wielkości historii
            if len(attack_stats['attack_rates']) > 60:  # Przechowaj maksymalnie godzinę danych
                attack_stats['attack_rates'] = attack_stats['attack_rates'][-60:]


def monitor_attacks(db_path, interval=5):
    """
    Monitoruje ataki w czasie rzeczywistym i wyświetla statystyki.
    
    Args:
        db_path (str): Ścieżka do bazy danych
        interval (int): Interwał odświeżania w sekundach
    """
    last_id = 0
    start_time = datetime.now()
    
    try:
        while True:
            # Pobierz nowe ataki
            new_attacks, last_id = get_attack_stats(db_path, last_id)
            
            # Aktualizuj statystyki
            if new_attacks:
                update_statistics(new_attacks)
            
            # Wyświetl statystyki
            clear_screen()
            print("═" * 80)
            print("█  HONEYNET - MONITORING ATAKÓW W CZASIE RZECZYWISTYM  █")
            print("═" * 80)
            
            # Czas działania
            current_time = datetime.now()
            uptime = current_time - start_time
            hours, remainder = divmod(uptime.total_seconds(), 3600)
            minutes, seconds = divmod(remainder, 60)
            
            print(f"Czas działania: {int(hours):02}:{int(minutes):02}:{int(seconds):02}")
            print(f"Ostatnia aktualizacja: {current_time.strftime('%Y-%m-%d %H:%M:%S')}")
            
            # Podstawowe statystyki
            with stats_lock:
                print("\n=== PODSUMOWANIE ATAKÓW ===")
                print(f"Wszystkie ataki:     {attack_stats['total_attacks']}")
                print(f"Ataki DDoS:          {attack_stats['ddos_attacks']}")
                print(f"SQL Injection:       {attack_stats['sql_injection_attacks']}")
                print(f"Przejęcia maszyn:    {attack_stats['machine_takeover_attacks']}")
                print(f"Unikalne źródła IP:  {len(attack_stats['unique_ips'])}")
                
                print("\n=== POZIOMY KRYTYCZNOŚCI ===")
                print(f"Krytyczne:  {attack_stats['severity_counts']['critical']}")
                print(f"Wysokie:    {attack_stats['severity_counts']['high']}")
                print(f"Średnie:    {attack_stats['severity_counts']['medium']}")
                print(f"Niskie:     {attack_stats['severity_counts']['low']}")
                
                # Częstotliwość ataków
                print("\n=== CZĘSTOTLIWOŚĆ ATAKÓW ===")
                if attack_stats['attack_rates']:
                    total_recent = sum(count for _, count in attack_stats['attack_rates'][-12:])  # Ostatnie 12 interwałów (ok. 1 minuta)
                    print(f"Ataki/minutę: {total_recent}")
                else:
                    print("Ataki/minutę: 0")
                    
                # Ostatnie ataki
                print("\n=== OSTATNIE ATAKI ===")
                if new_attacks:
                    print("ID | Czas                | Typ             | Źródło               | Krytyczność")
                    print("-" * 80)
                    for attack in new_attacks[-10:]:  # Pokaż ostatnie 10 ataków
                        attack_id = attack.get('id', '?')
                        timestamp = attack.get('timestamp', '')[:19]  # Obetnij milisekundy
                        attack_type = attack.get('attack_type', 'unknown')
                        source = f"{attack.get('source_ip', '?')}:{attack.get('source_port', '?')}"
                        severity = attack.get('severity', 'unknown')
                        
                        # Kolorowanie tekstu w terminalu
                        type_color = {
                            'ddos': '\033[91m',          # Czerwony
                            'sql_injection': '\033[93m', # Żółty
                            'machine_takeover': '\033[95m'  # Magenta
                        }.get(attack_type, '\033[0m')
                        
                        severity_color = {
                            'critical': '\033[91m',  # Czerwony
                            'high': '\033[93m',      # Żółty
                            'medium': '\033[94m',    # Niebieski
                            'low': '\033[92m'        # Zielony
                        }.get(severity.lower(), '\033[0m')
                        
                        reset = '\033[0m'
                        
                        print(f"{attack_id:3} | {timestamp} | {type_color}{attack_type:15}{reset} | {source:20} | {severity_color}{severity}{reset}")
                else:
                    print("Brak nowych ataków od ostatniego sprawdzenia.")
            
            print("\n" + "═" * 80)
            print("Naciśnij Ctrl+C, aby zatrzymać monitoring")
            
            # Czekaj na następne odświeżenie
            time.sleep(interval)
            
    except KeyboardInterrupt:
        print("\nMonitoring zatrzymany przez użytkownika.")
    except Exception as e:
        logger.error(f"Błąd podczas monitorowania: {e}")
        print(f"Wystąpił błąd: {e}")


def generate_hourly_report(db_path, report_dir='reports'):
    """
    Generuje godzinowy raport ataków.
    
    Args:
        db_path (str): Ścieżka do bazy danych
        report_dir (str): Katalog dla raportów
    """
    try:
        # Importuj generator raportów
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from honeynet.report_generator import generate_html, get_attack_data, get_statistics
        
        # Pobierz dane z ostatniej godziny
        now = datetime.now()
        hour_ago = now - timedelta(hours=1)
        
        # Format daty dla SQLite
        from_date = hour_ago.strftime('%Y-%m-%d %H:%M:%S')
        to_date = now.strftime('%Y-%m-%d %H:%M:%S')
        
        # Pobierz dane ataków
        attacks = get_attack_data(db_path, from_date, to_date)
        
        if not attacks:
            logger.info("Brak ataków do wygenerowania raportu.")
            return
            
        # Oblicz statystyki
        stats = get_statistics(attacks)
        
        # Generuj raport HTML
        timestamp = now.strftime('%Y%m%d_%H%M%S')
        output_file = os.path.join(report_dir, f"attack_report_{timestamp}.html")
        
        generate_html(attacks, stats, from_date, to_date, output_file)
        logger.info(f"Raport godzinowy wygenerowany: {output_file}")
        
    except Exception as e:
        logger.error(f"Błąd podczas generowania raportu: {e}")


def schedule_reports(db_path, report_dir='reports'):
    """
    Planuje generowanie raportów co godzinę.
    
    Args:
        db_path (str): Ścieżka do bazy danych
        report_dir (str): Katalog dla raportów
    """
    try:
        while True:
            # Oblicz czas do następnej pełnej godziny
            now = datetime.now()
            next_hour = now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
            wait_seconds = (next_hour - now).total_seconds()
            
            # Poczekaj do następnej pełnej godziny
            time.sleep(wait_seconds)
            
            # Generuj raport
            generate_hourly_report(db_path, report_dir)
            
    except KeyboardInterrupt:
        logger.info("Planowanie raportów zatrzymane przez użytkownika.")
    except Exception as e:
        logger.error(f"Błąd podczas planowania raportów: {e}")


def start_service(service_func, host, port, service_name):
    """Uruchamia pojedynczą usługę w osobnym wątku."""
    logger.info(f"Uruchamianie usługi {service_name} na {host}:{port}")
    try:
        service_func(host, port)
    except Exception as e:
        logger.error(f"Błąd podczas uruchamiania usługi {service_name}: {e}")


def main():
    """Funkcja główna uruchamiająca wszystkie komponenty honeynetu."""
    args = parse_arguments()

    # Tworzenie katalogów jeśli nie istnieją
    create_directories(['logs', 'database', 'reports'])

    # Konfiguracja logowania
    setup_logging(args.log_level, args.log_file)

    # Wyświetlenie bannera
    print_banner()

    # Inicjalizacja bazy danych
    db_path = args.db
    init_database(db_path)
    logger.info(f"Baza danych zainicjalizowana: {db_path}")

    # Lista portów dla każdej usługi
    ports = [int(p.strip()) for p in args.ports.split(',')]
    if len(ports) < 3:
        ports.extend([8000 + i for i in range(len(ports), 3)])

    # Uruchamianie usług w osobnych wątkach
    services = []
    with ThreadPoolExecutor(max_workers=5) as executor:
        if not args.no_camera:
            services.append(executor.submit(
                start_service, run_camera_service, args.ip, ports[0], "Kamera IP"
            ))

        if not args.no_logistics:
            services.append(executor.submit(
                start_service, run_logistics_service, args.ip, ports[1], "System logistyczny"
            ))

        if not args.no_machines:
            services.append(executor.submit(
                start_service, run_production_service, args.ip, ports[2], "Maszyny produkcyjne"
            ))

        # Uruchomienie monitoringu ataków jeśli włączono opcję
        if args.monitor:
            services.append(executor.submit(
                monitor_attacks, db_path, args.stats_interval
            ))
            
        # Uruchomienie automatycznego generowania raportów
        if args.generate_report:
            services.append(executor.submit(
                schedule_reports, db_path, 'reports'
            ))

        # Monitorowanie statusu usług
        try:
            active_services = []
            if not args.no_camera:
                active_services.append(f"Kamera IP (port {ports[0]})")
            if not args.no_logistics:
                active_services.append(f"System logistyczny (port {ports[1]})")
            if not args.no_machines:
                active_services.append(f"Maszyny produkcyjne (port {ports[2]})")

            logger.info(f"Honeynet uruchomiony pomyślnie. Aktywne usługi: {', '.join(active_services)}")
            print(f"\n[+] Honeynet uruchomiony na {args.ip}")
            for service in active_services:
                print(f"[+] Uruchomiono: {service}")
                
            if args.monitor:
                print("[+] Uruchomiono monitoring ataków w czasie rzeczywistym")
                
            if args.generate_report:
                print("[+] Uruchomiono automatyczne generowanie raportów co godzinę")
                
            print("\n[*] Naciśnij Ctrl+C, aby zatrzymać honeynet...\n")

            # Utrzymanie głównego wątku aktywnym
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("Otrzymano sygnał zatrzymania. Zamykanie honeynetu...")
            print("\n[!] Zatrzymywanie honeynetu...")
            # ThreadPoolExecutor automatycznie zamknie wątki przy wyjściu z bloku with


if __name__ == "__main__":
    main()