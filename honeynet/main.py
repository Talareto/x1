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
from concurrent.futures import ThreadPoolExecutor

# Dodajemy katalog główny projektu do ścieżki, aby można było importować moduły
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeynet.db_handler import init_database
from honeynet.ip_camera_service import run_camera_service
from honeynet.logistics_service import run_logistics_service
from honeynet.production_machine_service import run_production_service
from honeynet.utils import setup_logging, create_directories

# Konfiguracja logowania
logger = logging.getLogger('honeynet')


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
    with ThreadPoolExecutor(max_workers=5) as executor:
        services = []

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