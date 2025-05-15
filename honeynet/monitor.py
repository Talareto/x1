#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł do monitorowania ataków w czasie rzeczywistym.
"""

import argparse
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timedelta
import threading
import curses
from collections import deque
import signal

# Konfiguracja logowania
logger = logging.getLogger('monitor')

# Ścieżka do bazy danych
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'honeynet.db')


class AttackMonitor:
    """Klasa do monitorowania ataków w czasie rzeczywistym."""

    def __init__(self, db_path, refresh_interval=1):
        self.db_path = db_path
        self.refresh_interval = refresh_interval
        self.running = False
        self.last_attack_id = 0
        self.attack_buffer = deque(maxlen=100)  # Bufor ostatnich 100 ataków
        self.stats = {
            'total_attacks': 0,
            'ddos_attacks': 0,
            'sql_attacks': 0,
            'takeover_attacks': 0,
            'attacks_per_minute': deque(maxlen=60),
            'unique_ips': set()
        }

    def get_new_attacks(self):
        """Pobiera nowe ataki z bazy danych."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT * FROM attack_logs 
                WHERE id > ? 
                ORDER BY id ASC
                LIMIT 50
            """, (self.last_attack_id,))

            new_attacks = cursor.fetchall()

            if new_attacks:
                self.last_attack_id = new_attacks[-1]['id']
                return [dict(attack) for attack in new_attacks]

            return []

        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def update_stats(self, new_attacks):
        """Aktualizuje statystyki na podstawie nowych ataków."""
        for attack in new_attacks:
            self.stats['total_attacks'] += 1

            attack_type = attack.get('attack_type', '')
            if attack_type == 'ddos':
                self.stats['ddos_attacks'] += 1
            elif attack_type == 'sql_injection':
                self.stats['sql_attacks'] += 1
            elif attack_type == 'machine_takeover':
                self.stats['takeover_attacks'] += 1

            source_ip = attack.get('source_ip', '')
            if source_ip:
                self.stats['unique_ips'].add(source_ip)

            self.attack_buffer.append(attack)

        # Aktualizacja ataków na minutę
        current_minute = datetime.now().replace(second=0, microsecond=0)
        self.stats['attacks_per_minute'].append((current_minute, len(new_attacks)))

    def calculate_attack_rate(self):
        """Oblicza średnią liczbę ataków na minutę."""
        if not self.stats['attacks_per_minute']:
            return 0

        total_attacks = sum(count for _, count in self.stats['attacks_per_minute'])
        return total_attacks / len(self.stats['attacks_per_minute'])


def format_attack(attack):
    """Formatuje atak do wyświetlenia."""
    timestamp = attack.get('timestamp', '')[:19]  # Tylko data i czas
    attack_type = attack.get('attack_type', 'unknown')
    source_ip = attack.get('source_ip', 'unknown')
    source_port = attack.get('source_port', 0)
    dest_port = attack.get('destination_port', 0)
    severity = attack.get('severity', 'unknown')

    # Mapowanie typów ataków na bardziej czytelne nazwy
    type_map = {
        'ddos': 'DDoS',
        'sql_injection': 'SQL Injection',
        'machine_takeover': 'Machine Takeover'
    }

    display_type = type_map.get(attack_type, attack_type)

    # Formatowanie z kolorami dla różnych typów ataków
    type_colors = {
        'ddos': '\033[91m',  # Czerwony
        'sql_injection': '\033[93m',  # Żółty
        'machine_takeover': '\033[95m'  # Magenta
    }

    severity_colors = {
        'critical': '\033[91m',  # Czerwony
        'high': '\033[93m',  # Żółty
        'medium': '\033[94m',  # Niebieski
        'low': '\033[92m'  # Zielony
    }

    color = type_colors.get(attack_type, '')
    severity_color = severity_colors.get(severity.lower(), '')
    reset = '\033[0m'

    return f"{timestamp} | {color}{display_type:15}{reset} | {source_ip:15}:{source_port:<5} -> :{dest_port:<5} | {severity_color}{severity:8}{reset}"


def display_dashboard(monitor):
    """Wyświetla dashboard w trybie tekstowym."""
    os.system('clear' if os.name == 'posix' else 'cls')

    print("=== IoT Honeypot Attack Monitor ===")
    print(f"Monitoring started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Press Ctrl+C to exit")
    print()

    # Statystyki
    print("=== Attack Statistics ===")
    print(f"Total Attacks:    {monitor.stats['total_attacks']}")
    print(f"DDoS Attacks:     {monitor.stats['ddos_attacks']}")
    print(f"SQL Injections:   {monitor.stats['sql_attacks']}")
    print(f"Machine Takeover: {monitor.stats['takeover_attacks']}")
    print(f"Unique IPs:       {len(monitor.stats['unique_ips'])}")
    print(f"Attack Rate:      {monitor.calculate_attack_rate():.1f} attacks/min")
    print()

    # Ostatnie ataki
    print("=== Recent Attacks ===")
    print("Timestamp          | Type            | Source IP        :Port  -> :Port  | Severity")
    print("-" * 85)

    # Wyświetl ostatnie 20 ataków
    recent_attacks = list(monitor.attack_buffer)[-20:]
    for attack in recent_attacks:
        print(format_attack(attack))


def monitor_attacks(db_path, refresh_interval):
    """Główna funkcja monitorująca ataki."""
    monitor = AttackMonitor(db_path, refresh_interval)

    try:
        while True:
            new_attacks = monitor.get_new_attacks()

            if new_attacks:
                monitor.update_stats(new_attacks)
                display_dashboard(monitor)

            time.sleep(refresh_interval)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")


def monitor_attacks_curses(stdscr, db_path, refresh_interval):
    """Monitorowanie ataków z użyciem curses dla lepszego interfejsu."""
    monitor = AttackMonitor(db_path, refresh_interval)

    # Konfiguracja curses
    curses.curs_set(0)  # Ukryj kursor
    stdscr.nodelay(1)  # Nie blokuj na getch()
    stdscr.timeout(100)  # Timeout dla getch()

    # Definicja kolorów
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)  # DDoS
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # SQL
    curses.init_pair(3, curses.COLOR_MAGENTA, curses.COLOR_BLACK)  # Takeover
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Info
    curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLACK)  # Stats

    try:
        while True:
            new_attacks = monitor.get_new_attacks()

            if new_attacks:
                monitor.update_stats(new_attacks)

            # Wyczyść ekran
            stdscr.clear()

            # Nagłówek
            height, width = stdscr.getmaxyx()
            title = "IoT Honeypot Attack Monitor"
            stdscr.addstr(0, (width - len(title)) // 2, title, curses.A_BOLD)
            stdscr.addstr(1, 0, "Press 'q' to exit", curses.A_DIM)

            # Statystyki
            stats_row = 3
            stdscr.addstr(stats_row, 0, "=== Attack Statistics ===", curses.color_pair(5) | curses.A_BOLD)
            stdscr.addstr(stats_row + 1, 0, f"Total Attacks:    {monitor.stats['total_attacks']}")
            stdscr.addstr(stats_row + 2, 0, f"DDoS Attacks:     {monitor.stats['ddos_attacks']}", curses.color_pair(1))
            stdscr.addstr(stats_row + 3, 0, f"SQL Injections:   {monitor.stats['sql_attacks']}", curses.color_pair(2))
            stdscr.addstr(stats_row + 4, 0, f"Machine Takeover: {monitor.stats['takeover_attacks']}",
                          curses.color_pair(3))
            stdscr.addstr(stats_row + 5, 0, f"Unique IPs:       {len(monitor.stats['unique_ips'])}")
            stdscr.addstr(stats_row + 6, 0, f"Attack Rate:      {monitor.calculate_attack_rate():.1f} attacks/min")

            # Ostatnie ataki
            attacks_row = stats_row + 8
            stdscr.addstr(attacks_row, 0, "=== Recent Attacks ===", curses.color_pair(5) | curses.A_BOLD)

            # Nagłówki tabeli
            headers = "Timestamp         | Type            | Source IP       :Port  -> :Port  | Severity"
            stdscr.addstr(attacks_row + 1, 0, headers)
            stdscr.addstr(attacks_row + 2, 0, "-" * len(headers))

            # Wyświetl ataki
            display_row = attacks_row + 3
            max_attacks = height - display_row - 1
            recent_attacks = list(monitor.attack_buffer)[-max_attacks:]

            for i, attack in enumerate(recent_attacks):
                if display_row + i >= height - 1:
                    break

                # Formatowanie ataku
                timestamp = attack.get('timestamp', '')[:19]
                attack_type = attack.get('attack_type', 'unknown')
                source_ip = attack.get('source_ip', 'unknown')
                source_port = attack.get('source_port', 0)
                dest_port = attack.get('destination_port', 0)
                severity = attack.get('severity', 'unknown')

                # Wybór koloru
                color_pair = 0
                if attack_type == 'ddos':
                    color_pair = 1
                elif attack_type == 'sql_injection':
                    color_pair = 2
                elif attack_type == 'machine_takeover':
                    color_pair = 3

                # Wyświetl linię
                attack_line = f"{timestamp} | {attack_type:15} | {source_ip:15}:{source_port:<5} -> :{dest_port:<5} | {severity:8}"
                stdscr.addstr(display_row + i, 0, attack_line, curses.color_pair(color_pair))

            stdscr.refresh()

            # Sprawdź czy użytkownik nacisnął 'q'
            key = stdscr.getch()
            if key == ord('q'):
                break

            time.sleep(refresh_interval)

    except KeyboardInterrupt:
        pass


def parse_arguments():
    """Parsowanie argumentów wiersza poleceń."""
    parser = argparse.ArgumentParser(description='Monitor ataków w czasie rzeczywistym')
    parser.add_argument('--realtime', action='store_true', help='Tryb monitorowania w czasie rzeczywistym')
    parser.add_argument('--interval', type=int, default=1, help='Interwał odświeżania w sekundach')
    parser.add_argument('--db', type=str, default=DB_PATH, help='Ścieżka do bazy danych')
    parser.add_argument('--no-curses', action='store_true', help='Użyj prostego interfejsu tekstowego')

    return parser.parse_args()


def main():
    """Główna funkcja programu."""
    args = parse_arguments()

    if not os.path.exists(args.db):
        print(f"Error: Database file not found: {args.db}")
        sys.exit(1)

    if not args.realtime:
        print("Use --realtime flag to start real-time monitoring")
        sys.exit(1)

    print("Starting attack monitor...")
    print(f"Database: {args.db}")
    print(f"Refresh interval: {args.interval} seconds")
    print()

    try:
        if args.no_curses or os.name == 'nt':  # Windows nie obsługuje curses dobrze
            monitor_attacks(args.db, args.interval)
        else:
            curses.wrapper(monitor_attacks_curses, args.db, args.interval)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()