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
import json

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
        self.last_apt_id = 0
        self.attack_buffer = deque(maxlen=100)  # Bufor ostatnich 100 ataków
        self.apt_buffer = deque(maxlen=50)      # Bufor ostatnich 50 wykryć APT
        self.stats = {
            'total_attacks': 0,
            'ddos_attacks': 0,
            'sql_attacks': 0,
            'takeover_attacks': 0,
            'attacks_per_minute': deque(maxlen=60),
            'unique_ips': set(),
            'apt_groups': {},
            'apt_detections': 0
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

    def get_new_apt_detections(self):
        """Pobiera nowe wykrycia grup APT z bazy danych."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                SELECT a.*, l.attack_type, l.source_ip, l.severity 
                FROM apt_detections a
                JOIN attack_logs l ON a.attack_log_id = l.id
                WHERE a.id > ? 
                ORDER BY a.id ASC
                LIMIT 20
            """, (self.last_apt_id,))

            new_detections = cursor.fetchall()

            if new_detections:
                self.last_apt_id = new_detections[-1]['id']
                return [dict(detection) for detection in new_detections]

            return []

        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            return []
        finally:
            if conn:
                conn.close()

    def update_stats(self, new_attacks, new_apt_detections):
        """Aktualizuje statystyki na podstawie nowych ataków i wykryć APT."""
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

        # Aktualizacja statystyk grup APT
        for detection in new_apt_detections:
            self.stats['apt_detections'] += 1
            group_id = detection.get('group_id', '')
            
            if group_id not in self.stats['apt_groups']:
                self.stats['apt_groups'][group_id] = {
                    'name': detection.get('group_name', ''),
                    'count': 0,
                    'last_seen': None
                }
                
            self.stats['apt_groups'][group_id]['count'] += 1
            self.stats['apt_groups'][group_id]['last_seen'] = detection.get('timestamp', '')
            
            self.apt_buffer.append(detection)

        # Aktualizacja ataków na minutę
        current_minute = datetime.now().replace(second=0, microsecond=0)
        new_attacks_count = len(new_attacks)
        
        if new_attacks_count > 0:
            self.stats['attacks_per_minute'].append((current_minute, new_attacks_count))

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

    # Sprawdzenie czy zawiera informacje o wykrytej grupie APT
    additional_info = attack.get('additional_info', '{}')
    apt_info = ''
    
    if isinstance(additional_info, str):
        try:
            info_dict = json.loads(additional_info)
            if 'apt_detection' in info_dict:
                apt_group = info_dict['apt_detection'].get('group_name', '')
                confidence = info_dict['apt_detection'].get('confidence', 0)
                apt_info = f" [APT: {apt_group} ({confidence:.2f})]"
        except json.JSONDecodeError:
            pass

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

    return f"{timestamp} | {color}{display_type:15}{reset} | {source_ip:15}:{source_port:<5} -> :{dest_port:<5} | {severity_color}{severity:8}{reset}{apt_info}"


def format_apt_detection(detection):
    """Formatuje wykrycie grupy APT do wyświetlenia."""
    timestamp = detection.get('timestamp', '')[:19]  # Tylko data i czas
    group_id = detection.get('group_id', '')
    group_name = detection.get('group_name', '')
    confidence = detection.get('confidence', 0)
    attack_type = detection.get('attack_type', '')
    source_ip = detection.get('source_ip', '')
    severity = detection.get('severity', '')
    
    # Kolory dla różnych grup APT
    group_colors = {
        'BlackNova': '\033[91m',     # Czerwony
        'SilkRoad': '\033[93m',      # Żółty
        'GhostProtocol': '\033[95m', # Magenta
        'RedShift': '\033[94m',      # Niebieski
        'CosmicSpider': '\033[96m'   # Cyan
    }
    
    color = group_colors.get(group_id, '\033[0m')
    reset = '\033[0m'
    
    return f"{timestamp} | {color}{group_name:20}{reset} | {confidence:.2f} | {attack_type:15} | {source_ip:15} | {severity}"


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

    # Statystyki grup APT
    print("=== APT Groups Statistics ===")
    if monitor.stats['apt_detections'] > 0:
        print(f"Total APT Detections: {monitor.stats['apt_detections']}")
        print("\nGroup               | Count | Last Seen")
        print("-" * 60)
        
        for group_id, info in monitor.stats['apt_groups'].items():
            group_name = info['name']
            count = info['count']
            last_seen = info['last_seen'][:19] if info['last_seen'] else 'N/A'
            
            # Kolory dla różnych grup APT
            if 'BlackNova' in group_id:
                color = '\033[91m'  # Czerwony
            elif 'SilkRoad' in group_id:
                color = '\033[93m'  # Żółty
            elif 'GhostProtocol' in group_id:
                color = '\033[95m'  # Magenta
            elif 'RedShift' in group_id:
                color = '\033[94m'  # Niebieski
            elif 'CosmicSpider' in group_id:
                color = '\033[96m'  # Cyan
            else:
                color = '\033[0m'   # Brak koloru
                
            reset = '\033[0m'
            
            print(f"{color}{group_name:20}{reset} | {count:5} | {last_seen}")
    else:
        print("No APT groups detected yet.")
    print()

    # Ostatnie wykrycia grup APT
    if monitor.apt_buffer:
        print("=== Recent APT Detections ===")
        print("Timestamp          | Group                | Conf. | Attack Type     | Source IP        | Severity")
        print("-" * 100)
        
        # Wyświetl ostatnie 5 wykryć APT
        recent_apt = list(monitor.apt_buffer)[-5:]
        for detection in recent_apt:
            print(format_apt_detection(detection))
        print()

    # Ostatnie ataki
    print("=== Recent Attacks ===")
    print("Timestamp          | Type            | Source IP        :Port  -> :Port  | Severity")
    print("-" * 85)

    # Wyświetl ostatnie 15 ataków
    recent_attacks = list(monitor.attack_buffer)[-15:]
    for attack in recent_attacks:
        print(format_attack(attack))


def monitor_attacks_curses(stdscr, db_path, refresh_interval):
    """Monitorowanie ataków z użyciem curses dla lepszego interfejsu."""
    monitor = AttackMonitor(db_path, refresh_interval)

    # Konfiguracja curses
    curses.curs_set(0)  # Ukryj kursor
    stdscr.nodelay(1)  # Nie blokuj na getch()
    stdscr.timeout(100)  # Timeout dla getch()

    # Definicja kolorów
    curses.start_color()
    curses.init_pair(1, curses.COLOR_RED, curses.COLOR_BLACK)      # DDoS / BlackNova
    curses.init_pair(2, curses.COLOR_YELLOW, curses.COLOR_BLACK)   # SQL / SilkRoad
    curses.init_pair(3, curses.COLOR_MAGENTA, curses.COLOR_BLACK)  # Takeover / GhostProtocol
    curses.init_pair(4, curses.COLOR_GREEN, curses.COLOR_BLACK)    # Info
    curses.init_pair(5, curses.COLOR_CYAN, curses.COLOR_BLACK)     # Stats / CosmicSpider
    curses.init_pair(6, curses.COLOR_BLUE, curses.COLOR_BLACK)     # RedShift

    try:
        while True:
            new_attacks = monitor.get_new_attacks()
            new_apt_detections = monitor.get_new_apt_detections()

            if new_attacks or new_apt_detections:
                monitor.update_stats(new_attacks, new_apt_detections)

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

            # Statystyki grup APT
            apt_row = stats_row + 8
            stdscr.addstr(apt_row, 0, "=== APT Groups Statistics ===", curses.color_pair(5) | curses.A_BOLD)
            
            if monitor.stats['apt_detections'] > 0:
                stdscr.addstr(apt_row + 1, 0, f"Total APT Detections: {monitor.stats['apt_detections']}")
                stdscr.addstr(apt_row + 3, 0, "Group                | Count | Last Seen")
                stdscr.addstr(apt_row + 4, 0, "-" * 60)
                
                row = apt_row + 5
                for group_id, info in monitor.stats['apt_groups'].items():
                    if row >= height - 2:
                        break
                        
                    group_name = info['name']
                    count = info['count']
                    last_seen = info['last_seen'][:19] if info['last_seen'] else 'N/A'
                    
                    # Wybór koloru dla grupy
                    color_pair = 0
                    if 'BlackNova' in group_id:
                        color_pair = 1
                    elif 'SilkRoad' in group_id:
                        color_pair = 2
                    elif 'GhostProtocol' in group_id:
                        color_pair = 3
                    elif 'RedShift' in group_id:
                        color_pair = 6
                    elif 'CosmicSpider' in group_id:
                        color_pair = 5
                    
                    stdscr.addstr(row, 0, f"{group_name:20} | {count:5} | {last_seen}", 
                                 curses.color_pair(color_pair))
                    row += 1
            else:
                stdscr.addstr(apt_row + 1, 0, "No APT groups detected yet.")

            # Ostatnie wykrycia grup APT
            if monitor.apt_buffer:
                apt_detections_row = apt_row + len(monitor.stats['apt_groups']) + 3
                if apt_detections_row >= height - 2:
                    apt_detections_row = apt_row + 8  # Ogranicz jeśli zbyt wiele grup
                
                stdscr.addstr(apt_detections_row, 0, "=== Recent APT Detections ===", 
                             curses.color_pair(5) | curses.A_BOLD)
                stdscr.addstr(apt_detections_row + 1, 0, 
                             "Timestamp          | Group                | Conf. | Attack Type     | Source IP")
                stdscr.addstr(apt_detections_row + 2, 0, "-" * 80)
                
                row = apt_detections_row + 3
                # Wyświetl ostatnie wykrycia APT
                recent_apt = list(monitor.apt_buffer)[-5:]  # Ostatnie 5 wykryć
                for detection in recent_apt:
                    if row >= height - 2:
                        break
                        
                    timestamp = detection['timestamp'][:19]
                    group_name = detection['group_name']
                    confidence = detection['confidence']
                    attack_type = detection['attack_type']
                    source_ip = detection['source_ip']
                    
                    # Wybór koloru dla grupy
                    color_pair = 0
                    if 'BlackNova' in detection['group_id']:
                        color_pair = 1
                    elif 'SilkRoad' in detection['group_id']:
                        color_pair = 2
                    elif 'GhostProtocol' in detection['group_id']:
                        color_pair = 3
                    elif 'RedShift' in detection['group_id']:
                        color_pair = 6
                    elif 'CosmicSpider' in detection['group_id']:
                        color_pair = 5
                    
                    stdscr.addstr(row, 0, f"{timestamp} | ", curses.A_DIM)
                    stdscr.addstr(row, 21, f"{group_name:20}", curses.color_pair(color_pair))
                    stdscr.addstr(row, 43, f" | {confidence:.2f} | {attack_type:15} | {source_ip}")
                    row += 1

            # Ostatnie ataki
            attacks_row = height - min(len(monitor.attack_buffer), 15) - 3
            if attacks_row <= apt_row + 15:
                attacks_row = apt_row + 15  # Ogranicz jeśli zbyt dużo miejsca zajęły grupy APT
            
            stdscr.addstr(attacks_row, 0, "=== Recent Attacks ===", curses.color_pair(5) | curses.A_BOLD)
            stdscr.addstr(attacks_row + 1, 0, 
                         "Timestamp          | Type            | Source IP        :Port  -> :Port  | Severity")
            stdscr.addstr(attacks_row + 2, 0, "-" * 80)

            # Wyświetl ataki
            row = attacks_row + 3
            recent_attacks = list(monitor.attack_buffer)[-15:]  # Ostatnie 15 ataków
            for attack in recent_attacks:
                if row >= height - 1:
                    break

                timestamp = attack.get('timestamp', '')[:19]
                attack_type = attack.get('attack_type', 'unknown')
                source_ip = attack.get('source_ip', 'unknown')
                source_port = attack.get('source_port', 0)
                dest_port = attack.get('destination_port', 0)
                severity = attack.get('severity', 'unknown')

                # Sprawdź czy zawiera informacje o wykrytej grupie APT
                additional_info = attack.get('additional_info', '{}')
                apt_info = ''
                apt_color = 0
                
                if isinstance(additional_info, str):
                    try:
                        info_dict = json.loads(additional_info)
                        if 'apt_detection' in info_dict:
                            group_id = info_dict['apt_detection'].get('group_id', '')
                            apt_group = info_dict['apt_detection'].get('group_name', '')
                            confidence = info_dict['apt_detection'].get('confidence', 0)
                            apt_info = f" [APT: {apt_group}]"
                            
                            # Wybór koloru dla APT
                            if 'BlackNova' in group_id:
                                apt_color = 1
                            elif 'SilkRoad' in group_id:
                                apt_color = 2
                            elif 'GhostProtocol' in group_id:
                                apt_color = 3
                            elif 'RedShift' in group_id:
                                apt_color = 6
                            elif 'CosmicSpider' in group_id:
                                apt_color = 5
                    except json.JSONDecodeError:
                        pass

                # Wybór koloru dla typu ataku
                color_pair = 0
                if attack_type == 'ddos':
                    color_pair = 1
                elif attack_type == 'sql_injection':
                    color_pair = 2
                elif attack_type == 'machine_takeover':
                    color_pair = 3

                # Wyświetl linię
                attack_line = f"{timestamp} | {attack_type:15} | {source_ip:15}:{source_port:<5} -> :{dest_port:<5} | {severity:8}"
                stdscr.addstr(row, 0, attack_line, curses.color_pair(color_pair))
                
                # Dodaj informację o APT jeśli wykryto
                if apt_info:
                    stdscr.addstr(row, len(attack_line) + 1, apt_info, curses.color_pair(apt_color))
                
                row += 1

            stdscr.refresh()

            # Sprawdź czy użytkownik nacisnął 'q'
            key = stdscr.getch()
            if key == ord('q'):
                break

            time.sleep(refresh_interval)

    except KeyboardInterrupt:
        pass


def monitor_attacks(db_path, refresh_interval):
    """Główna funkcja monitorująca ataki."""
    monitor = AttackMonitor(db_path, refresh_interval)

    try:
        while True:
            new_attacks = monitor.get_new_attacks()
            new_apt_detections = monitor.get_new_apt_detections()

            if new_attacks or new_apt_detections:
                monitor.update_stats(new_attacks, new_apt_detections)
                display_dashboard(monitor)

            time.sleep(refresh_interval)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")


def get_apt_detections(db_path, limit=10):
    """
    Pobiera informacje o ostatnich wykryciach grup APT.
    
    Args:
        db_path (str): Ścieżka do bazy danych
        limit (int): Limit wyników
        
    Returns:
        list: Lista wykryć grup APT
    """
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
        SELECT a.*, l.attack_type, l.source_ip
        FROM apt_detections a
        JOIN attack_logs l ON a.attack_log_id = l.id
        ORDER BY a.id DESC
        LIMIT ?
        """
        
        cursor.execute(query, (limit,))
        detections = cursor.fetchall()
        
        return [dict(d) for d in detections]
        
    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania wykryć APT: {e}")
        return []
        
    finally:
        if conn:
            conn.close()


def parse_arguments():
    """Parsowanie argumentów wiersza poleceń."""
    parser = argparse.ArgumentParser(description='Monitor ataków w czasie rzeczywistym')
    parser.add_argument('--realtime', action='store_true', help='Tryb monitorowania w czasie rzeczywistym')
    parser.add_argument('--interval', type=int, default=1, help='Interwał odświeżania w sekundach')
    parser.add_argument('--db', type=str, default=DB_PATH, help='Ścieżka do bazy danych')
    parser.add_argument('--no-curses', action='store_true', help='Użyj prostego interfejsu tekstowego')
    parser.add_argument('--apt-only', action='store_true', help='Pokaż tylko wykrycia grup APT')

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
    
    if args.apt_only:
        print("Showing only APT group detections")
    
    print()

    try:
        if args.apt_only:
            # Wyświetl tylko wykrycia grup APT
            while True:
                apt_detections = get_apt_detections(args.db, 20)
                if apt_detections:
                    os.system('clear' if os.name == 'posix' else 'cls')
                    print("=== APT Group Detections ===")
                    print("Timestamp          | Group                | Conf. | Attack Type     | Source IP")
                    print("-" * 80)
                    
                    for detection in apt_detections:
                        print(format_apt_detection(detection))
                        
                    print("\nPress Ctrl+C to exit")
                else:
                    print("No APT detections found yet. Waiting...")
                    
                time.sleep(args.interval)
        elif args.no_curses or os.name == 'nt':  # Windows nie obsługuje curses dobrze
            monitor_attacks(args.db, args.interval)
        else:
            curses.wrapper(monitor_attacks_curses, args.db, args.interval)
    except KeyboardInterrupt:
        print("\nMonitoring stopped by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()