#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł obsługujący bazę danych dla honeynetu.
Zapisuje szczegółowe informacje o atakach dla wszystkich scenariuszy.
"""

import logging
import os
import sqlite3
import time
import json
from datetime import datetime

# Konfiguracja logowania
logger = logging.getLogger('honeynet.db')


def init_database(db_path):
    """
    Inicjalizuje bazę danych i tworzy tabele jeśli nie istnieją.

    Args:
        db_path (str): Ścieżka do pliku bazy danych
    """
    # Sprawdzenie czy katalog bazy danych istnieje
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Tabela główna z logami ataków
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        source_ip TEXT NOT NULL,
        source_port INTEGER,
        destination_ip TEXT NOT NULL,
        destination_port INTEGER,
        attack_type TEXT NOT NULL,
        protocol TEXT,
        attack_details_id INTEGER,
        severity TEXT,
        detected_patterns TEXT,
        session_id TEXT,
        raw_data BLOB,
        additional_info TEXT
    )
    ''')

    # Tabela dla szczegółów ataków DDoS
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS ddos_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_log_id INTEGER,
        packets_count INTEGER,
        packet_type TEXT,
        bandwidth_usage REAL,
        attack_duration REAL,
        attack_vector TEXT,
        packet_distribution TEXT,
        target_service TEXT,
        traffic_pattern TEXT,
        amplification_factor REAL,
        FOREIGN KEY (attack_log_id) REFERENCES attack_logs (id)
    )
    ''')

    # Tabela dla szczegółów ataków SQL Injection
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sql_injection_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_log_id INTEGER,
        query_type TEXT,
        vulnerable_parameter TEXT,
        injection_point TEXT,
        payload TEXT,
        database_type TEXT,
        success_status INTEGER,
        extracted_data TEXT,
        error_messages TEXT,
        injection_technique TEXT,
        FOREIGN KEY (attack_log_id) REFERENCES attack_logs (id)
    )
    ''')

    # Tabela dla szczegółów przejęć maszyn produkcyjnych
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS machine_takeover_details (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_log_id INTEGER,
        target_machine TEXT,
        exploit_used TEXT,
        authentication_attempts INTEGER,
        command_sequence TEXT,
        control_duration REAL,
        system_changes TEXT,
        access_level TEXT,
        machine_type TEXT,
        affected_operations TEXT,
        FOREIGN KEY (attack_log_id) REFERENCES attack_logs (id)
    )
    ''')

    conn.commit()
    conn.close()

    logger.info(f"Baza danych zainicjalizowana: {db_path}")


def log_attack(db_path, attack_data):
    """
    Zapisuje informacje o ataku do bazy danych.

    Args:
        db_path (str): Ścieżka do pliku bazy danych
        attack_data (dict): Słownik z danymi o ataku

    Returns:
        int: ID zapisanego ataku
    """
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Przygotowanie danych podstawowych o ataku
        timestamp = attack_data.get('timestamp', datetime.now().isoformat())
        source_ip = attack_data.get('source_ip', '')
        source_port = attack_data.get('source_port', 0)
        destination_ip = attack_data.get('destination_ip', '')
        destination_port = attack_data.get('destination_port', 0)
        attack_type = attack_data.get('attack_type', '')
        protocol = attack_data.get('protocol', '')
        severity = attack_data.get('severity', 'medium')
        detected_patterns = attack_data.get('detected_patterns', '')
        session_id = attack_data.get('session_id', '')
        raw_data = attack_data.get('raw_data', b'')

        # Dodatkowe informacje w formacie JSON
        additional_info = json.dumps(attack_data.get('additional_info', {}))

        # Dodanie wpisu głównego o ataku
        cursor.execute('''
        INSERT INTO attack_logs (
            timestamp, source_ip, source_port, destination_ip, destination_port,
            attack_type, protocol, severity, detected_patterns, session_id, raw_data, additional_info
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            timestamp, source_ip, source_port, destination_ip, destination_port,
            attack_type, protocol, severity, detected_patterns, session_id, raw_data, additional_info
        ))

        # Pobranie ID wstawionego wpisu
        attack_log_id = cursor.lastrowid

        # W zależności od typu ataku, zapisujemy szczegóły w odpowiedniej tabeli
        if attack_type == 'ddos':
            log_ddos_details(cursor, attack_log_id, attack_data)
        elif attack_type == 'sql_injection':
            log_sql_injection_details(cursor, attack_log_id, attack_data)
        elif attack_type == 'machine_takeover':
            log_machine_takeover_details(cursor, attack_log_id, attack_data)

        # Zatwierdzenie transakcji
        conn.commit()

        logger.info(f"Zapisano atak typu {attack_type} (ID: {attack_log_id}) z {source_ip}:{source_port}")
        return attack_log_id

    except sqlite3.Error as e:
        logger.error(f"Błąd bazy danych podczas zapisu ataku: {e}")
        if conn:
            conn.rollback()
        return None
    except Exception as e:
        logger.error(f"Nieoczekiwany błąd podczas zapisu ataku: {e}")
        if conn:
            conn.rollback()
        return None
    finally:
        if conn:
            conn.close()


def log_ddos_details(cursor, attack_log_id, attack_data):
    """Zapisuje szczegóły ataku DDoS."""
    ddos_details = attack_data.get('ddos_details', {})

    cursor.execute('''
    INSERT INTO ddos_details (
        attack_log_id, packets_count, packet_type, bandwidth_usage,
        attack_duration, attack_vector, packet_distribution,
        target_service, traffic_pattern, amplification_factor
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        attack_log_id,
        ddos_details.get('packets_count', 0),
        ddos_details.get('packet_type', ''),
        ddos_details.get('bandwidth_usage', 0.0),
        ddos_details.get('attack_duration', 0.0),
        ddos_details.get('attack_vector', ''),
        ddos_details.get('packet_distribution', ''),
        ddos_details.get('target_service', ''),
        ddos_details.get('traffic_pattern', ''),
        ddos_details.get('amplification_factor', 1.0)
    ))


def log_sql_injection_details(cursor, attack_log_id, attack_data):
    """Zapisuje szczegóły ataku SQL Injection."""
    sql_details = attack_data.get('sql_injection_details', {})

    cursor.execute('''
    INSERT INTO sql_injection_details (
        attack_log_id, query_type, vulnerable_parameter, injection_point,
        payload, database_type, success_status, extracted_data,
        error_messages, injection_technique
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        attack_log_id,
        sql_details.get('query_type', ''),
        sql_details.get('vulnerable_parameter', ''),
        sql_details.get('injection_point', ''),
        sql_details.get('payload', ''),
        sql_details.get('database_type', 'SQLite'),
        sql_details.get('success_status', 0),
        sql_details.get('extracted_data', ''),
        sql_details.get('error_messages', ''),
        sql_details.get('injection_technique', '')
    ))


def log_machine_takeover_details(cursor, attack_log_id, attack_data):
    """Zapisuje szczegóły przejęcia maszyny produkcyjnej."""
    takeover_details = attack_data.get('machine_takeover_details', {})

    cursor.execute('''
    INSERT INTO machine_takeover_details (
        attack_log_id, target_machine, exploit_used, authentication_attempts,
        command_sequence, control_duration, system_changes,
        access_level, machine_type, affected_operations
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        attack_log_id,
        takeover_details.get('target_machine', ''),
        takeover_details.get('exploit_used', ''),
        takeover_details.get('authentication_attempts', 0),
        takeover_details.get('command_sequence', ''),
        takeover_details.get('control_duration', 0.0),
        takeover_details.get('system_changes', ''),
        takeover_details.get('access_level', ''),
        takeover_details.get('machine_type', ''),
        takeover_details.get('affected_operations', '')
    ))


def get_attack_stats(db_path, start_date=None, end_date=None):
    """
    Pobiera statystyki ataków z bazy danych.

    Args:
        db_path (str): Ścieżka do pliku bazy danych
        start_date (str, optional): Data początkowa w formacie ISO
        end_date (str, optional): Data końcowa w formacie ISO

    Returns:
        dict: Statystyki ataków
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        query = "SELECT attack_type, COUNT(*) FROM attack_logs"
        params = []

        # Dodanie filtrowania po datach jeśli podano
        if start_date or end_date:
            query += " WHERE 1=1"

            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)

            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)

        query += " GROUP BY attack_type"

        cursor.execute(query, params)
        attack_counts = {attack_type: count for attack_type, count in cursor.fetchall()}

        # Pobranie liczby unikalnych źródeł ataków
        query = "SELECT COUNT(DISTINCT source_ip) FROM attack_logs"
        params = []

        if start_date or end_date:
            query += " WHERE 1=1"

            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)

            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)

        cursor.execute(query, params)
        unique_sources = cursor.fetchone()[0]

        # Pobranie statystyk poziomów krytyczności
        query = "SELECT severity, COUNT(*) FROM attack_logs"
        params = []

        if start_date or end_date:
            query += " WHERE 1=1"

            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)

            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)

        query += " GROUP BY severity"
        
        cursor.execute(query, params)
        severity_counts = {severity: count for severity, count in cursor.fetchall()}

        stats = {
            'total_attacks': sum(attack_counts.values()),
            'attack_types': attack_counts,
            'unique_sources': unique_sources,
            'severity_counts': severity_counts
        }

        return stats

    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania statystyk ataków: {e}")
        return {'error': str(e)}

    finally:
        if conn:
            conn.close()


def get_latest_attacks(db_path, limit=10):
    """
    Pobiera ostatnie ataki z bazy danych.
    
    Args:
        db_path (str): Ścieżka do pliku bazy danych
        limit (int): Limit wyników
        
    Returns:
        list: Lista ostatnich ataków
    """
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
        SELECT * FROM attack_logs
        ORDER BY id DESC
        LIMIT ?
        """
        
        cursor.execute(query, (limit,))
        attacks = cursor.fetchall()
        
        return [dict(attack) for attack in attacks]
        
    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania ostatnich ataków: {e}")
        return []
        
    finally:
        if conn:
            conn.close()


def get_attack_timeline(db_path, interval='hour', start_date=None, end_date=None):
    """
    Pobiera oś czasu ataków z bazy danych.
    
    Args:
        db_path (str): Ścieżka do pliku bazy danych
        interval (str): Interwał grupowania ('hour', 'day', 'month')
        start_date (str, optional): Data początkowa w formacie ISO
        end_date (str, optional): Data końcowa w formacie ISO
        
    Returns:
        list: Oś czasu ataków
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Funkcja grupująca w zależności od interwału
        if interval == 'hour':
            time_group = "substr(timestamp, 1, 13)"  # YYYY-MM-DDTHH
        elif interval == 'day':
            time_group = "substr(timestamp, 1, 10)"  # YYYY-MM-DD
        elif interval == 'month':
            time_group = "substr(timestamp, 1, 7)"   # YYYY-MM
        else:
            time_group = "substr(timestamp, 1, 10)"  # domyślnie dzień
        
        query = f"""
        SELECT {time_group} as time_period, attack_type, COUNT(*) as count
        FROM attack_logs
        """
        
        params = []
        
        # Dodanie filtrowania po datach jeśli podano
        if start_date or end_date:
            query += " WHERE 1=1"
            
            if start_date:
                query += " AND timestamp >= ?"
                params.append(start_date)
                
            if end_date:
                query += " AND timestamp <= ?"
                params.append(end_date)
                
        query += f" GROUP BY {time_group}, attack_type ORDER BY {time_group}"
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        
        # Przygotowanie wyników
        timeline = {}
        for time_period, attack_type, count in results:
            if time_period not in timeline:
                timeline[time_period] = {
                    'time': time_period,
                    'total': 0,
                    'ddos': 0,
                    'sql_injection': 0,
                    'machine_takeover': 0
                }
            
            timeline[time_period]['total'] += count
            if attack_type == 'ddos':
                timeline[time_period]['ddos'] += count
            elif attack_type == 'sql_injection':
                timeline[time_period]['sql_injection'] += count
            elif attack_type == 'machine_takeover':
                timeline[time_period]['machine_takeover'] += count
        
        # Konwersja do listy
        return list(timeline.values())
        
    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania osi czasu ataków: {e}")
        return []
        
    finally:
        if conn:
            conn.close()


def search_attacks(db_path, search_term, start_date=None, end_date=None, limit=100):
    """
    Wyszukuje ataki w bazie danych.
    
    Args:
        db_path (str): Ścieżka do pliku bazy danych
        search_term (str): Termin wyszukiwania
        start_date (str, optional): Data początkowa w formacie ISO
        end_date (str, optional): Data końcowa w formacie ISO
        limit (int): Limit wyników
        
    Returns:
        list: Lista znalezionych ataków
    """
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
        SELECT * FROM attack_logs
        WHERE (source_ip LIKE ? OR destination_ip LIKE ? OR attack_type LIKE ? 
               OR protocol LIKE ? OR severity LIKE ? OR detected_patterns LIKE ?)
        """
        
        search_param = f"%{search_term}%"
        params = [search_param, search_param, search_param, search_param, search_param, search_param]
        
        # Dodanie filtrowania po datach jeśli podano
        if start_date:
            query += " AND timestamp >= ?"
            params.append(start_date)
            
        if end_date:
            query += " AND timestamp <= ?"
            params.append(end_date)
            
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        attacks = cursor.fetchall()
        
        return [dict(attack) for attack in attacks]
        
    except sqlite3.Error as e:
        logger.error(f"Błąd podczas wyszukiwania ataków: {e}")
        return []
        
    finally:
        if conn:
            conn.close()