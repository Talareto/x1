#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł symulujący system logistyczny, rejestrujący ataki SQL Injection.
"""

import logging
import os
import random
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, g

# Konfiguracja logowania
logger = logging.getLogger('honeynet.logistics')

# Inicjalizacja aplikacji Flask
logistics_app = Flask(__name__)

# Ścieżka do bazy danych
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'honeynet.db')

# Ścieżka do bazy danych logistyki (symulowanej)
LOGISTICS_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database',
                                 'logistics.db')

# SQL patterns wskazujące na próby SQL Injection
SQL_INJECTION_PATTERNS = [
    r"['\"].*;.*--",
    r"\/\*.*\*\/",
    r"1\s*=\s*1",
    r"OR\s+1\s*=\s*1",
    r"DROP\s+TABLE",
    r"UNION\s+SELECT",
    r"SELECT\s+.*\s+FROM",
    r"DELETE\s+FROM",
    r"INSERT\s+INTO",
    r"SLEEP\s*\(",
    r"BENCHMARK\s*\(",
    r"WAITFOR\s+DELAY",
    r"XP_CMDSHELL"
]

# Skompilowane wyrażenia regularne dla zwiększonej wydajności
SQL_INJECTION_REGEX = [re.compile(pattern, re.IGNORECASE) for pattern in SQL_INJECTION_PATTERNS]

# HTML dla strony logowania
LOGIN_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>System Logistyczny - Logowanie</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 20px;
        }
        .login-container {
            max-width: 400px;
            margin: 100px auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            text-align: center;
            color: #2c3e50;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
            color: #2c3e50;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 3px;
            box-sizing: border-box;
        }
        button {
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            width: 100%;
            font-size: 16px;
        }
        button:hover {
            background-color: #2980b9;
        }
        .system-info {
            text-align: center;
            margin-top: 20px;
            color: #7f8c8d;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>System Logistyczny</h1>
        <form action="/login" method="POST">
            <div class="form-group">
                <label for="username">Nazwa użytkownika:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Hasło:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Zaloguj</button>
        </form>
        <div class="system-info">
            LogiTrack v3.5 &copy; 2024
        </div>
    </div>
</body>
</html>
'''

# HTML dla strony głównej po zalogowaniu
MAIN_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>System Logistyczny - Panel główny</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 0;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 15px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            margin: 0;
            font-size: 24px;
        }
        .user-info {
            display: flex;
            align-items: center;
        }
        .user-info span {
            margin-right: 15px;
        }
        .container {
            padding: 20px;
            max-width: 1200px;
            margin: 0 auto;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .card h2 {
            margin-top: 0;
            color: #2c3e50;
            font-size: 18px;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f8f9fa;
            color: #2c3e50;
        }
        .search-container {
            margin-bottom: 20px;
        }
        .search-container input {
            padding: 10px;
            width: 300px;
            border: 1px solid #ddd;
            border-radius: 3px;
        }
        .search-container button {
            padding: 10px 15px;
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        .search-container button:hover {
            background-color: #2980b9;
        }
        .status-active {
            color: green;
            font-weight: bold;
        }
        .status-inactive {
            color: red;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>LogiTrack v3.5 - System zarządzania logistyką</h1>
        <div class="user-info">
            <span>Zalogowany jako: admin</span>
            <a href="/logout" style="color: white;">Wyloguj</a>
        </div>
    </div>

    <div class="container">
        <div class="search-container">
            <form action="/search" method="GET">
                <input type="text" name="q" placeholder="Szukaj nadajnika po ID lub lokalizacji...">
                <button type="submit">Szukaj</button>
            </form>
        </div>

        <div class="dashboard">
            <div class="card">
                <h2>Statystyki systemu</h2>
                <p><strong>Aktywne nadajniki:</strong> 1,245</p>
                <p><strong>Aktywne pojazdy:</strong> 89</p>
                <p><strong>Monitorowane trasy:</strong> 53</p>
                <p><strong>Dzisiejsze dostawy:</strong> 347</p>
            </div>

            <div class="card">
                <h2>Status serwerów</h2>
                <p><strong>Serwer główny:</strong> <span class="status-active">Aktywny</span></p>
                <p><strong>Serwer zapasowy:</strong> <span class="status-active">Aktywny</span></p>
                <p><strong>Baza danych:</strong> <span class="status-active">Aktywna</span></p>
                <p><strong>Ostatnia aktualizacja:</strong> {{last_update}}</p>
            </div>

            <div class="card">
                <h2>Alerty</h2>
                <p><strong>Nadajniki offline:</strong> 3</p>
                <p><strong>Pojazdy opóźnione:</strong> 7</p>
                <p><strong>Naruszenia trasy:</strong> 1</p>
                <p><strong>Nieautoryzowany dostęp:</strong> 0</p>
            </div>
        </div>

        <div class="card">
            <h2>Ostatnio aktywne nadajniki</h2>
            <table>
                <thead>
                    <tr>
                        <th>ID Nadajnika</th>
                        <th>Typ</th>
                        <th>Lokalizacja</th>
                        <th>Status</th>
                        <th>Ostatnia aktualizacja</th>
                    </tr>
                </thead>
                <tbody>
                    {% for t in transmitters %}
                    <tr>
                        <td>{{t.id}}</td>
                        <td>{{t.type}}</td>
                        <td>{{t.location}}</td>
                        <td><span class="status-active">{{t.status}}</span></td>
                        <td>{{t.last_update}}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
'''


def from_database_import():
    """Importuje funkcje z modułu db_handler."""
    # Dodajemy ścieżkę do modułu bazy danych
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

    from honeynet.db_handler import log_attack

    return log_attack


def init_logistics_db():
    """Inicjalizuje bazę danych logistyki z przykładowymi danymi."""
    # Sprawdzenie czy katalog bazy danych istnieje
    os.makedirs(os.path.dirname(LOGISTICS_DB_PATH), exist_ok=True)

    conn = sqlite3.connect(LOGISTICS_DB_PATH)
    cursor = conn.cursor()

    # Tabela użytkowników
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        email TEXT,
        last_login TEXT
    )
    ''')

    # Tabela nadajników
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transmitters (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        serial_number TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL,
        status TEXT NOT NULL,
        location TEXT,
        last_update TEXT,
        battery_level INTEGER,
        signal_strength INTEGER,
        vehicle_id INTEGER
    )
    ''')

    # Tabela tras
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS routes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        start_point TEXT NOT NULL,
        end_point TEXT NOT NULL,
        distance REAL,
        estimated_time INTEGER,
        status TEXT,
        last_update TEXT
    )
    ''')

    # Tabela pojazdów
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS vehicles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        plate_number TEXT NOT NULL UNIQUE,
        type TEXT NOT NULL,
        model TEXT,
        driver_name TEXT,
        current_route_id INTEGER,
        status TEXT,
        last_position TEXT,
        fuel_level INTEGER,
        mileage INTEGER
    )
    ''')

    # Dodanie przykładowych danych
    try:
        # Przykładowi użytkownicy
        users = [
            ('admin', 'admin123', 'administrator', 'Jan Kowalski', 'admin@logitrack.pl'),
            ('user1', 'pass123', 'operator', 'Anna Nowak', 'a.nowak@logitrack.pl'),
            ('user2', 'pass456', 'driver', 'Piotr Wiśniewski', 'p.wisniewski@logitrack.pl')
        ]

        for user in users:
            cursor.execute(
                'INSERT OR IGNORE INTO users (username, password, role, full_name, email) VALUES (?, ?, ?, ?, ?)', user)

        # Przykładowe nadajniki
        transmitters = [
            ('TX-001', 'GPS', 'active', 'Warszawa, Żwirki i Wigury 15', datetime.now().isoformat(), 95, 90, 1),
            ('TX-002', 'RFID', 'active', 'Kraków, Rynek Główny 5', datetime.now().isoformat(), 80, 85, 2),
            ('TX-003', 'Bluetooth', 'active', 'Wrocław, Plac Grunwaldzki 12', datetime.now().isoformat(), 60, 75, 3),
            ('TX-004', 'GPS', 'inactive', 'Poznań, Stary Rynek 20', (datetime.now() - timedelta(hours=2)).isoformat(),
             10, 40, None),
            ('TX-005', 'RFID', 'active', 'Gdańsk, Długi Targ 10', datetime.now().isoformat(), 100, 95, 4)
        ]

        for transmitter in transmitters:
            cursor.execute('''INSERT OR IGNORE INTO transmitters 
                            (serial_number, type, status, location, last_update, battery_level, signal_strength, vehicle_id) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', transmitter)

        # Przykładowe trasy
        routes = [
            ('TRASA-WAW-KRK', 'Warszawa', 'Kraków', 290.5, 240, 'active', datetime.now().isoformat()),
            ('TRASA-WAW-GDA', 'Warszawa', 'Gdańsk', 340.0, 300, 'active', datetime.now().isoformat()),
            ('TRASA-KRK-WRO', 'Kraków', 'Wrocław', 270.0, 240, 'completed',
             (datetime.now() - timedelta(days=1)).isoformat()),
            ('TRASA-POZ-BER', 'Poznań', 'Berlin', 280.0, 300, 'planned', None),
            ('TRASA-GDA-SZC', 'Gdańsk', 'Szczecin', 360.0, 330, 'active', datetime.now().isoformat())
        ]

        for route in routes:
            cursor.execute('''INSERT OR IGNORE INTO routes 
                            (name, start_point, end_point, distance, estimated_time, status, last_update) 
                            VALUES (?, ?, ?, ?, ?, ?, ?)''', route)

        # Przykładowe pojazdy
        vehicles = [
            ('WX 12345', 'ciężarówka', 'Volvo FH16', 'Marek Nowak', 1, 'active', '52.22977, 21.01178', 80, 150000),
            ('KR 67890', 'dostawczy', 'Mercedes Sprinter', 'Tomasz Kowalski', 2, 'active', '50.06465, 19.94498', 60,
             85000),
            ('WR 11223', 'ciężarówka', 'MAN TGX', 'Robert Wiśniewski', 3, 'active', '51.10788, 17.03854', 90, 200000),
            ('PO 44556', 'dostawczy', 'Iveco Daily', 'Adam Kamiński', None, 'maintenance', '52.40692, 16.92993', 75,
             120000),
            ('GD 77889', 'ciężarówka', 'Scania R', 'Jacek Zieliński', 5, 'active', '54.35202, 18.64664', 95, 175000)
        ]

        for vehicle in vehicles:
            cursor.execute('''INSERT OR IGNORE INTO vehicles 
                            (plate_number, type, model, driver_name, current_route_id, status, last_position, fuel_level, mileage) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', vehicle)

        conn.commit()
        logger.info(f"Baza danych logistyki zainicjalizowana: {LOGISTICS_DB_PATH}")

    except sqlite3.Error as e:
        logger.error(f"Błąd podczas inicjalizacji bazy danych logistyki: {e}")

    finally:
        conn.close()


def detect_sql_injection(query_string):
    """
    Wykrywa próby SQL Injection w zapytaniu.

    Args:
        query_string (str): Ciąg zapytania do analizy

    Returns:
        tuple: (bool, str) - czy wykryto SQL injection, wykryta technika
    """
    if not query_string:
        return False, None

    query_string = str(query_string)

    # Sprawdzanie wzorców SQL Injection
    for i, pattern in enumerate(SQL_INJECTION_REGEX):
        if pattern.search(query_string):
            # Określanie techniki SQL Injection
            if i in [0, 1]:
                technique = "Comment-Based"
            elif i in [2, 3]:
                technique = "Boolean-Based"
            elif i in [4]:
                technique = "DDL Injection"
            elif i in [5]:
                technique = "UNION-Based"
            elif i in [6, 7, 8]:
                technique = "Classic SQL Statements"
            elif i in [9, 10, 11]:
                technique = "Time-Based Blind"
            elif i in [12]:
                technique = "System Command Execution"
            else:
                technique = "Unknown"

            return True, technique

    return False, None


def log_sql_injection_attempt(source_ip, source_port, payload, technique, path, success_status):
    """
    Loguje próbę ataku SQL Injection do bazy danych.

    Args:
        source_ip (str): Adres IP źródła ataku
        source_port (int): Port źródła ataku
        payload (str): Zidentyfikowany ładunek SQL
        technique (str): Technika ataku
        path (str): Ścieżka HTTP, na której wykryto atak
        success_status (int): Status wykonania ataku (0 - nieudany, 1 - udany)
    """
    log_attack = from_database_import()

    attack_data = {
        'timestamp': datetime.now().isoformat(),
        'source_ip': source_ip,
        'source_port': source_port,
        'destination_ip': request.host.split(':')[0] if request.host else '127.0.0.1',
        'destination_port': int(request.host.split(':')[1]) if ':' in request.host else 80,
        'attack_type': 'sql_injection',
        'protocol': 'HTTP',
        'severity': 'critical' if success_status else 'high',
        'detected_patterns': f'SQL Injection - {technique}',
        'session_id': f"sqli-{int(time.time())}-{source_ip}",
        'raw_data': request.data,
        'additional_info': {
            'user_agent': request.headers.get('User-Agent', ''),
            'request_path': path,
            'request_method': request.method,
            'headers': dict(request.headers),
            'cookies': dict(request.cookies),
            'referer': request.headers.get('Referer', '')
        },
        'sql_injection_details': {
            'query_type': request.method,
            'vulnerable_parameter': None,  # Will be identified in analyze_request
            'injection_point': path,
            'payload': payload,
            'database_type': 'SQLite',
            'success_status': success_status,
            'extracted_data': '',
            'error_messages': '',
            'injection_technique': technique
        }
    }

    # Identyfikacja podatnego parametru
    if request.method == 'GET':
        for param, value in request.args.items():
            is_sql, _ = detect_sql_injection(value)
            if is_sql:
                attack_data['sql_injection_details']['vulnerable_parameter'] = param
                break
    elif request.method == 'POST':
        for param, value in request.form.items():
            is_sql, _ = detect_sql_injection(value)
            if is_sql:
                attack_data['sql_injection_details']['vulnerable_parameter'] = param
                break

    # Symulacja wyciągnięcia danych (w prawdziwym ataku)
    if success_status:
        attack_data['sql_injection_details']['extracted_data'] = 'User accounts, routes, vehicle locations'

    log_attack(DB_PATH, attack_data)
    logger.warning(f"Wykryto próbę SQL Injection z {source_ip}:{source_port} - Technika: {technique}")


def get_logistics_db():
    """Pobiera połączenie do bazy danych logistyki dla bieżącego żądania."""
    if 'logistics_db' not in g:
        g.logistics_db = sqlite3.connect(LOGISTICS_DB_PATH)
        g.logistics_db.row_factory = sqlite3.Row
    return g.logistics_db


@logistics_app.teardown_appcontext
def close_connection(exception):
    """Zamyka połączenie z bazą danych po zakończeniu żądania."""
    db = g.pop('logistics_db', None)
    if db is not None:
        db.close()


@logistics_app.before_request
def analyze_request():
    """Analizuje każde przychodzące żądanie pod kątem ataków SQL Injection."""
    source_ip = request.remote_addr
    source_port = request.environ.get('REMOTE_PORT', 0)
    path = request.path

    payload = None
    technique = None

    # Sprawdzanie parametrów GET
    if request.args:
        for param, value in request.args.items():
            is_sql, detected_technique = detect_sql_injection(value)
            if is_sql:
                payload = value
                technique = detected_technique
                log_sql_injection_attempt(source_ip, source_port, payload, technique, path, 0)
                break

    # Sprawdzanie parametrów POST
    if request.method == 'POST' and request.form:
        for param, value in request.form.items():
            is_sql, detected_technique = detect_sql_injection(value)
            if is_sql:
                payload = value
                technique = detected_technique
                log_sql_injection_attempt(source_ip, source_port, payload, technique, path, 0)
                break

    # Sprawdzanie ciasteczek
    if request.cookies:
        for cookie_name, cookie_value in request.cookies.items():
            is_sql, detected_technique = detect_sql_injection(cookie_value)
            if is_sql:
                payload = cookie_value
                technique = detected_technique
                log_sql_injection_attempt(source_ip, source_port, payload, technique, path, 0)
                break


@logistics_app.route('/')
def index():
    """Główna strona systemu logistycznego - formularz logowania."""
    return LOGIN_PAGE


@logistics_app.route('/login', methods=['POST'])
def login():
    """Obsługa logowania z wykrywaniem SQL Injection."""
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    source_ip = request.remote_addr
    source_port = request.environ.get('REMOTE_PORT', 0)

    # Sprawdzanie SQL Injection w nazwie użytkownika i haśle
    is_sql_user, technique_user = detect_sql_injection(username)
    is_sql_pass, technique_pass = detect_sql_injection(password)

    if is_sql_user or is_sql_pass:
        payload = username if is_sql_user else password
        technique = technique_user if is_sql_user else technique_pass
        vulnerable_param = 'username' if is_sql_user else 'password'

        # Logowanie ataku SQL Injection
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'source_port': source_port,
            'destination_ip': request.host.split(':')[0] if request.host else '127.0.0.1',
            'destination_port': int(request.host.split(':')[1]) if ':' in request.host else 80,
            'attack_type': 'sql_injection',
            'protocol': 'HTTP',
            'severity': 'critical',
            'detected_patterns': f'SQL Injection - {technique}',
            'session_id': f"sqli-{int(time.time())}-{source_ip}",
            'raw_data': request.data,
            'additional_info': {
                'user_agent': request.headers.get('User-Agent', ''),
                'request_path': '/login',
                'request_method': 'POST',
                'headers': dict(request.headers)
            },
            'sql_injection_details': {
                'query_type': 'POST',
                'vulnerable_parameter': vulnerable_param,
                'injection_point': '/login',
                'payload': payload,
                'database_type': 'SQLite',
                'success_status': 1,  # Symulujemy udany atak
                'extracted_data': 'admin credentials',
                'error_messages': '',
                'injection_technique': technique
            }
        }

        log_attack = from_database_import()
        log_attack(DB_PATH, attack_data)

        # Symulacja podatnej odpowiedzi
        return jsonify({
            'error': 'Database error',
            'message': 'Error in SQLite: near "' + str(payload[:20]) + '": syntax error',
            'debug': {
                'query': f"SELECT * FROM users WHERE username='{username}' AND password='{password}'",
                'error_code': 'SQL_SYNTAX_ERROR'
            }
        }), 500

    # Normalna procedura logowania
    db = get_logistics_db()
    cursor = db.cursor()

    try:
        cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()

        if user:
            return f"Zalogowano jako: {user['full_name']} ({user['role']})", 200
        else:
            return "Nieprawidłowa nazwa użytkownika lub hasło", 401

    except sqlite3.Error as e:
        logger.error(f"Błąd bazy danych: {e}")
        return "Błąd serwera", 500


@logistics_app.route('/search')
def search():
    """Wyszukiwanie nadajników - endpoint podatny na SQL Injection."""
    query = request.args.get('q', '')

    source_ip = request.remote_addr
    source_port = request.environ.get('REMOTE_PORT', 0)

    # Sprawdzanie SQL Injection
    is_sql, technique = detect_sql_injection(query)

    if is_sql:
        # Logowanie ataku z symulacją udanego ataku
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'source_port': source_port,
            'destination_ip': request.host.split(':')[0] if request.host else '127.0.0.1',
            'destination_port': int(request.host.split(':')[1]) if ':' in request.host else 80,
            'attack_type': 'sql_injection',
            'protocol': 'HTTP',
            'severity': 'critical',
            'detected_patterns': f'SQL Injection - {technique}',
            'session_id': f"sqli-{int(time.time())}-{source_ip}",
            'raw_data': request.data,
            'additional_info': {
                'user_agent': request.headers.get('User-Agent', ''),
                'request_path': '/search',
                'request_method': 'GET',
                'headers': dict(request.headers)
            },
            'sql_injection_details': {
                'query_type': 'GET',
                'vulnerable_parameter': 'q',
                'injection_point': '/search',
                'payload': query,
                'database_type': 'SQLite',
                'success_status': 1,
                'extracted_data': 'transmitter locations, vehicle routes',
                'error_messages': '',
                'injection_technique': technique
            }
        }

        log_attack = from_database_import()
        log_attack(DB_PATH, attack_data)

        # Symulacja podatnej odpowiedzi z danymi
        return jsonify({
            'status': 'success',
            'data': {
                'transmitters': [
                    {'id': 'TX-001', 'location': 'Warszawa, Żwirki i Wigury 15', 'type': 'GPS'},
                    {'id': 'TX-002', 'location': 'Kraków, Rynek Główny 5', 'type': 'RFID'}
                ],
                'error': f"SQL syntax error near '{query[:20]}'"
            }
        })

    # Normalne wyszukiwanie
    db = get_logistics_db()
    cursor = db.cursor()

    try:
        # Bezpieczne zapytanie z parametryzacją
        cursor.execute('''
            SELECT serial_number, type, location, status, last_update 
            FROM transmitters 
            WHERE serial_number LIKE ? OR location LIKE ?
            LIMIT 10
        ''', (f'%{query}%', f'%{query}%'))

        results = cursor.fetchall()

        return jsonify({
            'status': 'success',
            'data': [dict(row) for row in results]
        })

    except sqlite3.Error as e:
        logger.error(f"Błąd podczas wyszukiwania: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Błąd serwera podczas wyszukiwania'
        }), 500


@logistics_app.route('/api/routes/<route_id>')
def get_route(route_id):
    """Pobiera szczegóły trasy - endpoint podatny na SQL Injection."""
    source_ip = request.remote_addr
    source_port = request.environ.get('REMOTE_PORT', 0)

    # Sprawdzanie SQL Injection w ID trasy
    is_sql, technique = detect_sql_injection(route_id)

    if is_sql:
        # Logowanie ataku
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'source_ip': source_ip,
            'source_port': source_port,
            'destination_ip': request.host.split(':')[0] if request.host else '127.0.0.1',
            'destination_port': int(request.host.split(':')[1]) if ':' in request.host else 80,
            'attack_type': 'sql_injection',
            'protocol': 'HTTP',
            'severity': 'high',
            'detected_patterns': f'SQL Injection - {technique}',
            'session_id': f"sqli-{int(time.time())}-{source_ip}",
            'raw_data': request.data,
            'additional_info': {
                'user_agent': request.headers.get('User-Agent', ''),
                'request_path': f'/api/routes/{route_id}',
                'request_method': 'GET',
                'headers': dict(request.headers)
            },
            'sql_injection_details': {
                'query_type': 'GET',
                'vulnerable_parameter': 'route_id',
                'injection_point': '/api/routes/',
                'payload': route_id,
                'database_type': 'SQLite',
                'success_status': 1,
                'extracted_data': 'route details',
                'error_messages': '',
                'injection_technique': technique
            }
        }

        log_attack = from_database_import()
        log_attack(DB_PATH, attack_data)

        # Symulacja błędu SQL
        return jsonify({
            'error': 'Database error',
            'message': f'Error in SQLite near "{route_id[:20]}": syntax error'
        }), 500

    # Normalne zapytanie
    db = get_logistics_db()
    cursor = db.cursor()

    try:
        cursor.execute('SELECT * FROM routes WHERE id = ?', (route_id,))
        route = cursor.fetchone()

        if route:
            return jsonify(dict(route))
        else:
            return jsonify({'error': 'Route not found'}), 404

    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania trasy: {e}")
        return jsonify({'error': 'Server error'}), 500


@logistics_app.route('/api/vehicles')
def get_vehicles():
    """Zwraca listę pojazdów - endpoint dla JSON API."""
    db = get_logistics_db()
    cursor = db.cursor()

    try:
        cursor.execute('SELECT * FROM vehicles LIMIT 50')
        vehicles = cursor.fetchall()

        return jsonify({
            'status': 'success',
            'data': [dict(vehicle) for vehicle in vehicles]
        })

    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania pojazdów: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Server error'
        }), 500


@logistics_app.route('/api/transmitters')
def get_transmitters():
    """Zwraca listę nadajników - endpoint dla JSON API."""
    db = get_logistics_db()
    cursor = db.cursor()

    try:
        cursor.execute('SELECT * FROM transmitters LIMIT 50')
        transmitters = cursor.fetchall()

        return jsonify({
            'status': 'success',
            'data': [dict(transmitter) for transmitter in transmitters]
        })

    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania nadajników: {e}")
        return jsonify({
            'status': 'error',
            'message': 'Server error'
        }), 500


@logistics_app.errorhandler(404)
def page_not_found(e):
    """Obsługa nieznanych ścieżek."""
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested URL was not found on this server.'
    }), 404


@logistics_app.errorhandler(500)
def internal_error(e):
    """Obsługa błędów serwera."""
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'The server encountered an internal error and was unable to complete your request.'
    }), 500


def run_logistics_service(host='0.0.0.0', port=8001):
    """
    Uruchamia symulowany system logistyczny.

    Args:
        host (str): Adres IP do nasłuchiwania
        port (int): Port do nasłuchiwania
    """
    # Inicjalizacja bazy danych logistyki
    init_logistics_db()

    logger.info(f"Uruchamianie symulacji systemu logistycznego na {host}:{port}")

    try:
        logistics_app.run(host=host, port=port, debug=False, threaded=True)
    except Exception as e:
        logger.error(f"Błąd podczas uruchamiania symulacji systemu logistycznego: {e}")


if __name__ == "__main__":
    # Konfiguracja logowania
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Uruchomienie usługi logistyki
    run_logistics_service()