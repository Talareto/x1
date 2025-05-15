#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł symulujący kamery IP, rejestrujący ataki DDoS.
"""

import logging
import os
import random
import socket
import sqlite3
import threading
import time
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string

# Konfiguracja logowania
logger = logging.getLogger('honeynet.camera')

# Inicjalizacja aplikacji Flask
camera_app = Flask(__name__)

# Globalne liczniki i statystyki
connection_stats = {
    'total_connections': 0,
    'suspicious_connections': 0,
    'connection_rate': 0,
    'last_reset_time': time.time(),
    'active_connections': 0,
    'connection_history': [],
    'source_ips': set(),
    'traffic_volume': 0
}

# Blokada do synchronizacji dostępu do statystyk
stats_lock = threading.Lock()

# Ścieżka do bazy danych
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'honeynet.db')

# Próg dla wykrywania ataków DDoS (połączeń na sekundę)
DDOS_THRESHOLD = 10

# HTML dla strony logowania kamery
LOGIN_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Kamera IP - Panel logowania</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
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
            color: #333;
        }
        .form-group {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 3px;
            box-sizing: border-box;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            width: 100%;
        }
        button:hover {
            background-color: #45a049;
        }
        .camera-brand {
            text-align: center;
            margin-top: 20px;
            color: #888;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Kamera IP</h1>
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
        <div class="camera-brand">
            SecureCam IP v2.1
        </div>
    </div>
</body>
</html>
'''

# HTML dla strony głównej kamery po zalogowaniu
CAMERA_MAIN_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SecureCam IP - Panel sterowania</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f0f0f0;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 5px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1 {
            text-align: center;
            color: #333;
        }
        .camera-view {
            width: 100%;
            height: 400px;
            background-color: #222;
            margin: 20px 0;
            position: relative;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 16px;
        }
        .controls {
            display: flex;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        button {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
        }
        button:hover {
            background-color: #45a049;
        }
        .settings {
            margin-top: 20px;
        }
        .row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
        }
        .camera-info {
            margin-top: 20px;
            padding: 10px;
            background-color: #f9f9f9;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SecureCam IP - Panel sterowania</h1>
        <div class="camera-view">
            [Podgląd kamery niedostępny - Błąd połączenia]
        </div>
        <div class="controls">
            <button>Przesuń w lewo</button>
            <button>Przesuń w górę</button>
            <button>Przesuń w dół</button>
            <button>Przesuń w prawo</button>
        </div>
        <div class="settings">
            <h3>Ustawienia kamery</h3>
            <div class="row">
                <span>Rozdzielczość:</span>
                <select>
                    <option>1920x1080</option>
                    <option>1280x720</option>
                    <option>800x600</option>
                </select>
            </div>
            <div class="row">
                <span>Jakość obrazu:</span>
                <select>
                    <option>Wysoka</option>
                    <option>Średnia</option>
                    <option>Niska</option>
                </select>
            </div>
            <div class="row">
                <span>Nagrywanie:</span>
                <input type="checkbox" checked>
            </div>
            <div class="row">
                <span>Detekcja ruchu:</span>
                <input type="checkbox">
            </div>
        </div>
        <div class="camera-info">
            <p><strong>Model kamery:</strong> SecureCam IP v2.1</p>
            <p><strong>Adres IP:</strong> {{ip_address}}</p>
            <p><strong>Status połączenia:</strong> <span style="color: red;">Problem z sygnałem</span></p>
            <p><strong>Wersja firmware:</strong> 3.2.1</p>
        </div>
    </div>
</body>
</html>
'''


def import_db_handler():
    """Importuje moduł db_handler."""
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    try:
        from honeynet.db_handler import log_attack
        return log_attack
    except ImportError as e:
        logger.error(f"Nie można zaimportować modułu db_handler: {e}")
        
        # Funkcja zastępcza w przypadku braku możliwości importu
        def fallback_log_attack(db_path, attack_data):
            logger.warning("Używam zastępczej funkcji log_attack!")
            logger.info(f"Atak: {attack_data.get('attack_type')} z {attack_data.get('source_ip')}")
            return None
            
        return fallback_log_attack


def reset_stats():
    """Resetuje liczniki statystyk co minutę."""
    while True:
        time.sleep(60)  # Resetowanie co minutę
        current_time = time.time()

        with stats_lock:
            elapsed = current_time - connection_stats['last_reset_time']
            if elapsed > 0:
                connection_stats['connection_rate'] = connection_stats['total_connections'] / elapsed
            connection_stats['total_connections'] = 0
            connection_stats['last_reset_time'] = current_time

            # Zachowujemy historię ostatnich 10 minut
            connection_stats['connection_history'].append({
                'timestamp': datetime.now().isoformat(),
                'rate': connection_stats['connection_rate'],
                'active': connection_stats['active_connections']
            })

            if len(connection_stats['connection_history']) > 10:
                connection_stats['connection_history'] = connection_stats['connection_history'][-10:]


def detect_ddos(source_ip, source_port):
    """
    Wykrywa potencjalne ataki DDoS na podstawie wzorców ruchu.

    Args:
        source_ip (str): Adres IP źródła połączenia
        source_port (int): Port źródła połączenia

    Returns:
        bool: True jeśli wykryto atak DDoS, False w przeciwnym razie
    """
    with stats_lock:
        connection_stats['total_connections'] += 1
        connection_stats['active_connections'] += 1
        connection_stats['source_ips'].add(source_ip)
        
        # Aktualizacja statystyki ruchu
        request_size = len(request.data) if request.data else 0
        connection_stats['traffic_volume'] += request_size

        current_time = time.time()
        elapsed = current_time - connection_stats['last_reset_time']

        if elapsed > 0:
            current_rate = connection_stats['total_connections'] / elapsed
        else:
            current_rate = 0

        # Wykrywanie potencjalnego ataku DDoS
        is_ddos = current_rate > DDOS_THRESHOLD

        if is_ddos:
            connection_stats['suspicious_connections'] += 1

            # Logowanie ataku do bazy danych
            log_attack = import_db_handler()

            attack_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_ip,
                'source_port': source_port,
                'destination_ip': request.host.split(':')[0] if request.host else '127.0.0.1',
                'destination_port': int(request.host.split(':')[1]) if ':' in request.host else 80,
                'attack_type': 'ddos',
                'protocol': 'HTTP',
                'severity': 'high' if current_rate > DDOS_THRESHOLD * 2 else 'medium',
                'detected_patterns': 'high_connection_rate',
                'session_id': f"ddos-{int(time.time())}-{source_ip}",
                'raw_data': request.data,
                'additional_info': {
                    'user_agent': request.headers.get('User-Agent', ''),
                    'request_path': request.path,
                    'request_method': request.method,
                    'headers': dict(request.headers)
                },
                'ddos_details': {
                    'packets_count': connection_stats['total_connections'],
                    'packet_type': 'HTTP',
                    'bandwidth_usage': connection_stats['traffic_volume'],
                    'attack_duration': elapsed,
                    'attack_vector': 'HTTP-FLOOD',
                    'packet_distribution': json.dumps({
                        'GET': request.method == 'GET',
                        'POST': request.method == 'POST'
                    }),
                    'target_service': 'IP-CAMERA',
                    'traffic_pattern': 'bursty' if current_rate > DDOS_THRESHOLD * 3 else 'steady',
                    'amplification_factor': 1.0
                }
            }

            attack_id = log_attack(DB_PATH, attack_data)
            logger.warning(
                f"Wykryto potencjalny atak DDoS z {source_ip}:{source_port} (rate: {current_rate:.2f} conn/s), ID: {attack_id}")

        return is_ddos


@camera_app.before_request
def check_request():
    """Sprawdza każde przychodzące żądanie pod kątem ataków."""
    source_ip = request.remote_addr
    source_port = request.environ.get('REMOTE_PORT', 0)

    # Rejestrowanie wszystkich żądań
    logger.debug(f"Żądanie od {source_ip}:{source_port} - {request.method} {request.path}")

    # Wykrywanie potencjalnych ataków
    detect_ddos(source_ip, source_port)


@camera_app.route('/')
def index():
    """Główna strona kamery IP - formularz logowania."""
    return LOGIN_PAGE


@camera_app.route('/login', methods=['POST'])
def login():
    """Obsługa logowania do kamery."""
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # Rejestrowanie prób logowania
    source_ip = request.remote_addr
    logger.info(f"Próba logowania od {source_ip} - użytkownik: {username}")

    # Symulacja logowania (zawsze nieudana)
    return "Błąd logowania: Nieprawidłowa nazwa użytkownika lub hasło.", 401


@camera_app.route('/api/status')
def camera_status():
    """Zwraca status kamery w formacie JSON."""
    return jsonify({
        'status': 'online',
        'model': 'SecureCam IP v2.1',
        'firmware': '3.2.1',
        'uptime': int(time.time() % 86400),  # Symulacja czasu pracy w sekundach
        'connection_quality': random.randint(60, 95)
    })


@camera_app.route('/api/stream')
def camera_stream():
    """Symulacja endpointu strumienia wideo."""
    # Symulujemy opóźnienie
    time.sleep(0.2)

    return "Stream niedostępny", 503


@camera_app.route('/api/settings', methods=['GET', 'POST'])
def camera_settings():
    """Obsługa ustawień kamery."""
    if request.method == 'GET':
        return jsonify({
            'resolution': '1920x1080',
            'quality': 'high',
            'recording': True,
            'motion_detection': False,
            'night_vision': True,
            'rotate': 0
        })
    else:
        # W przypadku POST zwracamy błąd autoryzacji
        return jsonify({
            'error': 'Unauthorized',
            'message': 'Authentication required'
        }), 401


@camera_app.route('/api/reboot', methods=['POST'])
def reboot_camera():
    """Symuluje restart kamery."""
    return jsonify({
        'status': 'rebooting',
        'message': 'Camera is rebooting, please wait...'
    })


@camera_app.route('/api/snapshot')
def take_snapshot():
    """Symuluje wykonanie zdjęcia z kamery."""
    # Symulujemy opóźnienie
    time.sleep(0.5)

    return "Snapshot niedostępny", 503


@camera_app.errorhandler(404)
def page_not_found(e):
    """Obsługa nieznanych ścieżek."""
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested URL was not found on this server.'
    }), 404


@camera_app.teardown_request
def teardown_request(exception=None):
    """Czyszczenie po zakończeniu obsługi żądania."""
    with stats_lock:
        connection_stats['active_connections'] = max(0, connection_stats['active_connections'] - 1)


def run_camera_service(host='0.0.0.0', port=8000):
    """
    Uruchamia symulowaną usługę kamery IP.

    Args:
        host (str): Adres IP do nasłuchiwania
        port (int): Port do nasłuchiwania
    """
    # Uruchomienie wątku resetującego statystyki
    stats_thread = threading.Thread(target=reset_stats, daemon=True)
    stats_thread.start()

    logger.info(f"Uruchamianie symulacji kamery IP na {host}:{port}")

    try:
        camera_app.run(host=host, port=port, debug=False, threaded=True)
    except Exception as e:
        logger.error(f"Błąd podczas uruchamiania symulacji kamery IP: {e}")


if __name__ == "__main__":
    # Konfiguracja logowania
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Uruchomienie usługi kamery
    run_camera_service()