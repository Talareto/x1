#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł symulujący maszyny produkcyjne, rejestrujący próby przejęcia kontroli.
"""

import logging
import os
import random
import socket
import sqlite3
import threading
import time
import json
import hashlib
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, g, make_response

# Konfiguracja logowania
logger = logging.getLogger('honeynet.production')

# Inicjalizacja aplikacji Flask
production_app = Flask(__name__)

# Ścieżka do bazy danych
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'honeynet.db')

# Globalne dane o sesjach i próbach logowania
session_data = {
    'active_sessions': {},
    'authentication_attempts': {},
    'command_history': {},
    'takeover_attempts': {},
    'machine_statuses': {}
}

# Blokada do synchronizacji dostępu do danych sesji
session_lock = threading.Lock()

# Lista domyślnych haseł często używanych w urządzeniach IoT/ICS
DEFAULT_PASSWORDS = [
    'admin', 'password', '123456', 'default', 'admin123', 'root', '12345',
    'machine', 'operator', 'system', 'control', 'plc', 'factory', 'production',
    'industrial', 'supervisor', 'maintenance', 'tech', 'manager', 'service'
]

# Lista eksploitów/podatności często wykorzystywanych
COMMON_EXPLOITS = [
    'CVE-2020-14750', 'CVE-2021-44228', 'CVE-2019-19781', 'CVE-2021-21972',
    'EternalBlue', 'Heartbleed', 'Shellshock', 'ROBOT', 'BlueKeep', 'ZeroLogon'
]

# HTML dla strony logowania
LOGIN_PAGE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Production Control System - Login</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #2e3440;
            color: #d8dee9;
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-container {
            background-color: #3b4252;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.3);
            width: 400px;
        }
        h1 {
            text-align: center;
            color: #88c0d0;
            margin-bottom: 30px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #e5e9f0;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #4c566a;
            border-radius: 5px;
            background-color: #434c5e;
            color: #eceff4;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background-color: #88c0d0;
            color: #2e3440;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
        }
        button:hover {
            background-color: #81a1c1;
        }
        .warning {
            text-align: center;
            color: #bf616a;
            margin-top: 20px;
            font-size: 12px;
        }
        .system-info {
            text-align: center;
            margin-top: 20px;
            font-size: 12px;
            color: #81a1c1;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Production Control System</h1>
        <form action="/auth" method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Login</button>
        </form>
        <div class="warning">
            AUTHORIZED PERSONNEL ONLY<br>
            All access attempts are logged and monitored
        </div>
        <div class="system-info">
            IndustrialControl v5.2.1 | PLC System Monitor
        </div>
    </div>
</body>
</html>
'''

# HTML dla panelu kontrolnego
CONTROL_PANEL = '''
<!DOCTYPE html>
<html>
<head>
    <title>Production Control Panel</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #2e3440;
            color: #d8dee9;
            margin:margin: 0;
            padding: 20px;
        }
        .header {
            background-color: #3b4252;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 {
            margin: 0;
            color: #88c0d0;
        }
        .logout-btn {
            background-color: #bf616a;
            color: white;
            border: none;
            padding: 8px 15px;
            border-radius: 5px;
            cursor: pointer;
        }
        .container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .machine-card {
            background-color: #3b4252;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.2);
        }
        .machine-card h2 {
            color: #88c0d0;
            margin-top: 0;
        }
        .status {
            font-weight: bold;
            margin: 10px 0;
        }
        .status.online {
            color: #a3be8c;
        }
        .status.offline {
            color: #bf616a;
        }
        .status.maintenance {
            color: #ebcb8b;
        }
        .control-buttons {
            margin-top: 15px;
        }
        .control-btn {
            background-color: #5e81ac;
            color: white;
            border: none;
            padding: 8px 12px;
            margin: 5px;
            border-radius: 5px;
            cursor: pointer;
        }
        .control-btn:hover {
            background-color: #81a1c1;
        }
        .control-btn.danger {
            background-color: #bf616a;
        }
        .metrics {
            margin-top: 15px;
            padding: 10px;
            background-color: #2e3440;
            border-radius: 5px;
        }
        .log-area {
            background-color: #3b4252;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            height: 200px;
            overflow-y: auto;
        }
        .log-entry {
            margin: 5px 0;
            font-family: monospace;
        }
        .log-entry.error {
            color: #bf616a;
        }
        .log-entry.warning {
            color: #ebcb8b;
        }
        .log-entry.info {
            color: #5e81ac;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Production Control Panel</h1>
        <button class="logout-btn" onclick="location.href='/logout'">Logout</button>
    </div>

    <div class="container">
        <div class="machine-card">
            <h2>Machine #1 - Assembly Line A</h2>
            <div class="status online">Status: OPERATIONAL</div>
            <div class="metrics">
                <div>Speed: 120 units/hour</div>
                <div>Efficiency: 94%</div>
                <div>Temperature: 32°C</div>
                <div>Power: 15.2 kW</div>
            </div>
            <div class="control-buttons">
                <button class="control-btn" onclick="sendCommand('machine1', 'start')">Start</button>
                <button class="control-btn danger" onclick="sendCommand('machine1', 'stop')">Stop</button>
                <button class="control-btn" onclick="sendCommand('machine1', 'reset')">Reset</button>
                <button class="control-btn" onclick="sendCommand('machine1', 'status')">Status</button>
            </div>
        </div>

        <div class="machine-card">
            <h2>Machine #2 - Packaging Unit</h2>
            <div class="status online">Status: OPERATIONAL</div>
            <div class="metrics">
                <div>Speed: 80 units/hour</div>
                <div>Efficiency: 91%</div>
                <div>Temperature: 28°C</div>
                <div>Power: 8.7 kW</div>
            </div>
            <div class="control-buttons">
                <button class="control-btn" onclick="sendCommand('machine2', 'start')">Start</button>
                <button class="control-btn danger" onclick="sendCommand('machine2', 'stop')">Stop</button>
                <button class="control-btn" onclick="sendCommand('machine2', 'reset')">Reset</button>
                <button class="control-btn" onclick="sendCommand('machine2', 'status')">Status</button>
            </div>
        </div>

        <div class="machine-card">
            <h2>Machine #3 - Quality Control</h2>
            <div class="status maintenance">Status: MAINTENANCE</div>
            <div class="metrics">
                <div>Speed: 0 units/hour</div>
                <div>Efficiency: -</div>
                <div>Temperature: 25°C</div>
                <div>Power: 0.1 kW</div>
            </div>
            <div class="control-buttons">
                <button class="control-btn" disabled>Start</button>
                <button class="control-btn danger" disabled>Stop</button>
                <button class="control-btn" disabled>Reset</button>
                <button class="control-btn" onclick="sendCommand('machine3', 'status')">Status</button>
            </div>
        </div>
    </div>

    <div class="log-area">
        <h3>System Log</h3>
        <div id="log-content">
            <div class="log-entry info">[INFO] System started</div>
            <div class="log-entry info">[INFO] Connected to PLC controllers</div>
            <div class="log-entry warning">[WARNING] Machine #3 requires maintenance</div>
        </div>
    </div>

    <script>
        function sendCommand(machine, command) {
            fetch(`/api/control/${machine}/${command}`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    addLogEntry('info', `Command '${command}' sent to ${machine}`);
                } else {
                    addLogEntry('error', `Failed to execute command: ${data.message}`);
                }
            })
            .catch(error => {
                addLogEntry('error', `Communication error: ${error}`);
            });
        }

        function addLogEntry(type, message) {
            const logContent = document.getElementById('log-content');
            const entry = document.createElement('div');
            entry.className = `log-entry ${type}`;
            const timestamp = new Date().toLocaleTimeString();
            entry.textContent = `[${timestamp}] [${type.toUpperCase()}] ${message}`;
            logContent.appendChild(entry);
            logContent.scrollTop = logContent.scrollHeight;
        }

        // Simulate periodic updates
        setInterval(() => {
            fetch('/api/system/status')
                .then(response => response.json())
                .then(data => {
                    console.log('System status updated:', data);
                })
                .catch(error => console.error('Error fetching status:', error));
        }, 5000);
    </script>
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


def generate_session_id():
    """Generuje unikalny identyfikator sesji."""
    return hashlib.sha256(f"{time.time()}_{random.random()}".encode()).hexdigest()[:32]


def detect_takeover_method(username, password, user_agent, request_data):
    """
    Wykrywa metodę przejęcia kontroli na podstawie analizy żądania.

    Args:
        username (str): Nazwa użytkownika
        password (str): Hasło
        user_agent (str): User agent klienta
        request_data (dict): Dodatkowe dane żądania

    Returns:
        str: Wykryta metoda ataku
    """
    # Analiza metody ataku
    if username in ['admin', 'root', 'operator'] and password in DEFAULT_PASSWORDS:
        return "bruteforce"

    if any(exploit in user_agent for exploit in COMMON_EXPLOITS):
        return "exploit"

    if 'malware' in user_agent.lower() or 'exploit' in user_agent.lower():
        return "malware"

    if username == "admin" and password == "admin":
        return "default_credentials"

    # Analiza wzorców w nagłówkach
    headers = request_data.get('headers', {})
    if 'X-Exploit' in headers or 'X-Malware' in headers:
        return "exploit"

    # Domyślnie zakładamy bruteforce
    return "bruteforce"


def detect_malicious_commands(command, machine_id):
    """
    Wykrywa złośliwe komendy w systemie produkcyjnym.

    Args:
        command (str): Komenda do wykonania
        machine_id (str): ID maszyny

    Returns:
        bool: True jeśli komenda jest złośliwa
    """
    malicious_patterns = [
        'rm -rf',
        'format',
        'delete',
        'drop',
        'exec',
        'system(',
        'eval(',
        'shell',
        'backdoor',
        'reverse',
        ';',
        '&&',
        '||'
    ]

    command_lower = command.lower()
    return any(pattern in command_lower for pattern in malicious_patterns)


@production_app.before_request
def track_authentication_attempts():
    """Śledzi próby uwierzytelnienia i wykrywa ataki."""
    source_ip = request.remote_addr
    source_port = request.environ.get('REMOTE_PORT', 0)

    with session_lock:
        if source_ip not in session_data['authentication_attempts']:
            session_data['authentication_attempts'][source_ip] = {
                'count': 0,
                'first_attempt': datetime.now(),
                'last_attempt': datetime.now(),
                'successful': False
            }

        # Aktualizacja licznika prób
        session_data['authentication_attempts'][source_ip]['count'] += 1
        session_data['authentication_attempts'][source_ip]['last_attempt'] = datetime.now()


@production_app.route('/')
def index():
    """Strona główna - formularz logowania."""
    return LOGIN_PAGE


@production_app.route('/auth', methods=['POST'])
def authenticate():
    """Obsługa uwierzytelniania z wykrywaniem prób przejęcia."""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    source_ip = request.remote_addr
    source_port = request.environ.get('REMOTE_PORT', 0)

    # Analiza metody ataku
    user_agent = request.headers.get('User-Agent', '')
    request_data = {
        'headers': dict(request.headers),
        'form': dict(request.form),
        'args': dict(request.args)
    }

    takeover_method = detect_takeover_method(username, password, user_agent, request_data)

    # Symulacja uwierzytelnienia
    is_successful = False
    if username == "admin" and password == "admin":
        is_successful = True
    elif username in ['operator', 'supervisor'] and password in DEFAULT_PASSWORDS:
        is_successful = True

    # Logowanie próby przejęcia
    with session_lock:
        attempts = session_data['authentication_attempts'][source_ip]['count']
        
        # Aktualizacja informacji o powodzeniu ataku
        session_data['authentication_attempts'][source_ip]['successful'] = is_successful
        
        # Dodanie do licznika prób przejęcia jeśli jest to atak
        if attempts > 3 or takeover_method != "default_credentials":
            # Dodaj do statystyk takeover_attempts
            if source_ip not in session_data['takeover_attempts']:
                session_data['takeover_attempts'][source_ip] = 0
            
            session_data['takeover_attempts'][source_ip] += 1
            
            # Logowanie ataku do bazy danych
            log_attack = import_db_handler()

            attack_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_ip,
                'source_port': source_port,
                'destination_ip': request.host.split(':')[0] if request.host else '127.0.0.1',
                'destination_port': int(request.host.split(':')[1]) if ':' in request.host else 80,
                'attack_type': 'machine_takeover',
                'protocol': 'HTTP',
                'severity': 'critical' if is_successful else 'high',
                'detected_patterns': f'Authentication attempt - {takeover_method}',
                'session_id': f"takeover-{int(time.time())}-{source_ip}",
                'raw_data': request.data,
                'additional_info': {
                    'user_agent': user_agent,
                    'request_path': '/auth',
                    'request_method': 'POST',
                    'headers': dict(request.headers),
                    'username_attempted': username,
                    'success': is_successful
                },
                'machine_takeover_details': {
                    'target_machine': 'Production Control System',
                    'exploit_used': takeover_method,
                    'authentication_attempts': attempts,
                    'command_sequence': '',
                    'control_duration': 0.0,
                    'system_changes': 'Authentication bypass' if is_successful else 'Failed login',
                    'access_level': 'admin' if is_successful else 'none',
                    'machine_type': 'PLC Controller',
                    'affected_operations': 'Production control' if is_successful else ''
                }
            }

            attack_id = log_attack(DB_PATH, attack_data)
            logger.warning(f"Wykryto próbę przejęcia maszyn przez {source_ip} - Metoda: {takeover_method}, ID: {attack_id}")

    if is_successful:
        # Utworzenie sesji
        session_id = generate_session_id()
        with session_lock:
            session_data['active_sessions'][session_id] = {
                'ip': source_ip,
                'username': username,
                'login_time': datetime.now(),
                'commands': []
            }

        # Zwrócenie panelu kontrolnego
        response = make_response(CONTROL_PANEL)
        response.set_cookie('session_id', session_id)
        return response
    else:
        return "Błąd uwierzytelnienia. Nieprawidłowe dane logowania.", 401


@production_app.route('/api/control/<machine_id>/<command>', methods=['POST'])
def control_machine(machine_id, command):
    """Obsługa poleceń sterowania maszynami."""
    session_id = request.cookies.get('session_id')
    source_ip = request.remote_addr

    if not session_id or session_id not in session_data['active_sessions']:
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 401

    # Sprawdzenie, czy komenda jest złośliwa
    is_malicious = detect_malicious_commands(command, machine_id)

    # Logowanie komendy
    with session_lock:
        session_data['active_sessions'][session_id]['commands'].append({
            'machine': machine_id,
            'command': command,
            'timestamp': datetime.now().isoformat(),
            'malicious': is_malicious
        })

        # Jeśli wykryto złośliwą komendę, loguj to jako eskalację ataku
        if is_malicious:
            log_attack = import_db_handler()

            commands_history = session_data['active_sessions'][session_id]['commands']
            command_sequence = json.dumps(commands_history)

            attack_data = {
                'timestamp': datetime.now().isoformat(),
                'source_ip': source_ip,
                'source_port': request.environ.get('REMOTE_PORT', 0),
                'destination_ip': request.host.split(':')[0] if request.host else '127.0.0.1',
                'destination_port': int(request.host.split(':')[1]) if ':' in request.host else 80,
                'attack_type': 'machine_takeover',
                'protocol': 'HTTP',
                'severity': 'critical',
                'detected_patterns': 'Malicious command execution',
                'session_id': session_id,
                'raw_data': request.data,
                'additional_info': {
                    'user_agent': request.headers.get('User-Agent', ''),
                    'request_path': f'/api/control/{machine_id}/{command}',
                    'request_method': 'POST',
                    'headers': dict(request.headers)
                },
                'machine_takeover_details': {
                    'target_machine': machine_id,
                    'exploit_used': 'command_injection',
                    'authentication_attempts': 0,
                    'command_sequence': command_sequence,
                    'control_duration': (datetime.now() - session_data['active_sessions'][session_id][
                        'login_time']).total_seconds(),
                    'system_changes': f'Executed command: {command}',
                    'access_level': 'admin',
                    'machine_type': 'PLC Controller',
                    'affected_operations': f'Machine {machine_id} control'
                }
            }

            attack_id = log_attack(DB_PATH, attack_data)
            logger.critical(
                f"Wykryto wykonanie złośliwej komendy: {command} na maszynie {machine_id} przez {source_ip}, ID: {attack_id}")

    # Symulacja wykonania komendy
    valid_commands = ['start', 'stop', 'reset', 'status']

    if command not in valid_commands and not is_malicious:
        return jsonify({
            'status': 'error',
            'message': 'Invalid command'
        }), 400

    # Symulacja odpowiedzi systemu
    if command == 'status':
        return jsonify({
            'status': 'success',
            'data': {
                'machine_id': machine_id,
                'operational': True,
                'speed': random.randint(80, 120),
                'efficiency': random.randint(85, 95),
                'temperature': random.randint(25, 35),
                'power': round(random.uniform(5.0, 20.0), 1)
            }
        })

    return jsonify({
        'status': 'success',
        'message': f'Command {command} executed on {machine_id}',
        'timestamp': datetime.now().isoformat()
    })


@production_app.route('/api/system/status')
def system_status():
    """Zwraca status systemu produkcyjnego."""
    machines = {
        'machine1': {
            'name': 'Assembly Line A',
            'status': 'operational',
            'metrics': {
                'speed': 120,
                'efficiency': 94,
                'temperature': 32,
                'power': 15.2
            }
        },
        'machine2': {
            'name': 'Packaging Unit',
            'status': 'operational',
            'metrics': {
                'speed': 80,
                'efficiency': 91,
                'temperature': 28,
                'power': 8.7
            }
        },
        'machine3': {
            'name': 'Quality Control',
            'status': 'maintenance',
            'metrics': {
                'speed': 0,
                'efficiency': 0,
                'temperature': 25,
                'power': 0.1
            }
        }
    }

    return jsonify({
        'status': 'success',
        'timestamp': datetime.now().isoformat(),
        'machines': machines,
        'system_health': 'normal'
    })


@production_app.route('/api/machines')
def get_machines():
    """Zwraca listę wszystkich maszyn."""
    machines = [
        {
            'id': 'machine1',
            'name': 'Assembly Line A',
            'type': 'Assembly',
            'status': 'operational',
            'location': 'Hall A',
            'last_maintenance': '2024-10-15'
        },
        {
            'id': 'machine2',
            'name': 'Packaging Unit',
            'type': 'Packaging',
            'status': 'operational',
            'location': 'Hall B',
            'last_maintenance': '2024-09-20'
        },
        {
            'id': 'machine3',
            'name': 'Quality Control',
            'type': 'QC',
            'status': 'maintenance',
            'location': 'Hall C',
            'last_maintenance': '2024-11-01'
        }
    ]

    return jsonify({
        'status': 'success',
        'data': machines
    })


@production_app.route('/api/system/logs')
def get_system_logs():
    """Zwraca logi systemowe."""
    logs = [
        {'timestamp': '2024-11-10T10:15:00', 'level': 'info', 'message': 'System started'},
        {'timestamp': '2024-11-10T10:16:00', 'level': 'info', 'message': 'Connected to PLC controllers'},
        {'timestamp': '2024-11-10T10:17:00', 'level': 'warning', 'message': 'Machine #3 requires maintenance'},
        {'timestamp': '2024-11-10T10:18:00', 'level': 'info', 'message': 'All systems operational'},
        {'timestamp': '2024-11-10T10:19:00', 'level': 'error', 'message': 'Communication timeout with sensor #42'},
        {'timestamp': '2024-11-10T10:20:00', 'level': 'info', 'message': 'Error recovered, system stable'}
    ]

    return jsonify({
        'status': 'success',
        'logs': logs
    })


@production_app.route('/logout')
def logout():
    """Wylogowanie użytkownika."""
    session_id = request.cookies.get('session_id')

    if session_id and session_id in session_data['active_sessions']:
        with session_lock:
            del session_data['active_sessions'][session_id]

    response = make_response('Logged out successfully')
    response.set_cookie('session_id', '', expires=0)
    return response


@production_app.errorhandler(404)
def page_not_found(e):
    """Obsługa nieznanych ścieżek."""
    return jsonify({
        'error': 'Not Found',
        'message': 'The requested resource was not found on this server.'
    }), 404


@production_app.errorhandler(500)
def internal_error(e):
    """Obsługa błędów serwera."""
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'The server encountered an internal error.'
    }), 500


def run_production_service(host='0.0.0.0', port=8002):
    """
    Uruchamia symulowane maszyny produkcyjne.

    Args:
        host (str): Adres IP do nasłuchiwania
        port (int): Port do nasłuchiwania
    """
    logger.info(f"Uruchamianie symulacji maszyn produkcyjnych na {host}:{port}")

    try:
        production_app.run(host=host, port=port, debug=False, threaded=True)
    except Exception as e:
        logger.error(f"Błąd podczas uruchamiania symulacji maszyn produkcyjnych: {e}")


if __name__ == "__main__":
    # Konfiguracja logowania
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Uruchomienie usługi maszyn produkcyjnych
    run_production_service()