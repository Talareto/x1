#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł zawierający funkcje pomocnicze dla skryptów atakujących.
"""

import logging
import random
import string
import time
import hashlib
import json
from datetime import datetime

# Konfiguracja logowania
logger = logging.getLogger('attack_utils')


def generate_random_string(length=10, chars=string.ascii_letters + string.digits):
    """
    Generuje losowy ciąg znaków.

    Args:
        length (int): Długość ciągu znaków
        chars (str): Zestaw znaków do wyboru

    Returns:
        str: Losowy ciąg znaków
    """
    return ''.join(random.choice(chars) for _ in range(length))


def generate_session_id():
    """
    Generuje unikalny identyfikator sesji.

    Returns:
        str: Identyfikator sesji
    """
    timestamp = str(time.time()).encode()
    random_data = generate_random_string(16).encode()
    return hashlib.sha256(timestamp + random_data).hexdigest()[:32]


def generate_random_ip():
    """
    Generuje losowy adres IP.

    Returns:
        str: Losowy adres IP
    """
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_random_mac():
    """
    Generuje losowy adres MAC.

    Returns:
        str: Losowy adres MAC
    """
    return ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])


def get_random_user_agent():
    """
    Zwraca losowy User-Agent.

    Returns:
        str: Losowy User-Agent
    """
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
    ]
    return random.choice(user_agents)


def format_size(size_bytes):
    """
    Formatuje rozmiar w bajtach do czytelnej postaci.

    Args:
        size_bytes (int): Rozmiar w bajtach

    Returns:
        str: Sformatowany rozmiar
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:3.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def format_duration(seconds):
    """
    Formatuje czas trwania do czytelnej postaci.

    Args:
        seconds (float): Czas w sekundach

    Returns:
        str: Sformatowany czas
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def save_attack_log(log_data, filename=None):
    """
    Zapisuje log ataku do pliku.

    Args:
        log_data (dict): Dane do zapisu
        filename (str, optional): Nazwa pliku. Jeśli nie podano, generuje automatycznie

    Returns:
        str: Ścieżka do zapisanego pliku
    """
    if filename is None:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"attack_log_{timestamp}.json"

    try:
        with open(filename, 'w') as f:
            json.dump(log_data, f, indent=4, default=str)
        logger.info(f"Attack log saved to: {filename}")
        return filename
    except Exception as e:
        logger.error(f"Error saving attack log: {e}")
        return None


def calculate_success_rate(total_attempts, successful_attempts):
    """
    Oblicza współczynnik sukcesu.

    Args:
        total_attempts (int): Całkowita liczba prób
        successful_attempts (int): Liczba udanych prób

    Returns:
        float: Współczynnik sukcesu (0-100)
    """
    if total_attempts == 0:
        return 0.0
    return (successful_attempts / total_attempts) * 100


def parse_target(target_string):
    """
    Parsuje string z celem ataku.

    Args:
        target_string (str): String w formacie "host:port" lub "host"

    Returns:
        tuple: (host, port)
    """
    if ':' in target_string:
        host, port = target_string.split(':')
        return host, int(port)
    else:
        return target_string, 80


def rate_limit(func):
    """
    Dekorator ograniczający częstotliwość wywołań funkcji.
    """
    last_call = {}
    minimum_interval = 0.1  # 100ms

    def wrapper(*args, **kwargs):
        current_time = time.time()
        func_id = id(func)

        if func_id in last_call:
            elapsed = current_time - last_call[func_id]
            if elapsed < minimum_interval:
                time.sleep(minimum_interval - elapsed)

        result = func(*args, **kwargs)
        last_call[func_id] = time.time()
        return result

    return wrapper


def print_banner(attack_type):
    """
    Wyświetla banner dla danego typu ataku.

    Args:
        attack_type (str): Typ ataku (ddos, sql_injection, machine_takeover)
    """
    banners = {
        'ddos': """
    ╔═══════════════════════════════════════╗
    ║         DDoS Attack Simulation        ║
    ║     For Educational Purposes Only     ║
    ╚═══════════════════════════════════════╝
    """,
        'sql_injection': """
    ╔═══════════════════════════════════════╗
    ║    SQL Injection Attack Simulation    ║
    ║     For Educational Purposes Only     ║
    ╚═══════════════════════════════════════╝
    """,
        'machine_takeover': """
    ╔═══════════════════════════════════════╗
    ║   Machine Takeover Attack Simulation  ║
    ║     For Educational Purposes Only     ║
    ╚═══════════════════════════════════════╝
    """
    }

    print(banners.get(attack_type, "Attack Simulation"))


class AttackLogger:
    """Klasa do logowania szczegółów ataku."""

    def __init__(self, log_file=None):
        self.log_file = log_file
        self.logs = []

    def log(self, message, level='INFO'):
        """
        Loguje wiadomość.

        Args:
            message (str): Wiadomość do zalogowania
            level (str): Poziom logowania
        """
        timestamp = datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'message': message
        }
        self.logs.append(log_entry)

        if self.log_file:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')

    def get_logs(self):
        """Zwraca wszystkie logi."""
        return self.logs

    def save_logs(self, filename):
        """
        Zapisuje logi do pliku.

        Args:
            filename (str): Nazwa pliku
        """
        with open(filename, 'w') as f:
            json.dump(self.logs, f, indent=4)


def obfuscate_payload(payload):
    """
    Prostą obfuskację payloadu.

    Args:
        payload (str): Payload do obfuskacji

    Returns:
        str: Obfuskowany payload
    """
    # Prosta obfuskacja - kodowanie base64
    import base64
    encoded = base64.b64encode(payload.encode()).decode()
    return f"eval(atob('{encoded}'))"


def generate_random_headers():
    """
    Generuje losowe nagłówki HTTP.

    Returns:
        dict: Słownik z nagłówkami
    """
    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept': random.choice([
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'application/json, text/plain, */*',
            '*/*'
        ]),
        'Accept-Language': random.choice([
            'en-US,en;q=0.5',
            'pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7',
            'de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7'
        ]),
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
        'Pragma': 'no-cache'
    }

    # Dodatkowe losowe nagłówki
    if random.random() > 0.5:
        headers['X-Forwarded-For'] = generate_random_ip()
    if random.random() > 0.7:
        headers['X-Real-IP'] = generate_random_ip()
    if random.random() > 0.8:
        headers['X-Client-IP'] = generate_random_ip()

    return headers