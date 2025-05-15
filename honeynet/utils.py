#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł zawierający funkcje pomocnicze dla honeynetu.
"""

import logging
import os
import sys
import socket
import time
import json
from datetime import datetime

# Konfiguracja logowania
logger = logging.getLogger('honeynet.utils')


def setup_logging(log_level='INFO', log_file=None):
    """
    Konfiguruje system logowania dla całej aplikacji.

    Args:
        log_level (str): Poziom logowania (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file (str): Ścieżka do pliku logów
    """
    # Konwersja poziomu logowania
    numeric_level = getattr(logging, log_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f'Invalid log level: {log_level}')

    # Tworzenie formatu logów
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    # Konfiguracja podstawowa
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        handlers=[]
    )

    # Dodanie handlera konsoli
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(logging.Formatter(log_format))
    logging.getLogger().addHandler(console_handler)

    # Dodanie handlera pliku jeśli podano
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(logging.Formatter(log_format))
        logging.getLogger().addHandler(file_handler)


def create_directories(dirs):
    """
    Tworzy katalogi jeśli nie istnieją.

    Args:
        dirs (list): Lista katalogów do utworzenia
    """
    for directory in dirs:
        os.makedirs(directory, exist_ok=True)
        logger.debug(f"Utworzono/sprawdzono katalog: {directory}")


def get_local_ip():
    """
    Pobiera lokalny adres IP maszyny.

    Returns:
        str: Lokalny adres IP
    """
    try:
        # Tworzymy tymczasowe połączenie UDP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def is_port_available(port, host='0.0.0.0'):
    """
    Sprawdza czy port jest dostępny.

    Args:
        port (int): Numer portu do sprawdzenia
        host (str): Adres hosta

    Returns:
        bool: True jeśli port jest dostępny, False w przeciwnym razie
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def find_available_port(start_port, end_port=None, host='0.0.0.0'):
    """
    Znajduje pierwszy dostępny port w podanym zakresie.

    Args:
        start_port (int): Port początkowy
        end_port (int, optional): Port końcowy
        host (str): Adres hosta

    Returns:
        int: Pierwszy dostępny port lub None jeśli nie znaleziono
    """
    if end_port is None:
        end_port = start_port + 100

    for port in range(start_port, end_port + 1):
        if is_port_available(port, host):
            return port

    return None


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
    Formatuje czas trwania w sekundach do czytelnej postaci.

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


def generate_random_ip():
    """
    Generuje losowy adres IP.

    Returns:
        str: Losowy adres IP
    """
    import random
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def parse_user_agent(user_agent):
    """
    Parsuje string User-Agent i zwraca informacje o przeglądarce.

    Args:
        user_agent (str): String User-Agent

    Returns:
        dict: Informacje o przeglądarce
    """
    # Podstawowa implementacja - w rzeczywistej aplikacji można użyć biblioteki
    info = {
        'browser': 'Unknown',
        'version': 'Unknown',
        'os': 'Unknown',
        'device': 'Unknown'
    }

    if not user_agent:
        return info

    # Wykrywanie przeglądarki
    if 'Firefox' in user_agent:
        info['browser'] = 'Firefox'
    elif 'Chrome' in user_agent:
        info['browser'] = 'Chrome'
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        info['browser'] = 'Safari'
    elif 'Edge' in user_agent:
        info['browser'] = 'Edge'
    elif 'MSIE' in user_agent or 'Trident' in user_agent:
        info['browser'] = 'Internet Explorer'

    # Wykrywanie systemu operacyjnego
    if 'Windows' in user_agent:
        info['os'] = 'Windows'
    elif 'Mac OS' in user_agent:
        info['os'] = 'macOS'
    elif 'Linux' in user_agent:
        info['os'] = 'Linux'
    elif 'Android' in user_agent:
        info['os'] = 'Android'
    elif 'iPhone' in user_agent or 'iPad' in user_agent:
        info['os'] = 'iOS'

    # Wykrywanie urządzenia
    if 'Mobile' in user_agent:
        info['device'] = 'Mobile'
    elif 'Tablet' in user_agent:
        info['device'] = 'Tablet'
    else:
        info['device'] = 'Desktop'

    return info


def sanitize_input(input_string):
    """
    Oczyszcza string wejściowy z potencjalnie niebezpiecznych znaków.

    Args:
        input_string (str): String do oczyszczenia

    Returns:
        str: Oczyszczony string
    """
    if not input_string:
        return ''

    # Lista znaków do usunięcia
    dangerous_chars = ['<', '>', ';', '&', '|', '`', ', ', '\\']

    sanitized = input_string
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')

    return sanitized


def generate_session_id():
    """
    Generuje unikalny identyfikator sesji.

    Returns:
        str: Identyfikator sesji
    """
    import hashlib
    import random

    return hashlib.sha256(
        f"{time.time()}_{random.random()}_{os.getpid()}".encode()
    ).hexdigest()[:32]


def calculate_checksum(data):
    """
    Oblicza sumę kontrolną dla danych.

    Args:
        data (bytes): Dane do obliczenia sumy kontrolnej

    Returns:
        str: Suma kontrolna (SHA256)
    """
    import hashlib

    if isinstance(data, str):
        data = data.encode()

    return hashlib.sha256(data).hexdigest()


def is_valid_ip(ip_address):
    """
    Sprawdza czy podany string jest prawidłowym adresem IP.

    Args:
        ip_address (str): Adres IP do sprawdzenia

    Returns:
        bool: True jeśli adres jest prawidłowy
    """
    try:
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False

        for part in parts:
            if not part.isdigit():
                return False
            num = int(part)
            if num < 0 or num > 255:
                return False

        return True
    except:
        return False


def mask_sensitive_data(data, mask_char='*'):
    """
    Maskuje wrażliwe dane.

    Args:
        data (str): Dane do zamaskowania
        mask_char (str): Znak do maskowania

    Returns:
        str: Zamaskowane dane
    """
    if not data or len(data) < 4:
        return mask_char * len(data) if data else ''

    # Pokazujemy tylko pierwsze i ostatnie 2 znaki
    return data[:2] + mask_char * (len(data) - 4) + data[-2:]


def load_config(config_file):
    """
    Ładuje konfigurację z pliku JSON.

    Args:
        config_file (str): Ścieżka do pliku konfiguracyjnego

    Returns:
        dict: Słownik z konfiguracją
    """
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"Plik konfiguracyjny {config_file} nie istnieje")
        return {}
    except json.JSONDecodeError:
        logger.error(f"Błąd parsowania pliku konfiguracyjnego {config_file}")
        return {}


def save_config(config, config_file):
    """
    Zapisuje konfigurację do pliku JSON.

    Args:
        config (dict): Konfiguracja do zapisania
        config_file (str): Ścieżka do pliku konfiguracyjnego

    Returns:
        bool: True jeśli zapis się powiódł
    """
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=4)
        return True
    except Exception as e:
        logger.error(f"Błąd zapisu konfiguracji do {config_file}: {e}")
        return False


def get_system_info():
    """
    Pobiera informacje o systemie.

    Returns:
        dict: Informacje o systemie
    """
    import platform
    import psutil

    return {
        'hostname': socket.gethostname(),
        'os': platform.system(),
        'os_version': platform.version(),
        'architecture': platform.architecture()[0],
        'processor': platform.processor(),
        'python_version': platform.python_version(),
        'memory_total': psutil.virtual_memory().total,
        'memory_available': psutil.virtual_memory().available,
        'cpu_count': psutil.cpu_count(),
        'cpu_percent': psutil.cpu_percent()
    }


class RateLimiter:
    """Klasa do ograniczania liczby żądań."""

    def __init__(self, max_requests, time_window):
        """
        Args:
            max_requests (int): Maksymalna liczba żądań
            time_window (int): Okno czasowe w sekundach
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}

    def is_allowed(self, client_id):
        """
        Sprawdza czy klient może wykonać żądanie.

        Args:
            client_id (str): Identyfikator klienta

        Returns:
            bool: True jeśli żądanie jest dozwolone
        """
        current_time = time.time()

        if client_id not in self.requests:
            self.requests[client_id] = []

        # Usuwanie starych żądań
        self.requests[client_id] = [
            req_time for req_time in self.requests[client_id]
            if current_time - req_time < self.time_window
        ]

        # Sprawdzanie limitu
        if len(self.requests[client_id]) >= self.max_requests:
            return False

        # Dodawanie nowego żądania
        self.requests[client_id].append(current_time)
        return True


def parse_http_headers(headers_string):
    """
    Parsuje string z nagłówkami HTTP.

    Args:
        headers_string (str): String z nagłówkami

    Returns:
        dict: Słownik z nagłówkami
    """
    headers = {}

    if not headers_string:
        return headers

    lines = headers_string.strip().split('\n')
    for line in lines:
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip()] = value.strip()

    return headers