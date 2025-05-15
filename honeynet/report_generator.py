#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł generujący raporty z zarejestrowanych ataków.
"""

import argparse
import csv
import json
import logging
import os
import sqlite3
from datetime import datetime
from jinja2 import Template

# Konfiguracja logowania
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('report_generator')

# Ścieżka do bazy danych
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'honeynet.db')

# Szablon HTML dla raportu
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Raport ataków IoT</title>
    <meta charset="UTF-8">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        h1, h2, h3 {
            color: #333;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .stat-box {
            display: inline-block;
            background-color: #e9ecef;
            padding: 10px 20px;
            margin: 10px;
            border-radius: 5px;
            text-align: center;
        }
        .stat-box h4 {
            margin: 0;
            color: #495057;
        }
        .stat-box .number {
            font-size: 24px;
            font-weight: bold;
            color: #007bff;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th {
            background-color: #007bff;
            color: white;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .attack-type-ddos {
            color: #dc3545;
        }
        .attack-type-sql {
            color: #fd7e14;
        }
        .attack-type-takeover {
            color: #6f42c1;
        }
        .severity-critical {
            color: #dc3545;
            font-weight: bold;
        }
        .severity-high {
            color: #fd7e14;
        }
        .severity-medium {
            color: #ffc107;
        }
        .severity-low {
            color: #28a745;
        }
        .charts {
            margin-top: 30px;
        }
        .chart-container {
            margin-bottom: 30px;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <h1>Raport ataków na urządzenia IoT</h1>
        <p>Wygenerowano: {{ generation_time }}</p>
        <p>Okres: {{ date_from }} - {{ date_to }}</p>

        <div class="summary">
            <h2>Podsumowanie</h2>
            <div class="stat-box">
                <h4>Wszystkie ataki</h4>
                <div class="number">{{ stats.total_attacks }}</div>
            </div>
            <div class="stat-box">
                <h4>Ataki DDoS</h4>
                <div class="number">{{ stats.ddos_attacks }}</div>
            </div>
            <div class="stat-box">
                <h4>Ataki SQL Injection</h4>
                <div class="number">{{ stats.sql_attacks }}</div>
            </div>
            <div class="stat-box">
                <h4>Przejęcia maszyn</h4>
                <div class="number">{{ stats.takeover_attacks }}</div>
            </div>
            <div class="stat-box">
                <h4>Unikalne źródła</h4>
                <div class="number">{{ stats.unique_sources }}</div>
            </div>
        </div>

        <div class="charts">
            <div class="chart-container">
                <h3>Rozkład typów ataków</h3>
                <canvas id="attackTypesChart" width="400" height="200"></canvas>
            </div>

            <div class="chart-container">
                <h3>Ataki w czasie</h3>
                <canvas id="attacksTimelineChart" width="800" height="300"></canvas>
            </div>

            <div class="chart-container">
                <h3>Poziomy krytyczności</h3>
                <canvas id="severityChart" width="400" height="200"></canvas>
            </div>
        </div>

        <h2>Szczegółowe dane ataków</h2>
        <table>
            <thead>
                <tr>
                    <th>Czas</th>
                    <th>Typ ataku</th>
                    <th>Źródło IP</th>
                    <th>Cel</th>
                    <th>Protokół</th>
                    <th>Krytyczność</th>
                    <th>Wzorce</th>
                </tr>
            </thead>
            <tbody>
                {% for attack in attacks %}
                <tr>
                    <td>{{ attack.timestamp }}</td>
                    <td class="attack-type-{{ attack.attack_type }}">{{ attack.attack_type_display }}</td>
                    <td>{{ attack.source_ip }}:{{ attack.source_port }}</td>
                    <td>{{ attack.destination_ip }}:{{ attack.destination_port }}</td>
                    <td>{{ attack.protocol }}</td>
                    <td class="severity-{{ attack.severity }}">{{ attack.severity }}</td>
                    <td>{{ attack.detected_patterns }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Top 10 źródeł ataków</h2>
        <table>
            <thead>
                <tr>
                    <th>Adres IP</th>
                    <th>Liczba ataków</th>
                    <th>Typy ataków</th>
                </tr>
            </thead>
            <tbody>
                {% for source in top_sources %}
                <tr>
                    <td>{{ source.ip }}</td>
                    <td>{{ source.count }}</td>
                    <td>{{ source.attack_types }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>

    <script>
        // Wykres typów ataków
        const attackTypesCtx = document.getElementById('attackTypesChart').getContext('2d');
        new Chart(attackTypesCtx, {
            type: 'pie',
            data: {
                labels: ['DDoS', 'SQL Injection', 'Machine Takeover'],
                datasets: [{
                    data: [{{ stats.ddos_attacks }}, {{ stats.sql_attacks }}, {{ stats.takeover_attacks }}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#6f42c1']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: 'Rozkład typów ataków'
                    }
                }
            }
        });

        // Wykres ataków w czasie
        const timelineCtx = document.getElementById('attacksTimelineChart').getContext('2d');
        new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: {{ timeline_labels | tojson }},
                datasets: [{
                    label: 'Liczba ataków',
                    data: {{ timeline_data | tojson }},
                    borderColor: '#007bff',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Wykres krytyczności
        const severityCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: ['Critical', 'High', 'Medium', 'Low'],
                datasets: [{
                    label: 'Liczba ataków',
                    data: [{{ stats.severity_critical }}, {{ stats.severity_high }}, {{ stats.severity_medium }}, {{ stats.severity_low }}],
                    backgroundColor: ['#dc3545', '#fd7e14', '#ffc107', '#28a745']
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    </script>
</body>
</html>
"""


def parse_arguments():
    """Parsowanie argumentów wiersza poleceń."""
    parser = argparse.ArgumentParser(description='Generator raportów z ataków IoT')
    parser.add_argument('--format', choices=['csv', 'json', 'html'], default='html',
                        help='Format raportu (domyślnie: html)')
    parser.add_argument('--from-date', type=str, help='Data początkowa (YYYY-MM-DD)')
    parser.add_argument('--to-date', type=str, help='Data końcowa (YYYY-MM-DD)')
    parser.add_argument('--output', type=str, help='Ścieżka do pliku wyjściowego')
    parser.add_argument('--db', type=str, default=DB_PATH, help='Ścieżka do bazy danych')

    return parser.parse_args()


def get_attack_data(db_path, from_date=None, to_date=None):
    """
    Pobiera dane o atakach z bazy danych.

    Args:
        db_path (str): Ścieżka do bazy danych
        from_date (str): Data początkowa
        to_date (str): Data końcowa

    Returns:
        list: Lista ataków
    """
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = """
        SELECT 
            a.*,
            d.packets_count as ddos_packets,
            d.bandwidth_usage as ddos_bandwidth,
            d.attack_duration as ddos_duration,
            s.payload as sql_payload,
            s.injection_technique as sql_technique,
            s.success_status as sql_success,
            m.target_machine as machine_target,
            m.exploit_used as machine_exploit,
            m.command_sequence as machine_commands
        FROM attack_logs a
        LEFT JOIN ddos_details d ON a.id = d.attack_log_id
        LEFT JOIN sql_injection_details s ON a.id = s.attack_log_id
        LEFT JOIN machine_takeover_details m ON a.id = m.attack_log_id
        WHERE 1=1
        """

        params = []

        if from_date:
            query += " AND a.timestamp >= ?"
            params.append(from_date)

        if to_date:
            query += " AND a.timestamp <= ?"
            params.append(to_date)

        query += " ORDER BY a.timestamp DESC"

        cursor.execute(query, params)
        attacks = cursor.fetchall()

        return [dict(attack) for attack in attacks]

    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania danych: {e}")
        return []

    finally:
        if conn:
            conn.close()


def get_statistics(attacks):
    """
    Oblicza statystyki na podstawie danych o atakach.

    Args:
        attacks (list): Lista ataków

    Returns:
        dict: Statystyki
    """
    stats = {
        'total_attacks': len(attacks),
        'ddos_attacks': 0,
        'sql_attacks': 0,
        'takeover_attacks': 0,
        'unique_sources': set(),
        'severity_critical': 0,
        'severity_high': 0,
        'severity_medium': 0,
        'severity_low': 0
    }

    for attack in attacks:
        attack_type = attack.get('attack_type', '')

        if attack_type == 'ddos':
            stats['ddos_attacks'] += 1
        elif attack_type == 'sql_injection':
            stats['sql_attacks'] += 1
        elif attack_type == 'machine_takeover':
            stats['takeover_attacks'] += 1

        source_ip = attack.get('source_ip', '')
        if source_ip:
            stats['unique_sources'].add(source_ip)

        severity = attack.get('severity', '').lower()
        if severity == 'critical':
            stats['severity_critical'] += 1
        elif severity == 'high':
            stats['severity_high'] += 1
        elif severity == 'medium':
            stats['severity_medium'] += 1
        elif severity == 'low':
            stats['severity_low'] += 1

    stats['unique_sources'] = len(stats['unique_sources'])

    return stats


def get_top_sources(attacks, limit=10):
    """
    Pobiera top źródeł ataków.

    Args:
        attacks (list): Lista ataków
        limit (int): Limit wyników

    Returns:
        list: Top źródła ataków
    """
    source_counts = {}
    source_types = {}

    for attack in attacks:
        source_ip = attack.get('source_ip', '')
        attack_type = attack.get('attack_type', '')

        if source_ip:
            source_counts[source_ip] = source_counts.get(source_ip, 0) + 1

            if source_ip not in source_types:
                source_types[source_ip] = set()
            source_types[source_ip].add(attack_type)

    # Sortowanie według liczby ataków
    sorted_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)

    top_sources = []
    for ip, count in sorted_sources[:limit]:
        top_sources.append({
            'ip': ip,
            'count': count,
            'attack_types': ', '.join(source_types[ip])
        })

    return top_sources


def get_timeline_data(attacks):
    """
    Przygotowuje dane do wykresu czasowego.

    Args:
        attacks (list): Lista ataków

    Returns:
        tuple: (labels, data)
    """
    timeline = {}

    for attack in attacks:
        timestamp = attack.get('timestamp', '')
        if timestamp:
            # Grupowanie po godzinach
            hour = timestamp[:13]  # YYYY-MM-DDTHH
            timeline[hour] = timeline.get(hour, 0) + 1

    # Sortowanie chronologicznie
    sorted_timeline = sorted(timeline.items())

    labels = [item[0] for item in sorted_timeline]
    data = [item[1] for item in sorted_timeline]

    return labels, data


def generate_csv(attacks, output_file):
    """
    Generuje raport w formacie CSV.

    Args:
        attacks (list): Lista ataków
        output_file (str): Ścieżka do pliku wyjściowego
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'timestamp', 'source_ip', 'source_port', 'destination_ip',
                'destination_port', 'attack_type', 'protocol', 'severity',
                'detected_patterns', 'session_id'
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()

            for attack in attacks:
                writer.writerow(attack)

        logger.info(f"Raport CSV zapisany: {output_file}")

    except Exception as e:
        logger.error(f"Błąd podczas generowania CSV: {e}")


def generate_json(attacks, stats, output_file):
    """
    Generuje raport w formacie JSON.

    Args:
        attacks (list): Lista ataków
        stats (dict): Statystyki
        output_file (str): Ścieżka do pliku wyjściowego
    """
    try:
        report_data = {
            'generation_time': datetime.now().isoformat(),
            'statistics': stats,
            'attacks': attacks
        }

        with open(output_file, 'w', encoding='utf-8') as jsonfile:
            json.dump(report_data, jsonfile, indent=4, ensure_ascii=False)

        logger.info(f"Raport JSON zapisany: {output_file}")

    except Exception as e:
        logger.error(f"Błąd podczas generowania JSON: {e}")


def generate_html(attacks, stats, from_date, to_date, output_file):
    """
    Generuje raport w formacie HTML.

    Args:
        attacks (list): Lista ataków
        stats (dict): Statystyki
        from_date (str): Data początkowa
        to_date (str): Data końcowa
        output_file (str): Ścieżka do pliku wyjściowego
    """
    try:
        # Przygotowanie danych do szablonu
        for attack in attacks:
            attack['attack_type_display'] = {
                'ddos': 'DDoS',
                'sql_injection': 'SQL Injection',
                'machine_takeover': 'Machine Takeover'
            }.get(attack.get('attack_type', ''), attack.get('attack_type', ''))

        top_sources = get_top_sources(attacks)
        timeline_labels, timeline_data = get_timeline_data(attacks)

        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            generation_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            date_from=from_date or 'początek',
            date_to=to_date or 'teraz',
            stats=stats,
            attacks=attacks,
            top_sources=top_sources,
            timeline_labels=timeline_labels,
            timeline_data=timeline_data
        )

        with open(output_file, 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(html_content)

        logger.info(f"Raport HTML zapisany: {output_file}")

    except Exception as e:
        logger.error(f"Błąd podczas generowania HTML: {e}")


def main():
    """Główna funkcja programu."""
    args = parse_arguments()

    # Weryfikacja formatów dat
    if args.from_date:
        try:
            datetime.strptime(args.from_date, '%Y-%m-%d')
        except ValueError:
            logger.error("Nieprawidłowy format daty początkowej. Użyj formatu YYYY-MM-DD")
            return

    if args.to_date:
        try:
            datetime.strptime(args.to_date, '%Y-%m-%d')
        except ValueError:
            logger.error("Nieprawidłowy format daty końcowej. Użyj formatu YYYY-MM-DD")
            return

    # Pobranie danych z bazy
    logger.info("Pobieranie danych z bazy...")
    attacks = get_attack_data(args.db, args.from_date, args.to_date)

    if not attacks:
        logger.warning("Brak danych do wygenerowania raportu")
        return

    logger.info(f"Znaleziono {len(attacks)} ataków")

    # Obliczanie statystyk
    stats = get_statistics(attacks)

    # Generowanie pliku wyjściowego
    if not args.output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f"attack_report_{timestamp}.{args.format}"

    # Generowanie raportu w odpowiednim formacie
    if args.format == 'csv':
        generate_csv(attacks, args.output)
    elif args.format == 'json':
        generate_json(attacks, stats, args.output)
    elif args.format == 'html':
        generate_html(attacks, stats, args.from_date, args.to_date, args.output)

    logger.info("Generowanie raportu zakończone")


if __name__ == "__main__":
    main()