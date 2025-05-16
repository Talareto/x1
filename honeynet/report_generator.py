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
        .apt-blacknova {
            color: #dc3545;
        }
        .apt-silkroad {
            color: #fd7e14;
        }
        .apt-ghostprotocol {
            color: #6f42c1;
        }
        .apt-redshift {
            color: #007bff;
        }
        .apt-cosmicspider {
            color: #20c997;
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
            <div class="stat-box">
                <h4>Wykryte grupy APT</h4>
                <div class="number">{{ stats.apt_detections }}</div>
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
            
            {% if stats.apt_detections > 0 %}
            <div class="chart-container">
                <h3>Rozkład grup APT</h3>
                <canvas id="aptGroupsChart" width="400" height="200"></canvas>
            </div>
            {% endif %}
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
                    <th>Grupa APT</th>
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
                    <td class="apt-{{ attack.apt_group_id | lower if attack.apt_group_id else '' }}">{{ attack.apt_group_name if attack.apt_group_name else 'Brak' }}</td>
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

        {% if stats.apt_detections > 0 %}
        <h2>Wykryte grupy APT</h2>
        <table>
            <thead>
                <tr>
                    <th>Grupa APT</th>
                    <th>Liczba wykryć</th>
                    <th>Procent wszystkich ataków</th>
                </tr>
            </thead>
            <tbody>
                {% for group in apt_groups %}
                <tr>
                    <td class="apt-{{ group.group_id | lower }}"><strong>{{ group.group_name }}</strong></td>
                    <td>{{ group.count }}</td>
                    <td>{{ "%.1f"|format(group.percentage) }}%</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <h2>Najnowsze wykrycia grup APT</h2>
        <table>
            <thead>
                <tr>
                    <th>Czas</th>
                    <th>Grupa APT</th>
                    <th>Pewność</th>
                    <th>Typ ataku</th>
                    <th>Źródło IP</th>
                </tr>
            </thead>
            <tbody>
                {% for detection in apt_detections %}
                <tr>
                    <td>{{ detection.timestamp }}</td>
                    <td class="apt-{{ detection.group_id | lower }}"><strong>{{ detection.group_name }}</strong></td>
                    <td>{{ "%.2f"|format(detection.confidence) }}</td>
                    <td>{{ detection.attack_type }}</td>
                    <td>{{ detection.source_ip }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% endif %}
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
        
        {% if stats.apt_detections > 0 %}
        // Wykres grup APT
        const aptGroupsCtx = document.getElementById('aptGroupsChart').getContext('2d');
        new Chart(aptGroupsCtx, {
            type: 'pie',
            data: {
                labels: {{ apt_group_labels | tojson }},
                datasets: [{
                    data: {{ apt_group_counts | tojson }},
                    backgroundColor: ['#dc3545', '#fd7e14', '#6f42c1', '#007bff', '#20c997']
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
                        text: 'Wykryte grupy APT'
                    }
                }
            }
        });
        {% endif %}
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
    parser.add_argument('--apt-only', action='store_true', help='Generuj raport tylko o grupach APT')

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
        
        # Pobierz informacje o grupach APT dla każdego ataku
        attacks_with_apt = []
        for attack in attacks:
            attack_dict = dict(attack)
            
            # Sprawdź czy atak ma przypisaną grupę APT
            apt_query = """
            SELECT * FROM apt_detections
            WHERE attack_log_id = ?
            """
            
            cursor.execute(apt_query, (attack_dict['id'],))
            apt_detection = cursor.fetchone()
            
            if apt_detection:
                apt_dict = dict(apt_detection)
                attack_dict['apt_group_id'] = apt_dict['group_id']
                attack_dict['apt_group_name'] = apt_dict['group_name']
                attack_dict['apt_confidence'] = apt_dict['confidence']
            else:
                attack_dict['apt_group_id'] = None
                attack_dict['apt_group_name'] = None
                attack_dict['apt_confidence'] = None
                
            attacks_with_apt.append(attack_dict)

        return attacks_with_apt

    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania danych: {e}")
        return []

    finally:
        if conn:
            conn.close()


def get_apt_data(db_path, from_date=None, to_date=None):
    """
    Pobiera dane o wykrytych grupach APT.

    Args:
        db_path (str): Ścieżka do bazy danych
        from_date (str): Data początkowa
        to_date (str): Data końcowa

    Returns:
        dict: Dane o grupach APT
    """
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Pobierz statystyki grup APT
        query = """
        SELECT group_id, group_name, COUNT(*) as count
        FROM apt_detections
        WHERE 1=1
        """

        params = []

        if from_date:
            query += " AND timestamp >= ?"
            params.append(from_date)

        if to_date:
            query += " AND timestamp <= ?"
            params.append(to_date)

        query += " GROUP BY group_id"

        cursor.execute(query, params)
        groups_stats = cursor.fetchall()

        # Pobierz najnowsze wykrycia
        query = """
        SELECT a.*, l.attack_type, l.source_ip, l.destination_ip
        FROM apt_detections a
        JOIN attack_logs l ON a.attack_log_id = l.id
        WHERE 1=1
        """

        params = []

        if from_date:
            query += " AND a.timestamp >= ?"
            params.append(from_date)

        if to_date:
            query += " AND a.timestamp <= ?"
            params.append(to_date)

        query += " ORDER BY a.timestamp DESC LIMIT 20"

        cursor.execute(query, params)
        recent_detections = cursor.fetchall()

        return {
            'groups': [dict(g) for g in groups_stats],
            'recent_detections': [dict(d) for d in recent_detections]
        }

    except sqlite3.Error as e:
        logger.error(f"Błąd podczas pobierania danych APT: {e}")
        return {'groups': [], 'recent_detections': []}

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
        'severity_low': 0,
        'apt_detections': 0,
        'apt_groups': {}
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
            
        # Zliczanie grup APT
        apt_group_id = attack.get('apt_group_id')
        if apt_group_id:
            stats['apt_detections'] += 1
            
            if apt_group_id not in stats['apt_groups']:
                stats['apt_groups'][apt_group_id] = {
                    'name': attack.get('apt_group_name', ''),
                    'count': 0
                }
                
            stats['apt_groups'][apt_group_id]['count'] += 1

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


def get_apt_groups_for_report(attacks_stats, apt_data):
    """
    Przygotowuje dane o grupach APT do raportu.

    Args:
        attacks_stats (dict): Statystyki ataków
        apt_data (dict): Dane o grupach APT

    Returns:
        list: Lista danych o grupach APT
    """
    apt_groups = []
    total_attacks = attacks_stats['total_attacks']
    
    for group in apt_data['groups']:
        group_id = group['group_id']
        group_name = group['group_name']
        count = group['count']
        
        apt_groups.append({
            'group_id': group_id,
            'group_name': group_name,
            'count': count,
            'percentage': (count / total_attacks * 100) if total_attacks > 0 else 0
        })
        
    # Sortowanie według liczby wykryć
    apt_groups.sort(key=lambda x: x['count'], reverse=True)
    
    return apt_groups


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
                'detected_patterns', 'session_id', 'apt_group_id', 'apt_group_name', 'apt_confidence'
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()

            for attack in attacks:
                writer.writerow(attack)

        logger.info(f"Raport CSV zapisany: {output_file}")

    except Exception as e:
        logger.error(f"Błąd podczas generowania CSV: {e}")


def generate_apt_csv(apt_data, output_file):
    """
    Generuje raport w formacie CSV tylko dla grup APT.

    Args:
        apt_data (dict): Dane o grupach APT
        output_file (str): Ścieżka do pliku wyjściowego
    """
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'timestamp', 'group_id', 'group_name', 'confidence',
                'attack_type', 'source_ip', 'attack_log_id'
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()

            for detection in apt_data['recent_detections']:
                writer.writerow(detection)

        logger.info(f"Raport APT CSV zapisany: {output_file}")

    except Exception as e:
        logger.error(f"Błąd podczas generowania CSV APT: {e}")


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


def generate_apt_json(apt_data, stats, output_file):
    """
    Generuje raport w formacie JSON tylko dla grup APT.

    Args:
        apt_data (dict): Dane o grupach APT
        stats (dict): Statystyki
        output_file (str): Ścieżka do pliku wyjściowego
    """
    try:
        report_data = {
            'generation_time': datetime.now().isoformat(),
            'statistics': {
                'total_apt_detections': sum(group['count'] for group in apt_data['groups']),
                'apt_groups': {group['group_id']: group['count'] for group in apt_data['groups']}
            },
            'apt_groups': apt_data['groups'],
            'recent_detections': apt_data['recent_detections']
        }

        with open(output_file, 'w', encoding='utf-8') as jsonfile:
            json.dump(report_data, jsonfile, indent=4, ensure_ascii=False)

        logger.info(f"Raport APT JSON zapisany: {output_file}")

    except Exception as e:
        logger.error(f"Błąd podczas generowania JSON APT: {e}")


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

        # Pobierz dane o grupach APT
        apt_data = get_apt_data(args.db, from_date, to_date)
        apt_groups = get_apt_groups_for_report(stats, apt_data)
        
        # Przygotuj dane dla wykresu grup APT
        apt_group_labels = [group['group_name'] for group in apt_groups]
        apt_group_counts = [group['count'] for group in apt_groups]

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
            timeline_data=timeline_data,
            apt_groups=apt_groups,
            apt_detections=apt_data['recent_detections'],
            apt_group_labels=apt_group_labels,
            apt_group_counts=apt_group_counts
        )

        with open(output_file, 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(html_content)

        logger.info(f"Raport HTML zapisany: {output_file}")

    except Exception as e:
        logger.error(f"Błąd podczas generowania HTML: {e}")


def generate_apt_html(apt_data, from_date, to_date, output_file):
    """
    Generuje raport w formacie HTML tylko dla grup APT.

    Args:
        apt_data (dict): Dane o grupach APT
        from_date (str): Data początkowa
        to_date (str): Data końcowa
        output_file (str): Ścieżka do pliku wyjściowego
    """
    try:
        # Przygotuj dane dla wykresu grup APT
        apt_group_labels = [group['group_name'] for group in apt_data['groups']]
        apt_group_counts = [group['count'] for group in apt_data['groups']]
        
        # Oblicz procent dla każdej grupy
        total_detections = sum(group['count'] for group in apt_data['groups'])
        for group in apt_data['groups']:
            group['percentage'] = (group['count'] / total_detections * 100) if total_detections > 0 else 0
        
        # Sortowanie według liczby wykryć
        apt_data['groups'].sort(key=lambda x: x['count'], reverse=True)
        
        # Przygotowanie oś czasu wykryć
        timeline = {}
        for detection in apt_data['recent_detections']:
            timestamp = detection.get('timestamp', '')
            if timestamp:
                # Grupowanie po dniach
                day = timestamp[:10]  # YYYY-MM-DD
                if day not in timeline:
                    timeline[day] = {}
                
                group_id = detection.get('group_id', '')
                if group_id not in timeline[day]:
                    timeline[day][group_id] = 0
                    
                timeline[day][group_id] += 1
        
        # Przygotuj dane dla wykresu osi czasu
        timeline_labels = sorted(timeline.keys())
        timeline_datasets = []
        
        # Kolory dla grup APT
        colors = {
            'BlackNova': '#dc3545',
            'SilkRoad': '#fd7e14',
            'GhostProtocol': '#6f42c1',
            'RedShift': '#007bff',
            'CosmicSpider': '#20c997'
        }
        
        # Tworzenie dataset dla każdej grupy
        for group in apt_data['groups']:
            group_id = group['group_id']
            dataset = {
                'label': group['group_name'],
                'data': [timeline.get(day, {}).get(group_id, 0) for day in timeline_labels],
                'borderColor': colors.get(group_id, '#000000'),
                'backgroundColor': colors.get(group_id, '#000000'),
                'tension': 0.1
            }
            timeline_datasets.append(dataset)
        
        # Tworzenie szablonu HTML dla raportu APT
        apt_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Raport wykrytych grup APT</title>
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
                .charts {
                    margin-top: 30px;
                }
                .chart-container {
                    margin-bottom: 30px;
                }
                .apt-blacknova {
                    color: #dc3545;
                }
                .apt-silkroad {
                    color: #fd7e14;
                }
                .apt-ghostprotocol {
                    color: #6f42c1;
                }
                .apt-redshift {
                    color: #007bff;
                }
                .apt-cosmicspider {
                    color: #20c997;
                }
            </style>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        </head>
        <body>
            <div class="container">
                <h1>Raport wykrytych grup APT</h1>
                <p>Wygenerowano: {{ generation_time }}</p>
                <p>Okres: {{ date_from }} - {{ date_to }}</p>

                <div class="summary">
                    <h2>Podsumowanie</h2>
                    <div class="stat-box">
                        <h4>Wykryte grupy APT</h4>
                        <div class="number">{{ apt_groups|length }}</div>
                    </div>
                    <div class="stat-box">
                        <h4>Całkowita liczba wykryć</h4>
                        <div class="number">{{ total_detections }}</div>
                    </div>
                </div>

                <div class="charts">
                    <div class="chart-container">
                        <h3>Rozkład grup APT</h3>
                        <canvas id="aptGroupsChart" width="400" height="200"></canvas>
                    </div>

                    <div class="chart-container">
                        <h3>Wykrycia w czasie</h3>
                        <canvas id="detectionsTimelineChart" width="800" height="300"></canvas>
                    </div>
                </div>

                <h2>Statystyki grup APT</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Grupa APT</th>
                            <th>Liczba wykryć</th>
                            <th>Procent</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for group in apt_groups %}
                        <tr>
                            <td class="apt-{{ group.group_id | lower }}"><strong>{{ group.group_name }}</strong></td>
                            <td>{{ group.count }}</td>
                            <td>{{ "%.1f"|format(group.percentage) }}%</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>

                <h2>Najnowsze wykrycia grup APT</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Czas</th>
                            <th>Grupa APT</th>
                            <th>Pewność</th>
                            <th>Typ ataku</th>
                            <th>Źródło IP</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for detection in recent_detections %}
                        <tr>
                            <td>{{ detection.timestamp }}</td>
                            <td class="apt-{{ detection.group_id | lower }}"><strong>{{ detection.group_name }}</strong></td>
                            <td>{{ "%.2f"|format(detection.confidence) }}</td>
                            <td>{{ detection.attack_type }}</td>
                            <td>{{ detection.source_ip }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>

            <script>
                // Wykres grup APT
                const aptGroupsCtx = document.getElementById('aptGroupsChart').getContext('2d');
                new Chart(aptGroupsCtx, {
                    type: 'pie',
                    data: {
                        labels: {{ apt_group_labels | tojson }},
                        datasets: [{
                            data: {{ apt_group_counts | tojson }},
                            backgroundColor: ['#dc3545', '#fd7e14', '#6f42c1', '#007bff', '#20c997']
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
                                text: 'Wykryte grupy APT'
                            }
                        }
                    }
                });

                // Wykres osi czasu wykryć
                const timelineCtx = document.getElementById('detectionsTimelineChart').getContext('2d');
                new Chart(timelineCtx, {
                    type: 'line',
                    data: {
                        labels: {{ timeline_labels | tojson }},
                        datasets: {{ timeline_datasets | tojson }}
                    },
                    options: {
                        responsive: true,
                        scales: {
                            y: {
                                beginAtZero: true,
                                stacked: false
                            },
                            x: {
                                grid: {
                                    display: false
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                position: 'top'
                            },
                            title: {
                                display: true,
                                text: 'Wykrycia grup APT w czasie'
                            }
                        }
                    }
                });
            </script>
        </body>
        </html>
        """
        
        template = Template(apt_template)
        html_content = template.render(
            generation_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            date_from=from_date or 'początek',
            date_to=to_date or 'teraz',
            apt_groups=apt_data['groups'],
            total_detections=sum(group['count'] for group in apt_data['groups']),
            recent_detections=apt_data['recent_detections'],
            apt_group_labels=apt_group_labels,
            apt_group_counts=apt_group_counts,
            timeline_labels=timeline_labels,
            timeline_datasets=timeline_datasets
        )

        with open(output_file, 'w', encoding='utf-8') as htmlfile:
            htmlfile.write(html_content)

        logger.info(f"Raport APT HTML zapisany: {output_file}")

    except Exception as e:
        logger.error(f"Błąd podczas generowania HTML APT: {e}")


def main():
    """Główna funkcja programu."""
    global args
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

    # Generowanie pliku wyjściowego
    if not args.output:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        args.output = f"attack_report_{timestamp}.{args.format}"

    if args.apt_only:
        # Pobierz dane tylko o grupach APT
        apt_data = get_apt_data(args.db, args.from_date, args.to_date)
        
        if not apt_data['groups']:
            logger.warning("Brak danych o grupach APT do wygenerowania raportu")
            return
            
        logger.info(f"Znaleziono {len(apt_data['groups'])} grup APT, {len(apt_data['recent_detections'])} wykryć")
        
        # Generowanie raportu o grupach APT w odpowiednim formacie
        if args.format == 'csv':
            generate_apt_csv(apt_data, args.output)
        elif args.format == 'json':
            generate_apt_json(apt_data, {}, args.output)
        elif args.format == 'html':
            generate_apt_html(apt_data, args.from_date, args.to_date, args.output)
    else:
        # Standardowe generowanie raportu
        logger.info("Pobieranie danych z bazy...")
        attacks = get_attack_data(args.db, args.from_date, args.to_date)

        if not attacks:
            logger.warning("Brak danych do wygenerowania raportu")
            return

        logger.info(f"Znaleziono {len(attacks)} ataków")

        # Obliczanie statystyk
        stats = get_statistics(attacks)

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