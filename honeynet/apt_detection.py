#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Moduł wykrywania grup APT (Advanced Persistent Threat) na podstawie wzorców ataków.
"""

import logging
import time
import json
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Konfiguracja logowania
logger = logging.getLogger('honeynet.apt_detection')

# Przechowuje historię ataków dla analizy wzorców
attack_history = {
    'by_source_ip': defaultdict(list),      # Historia ataków według źródeł IP
    'by_session': defaultdict(list),        # Historia ataków według sesji
    'timeline': deque(maxlen=1000),         # Ogólna oś czasu ataków
    'detected_groups': defaultdict(int),    # Liczniki wykrytych grup
    'last_detections': deque(maxlen=100)    # Ostatnie wykryte grupy
}

# Definicje wzorców dla grup APT
APT_PATTERNS = {
    'BlackNova': {
        'name': 'BlackNova Collective',
        'description': 'Zaawansowana grupa specjalizująca się w atakach DDoS i rozpoznaniu infrastruktury.',
        'confidence_threshold': 0.7,  # Próg pewności dla wykrycia
        'patterns': {
            'user_agent': ['BNC-Scanner', 'BlackNova', 'BNC-Agent'],
            'attack_sequence': ['recon', 'ddos'],
            'headers': ['X-Attack-ID', 'X-Source-IP'],
            'ddos_method': ['HTTP', 'FLOOD'],
            'time_pattern': None  # Brak specyficznego wzorca czasowego
        }
    },
    'SilkRoad': {
        'name': 'SilkRoad Syndicate',
        'description': 'Grupa specjalizująca się w wyrafinowanych atakach SQL Injection.',
        'confidence_threshold': 0.75,
        'patterns': {
            'user_agent': ['SRScanner', 'SilkRoadAgent', 'SR-Infiltrator'],
            'attack_sequence': ['scan', 'union_injection', 'data_extraction'],
            'payload_fragments': ['sr_bypass_', 'silk_extract', 'sr_dump'],
            'sql_techniques': ['UNION', 'time-based', 'blind'],
            'time_pattern': None
        }
    },
    'GhostProtocol': {
        'name': 'GhostProtocol Team',
        'description': 'Elitarna grupa APT specjalizująca się w przejmowaniu kontroli nad urządzeniami przemysłowymi.',
        'confidence_threshold': 0.8,
        'patterns': {
            'user_agent': ['Ghost-Scanner', 'GP-Agent', 'GhostProtocol'],
            'attack_sequence': ['takeover', 'command_execution', 'log_cleanup'],
            'headers': ['X-Ghost-Protocol', 'GP-Operation'],
            'command_sequence': ['stop', 'reset', 'exec'],
            'time_pattern': 'night'  # Preferencja do ataków nocnych
        }
    },
    'RedShift': {
        'name': 'RedShift Brigade',
        'description': 'Grupa specjalizująca się w hybrydowych atakach, łącząc DDoS z SQL Injection.',
        'confidence_threshold': 0.65,
        'patterns': {
            'user_agent': ['RS-Scanner', 'RedShift', 'RSB-Agent'],
            'attack_sequence': ['ddos', 'sql_injection'],
            'headers': ['X-RedShift-Operation', 'RSB-Marker'],
            'time_pattern': 'sequential',  # Ataki sekwencyjne
            'time_window': 1800  # 30 minut między atakami
        }
    },
    'CosmicSpider': {
        'name': 'CosmicSpider Network',
        'description': 'Wysoce wyrafinowana grupa APT specjalizująca się w wieloetapowym przejmowaniu infrastruktury.',
        'confidence_threshold': 0.85,
        'patterns': {
            'user_agent': ['CS-Scanner', 'CosmicSpider', 'CS-Nebula'],
            'attack_sequence': ['recon', 'ddos', 'sql_injection', 'takeover'],
            'payload_fragments': ['cs_payload', 'cosmic_extract', 'spider_implant'],
            'time_pattern': 'distributed',  # Ataki rozłożone w czasie
            'time_window': 86400  # 24 godziny
        }
    }
}

def analyze_attack(attack_data):
    """
    Analizuje dane ataku i wykrywa potencjalne dopasowania do grup APT.
    
    Args:
        attack_data (dict): Dane o ataku z bazy danych
        
    Returns:
        dict: Informacje o wykrytej grupie (lub None)
    """
    # Dodaj atak do historii
    source_ip = attack_data.get('source_ip', 'unknown')
    session_id = attack_data.get('session_id', 'unknown')
    attack_type = attack_data.get('attack_type', 'unknown')
    
    attack_history['by_source_ip'][source_ip].append(attack_data)
    attack_history['by_session'][session_id].append(attack_data)
    attack_history['timeline'].append(attack_data)
    
    # Analizuj ataki i oceń dopasowanie do wzorców APT
    results = {}
    
    for group_id, group_info in APT_PATTERNS.items():
        confidence = calculate_confidence(attack_data, group_info, source_ip, session_id)
        results[group_id] = confidence
    
    # Znajdź grupę z najwyższym współczynnikiem pewności
    best_match = max(results.items(), key=lambda x: x[1])
    group_id, confidence = best_match
    
    # Jeśli pewność jest powyżej progu, uznaj za wykrytą grupę
    if confidence >= APT_PATTERNS[group_id]['confidence_threshold']:
        detection_info = {
            'group_id': group_id,
            'group_name': APT_PATTERNS[group_id]['name'],
            'confidence': confidence,
            'timestamp': datetime.now().isoformat(),
            'attack_id': attack_data.get('id'),
            'source_ip': source_ip,
            'attack_type': attack_type,
            'evidence': collect_evidence(attack_data, group_id)
        }
        
        # Aktualizuj liczniki i historię detekcji
        attack_history['detected_groups'][group_id] += 1
        attack_history['last_detections'].append(detection_info)
        
        logger.warning(
            f"Wykryto potencjalny atak grupy APT: {APT_PATTERNS[group_id]['name']} (pewność: {confidence:.2f})"
        )
        
        return detection_info
    
    return None

def calculate_confidence(attack_data, group_info, source_ip, session_id):
    """
    Oblicza poziom pewności dopasowania ataku do wzorca grupy APT.
    
    Args:
        attack_data (dict): Dane o ataku
        group_info (dict): Informacje o grupie APT
        source_ip (str): Adres IP źródła ataku
        session_id (str): Identyfikator sesji
        
    Returns:
        float: Współczynnik pewności (0.0 - 1.0)
    """
    patterns = group_info['patterns']
    evidence_points = 0
    max_points = 0
    
    # Sprawdź User-Agent
    user_agent = attack_data.get('additional_info', {}).get('user_agent', '')
    if 'user_agent' in patterns and any(ua in user_agent for ua in patterns['user_agent']):
        evidence_points += 2
    max_points += 2
    
    # Sprawdź nagłówki
    headers = attack_data.get('additional_info', {}).get('headers', {})
    if 'headers' in patterns and any(header in headers for header in patterns['headers']):
        evidence_points += 2
    max_points += 2
    
    # Sprawdź typ ataku
    attack_type = attack_data.get('attack_type', '')
    attack_sequence = []
    
    # Pobierz sekwencję ataków dla tego źródła IP
    ip_history = attack_history['by_source_ip'][source_ip]
    if ip_history:
        attack_sequence = [attack.get('attack_type', '') for attack in ip_history[-5:]]  # Ostatnie 5 ataków
        
        if 'attack_sequence' in patterns:
            # Sprawdź czy sekwencja pasuje do wzorca
            expected_sequence = patterns['attack_sequence']
            if len(attack_sequence) >= len(expected_sequence):
                matches = sum(1 for i in range(len(attack_sequence) - len(expected_sequence) + 1)
                             if attack_sequence[i:i+len(expected_sequence)] == expected_sequence)
                if matches > 0:
                    evidence_points += 3
            max_points += 3
    
    # Sprawdź payload ataku
    if 'payload_fragments' in patterns:
        # DDoS
        if attack_type == 'ddos':
            raw_data = attack_data.get('raw_data', b'').decode('utf-8', errors='ignore')
            if any(fragment in raw_data for fragment in patterns['payload_fragments']):
                evidence_points += 2
            max_points += 2
            
        # SQL Injection
        elif attack_type == 'sql_injection':
            sql_details = attack_data.get('sql_injection_details', {})
            payload = sql_details.get('payload', '')
            if any(fragment in payload for fragment in patterns['payload_fragments']):
                evidence_points += 3
            max_points += 3
            
        # Machine Takeover
        elif attack_type == 'machine_takeover':
            takeover_details = attack_data.get('machine_takeover_details', {})
            command_sequence = takeover_details.get('command_sequence', '')
            if any(fragment in command_sequence for fragment in patterns['payload_fragments']):
                evidence_points += 3
            max_points += 3
    
    # Sprawdź szczegóły specyficzne dla danego typu ataku
    if attack_type == 'ddos' and 'ddos_method' in patterns:
        ddos_details = attack_data.get('ddos_details', {})
        attack_vector = ddos_details.get('attack_vector', '')
        if any(method in attack_vector for method in patterns['ddos_method']):
            evidence_points += 2
        max_points += 2
        
    elif attack_type == 'sql_injection' and 'sql_techniques' in patterns:
        sql_details = attack_data.get('sql_injection_details', {})
        technique = sql_details.get('injection_technique', '')
        if any(t in technique for t in patterns['sql_techniques']):
            evidence_points += 2
        max_points += 2
        
    elif attack_type == 'machine_takeover' and 'command_sequence' in patterns:
        takeover_details = attack_data.get('machine_takeover_details', {})
        command_seq = takeover_details.get('command_sequence', '')
        if all(cmd in command_seq for cmd in patterns['command_sequence']):
            evidence_points += 3
        max_points += 3
    
    # Sprawdź wzorce czasowe
    if 'time_pattern' in patterns and patterns['time_pattern']:
        time_pattern = patterns['time_pattern']
        attack_time = datetime.fromisoformat(attack_data.get('timestamp', datetime.now().isoformat())[:19])
        
        if time_pattern == 'night':
            # Sprawdź czy atak odbył się w nocy (22:00 - 6:00)
            hour = attack_time.hour
            if 22 <= hour or hour <= 6:
                evidence_points += 1
            max_points += 1
            
        elif time_pattern == 'sequential' and 'time_window' in patterns:
            # Sprawdź czy ataki następują w określonych odstępach czasu
            window = patterns['time_window']
            prev_attacks = [a for a in ip_history if a != attack_data]
            
            if prev_attacks:
                prev_time = datetime.fromisoformat(prev_attacks[-1].get('timestamp', '')[:19])
                time_diff = (attack_time - prev_time).total_seconds()
                
                if abs(time_diff - window) <= window * 0.2:  # 20% tolerancji
                    evidence_points += 2
                max_points += 2
                
        elif time_pattern == 'distributed' and 'time_window' in patterns:
            # Sprawdź czy ataki są rozłożone w czasie
            daily_window = patterns['time_window']
            attacks_in_window = [
                a for a in ip_history 
                if abs((attack_time - datetime.fromisoformat(a.get('timestamp', '')[:19])).total_seconds()) <= daily_window
            ]
            
            if len(attacks_in_window) >= 3:  # Przynajmniej 3 ataki w oknie czasowym
                evidence_points += 2
            max_points += 2
    
    # Oblicz współczynnik pewności
    if max_points == 0:
        return 0
    
    return evidence_points / max_points

def collect_evidence(attack_data, group_id):
    """
    Zbiera dowody, które przyczyniły się do identyfikacji grupy APT.
    
    Args:
        attack_data (dict): Dane o ataku
        group_id (str): Identyfikator zidentyfikowanej grupy
        
    Returns:
        dict: Zebrane dowody
    """
    evidence = {}
    patterns = APT_PATTERNS[group_id]['patterns']
    
    # Zbierz dowody z User-Agent
    user_agent = attack_data.get('additional_info', {}).get('user_agent', '')
    for ua in patterns.get('user_agent', []):
        if ua in user_agent:
            evidence['user_agent'] = user_agent
            break
    
    # Zbierz dowody z nagłówków
    headers = attack_data.get('additional_info', {}).get('headers', {})
    matching_headers = {}
    for header in patterns.get('headers', []):
        if header in headers:
            matching_headers[header] = headers[header]
    
    if matching_headers:
        evidence['headers'] = matching_headers
    
    # Zbierz dowody z payloadu
    if 'payload_fragments' in patterns:
        attack_type = attack_data.get('attack_type', '')
        
        if attack_type == 'sql_injection':
            sql_details = attack_data.get('sql_injection_details', {})
            payload = sql_details.get('payload', '')
            for fragment in patterns['payload_fragments']:
                if fragment in payload:
                    evidence['sql_payload'] = payload
                    break
        
        elif attack_type == 'machine_takeover':
            takeover_details = attack_data.get('machine_takeover_details', {})
            command_sequence = takeover_details.get('command_sequence', '')
            if command_sequence:
                evidence['command_sequence'] = command_sequence
    
    # Dodaj informacje specyficzne dla typu ataku
    attack_type = attack_data.get('attack_type', '')
    
    if attack_type == 'ddos':
        ddos_details = attack_data.get('ddos_details', {})
        evidence['ddos_details'] = {
            'method': ddos_details.get('attack_vector', ''),
            'duration': ddos_details.get('attack_duration', 0),
            'packets': ddos_details.get('packets_count', 0)
        }
    
    elif attack_type == 'sql_injection':
        sql_details = attack_data.get('sql_injection_details', {})
        evidence['sql_details'] = {
            'technique': sql_details.get('injection_technique', ''),
            'success': sql_details.get('success_status', 0),
            'parameter': sql_details.get('vulnerable_parameter', '')
        }
    
    elif attack_type == 'machine_takeover':
        takeover_details = attack_data.get('machine_takeover_details', {})
        evidence['takeover_details'] = {
            'target': takeover_details.get('target_machine', ''),
            'exploit': takeover_details.get('exploit_used', ''),
            'access_level': takeover_details.get('access_level', '')
        }
    
    return evidence

def get_apt_stats():
    """
    Zwraca statystyki wykrytych grup APT.
    
    Returns:
        dict: Statystyki grup APT
    """
    stats = {
        'total_detections': sum(attack_history['detected_groups'].values()),
        'by_group': {group_id: {
            'name': APT_PATTERNS[group_id]['name'],
            'count': count,
            'percentage': (count / sum(attack_history['detected_groups'].values()) * 100) if sum(attack_history['detected_groups'].values()) > 0 else 0
        } for group_id, count in attack_history['detected_groups'].items() if count > 0},
        'recent_detections': list(attack_history['last_detections'])
    }
    
    return stats

def reset_history():
    """Resetuje historię ataków."""
    attack_history['by_source_ip'].clear()
    attack_history['by_session'].clear()
    attack_history['timeline'].clear()
    attack_history['last_detections'].clear()
    # Nie resetujemy liczników grup, aby zachować statystyki

def create_apt_report(output_file=None):
    """
    Tworzy raport o wykrytych grupach APT.
    
    Args:
        output_file (str, optional): Ścieżka do pliku wyjściowego
        
    Returns:
        str: Ścieżka do wygenerowanego pliku raportu
    """
    stats = get_apt_stats()
    
    report = {
        'generated_at': datetime.now().isoformat(),
        'total_detections': stats['total_detections'],
        'groups': stats['by_group'],
        'recent_detections': stats['recent_detections'][:10]  # Ostatnie 10 wykryć
    }
    
    if not output_file:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"apt_report_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=4)
    
    logger.info(f"Raport APT zapisany: {output_file}")
    return output_file