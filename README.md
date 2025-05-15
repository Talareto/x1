# IoT Honeynet i Symulacje Ataków

Repozytorium zawiera zestaw narzędzi do symulacji i monitorowania ataków na urządzenia IoT w trzech scenariuszach:
1. Atak DDoS na kamery IP
2. Atak SQL Injection na system logistyczny
3. Przejęcie kontroli nad maszynami produkcyjnymi

## Struktura projektu

```
iot-honeynet-project/
├── README.md
├── requirements.txt
├── honeynet/
│   ├── main.py
│   ├── db_handler.py
│   ├── ip_camera_service.py 
│   ├── logistics_service.py
│   ├── production_machine_service.py
│   └── utils.py
├── attack_simulations/
│   ├── ddos_attack.py
│   ├── sql_injection_attack.py
│   ├── machine_takeover_attack.py
│   └── utils.py
└── database/
    └── honeynet.db
```

## Wymagania

```bash
pip install -r requirements.txt
```

## Uruchomienie Honeynetu

Honeynet uruchamiamy poleceniem:

```bash
python honeynet/main.py
```

Domyślnie zostaną uruchomione trzy usługi:
- Symulowana kamera IP na porcie 8000
- Symulowany system logistyczny na porcie 8001
- Symulowane maszyny produkcyjne na porcie 8002

Wszystkie dane o atakach są zapisywane w bazie SQLite `database/honeynet.db`.

## Uruchamianie symulacji ataków

### 1. Atak DDoS na kamery IP

```bash
python attack_simulations/ddos_attack.py --target localhost:8000 --intensity high
```

Parametry:
- `--target` - adres celu ataku (domyślnie: localhost:8000)
- `--intensity` - intensywność ataku (low, medium, high)
- `--duration` - czas trwania ataku w sekundach (domyślnie: 30)

### 2. Atak SQL Injection na system logistyczny

```bash
python attack_simulations/sql_injection_attack.py --target localhost:8001 --method union
```

Parametry:
- `--target` - adres celu ataku (domyślnie: localhost:8001)
- `--method` - metoda ataku (union, error, blind, time)
- `--verbose` - szczegółowe logowanie (domyślnie: True)

### 3. Przejęcie maszyn produkcyjnych

```bash
python attack_simulations/machine_takeover_attack.py --target localhost:8002 --method bruteforce
```

Parametry:
- `--target` - adres celu ataku (domyślnie: localhost:8002)
- `--method` - metoda ataku (bruteforce, exploit, malware)
- `--output` - plik wyjściowy do zapisu wykradzionych danych

## Struktura bazy danych

Baza danych zawiera następujące tabele:
- `attack_logs` - główna tabela z informacjami o wszystkich atakach
- `ddos_details` - szczegółowe informacje o atakach DDoS
- `sql_injection_details` - szczegółowe informacje o atakach SQL Injection
- `machine_takeover_details` - szczegółowe informacje o przejęciach maszyn

## Monitorowanie ataków w czasie rzeczywistym

Wszystkie ataki są rejestrowane w czasie rzeczywistym i zapisywane do bazy danych. Możesz monitorować je poprzez uruchomienie dodatkowej konsoli:

```bash
python honeynet/monitor.py --realtime
```

## Generowanie raportów

Aby wygenerować raport z zarejestrowanych ataków:

```bash
python honeynet/report_generator.py --format csv --from-date 2023-01-01
```

Parametry:
- `--format` - format raportu (csv, json, html)
- `--from-date` - data początkowa
- `--to-date` - data końcowa
- `--output` - ścieżka do pliku wyjściowego

## Uwagi bezpieczeństwa

⚠️ **UWAGA**: To oprogramowanie zostało stworzone wyłącznie do celów edukacyjnych i badawczych. Używanie tych narzędzi przeciwko systemom bez wyraźnej zgody ich właścicieli jest nielegalne.