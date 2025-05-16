IoT Honeynet i Symulacje Ataków z Wykrywaniem Grup APT
Repozytorium zawiera zaawansowany zestaw narzędzi do symulacji, monitorowania i analizy ataków na urządzenia IoT w różnych scenariuszach, z dodatkową funkcjonalnością wykrywania i przypisywania ataków do konkretnych grup zagrożeń (APT - Advanced Persistent Threat). System implementuje trzy główne scenariusze ataków oraz pięć fikcyjnych grup APT, każda z charakterystycznymi wzorcami działania.
Scenariusze Ataków

Atak DDoS na kamery IP
Atak SQL Injection na system logistyczny
Przejęcie kontroli nad maszynami produkcyjnymi

Symulowane Grupy APT
System wykrywa i symuluje następujące grupy zagrożeń:

BlackNova Collective

Specjalizacja: Zaawansowane ataki DDoS i rozpoznanie infrastruktury
Charakterystyka: Agresywne, wielowektorowe ataki z minimalnym opóźnieniem, charakterystyczne nagłówki HTTP


SilkRoad Syndicate

Specjalizacja: Wyrafinowane ataki SQL Injection
Charakterystyka: Specyficzne payloady zawierające markery "sr_bypass_", sekwencyjne techniki ataku


GhostProtocol Team

Specjalizacja: Przejęcie kontroli nad maszynami produkcyjnymi
Charakterystyka: Systematyczne ataki z sekwencją komend "stop-reset-wyczyść logi", instalacja backdoorów


RedShift Brigade

Specjalizacja: Hybrydowe ataki (DDoS + SQL Injection)
Charakterystyka: Sekwencyjne ataki z regularnym czasowaniem, charakterystyczne markery "RSB"


CosmicSpider Network

Specjalizacja: Wieloetapowe przejęcie infrastruktury
Charakterystyka: Zmienne wzorce czasowe, charakterystyczne sygnatury "cs_payload", kompleksowe ataki



Struktura projektu
iot-honeynet-project/
├── README.md
├── requirements.txt
├── honeynet/
│   ├── main.py                      # Główny moduł uruchamiający usługi
│   ├── db_handler.py                # Obsługa bazy danych
│   ├── ip_camera_service.py         # Symulacja kamer IP
│   ├── logistics_service.py         # Symulacja systemu logistycznego
│   ├── production_machine_service.py # Symulacja maszyn produkcyjnych
│   ├── apt_detection.py             # Moduł wykrywania grup APT
│   ├── monitor.py                   # Moduł monitoringu w czasie rzeczywistym
│   ├── report_generator.py          # Generator raportów
│   └── utils.py                     # Funkcje pomocnicze
├── attack_simulations/
│   ├── ddos_attack.py               # Symulacja ataku DDoS
│   ├── sql_injection_attack.py      # Symulacja ataku SQL Injection
│   ├── machine_takeover_attack.py   # Symulacja przejęcia maszyn
│   └── utils.py                     # Funkcje pomocnicze dla ataków
└── database/
    └── honeynet.db                  # Baza danych SQLite
Wymagania
Zainstaluj wymagane zależności:
bashpip install -r requirements.txt
Uruchomienie Honeynetu
Honeynet uruchamiamy poleceniem:
bashpython honeynet/main.py
Domyślnie zostaną uruchomione trzy usługi:

Symulowana kamera IP na porcie 8000
Symulowany system logistyczny na porcie 8001
Symulowane maszyny produkcyjne na porcie 8002

Wszystkie dane o atakach są zapisywane w bazie SQLite database/honeynet.db, w tym atrybuty identyfikujące grupy APT.
Dodatkowe opcje uruchomienia
bash# Uruchomienie z monitoringiem ataków w czasie rzeczywistym
python honeynet/main.py --monitor

# Uruchomienie z monitoringiem tylko grup APT
python honeynet/main.py --monitor --apt-monitor

# Uruchomienie z automatycznym generowaniem raportów co godzinę
python honeynet/main.py --generate-report

# Uruchomienie na niestandardowych portach
python honeynet/main.py --ports 9000,9001,9002
Uruchamianie symulacji ataków
1. Atak DDoS na kamery IP
bash# Podstawowe użycie
python attack_simulations/ddos_attack.py --target localhost:8000 --intensity high

# Symulacja ataku grupy BlackNova
python attack_simulations/ddos_attack.py --target localhost:8000 --intensity high --apt-group BlackNova
Parametry:

--target - adres celu ataku (domyślnie: localhost:8000)
--intensity - intensywność ataku (low, medium, high)
--duration - czas trwania ataku w sekundach (domyślnie: 30)
--apt-group - symulacja ataku konkretnej grupy APT (BlackNova, RedShift, CosmicSpider, None)

2. Atak SQL Injection na system logistyczny
bash# Podstawowe użycie
python attack_simulations/sql_injection_attack.py --target localhost:8001 --method union

# Symulacja ataku grupy SilkRoad
python attack_simulations/sql_injection_attack.py --target localhost:8001 --method union --apt-group SilkRoad
Parametry:

--target - adres celu ataku (domyślnie: localhost:8001)
--method - metoda ataku (union, error, blind, time, all)
--verbose - szczegółowe logowanie (domyślnie: False)
--apt-group - symulacja ataku konkretnej grupy APT (SilkRoad, RedShift, CosmicSpider, None)

3. Przejęcie maszyn produkcyjnych
bash# Podstawowe użycie
python attack_simulations/machine_takeover_attack.py --target localhost:8002 --method bruteforce

# Symulacja ataku grupy GhostProtocol
python attack_simulations/machine_takeover_attack.py --target localhost:8002 --method bruteforce --apt-group GhostProtocol
Parametry:

--target - adres celu ataku (domyślnie: localhost:8002)
--method - metoda ataku (bruteforce, exploit, malware)
--output - plik wyjściowy do zapisu wykradzionych danych
--apt-group - symulacja ataku konkretnej grupy APT (GhostProtocol, CosmicSpider, None)

Struktura bazy danych
Baza danych zawiera następujące tabele:

attack_logs - główna tabela z informacjami o wszystkich atakach
ddos_details - szczegółowe informacje o atakach DDoS
sql_injection_details - szczegółowe informacje o atakach SQL Injection
machine_takeover_details - szczegółowe informacje o przejęciach maszyn
apt_detections - informacje o wykrytych grupach APT

Monitorowanie ataków w czasie rzeczywistym
Wszystkie ataki są rejestrowane w czasie rzeczywistym i zapisywane do bazy danych. Możesz monitorować je poprzez uruchomienie dodatkowej konsoli:
bash# Monitorowanie wszystkich ataków
python honeynet/monitor.py --realtime

# Monitorowanie tylko wykryć grup APT
python honeynet/monitor.py --realtime --apt-only
Generowanie raportów
Aby wygenerować raport z zarejestrowanych ataków:
bash# Generowanie standardowego raportu
python honeynet/report_generator.py --format html --from-date 2023-01-01

# Generowanie raportu tylko o grupach APT
python honeynet/report_generator.py --format html --from-date 2023-01-01 --apt-only
Parametry:

--format - format raportu (csv, json, html)
--from-date - data początkowa
--to-date - data końcowa
--output - ścieżka do pliku wyjściowego
--apt-only - generuj raport tylko o grupach APT

Charakterystyki grup APT
BlackNova Collective
Grupa specjalizująca się w atakach DDoS, używa agresywnego, wielowątkowego podejścia z minimalnymi opóźnieniami. Pozostawia charakterystyczne markery "BNC-Scanner" w nagłówkach User-Agent oraz używa niestandardowych nagłówków "X-Attack-ID" i "X-Source-IP". Ich ataki charakteryzują się wysokim "burstowym" wykorzystaniem zasobów.
SilkRoad Syndicate
Wyrafinowana grupa prowadząca ataki SQL Injection. Używa specyficznych payloadów zawierających fragmenty "sr_bypass_", preferuje ataki UNION-based i ERROR-based. Ataki wykonywane są w określonej sekwencji: rekonesans, weryfikacja podatności, ekstrakcja danych.
GhostProtocol Team
Grupa skupiająca się na przejęciu kontroli nad urządzeniami przemysłowymi. Używa exploitów typu zero-day i precyzyjnych sekwencji komend. Charakteryzuje się usuwaniem logów po przejęciu kontroli i instalacją backdoorów. Pozostawia markery "Ghost-Protocol" w nagłówkach HTTP.
RedShift Brigade
Specjalizuje się w atakach hybrydowych, łącząc DDoS z SQL Injection. Ataki następują w określonych odstępach czasowych, a grupa używa nagłówków "X-RedShift-Operation" i specyficznych markerów "RSB" w payloadach. Ataki często następują sekwencyjnie przeciwko różnym usługom.
CosmicSpider Network
Najbardziej zaawansowana grupa, prowadząca wieloetapowe przejęcie infrastruktury. Używa kombinacji wszystkich trzech typów ataków, z charakterystycznymi "odciskami palców" zawierającymi fragmenty "cs_payload". Ataki charakteryzują się zmiennymi wzorcami czasowymi i złożoną sekwencją.
Mechanizm wykrywania grup APT
System wykorzystuje analizę wzorców ataków do przypisania ich do konkretnych grup APT. Analiza obejmuje:

Nagłówki HTTP - wykrywanie charakterystycznych nagłówków używanych przez poszczególne grupy
Payload ataków - analiza zawartości payloadów pod kątem charakterystycznych markerów
Sekwencje ataków - obserwacja kolejności i czasowania różnych typów ataków
Wzorce czasowe - analiza rozkładu czasowego ataków

Moduł apt_detection.py implementuje algorytm wykrywający, przypisujący atak do konkretnej grupy z określonym poziomem pewności (confidence).
Uwagi bezpieczeństwa
⚠️ UWAGA: To oprogramowanie zostało stworzone wyłącznie do celów edukacyjnych i badawczych. Używanie tych narzędzi przeciwko systemom bez wyraźnej zgody ich właścicieli jest nielegalne.
Licencja
Ten projekt jest udostępniany na licencji MIT. Zobacz plik LICENSE dla szczegółów.
Autorzy
Autorzy: [Twoje imię i nazwisko lub nazwa organizacji]
Kontakt
W przypadku pytań lub problemów, skontaktuj się z [Twoje dane kontaktowe].