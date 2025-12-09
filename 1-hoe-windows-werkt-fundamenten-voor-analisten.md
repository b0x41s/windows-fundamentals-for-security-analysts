# 1. Hoe Windows werkt (Fundamenten voor Analisten)

## 1.1 Wat gebeurt er wanneer een programma start?
Wanneer je een programma opent, voert Windows een voorspelbare reeks stappen uit. Als je deze stappen begrijpt, kun je EDR-telemetrie sneller interpreteren.

- Windows valideert het uitvoerbare bestand en leest de headers
- Er wordt een nieuw proces aangemaakt met een eigen virtuele geheugenruimte
- De primary thread wordt gecreëerd en klaargezet om te starten
- De loader laadt benodigde modules, DLL’s, vanuit bekende paden
- Initialisatiecode draait, daarna begint het programma met uitvoeren

Wat je in Elastic vaak ziet:
- process.start met parent, command line en integriteitsniveau
- dll_load voor belangrijke modules
- file, registry en network events zodra het proces acties uitvoert

Belangrijke observatie:
- Elk proces heeft een levenscyclus, start, acties, eindigt. Telemetrie volgt deze cyclus en helpt je anomalieën te herkennen

Praktische contextvelden om direct te beoordelen:
- parent.name en parent.command_line, is de herkomst logisch
- user.name en integrity level, mag deze gebruiker dit doen
- process.executable en code signing, klopt pad en signatuur
- timing in de keten, snelle procesexplosies vallen op

## 1.2 Processen, threads en modules uitgelegd
Denk in drie bouwstenen. Samen verklaren ze het grootste deel van je EDR-signalen.

- Proces, de container
  - Heeft een eigen adresruimte, environment, handle-tabel en token
  - Isolatie tussen processen is de standaard, toegang moet expliciet
- Thread, de uitvoering
  - De CPU voert instructies uit per thread
  - Aanvallen die injectie doen, creëren vaak threads in een ander proces
- Module, de functionaliteit
  - DLL’s leveren functies, bijvoorbeeld bestanden openen of netwerkverkeer
  - Onverwachte modules kunnen misbruik of misconfiguraties tonen

Detectiehaakjes:
- process.parent.name en command line patronen
- thread creation, vooral in een ander proces
- dll loads die niet passen bij het procesdoel

Veelvoorkomende valkuilen:
- service hosts vervullen meerdere rollen, vergelijk gedrag met peers
- ontwikkeltools en EDR’s vertonen legitiem injectie-achtig gedrag, whitelist per vendor

## 1.3 User Mode vs Kernel Mode in begrijpelijke taal
Windows werkt met twee niveaus. Dit bepaalt waar acties plaatsvinden en wat EDR kan zien.

- User Mode
  - Hier draaien applicaties en veel Windows componenten
  - Geen directe hardwaretoegang, alles via systeemfuncties
- Kernel Mode
  - Hier draait de kernel en drivers
  - Voert de werkelijke systeemacties uit, bijvoorbeeld I/O en geheugenbeheer

Waarom dit belangrijk is:
- Verdacht gedrag start meestal in User Mode, impact wordt afgedwongen in Kernel Mode
- EDR observeert beide lagen, daarom zie je zowel hoge niveau acties als lage niveau gevolgen

Kijk ook naar overgangsmomenten:
- API-call in User Mode gevolgd door kernelactie, bestand openen, handle toekennen
- mislukte kernelacties, access denied, relevant tijdens brute attempts

## 1.4 Hoe applicaties acties uitvoeren, bestanden, netwerk, registry
Een simpele kapstok, bijna alles volgt dit patroon.

1. Applicatie roept een API aan, bijvoorbeeld CreateFile, RegSetValue, connect
2. Windows controleert rechten, token, ACL’s, integriteit
3. Kernel voert de actie uit en retourneert resultaat
4. Telemetrie wordt vastgelegd en verrijkt

Waar je op let:
- Toegang tot gevoelige paden, bijvoorbeeld Windows, System32, ProgramData, AppData\Roaming\Microsoft\Windows\Start Menu, Run keys in de registry
- Netwerk naar ongewone bestemmingen of protocollen buiten het normale profiel van het proces
- Schrijfacties gevolgd door module loads of nieuwe processtarts

Klein voorbeeld, simplistisch procespad:
```
app.exe
  -> CreateFile("C:\\Users\\<user>\\AppData\\Roaming\\...startup.lnk")
  -> RegSetValue(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run)
  -> connect("203.0.113.10:443")
```
In Elastic verwacht je achtereenvolgens file, registry en network events, eventueel gevolgd door process of dll_load als er persistence of executie plaatsvindt.

Triagevragen bij deze sequenties:
- past het bij de rol van dit proces
- is er een legitieme installer of updater actief
- komt het pad of domein vaker voor in jouw omgeving

## 1.5 Waar EDR telemetry ontstaat
Telemetry komt uit meerdere lagen die elkaar aanvullen.

- Proceslevenscyclus, start, eind, hernoeming, argumenten
- Resource-actie, file create, write, delete, registry set, key create, network connect, DNS
- Moduleladers, dll_load en image loads, inclusief signering en pad
- Geheugen, allocaties, protectie-flags, RWX risico’s, wijzigingen die injectie aanduiden
- Toegang, OpenProcess met hoge rechten, handle duplicatie, token manipulatie

Elastic koppelt deze bronnen, zodat je tijdreeksen en causale ketens ziet. Dit maakt het mogelijk om gedragspatronen te detecteren in plaats van losse indicatoren.

Praktische tips om ruis te verminderen:
- filter bekende updatepaden en gesigneerde updaters van vertrouwde vendors
- normaliseer event.action namen in queries, zodat vergelijkbare acties samenkomen
- gebruik tijdvensters, sequences en procesgroepen in plaats van losse events

## 1.6 De rol van systeem-DLL’s, Kernel32, Advapi32, Ntdll etc.
DLL’s zijn de gereedschapskist van een proces. Enkele kernspelers die je vaak terugziet:

- Kernel32.dll, basis I/O, processen, geheugen
- Advapi32.dll, registry, services, security API’s
- User32.dll, vensters, interactie, relevant voor UI-automatisering of misbruik
- Ws2_32.dll, netwerk, sockets
- Ntdll.dll, laag bij de kernel, native API, vaak zichtbaar bij geavanceerde technieken

Detectie-inzichten:
- Ongewone dll_load in processen met beperkte functie, bijvoorbeeld een serviceproces dat UI-modules laadt
- Ongetekende of vreemd gelocaliseerde DLL’s in System32-achtige context
- Plotselinge loads van netwerk- of cryptografie-DLL’s in processen die normaal offline zijn

Kleine checks tijdens triage:
- hoort deze DLL bij het normale startprofiel van dit proces
- klopt de padlocatie, is het side-by-side of in een zoekpad gevoelig voor hijacking
- is de signering consistent met het uitvoerbare bestand

## 1.7 Waarom sommige acties verdacht lijken, praktijkvoorbeelden
Context maakt het verschil. Hieronder patronen die je vaak wil onderzoeken.

- Parent-child mismatch
  - Office-app start PowerShell of cmd met scripts, vooral met verdachte argumenten
- Regelvreemde module
  - Niet-standaard DLL’s in een systeemproces, of bekende hijacking locaties naast een legitiem exe-bestand
- Persistence vlak voor uitgaand verkeer
  - Registry Run key write gevolgd door netwerkconnecties naar zeldzame domeinen
- Geheugenmutaties gevolgd door thread start
  - VirtualAlloc met uitvoerrechten, daarna CreateRemoteThread in een ander proces
- Handle open naar beschermd proces
  - OpenProcess met uitgebreide rechten tegen browser, LSASS of EDR-proces

Hoe je dit beoordeelt:
- Controleer of het gedrag past bij de rol van het proces
- Kijk naar timing en volgorde, schrijf, laad, voer uit
- Combineer met reputatie, signering en padhygiëne

Snelle query-ideeën, conceptueel:
- parent is office en child is powershell met download arguments
- dll_load van ongetekende module in system32 pad
- memory_allocate, memory_write en create_remote_thread in kort venster

## 1.8 Overzichtsdiagram, Programma, Windows, Kernel, EDR
Een eenvoudige weergave om het geheel te onthouden.

```
Programma in User Mode
   |
   |  API-calls via DLL’s
   v
Windows Kernel, controleert rechten en voert uit
   |
   |  Telemetrie over acties
   v
Elastic Security EDR, verrijkt, correleert, alerteert
   |
   v
Analist beoordeelt gedrag in context
```

## Samenvatting
- Een proces start, laadt modules, voert threads uit en raakt bronnen aan, die cyclus vormt je telemetrie
- User Mode initieert, Kernel Mode dwingt af, EDR observeert beide en bouwt context op
- Let op parent-child relaties, onverwachte DLL’s, geheugenprotecties, gevoelige paden en netwerk in ongebruikelijke processen
- Systeem-DLL’s vertellen welk type functionaliteit gebruikt wordt, afwijkingen vallen op
- Detectie is het verbinden van gebeurtenissen in volgorde, wie deed wat, wanneer en met welke rechten
