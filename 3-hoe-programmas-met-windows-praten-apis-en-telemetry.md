# 3. Hoe programma’s met Windows praten, API’s en Telemetry

## 3.1 Windows API’s voor beginners
Een API is een verzameling functies die programma’s gebruiken om iets te doen in Windows. In plaats van direct met hardware of kernel te praten, roepen applicaties functies aan in DLL’s. Bekende voorbeelden zijn bestanden openen, netwerkverbindingen maken of nieuwe processen starten.

Praktisch beeld:
- applicatie roept een functie aan in een DLL, bijvoorbeeld Kernel32.dll of Advapi32.dll
- de functie vertaalt dit naar lagere systeemaanroepen
- de kernel voert de actie uit en retourneert een resultaat
- EDR registreert de poging en het resultaat, eventueel met details over paden en rechten

Waarom dit helpt bij detection:
- elke verdachte actie laat sporen na in de vorm van events
- API’s komen in patronen, door de volgorde te bekijken herken je intentie
- afwijkende API-keuzes kunnen wijzen op omzeiling of misbruik

## 3.2 Win32 API, Native API en waarom dit ertoe doet
Er zijn grofweg twee niveaus die je als analist moet kennen:

- Win32 API
  - hogere laag, vertrouwd door de meeste applicaties
  - functies in Kernel32.dll, Advapi32.dll, User32.dll, Ws2_32.dll
  - stabieler en beter gedocumenteerd
- Native API
  - lagere laag, blootgelegd via Ntdll.dll
  - functies beginnen vaak met Nt of Zw
  - gebruikt door systeemcomponenten en door geavanceerde software

Detectie-inzicht:
- als een applicatie direct Native API gebruikt voor gevoelige acties, kan dit wijzen op omzeiling van monitoring op hoger niveau
- de uitkomst is hetzelfde, de kernel voert de actie uit, maar de eventstroom kan net anders zijn

## 3.3 Waar lopen API-calls in de EDR-telemetry terug
EDR registreert niet elke afzonderlijke API-call, maar de gevolgen, de objecten en de context. Je ziet daarom terug:

- CreateProcess, Start, event.category: process, event.action: process.start
- CreateFile, Open, Write, Read, event.category: file, event.action: file_create, file_write, file_read
- RegSetValue, RegCreateKey, event.category: registry, event.action: registry_set, registry_add
- connect, bind, send, event.category: network, event.action: network_connection, dns, http
- LoadLibrary, LdrLoadDll, event.category: library, event.action: dll_load
- VirtualAlloc, VirtualProtect, WriteProcessMemory, event.category: memory, event.action: memory_allocate, memory_protect, memory_write
- OpenProcess, DuplicateHandle, event.category: access, event.action: open_process, duplicate_handle

Tip, denk in categorie en actie. De specifieke API-naam hoeft niet zichtbaar te zijn, de intentie is wel zichtbaar in het event.

## 3.4 Veelvoorkomende API’s die verdacht gedrag veroorzaken
Conceptueel, dit zijn functies of families die vaak terugkomen in incidenten:

- OpenProcess met uitgebreide rechten, voorbereiding voor inspectie of injectie
- VirtualAllocEx, WriteProcessMemory, VirtualProtectEx, geheugenallocatie en wijziging in een ander proces
- CreateRemoteThread of QueueUserAPC, uitvoeren van code in een ander proces
- LoadLibraryW of LdrLoadDll op ongebruikelijke paden, DLL hijacking of sideloading
- SetWindowsHookEx of Creatie van globale hooks, code-injectie via UI-mechanismen
- NtUnmapViewOfSection en herladen van een image, hollowing
- WMI en COM, bijvoorbeeld CoCreateInstance, ExecMethod, remote uitvoering zonder klassiek procespad

Contextvragen bij deze families:
- past het bij het type proces, bijvoorbeeld een teksteditor met process access
- zie je vlak ervoor of erna schrijven naar schijf of registry
- is er een netwerkactie die het gedrag verklaart of juist verdachter maakt

## 3.5 Hoe aanvallers API’s misbruiken, conceptueel
Aanvallers variëren in hoe ze API’s gebruiken om monitoring te ontwijken. De kern voor analisten is het herkennen van de bijeffecten.

- Dynamische resolutie, GetProcAddress, laten zien dat een app functies pas op het laatste moment zoekt
- String-obfuscatie, API-namen of paden verhullen, maar paden en outcomes blijven zichtbaar
- Indirecte paden, Native API via Ntdll direct, minder zichtbare hooks in hogere lagen
- Section-based technieken, minder WriteProcessMemory, maar wel mapping en protectie-aanpassingen

Detectie blijft mogelijk door te letten op:
- volgorde en samenhang, alloceren, schrijven, beschermen, uitvoeren
- objecten en rechten, wie opent wat met welke access mask
- pad en signering, combineer herkomst met bestemming

## 3.6 Debugging van API-fouten als analist
Fouten zijn informatie. Herhaalde mislukte pogingen of specifieke error codes geven richting.

- access denied bij OpenProcess of CreateFile, mogelijke privilege-escalatiepoging
- file in use of sharing violation, indicator dat een actor concurrent met een legitiem proces werkt
- invalid parameter of not found bij registry of services, verken padfouten of staging-artefacten

Praktische triage:
- sorteer op @timestamp en groepeer per process.entity_id om herhaalde pogingen te zien
- kijk naar de eerste mislukking en de eerste successtatus, wat veranderde er tussendoor
- koppel errors aan user context en integrity level

## 3.7 Waarom sommige aanvallen API-calls verbergen
Sommige technieken proberen detectie te omzeilen door minder zichtbare paden te gebruiken.

- directe syscalls of syscall-stomping, om hooks op hoger niveau te mijden
- manual mapping van DLL’s, zonder traditionele LoadLibrary
- living off the land, via ingebouwde tools of COM, minder opvallend in procesketens

Hoe je dit alsnog ziet:
- side-effects, geheugenprotecties, nieuwe threads, handles en module-aanwezigheid
- procescontext, parent-chain en afwijkende command lines
- resourcegebruik, bestanden, registry en netwerk in onlogische combinaties

## 3.8 Mapping, API call naar Elastic event.category en event.action
Gebruik deze mentale mapping tijdens triage, de exacte velden kunnen per versie verschillen, het concept blijft gelijk.

- Processen
  - CreateProcess → process.start
  - ExitProcess → process.end
- Bestanden
  - CreateFile, WriteFile → file_create, file_write
  - DeleteFile, MoveFile → file_delete, file_rename
- Registry
  - RegSetValue, RegCreateKey → registry_set, registry_add
  - RegDeleteValue → registry_delete
- Netwerk
  - connect, send → network_connection, network_traffic
  - DNS-queries → dns
- Modules
  - LoadLibrary, LdrLoadDll → dll_load
- Geheugen en threads
  - VirtualAlloc, VirtualProtect → memory_allocate, memory_protect
  - WriteProcessMemory → memory_write
  - CreateRemoteThread, QueueUserAPC → create_remote_thread, thread_hijack
- Toegang en handles
  - OpenProcess, DuplicateHandle → open_process, duplicate_handle

Kleine richtlijnen voor detection:
- werk met sequences, bij elkaar passende acties binnen een tijdvenster
- benoem uitzonderingen, JIT, AV en EDR, om ruis te beperken
- geef extra gewicht aan cross-process acties richting gevoelige doelprocessen

## Samenvatting
- API’s zijn de taal waarmee applicaties met Windows praten, EDR laat je de gevolgen zien
- Win32 en Native API leiden tot vergelijkbare outcomes, maar verschillen in zichtbaarheid
- Map API-intenties naar event.category en event.action om sneller te triëren
- Let op sequences, rechten en context om misbruik te onderscheiden van legitiem gedrag

