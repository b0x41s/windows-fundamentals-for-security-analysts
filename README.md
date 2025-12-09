# Windows Internals for Detection Engineers, index

![Course banner](./pictures/coursebanner.png)

Korte index voor snelle navigatie door alle hoofdstukken. Geschikt voor security analisten, SOC/DFIR en detection engineers die met Elastic Security EDR werken.

Aanpak voor lezen:
- lees lineair voor een stevig fundament
- spring naar een specifiek onderwerp tijdens triage of hunting
- combineer met je eigen Elastic queries en dashboards

Let op: queryvoorbeelden in deze repository zijn conceptueel/pseudo en bedoeld als denkrichting. Pas ze aan op jouw datamodel (Elastic) en omgeving.

## **INHOUDSOPGAVE — Windows Internals for Detection Engineers**

---

## **[00. Introductie & Doel van deze training](00-introductie-en-doel.md)**

0.1 Waarom Windows begrijpen essentieel is voor analisten
0.2 Hoe Elastic Security EDR naar Windows kijkt
0.3 Hoe dit document gebruikt moet worden
0.4 Belangrijkste beveiligings- en detectieconcepten

---

## **[01. Hoe Windows werkt (Fundamenten voor Analisten)](01-hoe-windows-werkt-fundamenten-voor-analisten.md)**

1.1 Wat gebeurt er wanneer een programma start?
1.2 Processen, threads en modules uitgelegd
1.3 User Mode vs Kernel Mode in begrijpelijke taal
1.4 Hoe applicaties acties uitvoeren (bestanden, netwerk, registry)
1.5 Waar EDR-telemetrie ontstaat
1.6 De rol van systeem-DLL’s (Kernel32, Advapi32, Ntdll etc.)
1.7 Waarom sommige acties verdacht lijken (praktijkvoorbeelden)
1.8 Overzichtsdiagram: Programma → Windows → Kernel → EDR

---

## **[02. Windows Geheugen Begrijpen voor Threat Detection](02-windows-geheugen-begrijpen-voor-threat-detection.md)**

2.1 Waarom geheugen een cruciaal onderdeel is van detection
2.2 Hoe Windows geheugen indeelt: simpel uitgelegd
2.3 Private memory, image memory, shared memory
2.4 Memory permissions (R, W, X) en waarom RWX verdacht is
2.5 Veelvoorkomende memory events die analisten zien
2.6 Injectiegedrag herkennen via memory changes
2.7 Wat EDR registreert over geheugen (Elastic-specifiek)
2.8 Diagrammen: memory layout & suspicious patterns

---

## **[03. Hoe programma’s met Windows praten (API’s & Telemetrie)](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md)**

3.1 Windows API’s voor beginners
3.2 Win32 API, Native API en waarom dit ertoe doet
3.3 Waar lopen API-calls in de EDR-telemetrie terug?
3.4 Veelvoorkomende API’s die verdacht gedrag veroorzaken
3.5 Hoe malware API’s misbruikt (conceptueel, niet offensief)
3.6 Debugging van API-fouten als analist
3.7 Waarom sommige aanvallen API-calls verbergen
3.8 Mapping: API call → Elastic event.category / event.action

---

## **[04. Portable Executables: Hoe Windows bestanden laadt](04-portable-executables-hoe-windows-bestanden-laadt.md)**

4.1 Hoe Windows programma’s en DLL’s in geheugen plaatst
4.2 Wat elke analist moet weten over PE’s (zonder reverse engineering)
4.3 Imports, exports en waarom dit zichtbaar is in EDR-data
4.4 Verdachte PE-kenmerken: high entropy, rare sections
4.5 DLL load events interpreteren
4.6 Waarom packed executables verdacht zijn
4.7 Hoe de loader werkt in relatie tot detection
4.8 Diagrammen: PE simplified

---

## **[05. DLL’s en Module Loading: Gedrag dat analisten moeten herkennen](05-dlls-en-module-loading-gedrag-dat-analisten-moeten-herkennen.md)**

5.1 Wat is een DLL en waarom gebruikt Windows dit overal?
5.2 Normale vs. verdachte DLL patronen
5.3 DLL search order & hijacking uitgelegd
5.4 Rundll32 als aanvalstechniek
5.5 Verdachte module loads in Elastic herkennen
5.6 Misbruik van delay loading en API-resolutie
5.7 Praktische detection tips per DLL-misbruikvorm

---

## **[06. Hoe moderne EDR’s detecteren wat Windows doet](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md)**

6.1 Signature-based detection
6.2 Heuristiek en gedragspatronen
6.3 Wat Elastic EDR doet in User Mode & Kernel Mode
6.4 Hooking en hoe aanvallers dit proberen te omzeilen
6.5 Indicatoren van EDR-bypass technieken
6.6 Sandboxing en automatische analyse
6.7 Waarom context belangrijker is dan losse events
6.8 Detection best practices voor analisten

---

## **[07. Processen: Alles wat een analist moet weten](07-processen-alles-wat-een-analist-moet-weten.md)**

7.1 Wat een proces eigenlijk is (praktisch uitgelegd)
7.2 Parent-child relaties interpreteren
7.3 Process tree anomalies (Elastic visualisaties)
7.4 Suspicious process patterns (PowerShell, WMI, LOLBins)
7.5 Hoe modules, memory en threads bij een proces horen
7.6 Process events in Elastic (process.start, process.end, etc.)
7.7 Praktische hunting queries

---

## **[08. Threads & Execution Context (zonder extreem low-level te worden)](08-threads-en-execution-context.md)**

8.1 Wat een thread doet en waarom het relevant is voor detection
8.2 Remote thread creation als injectie
8.3 APC’s en thread hijacking op conceptueel niveau
8.4 TEB/PEB: wat analisten moeten weten (en wat niet)
8.5 Elastic EDR indicators voor thread misbruik
8.6 Visualisatie: “Hoe een thread gestart wordt”

---

## **[09. Handles & Toegangsrechten Begrijpen](09-handles-en-toegangsrechten-begrijpen.md)**

9.1 Wat een handle is (analistenversie)
9.2 Waarom attackers handles openen naar andere processen
9.3 Process access rights die alarmbellen moeten doen rinkelen
9.4 Elastic detection patterns voor OpenProcess
9.5 Token access & privilege escalation
9.6 Suspicious handle duplication
9.7 Use cases: ransomware, credential theft
9.8 Mapping naar MITRE ATT&CK

---

## **[10. Windows Security Model: Wat Analisten Echt Moeten Begrijpen](10-windows-security-model-wat-analisten-echt-moeten-begrijpen.md)**

10.1 Tokens, gebruikerscontext, integriteitsniveaus
10.2 Privileges (SeDebugPrivilege etc.)
10.3 UAC & elevation
10.4 Authentication basics (NTLM / Kerberos)
10.5 Waarom Access Tokens cruciaal zijn voor detection
10.6 Elastic indicators voor privilege escalation
10.7 Praktische aanvallen en detectiepatronen

---

## **[11. Windows Services & Persistence Mechanisms](11-windows-services-en-persistence-mechanisms.md)**

11.1 Hoe Windows services werken
11.2 Normale vs. verdachte service-creatie
11.3 Services als persistentie via registry
11.4 Elastic detection patterns voor nieuwe services
11.5 Misconfiguraties die aanvallers misbruiken
11.6 Diagram: service lifecycle

---

## **[12. Windows Registry voor Security Analisten](12-windows-registry-voor-security-analisten.md)**

12.1 Wat de registry is en waarom analisten ernaar kijken
12.2 Belangrijke hives en paden
12.3 Run keys & persistentie
12.4 Registry events in Elastic
12.5 Detectie van malicious registry writes
12.6 Registry artefacten in incident response
12.7 Practical hunting queries

---

## **[13. Logging, Telemetrie & Sysmon/ETW Mapping](13-logging-telemetry-en-sysmon-etw-mapping.md)**

13.1 Verschil tussen Windows logs & EDR-telemetrie
13.2 Belangrijkste event logs voor analisten
13.3 Sysmon events en Elastic mappings
13.4 ETW als bron voor EDR
13.5 Detectie op basis van event correlation
13.6 Hoe je ruis minimaliseert in detection

---

## **[14. WoW64 en 32/64-bit gedrag in Windows](14-wow64-en-32-64-bit-gedrag-in-windows.md)**

14.1 Wat WoW64 is en waarom het soms verwarrend is
14.2 Waarom sommige processen 32-bit zijn op 64-bit systemen
14.3 Hoe EDR hiermee omgaat
14.4 Verdachte cross-architecture patronen
14.5 Indicatoren voor evasive behavior

---

## **[15. MITRE ATT&CK Mapping: Van Theorie naar Praktijk](15-mitre-attack-mapping-van-theorie-naar-praktijk.md)**

15.1 Hoe analisten Windows events koppelen aan ATT&CK
15.2 Memory injectie → T1055
15.3 Process creation anomalies → T1059 / T1036
15.4 DLL hijacking → T1574
15.5 Persistence technieken → T1547
15.6 Privilege escalation → T1068 / T1134
15.7 Token misbruik → T1134.001
15.8 Complete mapping tabel voor Elastic EDR

Suggesties of aanvullingen? Open gerust een issue of pull request.
