# Windows fundamentals for security analysts

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

- [0.1 Waarom Windows begrijpen essentieel is voor analisten](00-introductie-en-doel.md#01-waarom-windows-begrijpen-essentieel-is-voor-analisten)
- [0.2 Hoe Elastic Security EDR naar Windows kijkt](00-introductie-en-doel.md#02-hoe-elastic-security-edr-naar-windows-kijkt)
- [0.3 Hoe dit document gebruikt moet worden](00-introductie-en-doel.md#03-hoe-dit-document-gebruikt-moet-worden)
- [0.4 Belangrijkste beveiligings- en detectieconcepten](00-introductie-en-doel.md#04-belangrijkste-beveiligings--en-detectieconcepten)

---

## **[01. Hoe Windows werkt (Fundamenten voor Analisten)](01-hoe-windows-werkt-fundamenten-voor-analisten.md)**

- [1.1 Wat gebeurt er wanneer een programma start?](01-hoe-windows-werkt-fundamenten-voor-analisten.md#11-wat-gebeurt-er-wanneer-een-programma-start)
- [1.2 Processen, threads en modules uitgelegd](01-hoe-windows-werkt-fundamenten-voor-analisten.md#12-processen-threads-en-modules-uitgelegd)
- [1.3 User Mode vs Kernel Mode in begrijpelijke taal](01-hoe-windows-werkt-fundamenten-voor-analisten.md#13-user-mode-vs-kernel-mode-in-begrijpelijke-taal)
- [1.4 Hoe applicaties acties uitvoeren (bestanden, netwerk, registry)](01-hoe-windows-werkt-fundamenten-voor-analisten.md#14-hoe-applicaties-acties-uitvoeren-bestanden-netwerk-registry)
- [1.5 Waar EDR-telemetrie ontstaat](01-hoe-windows-werkt-fundamenten-voor-analisten.md#15-waar-edr-telemetry-ontstaat)
- [1.6 De rol van systeem-DLL’s (Kernel32, Advapi32, Ntdll etc.)](01-hoe-windows-werkt-fundamenten-voor-analisten.md#16-de-rol-van-systeem-dlls-kernel32-advapi32-ntdll-etc)
- [1.7 Waarom sommige acties verdacht lijken (praktijkvoorbeelden)](01-hoe-windows-werkt-fundamenten-voor-analisten.md#17-waarom-sommige-acties-verdacht-lijken-praktijkvoorbeelden)
- [1.8 Overzichtsdiagram: Programma → Windows → Kernel → EDR](01-hoe-windows-werkt-fundamenten-voor-analisten.md#18-overzichtsdiagram-programma-windows-kernel-edr)

---

## **[02. Windows Geheugen Begrijpen voor Threat Detection](02-windows-geheugen-begrijpen-voor-threat-detection.md)**

- [2.1 Waarom geheugen een cruciaal onderdeel is van detection](02-windows-geheugen-begrijpen-voor-threat-detection.md#21-waarom-geheugen-een-cruciaal-onderdeel-is-van-detection)
- [2.2 Hoe Windows geheugen indeelt: simpel uitgelegd](02-windows-geheugen-begrijpen-voor-threat-detection.md#22-hoe-windows-geheugen-indeelt-simpel-uitgelegd)
- [2.3 Private memory, image memory, shared memory](02-windows-geheugen-begrijpen-voor-threat-detection.md#23-private-memory-image-memory-shared-memory)
- [2.4 Memory permissions (R, W, X) en waarom RWX verdacht is](02-windows-geheugen-begrijpen-voor-threat-detection.md#24-memory-permissions-r-w-x-en-waarom-rwx-verdacht-is)
- [2.5 Veelvoorkomende memory events die analisten zien](02-windows-geheugen-begrijpen-voor-threat-detection.md#25-veelvoorkomende-memory-events-die-analisten-zien)
- [2.6 Injectiegedrag herkennen via memory changes](02-windows-geheugen-begrijpen-voor-threat-detection.md#26-injectiegedrag-herkennen-via-memory-changes)
- [2.7 Wat EDR registreert over geheugen (Elastic-specifiek)](02-windows-geheugen-begrijpen-voor-threat-detection.md#27-wat-edr-registreert-over-geheugen-elastic-specifiek)
- [2.8 Diagrammen: memory layout & suspicious patterns](02-windows-geheugen-begrijpen-voor-threat-detection.md#28-diagrammen-memory-layout-en-suspicious-patterns)

---

## **[03. Hoe programma’s met Windows praten (API’s & Telemetrie)](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md)**

- [3.1 Windows API’s voor beginners](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md#31-windows-apis-voor-beginners)
- [3.2 Win32 API, Native API en waarom dit ertoe doet](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md#32-win32-api-native-api-en-waarom-dit-ertoe-doet)
- [3.3 Waar lopen API-calls in de EDR-telemetrie terug?](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md#33-waar-lopen-api-calls-in-de-edr-telemetrie-terug)
- [3.4 Veelvoorkomende API’s die verdacht gedrag veroorzaken](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md#34-veelvoorkomende-apis-die-verdacht-gedrag-veroorzaken)
- [3.5 Hoe malware API’s misbruikt (conceptueel, niet offensief)](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md#35-hoe-aanvallers-apis-misbruiken-conceptueel)
- [3.6 Debugging van API-fouten als analist](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md#36-debugging-van-api-fouten-als-analist)
- [3.7 Waarom sommige aanvallen API-calls verbergen](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md#37-waarom-sommige-aanvallen-api-calls-verbergen)
- [3.8 Mapping: API call → Elastic event.category / event.action](03-hoe-programmas-met-windows-praten-apis-en-telemetry.md#38-mapping-api-call-naar-elastic-eventcategory-en-eventaction)

---

## **[04. Portable Executables: Hoe Windows bestanden laadt](04-portable-executables-hoe-windows-bestanden-laadt.md)**

- [4.1 Hoe Windows programma’s en DLL’s in geheugen plaatst](04-portable-executables-hoe-windows-bestanden-laadt.md#41-hoe-windows-programmas-en-dlls-in-geheugen-plaatst)
- [4.2 Wat elke analist moet weten over PE’s (zonder reverse engineering)](04-portable-executables-hoe-windows-bestanden-laadt.md#42-wat-elke-analist-moet-weten-over-pes-zonder-reverse-engineering)
- [4.3 Imports, exports en waarom dit zichtbaar is in EDR-data](04-portable-executables-hoe-windows-bestanden-laadt.md#43-imports-exports-en-waarom-dit-zichtbaar-is-in-edr-data)
- [4.4 Verdachte PE-kenmerken: high entropy, rare sections](04-portable-executables-hoe-windows-bestanden-laadt.md#44-verdachte-pe-kenmerken-high-entropy-rare-sections)
- [4.5 DLL load events interpreteren](04-portable-executables-hoe-windows-bestanden-laadt.md#45-dll-load-events-interpreteren)
- [4.6 Waarom packed executables verdacht zijn](04-portable-executables-hoe-windows-bestanden-laadt.md#46-waarom-packed-executables-verdacht-zijn)
- [4.7 Hoe de loader werkt in relatie tot detection](04-portable-executables-hoe-windows-bestanden-laadt.md#47-hoe-de-loader-werkt-in-relatie-tot-detection)
- [4.8 Diagrammen: PE simplified](04-portable-executables-hoe-windows-bestanden-laadt.md#48-diagrammen-pe-simplified)

---

## **[05. DLL’s en Module Loading: Gedrag dat analisten moeten herkennen](05-dlls-en-module-loading-gedrag-dat-analisten-moeten-herkennen.md)**

- [5.1 Wat is een DLL en waarom gebruikt Windows dit overal?](05-dlls-en-module-loading-gedrag-dat-analisten-moeten-herkennen.md#51-wat-is-een-dll-en-waarom-gebruikt-windows-dit-overal)
- [5.2 Normale vs. verdachte DLL patronen](05-dlls-en-module-loading-gedrag-dat-analisten-moeten-herkennen.md#52-normale-vs-verdachte-dll-patronen)
- [5.3 DLL search order & hijacking uitgelegd](05-dlls-en-module-loading-gedrag-dat-analisten-moeten-herkennen.md#53-dll-search-order--hijacking-uitgelegd)
- [5.4 Rundll32 als aanvalstechniek](05-dlls-en-module-loading-gedrag-dat-analisten-moeten-herkennen.md#54-rundll32-als-aanvalstechniek)
- [5.5 Verdachte module loads in Elastic herkennen](05-dlls-en-module-loading-gedrag-dat-analisten-moeten-herkennen.md#55-verdachte-module-loads-in-elastic-herkennen)
- [5.6 Misbruik van delay loading en API-resolutie](05-dlls-en-module-loading-gedrag-dat-analisten-moeten-herkennen.md#56-misbruik-van-delay-loading-en-api-resolutie)
- [5.7 Praktische detection tips per DLL-misbruikvorm](05-dlls-en-module-loading-gedrag-dat-analisten-moeten-herkennen.md#57-praktische-detection-tips-per-dll-misbruikvorm)

---

## **[06. Hoe moderne EDR’s detecteren wat Windows doet](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md)**

- [6.1 Signature-based detection](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md#61-signature-based-detection)
- [6.2 Heuristiek en gedragspatronen](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md#62-heuristiek-en-gedragspatronen)
- [6.3 Wat Elastic EDR doet in User Mode & Kernel Mode](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md#63-wat-elastic-edr-doet-in-user-mode--kernel-mode)
- [6.4 Hooking en hoe aanvallers dit proberen te omzeilen](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md#64-hooking-en-hoe-aanvallers-dit-proberen-te-omzeilen)
- [6.5 Indicatoren van EDR-bypass technieken](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md#65-indicatoren-van-edr-bypass-technieken)
- [6.6 Sandboxing en automatische analyse](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md#66-sandboxing-en-automatische-analyse)
- [6.7 Waarom context belangrijker is dan losse events](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md#67-waarom-context-belangrijker-is-dan-losse-events)
- [6.8 Detection best practices voor analisten](06-hoe-moderne-edrs-detecteren-wat-windows-doet.md#68-detection-best-practices-voor-analisten)

---

## **[07. Processen: Alles wat een analist moet weten](07-processen-alles-wat-een-analist-moet-weten.md)**

- [7.1 Wat een proces eigenlijk is (praktisch uitgelegd)](07-processen-alles-wat-een-analist-moet-weten.md#71-wat-een-proces-eigenlijk-is-praktisch-uitgelegd)
- [7.2 Parent-child relaties interpreteren](07-processen-alles-wat-een-analist-moet-weten.md#72-parent-child-relaties-interpreteren)
- [7.3 Process tree anomalies (Elastic visualisaties)](07-processen-alles-wat-een-analist-moet-weten.md#73-process-tree-anomalies-elastic-visualisaties)
- [7.4 Suspicious process patterns (PowerShell, WMI, LOLBins)](07-processen-alles-wat-een-analist-moet-weten.md#74-suspicious-process-patterns-powershell-wmi-lolbins)
- [7.5 Hoe modules, memory en threads bij een proces horen](07-processen-alles-wat-een-analist-moet-weten.md#75-hoe-modules-memory-en-threads-bij-een-proces-horen)
- [7.6 Process events in Elastic (process.start, process.end, etc.)](07-processen-alles-wat-een-analist-moet-weten.md#76-process-events-in-elastic-processstart-processend-enzovoort)
- [7.7 Praktische hunting queries](07-processen-alles-wat-een-analist-moet-weten.md#77-praktische-hunting-queries)

---

## **[08. Threads & Execution Context (zonder extreem low-level te worden)](08-threads-en-execution-context.md)**

- [8.1 Wat een thread doet en waarom het relevant is voor detection](08-threads-en-execution-context.md#81-wat-een-thread-doet-en-waarom-het-relevant-is-voor-detection)
- [8.2 Remote thread creation als injectie](08-threads-en-execution-context.md#82-remote-thread-creation-als-injectie)
- [8.3 APC’s en thread hijacking op conceptueel niveau](08-threads-en-execution-context.md#83-apcs-en-thread-hijacking-op-conceptueel-niveau)
- [8.4 TEB/PEB: wat analisten moeten weten (en wat niet)](08-threads-en-execution-context.md#84-teb-en-peb-wat-analisten-moeten-weten-en-wat-niet)
- [8.5 Elastic EDR indicators voor thread misbruik](08-threads-en-execution-context.md#85-elastic-edr-indicators-voor-thread-misbruik)
- [8.6 Visualisatie: “Hoe een thread gestart wordt”](08-threads-en-execution-context.md#86-visualisatie-hoe-een-thread-gestart-wordt)

---

## **[09. Handles & Toegangsrechten Begrijpen](09-handles-en-toegangsrechten-begrijpen.md)**

- [9.1 Wat een handle is (analistenversie)](09-handles-en-toegangsrechten-begrijpen.md#91-wat-een-handle-is-analistenversie)
- [9.2 Waarom attackers handles openen naar andere processen](09-handles-en-toegangsrechten-begrijpen.md#92-waarom-attackers-handles-openen-naar-andere-processen)
- [9.3 Process access rights die alarmbellen moeten doen rinkelen](09-handles-en-toegangsrechten-begrijpen.md#93-process-access-rights-die-alarmbellen-moeten-doen-rinkelen)
- [9.4 Elastic detection patterns voor OpenProcess](09-handles-en-toegangsrechten-begrijpen.md#94-elastic-detection-patterns-voor-openprocess)
- [9.5 Token access & privilege escalation](09-handles-en-toegangsrechten-begrijpen.md#95-token-access--privilege-escalation)
- [9.6 Suspicious handle duplication](09-handles-en-toegangsrechten-begrijpen.md#96-suspicious-handle-duplication)
- [9.7 Use cases: ransomware, credential theft](09-handles-en-toegangsrechten-begrijpen.md#97-use-cases-ransomware-credential-theft)
- [9.8 Mapping naar MITRE ATT&CK](09-handles-en-toegangsrechten-begrijpen.md#98-mapping-naar-mitre-attck)

---

## **[10. Windows Security Model: Wat Analisten Echt Moeten Begrijpen](10-windows-security-model-wat-analisten-echt-moeten-begrijpen.md)**

- [10.1 Tokens, gebruikerscontext, integriteitsniveaus](10-windows-security-model-wat-analisten-echt-moeten-begrijpen.md#101-tokens-gebruikerscontext-integriteitsniveaus)
- [10.2 Privileges (SeDebugPrivilege etc.)](10-windows-security-model-wat-analisten-echt-moeten-begrijpen.md#102-privileges-sedebugprivilege-en-consorten)
- [10.3 UAC & elevation](10-windows-security-model-wat-analisten-echt-moeten-begrijpen.md#103-uac-en-elevation)
- [10.4 Authentication basics (NTLM / Kerberos)](10-windows-security-model-wat-analisten-echt-moeten-begrijpen.md#104-authenticatie-basis-ntlm-en-kerberos)
- [10.5 Waarom Access Tokens cruciaal zijn voor detection](10-windows-security-model-wat-analisten-echt-moeten-begrijpen.md#105-waarom-access-tokens-cruciaal-zijn-voor-detection)
- [10.6 Elastic indicators voor privilege escalation](10-windows-security-model-wat-analisten-echt-moeten-begrijpen.md#106-elastic-indicators-voor-privilege-escalation)
- [10.7 Praktische aanvallen en detectiepatronen](10-windows-security-model-wat-analisten-echt-moeten-begrijpen.md#107-praktische-aanvallen-en-detectiepatronen)

---

## **[11. Windows Services & Persistence Mechanisms](11-windows-services-en-persistence-mechanisms.md)**

- [11.1 Hoe Windows services werken](11-windows-services-en-persistence-mechanisms.md#111-hoe-windows-services-werken)
- [11.2 Normale vs. verdachte service-creatie](11-windows-services-en-persistence-mechanisms.md#112-normale-vs-verdachte-service-creatie)
- [11.3 Services als persistentie via registry](11-windows-services-en-persistence-mechanisms.md#113-services-als-persistentie-via-registry)
- [11.4 Elastic detection patterns voor nieuwe services](11-windows-services-en-persistence-mechanisms.md#114-elastic-detection-patterns-voor-nieuwe-services)
- [11.5 Misconfiguraties die aanvallers misbruiken](11-windows-services-en-persistence-mechanisms.md#115-misconfiguraties-die-aanvallers-misbruiken)
- [11.6 Diagram: service lifecycle](11-windows-services-en-persistence-mechanisms.md#116-diagram-service-lifecycle)

---

## **[12. Windows Registry voor Security Analisten](12-windows-registry-voor-security-analisten.md)**

- [12.1 Wat de registry is en waarom analisten ernaar kijken](12-windows-registry-voor-security-analisten.md#121-wat-de-registry-is-en-waarom-analisten-ernaar-kijken)
- [12.2 Belangrijke hives en paden](12-windows-registry-voor-security-analisten.md#122-belangrijke-hives-en-paden)
- [12.3 Run keys & persistentie](12-windows-registry-voor-security-analisten.md#123-run-keys-en-persistentie)
- [12.4 Registry events in Elastic](12-windows-registry-voor-security-analisten.md#124-registry-events-in-elastic)
- [12.5 Detectie van malicious registry writes](12-windows-registry-voor-security-analisten.md#125-detectie-van-malicious-registry-writes)
- [12.6 Registry artefacten in incident response](12-windows-registry-voor-security-analisten.md#126-registry-artefacten-in-incident-response)
- [12.7 Practical hunting queries](12-windows-registry-voor-security-analisten.md#127-practical-hunting-queries)

---

## **[13. Logging, Telemetrie & Sysmon/ETW Mapping](13-logging-telemetry-en-sysmon-etw-mapping.md)**

- [13.1 Verschil tussen Windows logs & EDR-telemetrie](13-logging-telemetry-en-sysmon-etw-mapping.md#131-verschil-tussen-windows-logs-en-edr-telemetrie)
- [13.2 Belangrijkste event logs voor analisten](13-logging-telemetry-en-sysmon-etw-mapping.md#132-belangrijkste-event-logs-voor-analisten)
- [13.3 Sysmon events en Elastic mappings](13-logging-telemetry-en-sysmon-etw-mapping.md#133-sysmon-events-en-elastic-mappings)
- [13.4 ETW als bron voor EDR](13-logging-telemetry-en-sysmon-etw-mapping.md#134-etw-als-bron-voor-edr)
- [13.5 Detectie op basis van event correlation](13-logging-telemetry-en-sysmon-etw-mapping.md#135-detectie-op-basis-van-event-correlation)
- [13.6 Hoe je ruis minimaliseert in detection](13-logging-telemetry-en-sysmon-etw-mapping.md#136-hoe-je-ruis-minimaliseert-in-detection)

---

## **[14. WoW64 en 32/64-bit gedrag in Windows](14-wow64-en-32-64-bit-gedrag-in-windows.md)**

- [14.1 Wat WoW64 is en waarom het soms verwarrend is](14-wow64-en-32-64-bit-gedrag-in-windows.md#141-wat-wow64-is-en-waarom-het-soms-verwarrend-is)
- [14.2 Waarom sommige processen 32-bit zijn op 64-bit systemen](14-wow64-en-32-64-bit-gedrag-in-windows.md#142-waarom-sommige-processen-32-bit-zijn-op-64-bit-systemen)
- [14.3 Hoe EDR hiermee omgaat](14-wow64-en-32-64-bit-gedrag-in-windows.md#143-hoe-edr-hiermee-omgaat)
- [14.4 Verdachte cross-architecture patronen](14-wow64-en-32-64-bit-gedrag-in-windows.md#144-verdachte-cross-architecture-patronen)
- [14.5 Indicatoren voor evasive behavior](14-wow64-en-32-64-bit-gedrag-in-windows.md#145-indicatoren-voor-evasive-behavior)

---

## **[15. MITRE ATT&CK Mapping: Van Theorie naar Praktijk](15-mitre-attack-mapping-van-theorie-naar-praktijk.md)**

- [15.1 Hoe analisten Windows events koppelen aan ATT&CK](15-mitre-attack-mapping-van-theorie-naar-praktijk.md#151-hoe-analisten-windows-events-koppelen-aan-attck)
- [15.2 Memory injectie → T1055](15-mitre-attack-mapping-van-theorie-naar-praktijk.md#152-memory-injectie-t1055)
- [15.3 Process creation anomalies → T1059 / T1036](15-mitre-attack-mapping-van-theorie-naar-praktijk.md#153-process-creation-anomalies-t1059-en-t1036)
- [15.4 DLL hijacking → T1574](15-mitre-attack-mapping-van-theorie-naar-praktijk.md#154-dll-hijacking-t1574)
- [15.5 Persistence technieken → T1547](15-mitre-attack-mapping-van-theorie-naar-praktijk.md#155-persistence-technieken-t1547)
- [15.6 Privilege escalation → T1068 / T1134](15-mitre-attack-mapping-van-theorie-naar-praktijk.md#156-privilege-escalation-t1068-en-t1134)
- [15.7 Token misbruik → T1134.001](15-mitre-attack-mapping-van-theorie-naar-praktijk.md#157-token-misbruik-t1134001)
- [15.8 Complete mapping tabel voor Elastic EDR](15-mitre-attack-mapping-van-theorie-naar-praktijk.md#158-compacte-mappingtabel-voor-elastic-edr)

Suggesties of aanvullingen? Open gerust een issue of pull request.
