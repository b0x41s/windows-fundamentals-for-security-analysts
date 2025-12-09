# 0. Introductie & Doel van deze training

## 0.1 Waarom Windows begrijpen essentieel is voor analisten
Windows is de bron van vrijwel alle EDR-signalen die we beoordelen. Wanneer je weet hoe processen starten, welke componenten betrokken zijn en hoe acties worden afgedwongen, kun je alerts in context plaatsen. Analisten die begrijpen hoe Windows beslissingen neemt over bestanden, geheugen en communicatie, herkennen sneller afwijkingen die wijzen op misbruik. Zonder die basis blijft telemetrie een rij losse events en kost het meer tijd om legitimiteit, misconfiguraties of echte aanvallen van elkaar te scheiden.

Leerdoelen van dit traject:
- je kunt de levenscyclus van een proces uitleggen en herkennen in telemetrie
- je herkent normale versus verdachte patronen in modules en geheugen
- je begrijpt hoe API-calls zich vertalen naar Elastic events
- je kunt triage onderbouwen met context, volgorde en rechten

## 0.2 Hoe Elastic Security EDR naar Windows kijkt
Elastic Security EDR volgt de levensloop van elk proces. Het verzamelt process.start, dll_load, file, registry, network en memory events door in zowel User Mode als Kernel Mode mee te kijken. Het product combineert deze gebeurtenissen in een tijdlijn, voorziet ze van enriched velden zoals command line, parent chain, hashes en context uit Elastic-detections. Daardoor kun je herkennen:
- welke component een actie initieerde
- welke resources zijn aangeraakt
- welke policy of detection rule de alert veroorzaakte
- hoe de activiteit zich verhoudt tot eerdere of latere events

Wat je praktisch terugziet in de interface:
- tijdlijn met procesboom, parent en child relaties
- detailscherm met event.category en event.action
- velden voor signering, pad, hash en user context
- correlaties met rules, ML jobs en eerdere observaties

## 0.3 Hoe dit document gebruikt moet worden
Gebruik dit document als referentiegids tijdens triage of threat hunting:
- lees hoofdstukken lineair wanneer je je fundament wilt opbouwen
- spring naar specifieke onderwerpen, bijvoorbeeld geheugen, services of handles, tijdens een onderzoek
- combineer de uitleg met live queries in Elastic zodat theorie direct aan je praktijkcases hangt
- gebruik de diagrammen en kernpunten voor kennisdeling binnen het SOC-team
Het materiaal is geen deep-dive reverse engineering handboek, maar een vertaling van Windows-internals naar praktische detection inzichten.

Aanpak tijdens een onderzoek, kort stappenplan:
- begin met de procesboom, bepaal herkomst en doel
- check recente module en geheugenacties, zoek volgordes
- beoordeel paden, signering en rechten van betrokken objecten
- verbind met netwerk en registry om intentie te duiden
- sluit uit wat legitiem is, focus op wat overblijft

## 0.4 Belangrijkste beveiligings- en detectieconcepten
Door de hoofdstukken heen komen steeds dezelfde principes terug:
- Context staat centraal, één event is zelden voldoende, combineer procesketen, resourcegebruik en tijdsverloop
- Toegangspaden zijn beslissend, wie een resource mag openen bepaalt of een actie legitiem is, let op privileges, tokens en handles
- Geheugen en modules verraden misbruik, onverwachte RWX-pagina’s of vreemde DLL’s zijn vaak de eerste indicator
- API’s vormen de brug, ieder verdacht patroon vertaalt uiteindelijk naar ongebruikelijke API-calls of call-sequenties
- Detection is correlatie, Elastic gebruikt rules, ML en sequences, begrijp hoe observaties passen in MITRE ATT&CK

Begrippen die we steeds gebruiken, in praktische taal:
- proces, container met geheugen, threads en token
- thread, uitvoerende context van de CPU
- module, DLL of exe die code of data levert
- handle, verwijzing met rechten naar een object
- token, identiteit en privileges van een proces of thread

## Samenvatting
- Windows-kennis maakt EDR-telemetrie begrijpelijk en versnelt triage
- Elastic volgt processen end-to-end en levert contextrijke gebeurtenissen
- Gebruik dit document als naslagwerk tijdens hunting en incident response
- Focus op context, toegang, geheugen, API-gebruik en correlatie
