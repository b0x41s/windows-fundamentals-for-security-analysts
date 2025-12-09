# 13. Logging, Telemetry en Sysmon/ETW Mapping

## 13.1 Verschil tussen Windows logs en EDR-telemetrie
Windows logs en EDR-telemetrie vullen elkaar aan, ze zijn niet hetzelfde.

- Windows event logs
  - geschreven door het besturingssysteem en applicaties, vaak in het Event Log
  - nuttig voor compliance, audit en breed systeemoverzicht
  - kunnen ontbrekende details hebben, afhankelijk van auditpolicy en kanaal
- EDR-telemetrie
  - verzameld door een sensor die procesgedrag observeert in User Mode en Kernel Mode
  - gericht op security, met extra context, correlaties en verrijking
  - doorgaans fijnmaziger bij proces, geheugen, module en toegangspaden

Detectie-inzicht, gebruik EDR-telemetrie voor gedrag en volgorde, gebruik Windows logs om bredere context te bevestigen, aanmeldingen, policies, service status.

## 13.2 Belangrijkste event logs voor analisten
Niet elk logkanaal is even waardevol voor detection. Deze komen het vaakst terug in triage.

- Security, aanmeldingen, procescreatie als audit is geconfigureerd, rechtengebruik
- System, service events, driverlaadfouten, systeemstatus
- Application, applicatiespecifieke fouten en waarschuwingen
- Microsoft-Windows-PowerShell/Operational, scriptuitvoering, module logging als geconfigureerd
- Microsoft-Windows-Windows Defender/Operational, detecties en statuswijzigingen
- TaskScheduler, taakcreatie en uitvoering
- DNS Client events, naamresolutie bij sommige configuraties

Praktische tips:
- auditpolicy bepaalt wat je ziet, logon types en process creation logging zijn essentieel
- combineer met EDR voor tijdlijnen, wie logde in, wat startte daarna, welke resources werden aangeraakt

## 13.3 Sysmon events en Elastic mappings
Sysmon verrijkt Windows met extra, securitygerichte events. Veel SOC’s gebruiken Sysmon naast EDR of als aanvullende bron. Onderstaande mapping is conceptueel, velden kunnen per integratie verschillen.

- Process Create, Sysmon 1 → Elastic, event.category: process, event.action: process_start
- Network Connection, Sysmon 3 → Elastic, event.category: network, event.action: network_connection
- Image Load, Sysmon 7 → Elastic, event.category: library, event.action: dll_load
- Create Remote Thread, Sysmon 8 → Elastic, event.category: process, event.action: create_remote_thread
- Process Access, Sysmon 10 → Elastic, event.category: access, event.action: open_process
- File Create, Sysmon 11 → Elastic, event.category: file, event.action: file_create
- Registry Set, Sysmon 13 → Elastic, event.category: registry, event.action: registry_set
- FileCreateStreamHash, Sysmon 15 → Elastic, event.category: file, event.action: file_create_stream
- Pipe Created/Connected, Sysmon 17/18 → Elastic, event.category: ipc, event.action: pipe_create/pipe_connect
- DNS Query, Sysmon 22 → Elastic, event.category: network, event.action: dns

Waarom deze mapping helpt:
- je onderhoudt één set queries op event.category en event.action
- je kunt bronnen combineren, EDR, Sysmon en Windows logs, binnen hetzelfde mentale model

Ruisreductie bij Sysmon:
- tune ruleset, minimaliseer brede includes, focus op paden, signering en parentage
- log DNS en network selectief, of corrigeer met allowlists voor veelvoorkomende domeinen

## 13.4 ETW als bron voor EDR
ETW, Event Tracing for Windows, is een mechanisme waarmee componenten gestructureerde events uitsturen. Moderne EDR’s gebruiken ETW als één van de bronnen.

Conceptueel beeld:
- providers, bijvoorbeeld Kernel-Process, Kernel-ImageLoad, PowerShell, Security-auditing
- sessies, consumeren events en sturen ze door naar de sensor
- filtering en sampling, om volume beheersbaar te houden

Wat je als analist moet onthouden:
- ETW verklaart waarom sommige EDR-events zeer gedetailleerd zijn, met velden rechtstreeks uit providers
- het is geen garantie op compleetheid, providers kunnen uitgeschakeld of gelimiteerd zijn
- aanvallers proberen ETW te verminderen, let op daling in telemetry of registry/policy-wijzigingen rond tracing

Praktische aanwijzing, je detecteert ETW-manipulatie via bijeffecten, minder events waar je ze wel verwacht, writes naar tracing keys of service-interventies.

## 13.5 Detectie op basis van event correlation
Sterke detecties ontstaan door meerdere zwakke signalen te combineren over een tijdvenster. Dit geldt voor bronnen onderling en binnen de EDR-telemetrie.

Principes:
- werk met sequences, bijvoorbeeld, file_create → registry_set → process_start
- voer correlatie uit per entiteit, process.entity_id, target.process.entity_id, user.id, host.id
- geef hogere score aan cross-process acties en gevoelige doelen, LSASS, browsers, EDR-processen
- voeg pad-hygiëne, signering en uitgever toe als filters

Korte, conceptuele voorbeelden:
```
-- Persistence via Run key na file drop
file where event.action:file_create and file.path:(*\\Users\\* or *\\ProgramData\\*)
then within 5m registry where event.action:registry_set and registry.path:*\\Run*
then within 10m process where event.action:process_start and process.executable == registry.data.strings
```

```
-- Injectie richting browser
window by target.process.entity_id 2m
sequence: open_process -> memory_allocate -> memory_write -> memory_protect -> create_remote_thread
filters: target.process.name in (chrome.exe, msedge.exe)
```

```
-- Sideloading vanuit applicatiemap met userschrijfrechten
event.action:"dll_load" and not file.path:"C:\\Windows\\System32\\*" and 
file.path:(*\\AppData\\* or *\\Temp\\* or *\\Program Files\\*) and not code_signature.trusted:true
```

## 13.6 Hoe je ruis minimaliseert in detection
Tuning is een doorlopend proces. Je doel is hoge signaal, laag ruis, zonder zicht te verliezen op echte aanvallen.

Aanpak in stappen:
- baseline je omgeving, identificeer veelvoorkomende processen, paden en updates
- gebruik trust-signalen, code_signature.trusted, bekende vendors, bekende updatepaden
- maak uitzonderingen specifiek, per proces en per pad, vermijd brede wildcards
- werk met tijdvensters en sequences in plaats van losse events, dit verhoogt precisie
- documenteer aannames, herzie uitzonderingen periodiek, verwijder wat niet meer nodig is
- monitor rule performance, false positives per dag en mean time to triage

Praktische tips:
- label rules met MITRE ATT&CK zodat analisten snel scenario’s herkennen
- voeg korte triage-instructies toe aan alerts, welke velden eerst checken, parent, path, signering, integriteit
- gebruik meerdere bronnen parallel, EDR, Sysmon en Windows logs, om bevindingen te bevestigen

## Samenvatting
- Windows logs en EDR-telemetrie vullen elkaar aan, EDR geeft gedragscontext, logs geven breed systeembeeld
- Sysmon biedt extra events die goed te mappen zijn naar Elastic’s event.category en event.action
- ETW is een belangrijke bron onder de motorkap, daling of manipulatie zie je via bijeffecten
- Sterke detecties zijn sequences met context, pad, signering en rechten, afgestemd op gevoelige doelen
- Minimaliseer ruis met baselining, specifieke uitzonderingen en continue evaluatie van rule-prestaties
