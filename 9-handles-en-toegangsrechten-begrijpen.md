# 9. Handles en Toegangsrechten Begrijpen

## 9.1 Wat een handle is, analistenversie
Een handle is een verwijzing met rechten naar een object in Windows, bijvoorbeeld een proces, bestand, token, thread of registry key. Zie het als een toegangskaartje, niet het object zelf. Met de handle bepaalt Windows wat je met het object mag doen.

Belangrijke punten:
- een handle bestaat altijd binnen de context van een proces, elke handle staat in de handle-tabel van dat proces
- de handle heeft een access mask, een verzameling rechten die aangevraagd en toegekend zijn
- zonder handle, geen actie, processen openen eerst een handle en voeren daarna pas bewerkingen uit

Waarom dit belangrijk is voor detection:
- aanvallers moeten handles openen naar doelprocessen of tokens om te injecteren of privileges te verhogen
- de combinatie van doelobject plus rechten vertelt veel over intentie

## 9.2 Waarom attackers handles openen naar andere processen
Aanvallers willen uitvoeren in of informatie uitlezen van andere processen. Daarvoor is toegang nodig. Typische doelen:

- browsers, om tokens of gevoelige data te stelen
- LSASS, om referenties te lezen of tokens te dupliceren
- EDR of beveiligingsprocessen, om te stoppen, belemmeren of te omzeilen
- hoogprivilege services, om code te draaien met meer rechten

Veel gebruikte stappen, conceptueel:
- OpenProcess met uitgebreide rechten op het doel
- Geheugenallocatie en schrijven in het doel
- Thread starten of kapen in het doel
- Of, een token uit het doelproces verkrijgen en daarmee impersoneren

## 9.3 Process access rights die alarmbellen moeten doen rinkelen
Bij OpenProcess kies je expliciet de rechten, dit vormt het access mask. Niet alle rechten zijn gelijkwaardig voor detection.

Verdachte of gevoelige rechten, conceptueel:
- PROCESS_VM_WRITE, schrijven naar geheugen van het doel
- PROCESS_VM_OPERATION, alloceren of wijzigen van geheugenrechten in het doel
- PROCESS_CREATE_THREAD, nieuwe thread starten in het doel
- PROCESS_DUP_HANDLE, handles dupliceren, bijvoorbeeld om bij tokens te komen
- PROCESS_QUERY_LIMITED_INFORMATION, op zichzelf niet verdacht, maar vaak stap in keten
- PROCESS_SUSPEND_RESUME, threads pauzeren of hervatten, gebruikt bij kaping
- PROCESS_TERMINATE, proces beëindigen, relevant bij sabotage van beveiliging

Context is leidend:
- dezelfde rechten richting LSASS of een browser zijn alarmerender dan richting een eigen childproces
- een tool van een securityvendor kan vergelijkbare rechten vragen, signering en pad helpen ruis te verlagen

## 9.4 Elastic detection patterns voor OpenProcess
Zo koppel je handle-gebruik aan verdacht gedrag in Elastic.

Signalen om te combineren:
- open_process naar hoogwaardig doel, gevolgd door memory_allocate, memory_write, memory_protect en create_remote_thread
- open_process met PROCESS_DUP_HANDLE gevolgd door duplicate_handle en token-gerelateerde acties
- open_process naar EDR of AV proces, gevolgd door thread acties of termination pogingen

Conceptuele query-ideeën:
```
-- Cross-process injectie richting gevoelige doelen in 2 minuten
window by target.process.entity_id 2m
sequence: open_process -> memory_allocate -> memory_write -> memory_protect -> create_remote_thread
filters: target.process.name in (lsass.exe, chrome.exe, msedge.exe)
exclude: process.name in (MsMpEng.exe, Elastic*, Crowd*, Sentinel*)
```

```
-- OpenProcess naar beveiligingsprocessen
event.action:"open_process" and 
target.process.name:("MsMpEng.exe" "Elastic*" "Crowd*" "Sentinel*" "avp.exe" "bdservicehost.exe") and 
not process.code_signature.trusted:true
```

## 9.5 Token access en privilege escalation
Tokens vertegenwoordigen de identiteit en privileges van een proces of thread. Misbruik van tokens leidt tot privilege-escalatie of laterale beweging.

Relevante tokenrechten en acties, conceptueel:
- TOKEN_DUPLICATE, een token kopiëren om te impersoneren
- TOKEN_IMPERSONATE, tijdelijk handelen als een andere identiteit
- TOKEN_ASSIGN_PRIMARY, token koppelen aan een nieuw proces voor elevated uitvoering
- TOKEN_ADJUST_PRIVILEGES, privileges aan of uit zetten, bijvoorbeeld SeDebugPrivilege activeren
- OpenProcessToken en DuplicateToken(Ex), standaardpad naar tokenmisbruik

Detectie-inzichten:
- open_process naar een hoger geprivilegieerd proces, gevolgd door OpenProcessToken, DuplicateToken en CreateProcessAsUser
- aanpassingen aan privileges kort voor gevoelige acties, bijvoorbeeld debug privilege aan, daarna process access naar LSASS
- tokengebruik door processen die daar normaal niet om bekend staan, bijvoorbeeld Office-apps

Korte, conceptuele query-ideeën:
```
-- Token duplicatie gevolgd door nieuw proces met hoger recht
window by process.entity_id 5m
sequence: open_process -> open_process_token -> duplicate_token -> create_process_as_user
```

```
-- Privileges aanpassen, kort voor process access
sequence within 2m
event.action:adjust_token_privileges -> event.action:open_process
```

## 9.6 Suspicious handle duplication
DuplicateHandle kopieert een bestaande handle naar een ander proces. Dit is nuttig voor legitieme IPC, maar ook bruikbaar om beveiligingsgrenzen te omzeilen.

Verdachte patronen:
- duplicate_handle waarbij het bronproces een beveiligingsproces is en het doelproces door de actor wordt gecontroleerd
- duplicate_handle gevolgd door toegang tot een token of thread die normaal afgeschermd is
- duplicate_handle direct na open_process met PROCESS_DUP_HANDLE

Waar je op let:
- bron en doel, horen ze bij elkaar in dezelfde suite of vendor
- type object dat gedupliceerd wordt, token, process, thread
- vervolgevents, impersonatie of threadstart

## 9.7 Use cases, ransomware en credential theft
Handles spelen een grote rol in twee veelvoorkomende dreigingscategorieën.

Ransomware, indicaties:
- massaal openen van file handles met schrijf- of delete-rechten
- snelle reeksen file_write en file_rename, vaak met extensiewijziging
- open_process naar shadow copy of backup gerelateerde services om te stoppen

Credential theft, indicaties:
- open_process naar LSASS of inloggerelateerde processen, gevolgd door memory_read of dump-activiteiten
- tokenduplicatie en impersonatie om toegang te krijgen tot netwerkresources
- handleactie richting beveiligingsprocessen om monitoring te verminderen

Praktische aanpak:
- voor ransomware, detecteer handle-explosies op bestanden, combineer met pathprofielen en extensiewijzigingen
- voor credential theft, detecteer open_process en memory-acties richting LSASS, plus tokenacties

## 9.8 Mapping naar MITRE ATT&CK
Koppel handle- en tokenmisbruik aan bekende tactieken en technieken.

Relevante mappings, conceptueel:
- T1055, Process Injection, open_process, memory_write, create_remote_thread
- T1003.001, OS Credential Dumping, LSASS Memory, open_process op LSASS, geheugenlezing
- T1134, Access Token Manipulation, duplicate_token, impersonatie, assign primary token
- T1562.001, Impair Defenses, open_process en termination of patching van beveiligingsprocessen
- T1547, Boot or Logon Autostart, indirect relevant wanneer tokens worden misbruikt om persistence te plaatsen

Gebruik ATT&CK voor rapportage en rule-labeling, zorg dat je in rules duidelijk maakt welke stap in de keten je raakt.

## Samenvatting
- Een handle is een toegangskaartje met rechten naar een object, zonder handle geen actie
- Verdachte processrechten zijn onder meer VM_WRITE, VM_OPERATION, CREATE_THREAD, DUP_HANDLE en SUSPEND_RESUME, vooral richting gevoelige doelen
- OpenProcess, DuplicateHandle en tokenacties vormen samen een duidelijk beeld van injectie of privilege-escalatie
- Ransomware toont file-handle explosies, credential theft richt zich op LSASS en tokens
- Label je detecties met ATT&CK en bouw sequences die open_process, geheugenwijzigingen en thread- of tokenacties koppelen binnen een kort tijdsvenster

