# 15. MITRE ATT&CK Mapping, van theorie naar praktijk

## 15.1 Hoe analisten Windows events koppelen aan ATT&CK
ATT&CK geeft een gemeenschappelijke taal voor tactieken en technieken. De kunst is om jouw Windows en EDR-events hier systematisch aan te koppelen.

Aanpak in vijf stappen:
- beschrijf het gedrag, in gewone taal, injectie in browser, servicecreatie, Run key write
- bepaal de tactiek, bijvoorbeeld Defense Evasion, Privilege Escalation of Persistence
- kies de techniek en subtechniek, bijvoorbeeld T1055, Process Injection, of T1547.001, Registry Run Keys
- anker de mapping aan concrete Elastic events en sequences
- documenteer dekking en uitzonderingen, wat zie je wel, wat niet, welke ruis filter je weg

Praktische richtlijn, map op het laagste niveau dat je betrouwbaar kunt onderbouwen met telemetrie, liever een subtechniek dan alleen een hoofdtechniek.

## 15.2 Memory injectie, T1055
Gedrag, een proces manipuleert geheugen in een ander proces en start daar code.

Kernsignalen in Elastic:
- open_process, richting doelproces met uitgebreide rechten
- memory_allocate en memory_write in het doel
- memory_protect, RW naar RX
- create_remote_thread of queue_user_apc in het doel

Conceptuele sequence, 2 minuten venster:
```
window by target.process.entity_id 2m
sequence: open_process -> memory_allocate -> memory_write -> memory_protect -> create_remote_thread
filters: target.process.name in (chrome.exe, msedge.exe, lsass.exe)
```

Mapping, T1055 Process Injection, precisie omhoog door subvarianten te labelen, remote thread, APC, section based.

## 15.3 Process creation anomalies, T1059 en T1036
Gedrag, scripthosts of shells met verdachte herkomst of vermomming.

Kernsignalen:
- process.start waar parent Office of browser is en child een scripthost of shell
- command_line met download, encode of invocaties die niet passen bij de rol
- masquerading, uitvoerbare naam en pad die niet kloppen met signering en metadata

Voorbeelden, conceptueel:
```
event.category:process and event.action:process_start and 
process.parent.name:(winword.exe excel.exe powerpnt.exe) and 
process.name:(powershell.exe pwsh.exe wscript.exe cscript.exe cmd.exe)
```

```
process where process.name:(powershell.exe cmd.exe rundll32.exe) and 
process.code_signature.trusted:false and file.path:(*\\Users\\* or *\\AppData\\* or *\\Temp\\*)
```

Mapping, T1059 Command and Scripting Interpreter, T1036 Masquerading.

## 15.4 DLL hijacking, T1574
Gedrag, een proces laadt een DLL met een bekende naam vanuit een onjuiste locatie door zoekvolgorde of sideloading te misbruiken.

Kernsignalen:
- dll_load van bekende namen buiten `C:\Windows\System32` of `WinSxS`
- file.create in dezelfde map kort voor de dll_load
- ongetekende module geladen in hoogwaardig proces

Query, conceptueel:
```
event.action:"dll_load" and not file.path:"C:\\Windows\\System32\\*" and 
file.path:(*\\AppData\\* or *\\Program Files\\* or *\\Temp\\*) and 
not code_signature.trusted:true
```

Mapping, T1574 Hijack Execution Flow, subtechniek 001, DLL Search Order Hijacking, of 002, DLL Side-Loading, afhankelijk van context.

## 15.5 Persistence technieken, T1547
Gedrag, configuraties die opstart of logon gedrag beïnvloeden, starten code opnieuw na reboot of login.

Veelvoorkomende paden en mapping:
- Registry Run keys, T1547.001, Run Keys, Startup Folder
- Services, T1543, Create or Modify System Process, gerelateerd aan T1547 bij autostart
- IFEO Debugger en SilentProcessExit, T1546, Event Triggered Execution
- Scheduled Tasks, T1053, Scheduled Task, gekoppeld aan persistentie via T1547

Sequence, file drop naar Run key naar process start:
```
file where event.action:file_create and file.path:(*\\Users\\* or *\\ProgramData\\*)
then within 5m registry where event.action:registry_set and registry.path:*\\Run*
then within 10m process where event.action:process_start and process.executable == registry.data.strings
```

## 15.6 Privilege escalation, T1068 en T1134
Gedrag, verhogen van rechten via exploit of door tokenmanipulatie.

Signalen voor T1134 Access Token Manipulation:
- open_process_token, duplicate_token, assign primary token, create_process_with_token
- childproces met hoger integriteitsniveau dan de parent zonder legitiem elevatiepad

Conceptuele sequence:
```
window by process.entity_id 5m
sequence: open_process_token -> duplicate_token -> create_process_with_token
```

T1068 Exploitation for Privilege Escalation is lastiger om direct te mappen zonder exploitdetails. Kijk naar bijeffecten, plotselinge elevation, nieuwe service of driverloads, gevolgd door hoog privilege gedrag.

## 15.7 Token misbruik, T1134.001
Gedrag, dupliceren of impersoneren van tokens om toegang te krijgen zonder nieuwe aanmelding.

Kernsignalen:
- open_process naar hoger geprivilegieerd proces, vaak service of LSASS
- open_process_token, duplicate_token of impersonate, gevolgd door nieuwe process.start als andere gebruiker
- privileges aanzetten, SeImpersonatePrivilege, kort voor tokenacties

Query, conceptueel:
```
window by process.entity_id 5m
sequence: open_process -> open_process_token -> duplicate_token -> create_process_as_user
```

Mapping, T1134.001 Token Impersonation, vaak samen met T1055 wanneer tokenmisbruik leidt tot injectie in hoogwaardig doel.

## 15.8 Compacte mappingtabel voor Elastic EDR
Gebruik deze lijst als startpunt voor rules en triage. Pas aan op jouw datamodel en omgeving.

| Gedrag | Elastic events, kern | ATT&CK techniek |
| --- | --- | --- |
| Remote injectie in doelproces | open_process → memory_allocate → memory_write → memory_protect → create_remote_thread | T1055 Process Injection |
| APC injectie | memory_write → queue_user_apc | T1055 Process Injection |
| Manual mapping, fileless | memory_allocate → memory_write → memory_protect, geen dll_load | T1055 Process Injection |
| Office start scripthost | process_start, parent Office, child powershell, wscript, cmd | T1059 Command Interpreter |
| Masquerading, omgedoopte binary | process_start, pad en signering mismatch | T1036 Masquerading |
| DLL sideloading | dll_load buiten System32, voorafgegaan door file_create | T1574.002 DLL Side-Loading |
| Search order hijacking | dll_load bekende naam uit applicatiemap | T1574.001 DLL Search Order Hijacking |
| Run key persistentie | registry_set naar Run, gevolgd door process_start | T1547.001 Run Keys |
| Nieuwe service persistentie | registry_set onder Services, gevolgd door process_start via services.exe | T1543 Create or Modify System Process |
| Token duplicatie en impersonatie | open_process_token → duplicate_token → create_process_with_token | T1134.001 Token Impersonation |
| UAC bypass indicatie | child High, parent Medium, geen bekend elevatiepad | T1548 Abuse Elevation Control Mechanism |
| LSASS targeting | open_process naar lsass.exe gevolgd door memory_read of dump | T1003.001 OS Credential Dumping |

Checklist bij mapping:
- dekking, welke events heb je nodig, waar komen ze vandaan, EDR, Sysmon, Windows logs
- uitzonderingen, welke legitieme processen veroorzaken hetzelfde patroon, definieer vendor en padfilters
- metrics, meet false positives en detection time, herzie mapping periodiek

## Samenvatting
- Map gedrag naar ATT&CK door tactiek, techniek en subtechniek te kiezen op basis van observeerbare events en sequences
- Voor injectie, T1055, bouw sequence rules met open_process, memory en threadacties, filter JIT en security tooling
- Voor process anomalies, T1059 en T1036, combineer parentage, pad en signering
- Voor persistentie, T1547, koppel file drops aan registry of servicewijzigingen en uiteindelijke processtart
- Voor privilege en tokens, T1134 en subtechnieken, volg tokenacties en integriteitsniveaus, label uitzonderingen expliciet

