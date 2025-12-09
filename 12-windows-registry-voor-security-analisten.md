# 12. Windows Registry voor Security Analisten

## 12.1 Wat de registry is en waarom analisten ernaar kijken
De Windows Registry is een hiërarchische database met configuratie voor systeem en gebruikers. Applicaties, services en componenten lezen en schrijven hier om opstartgedrag, integratie en beveiligingsinstellingen te bepalen. Voor analisten is de registry belangrijk omdat veel persistentie en policy-wijzigingen hier zichtbaar zijn.

Waarom dit relevant is voor detection:
- persistentie, Run keys, services, COM en andere mechanismen verwijzen naar bestanden of DLL’s
- sabotage, uitschakelen of aanpassen van beveiligingsfeatures gaat vaak via policiesleutels
- context, registry-writes volgen vaak kort na file drops of voorafgaand aan processtart

Praktische kijkregel, verbind registry-writes altijd met proces, pad en signering om intentie te duiden.

## 12.2 Belangrijke hives en paden
Hives zijn de wortels van de registry. Ken de verschillen, vooral tussen machinebreed en gebruikersspecifiek.

- HKLM, HKEY_LOCAL_MACHINE, systeembreed, vereist hogere rechten
- HKCU, HKEY_CURRENT_USER, per gebruiker, makkelijker te schrijven, vaak gebruikt voor stealthy persistentie
- HKU, HKEY_USERS, alle geladen gebruikershives, HKCU is een alias naar de huidige gebruiker
- HKCR, HKEY_CLASSES_ROOT, samenvoeging van associaties uit HKLM en HKCU
- HKCC, HKEY_CURRENT_CONFIG, hardwareprofiel, minder relevant voor detection

Bestanden op schijf, context voor IR:
- HKLM hives, `C:\Windows\System32\Config\SYSTEM`, `SOFTWARE`, `SECURITY`, `SAM`
- HKCU hives, `C:\Users\<user>\NTUSER.DAT` en `AppData\Local\Microsoft\Windows\UsrClass.dat`

Paden die vaak relevant zijn voor security, conceptueel en niet uitputtend:
- Opstart en shell
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` en `RunOnce`
  - `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` en `RunOnce`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit`, `Shell`
- Services en drivers
  - `HKLM\SYSTEM\CurrentControlSet\Services\<Naam>` en `...\Parameters\ServiceDll`
- IFEO en debugpaden
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger`
  - `...\SilentProcessExit` en `GlobalFlag` varianten
- COM en shell extensies
  - `HKCR\CLSID\{GUID}\InprocServer32` en `HKCU\Software\Classes\CLSID\{GUID}\InprocServer32`
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved`
- Task Scheduler artefacten
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks` en `...\Tree`
- Defender en policies, voorzichtig beoordelen
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\*`

Let op WOW64 varianten op 64 bit, `HKLM\SOFTWARE\WOW6432Node\...` voor 32 bit processen.

## 12.3 Run keys en persistentie
Run keys starten programma’s bij login of boot. Ze zijn eenvoudig en daarom populair voor zowel legitiem gebruik als misbruik.

Kenmerken en verschillen:
- HKLM Run, systeembreed, start voor elke gebruiker, hogere rechten nodig
- HKCU Run, per gebruiker, start bij die specifieke login, geen admin nodig
- RunOnce start één keer, daarna wordt de waarde meestal verwijderd

Verdachte patronen:
- writes naar Run vanuit Office, browser of scripting hosts
- paden naar `AppData`, `Temp`, `Downloads`, netwerkshares
- ongetekende binaries of willekeurige namen, combinatie met recente file drops

Praktische triage:
- verifieer of het pad recent is aangemaakt of gewijzigd
- koppel aan het proces dat de write deed, klopt de vendor en signering
- check of na login het proces ook daadwerkelijk start en welke modules het laadt

## 12.4 Registry events in Elastic
Elastic registreert registry-activiteiten in een consistente structuur.

Veelgebruikte velden:
- event.category: registry, event.action: registry_set, registry_add, registry_delete
- registry.path, registry.key, registry.value, registry.data.strings of bytes
- process.*, parent.*, user.*, host.* voor context
- soms old en new value, afhankelijk van bron

Context om mee te nemen:
- mapping naar 32 of 64 bit pad, let op WOW64-omleiding
- tijdsverloop, registry-writes volgen vaak op file.create of gaan vooraf aan process.start

## 12.5 Detectie van malicious registry writes
Focus op sequences en combineer meerdere zwakke signalen.

Sterke combinaties:
- file.create naar gebruikerspad, gevolgd door registry_set naar Run, gevolgd door process.start bij login
- registry_set bij IFEO Debugger of SilentProcessExit, gevolgd door childprocessen met onverwachte parentage
- wijzigingen aan `Winlogon\Userinit` of `Shell`, gevolgd door afwijkend shellgedrag of extra childprocessen
- Defender of beleidskeys die functies uitzetten, gevolgd door daling in telemetry of servicewijzigingen

Ruis verminderen:
- whitelist bekende installers en updaters per vendor
- weeg signering, pad en parent zwaar mee
- corrigeer voor beheertools en RMM die legitiem registry aanpassen

Triage-checklist:
- wie schreef de key, process.name, command_line, code_signature
- wat is de waarde, pad, naamgeving, flags, komt dit vaker voor
- wat gebeurde er net ervoor en erna, file drop, service start, processtart

## 12.6 Registry artefacten in incident response
Registry helpt om tijdlijnen en persistentie te reconstrueren.

Artefacten en aandachtspunten, conceptueel:
- LastWrite times van sleutels, orden acties zonder elk event te hebben
- per-user hives, vergeet uitgelogde gebruikers niet, laad HKU hives waar nodig
- TaskCache voor geplande taken, koppeling naar `Tree` en naar bestanden op schijf
- COM en CLSID entries, InprocServer32 wijst naar de DLL, vergelijken met file hashes en signering
- Defender en policywijzigingen, verklaren waarom logging of protección afneemt

Grenzen en valkuilen:
- sommige keys worden automatisch herschreven door legitieme software, vergelijk met baseline
- timestamps kunnen beïnvloed worden door systeemacts of restore, combineer met andere bronnen

## 12.7 Practical hunting queries
Conceptuele voorbeelden, pas aan op jouw datamodel en naming.

Nieuwe Run key in gebruikerspad:
```
event.category:registry and event.action:registry_set and 
registry.path:("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*" "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*") and 
registry.data.strings:(*\\Users\\*\\AppData\\* or *\\Temp\\* or *\\Downloads\\*)
```

IFEO Debugger misbruik:
```
event.action:registry_set and 
registry.path:"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\*\\Debugger"
```

Winlogon Shell of Userinit wijziging:
```
event.action:registry_set and 
registry.path:("HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell" 
               "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Userinit") and 
not registry.data.strings:(explorer.exe*)
```

Defender policies aangepast:
```
event.action:registry_set and 
registry.path:"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\*" and 
not process.code_signature.trusted:true
```

Run write gevolgd door processtart bij login:
```
registry where event.action:registry_set and registry.path:*\\Run* 
then within 10m process where process.start and user.name != "SYSTEM"
```

## Samenvatting
- De registry is een centrale plek voor persistentie en policywijzigingen, verbind writes met proces, pad en signering
- Ken hives en veelgebruikte paden, onderscheid HKLM en HKCU en let op WOW64
- Run keys zijn eenvoudig maar veelgebruikt, verdacht zijn writes vanuit Office of browser naar gebruikerspaden
- Elastic registreert registry_set, registry_add en registry_delete, combineer met file en process voor sterke sequences
- In IR helpen hives, LastWrite en TaskCache om tijdlijnen en persistentie te reconstrueren, vergelijk altijd met baseline

