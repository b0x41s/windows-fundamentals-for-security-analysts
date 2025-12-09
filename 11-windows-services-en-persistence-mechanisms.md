# 11. Windows Services en Persistence Mechanisms

## 11.1 Hoe Windows services werken
Services zijn programma’s die zonder interactie van een ingelogde gebruiker draaien. Ze worden beheerd door de Service Control Manager, SCM, die zelf als `services.exe` draait. Configuratie staat primair in de registry onder `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceNaam>`.

Praktische elementen:
- Service account, LocalSystem, LocalService, NetworkService of een specifiek account
- Starttype, Automatic, Automatic Delayed Start, Manual, Disabled
- ImagePath of ServiceDll, het uitvoerbare pad dat bij start wordt geladen
- Service type, eigen proces of gedeeld hostproces, bijvoorbeeld svchost-groep met ServiceDll

Lifecycle in vogelvlucht:
- aanmaken of configureren, schrijfacties in `...\Services\<naam>` en eventueel aanvullende sleutels
- starten, SCM lanceert de binary of svchost laadt de ServiceDll
- draaien, het serviceproces verwerkt taken en kan childprocessen starten
- stoppen of verwijderen, SCM past status aan of verwijdert configuratie

Wat je in telemetrie ziet:
- registry writes bij aanmaken of wijzigen
- process.start vanuit `services.exe` of `svchost.exe` richting de service-binary
- file events rondom de service-binary of bijbehorende DLL

## 11.2 Normale vs. verdachte service-creatie
Legitieme creatie heeft een herkenbaar profiel. Verdachte creatie wijkt daarvan af op pad, signering, account of timing.

Normaal profiel:
- uitgevoerd door installer of updater, parent met bekende vendor en geldige signering
- binaries in `C:\Program Files\` of `C:\Windows\System32\`, correct gesigneerd
- duidelijke servicenaam en beschrijving die past bij het product
- starttype passend bij de functie, vaak Automatic of Manual

Verdachte signalen:
- aangemaakt door Office, archivers of scripting hosts onder gebruikerscontext
- ImagePath in gebruikersschrijfbare paden, `AppData`, `Temp`, gedeelde schijven
- ongetekend of signer mismatch met de parent of productfamilie
- willekeurige servicenaam, vage beschrijving, opvallend korte of verborgen paden
- snelle creatie gevolgd door netwerk outbound of procesinjectie

Triage-aanpak:
- controleer parent, pad en signering, past dit bij legitieme installatie
- vergelijk met installatie-logs of software-inventaris
- verbind met voorafgaande file.create in dezelfde map

## 11.3 Services als persistentie via registry
Services bieden hardnekkige persistentie omdat ze bij boot of login starten.

Belangrijke registry-punten:
- `HKLM\SYSTEM\CurrentControlSet\Services\<naam>\ImagePath`, wijst naar exe voor services in een eigen proces
- `HKLM\SYSTEM\CurrentControlSet\Services\<naam>\Parameters\ServiceDll`, voor services gehost door `svchost.exe`
- `Start` waarde, 2 is automatisch, 3 is manueel, wijziging naar 2 verhoogt persistentie
- svchost-groepen, `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost`, bepalen welke services in welke hostgroep laden

Detectie-inzichten:
- nieuwe keys of waarden onder `...\Services\*` die naar gebruikerspaden of ongebruikelijke locaties wijzen
- wijzigingen aan `ImagePath`, `ServiceDll` of `Start` bij bestaande services
- laten weggeschreven binaries kort vóór registry-wijzigingen, zelfde map en naamcluster

## 11.4 Elastic detection patterns voor nieuwe services
Koppel proces-, registry- en file-events om servicecreatie en misbruik te herkennen.

Signalen en correlaties:
- process.start van `sc.exe`, `powershell.exe` met `New-Service`, `reg.exe`, `schtasks.exe` is geen service maar relevant in dezelfde keten
- registry.set bij `HKLM\SYSTEM\CurrentControlSet\Services\*` met `ImagePath`, `ServiceDll`, `Start`
- file.create of file.rename in dezelfde map als de nieuwe `ImagePath` kort voorafgaand aan de registry-set
- service start direct erna, zichtbaar als child van `services.exe` of `svchost.exe`

Conceptuele query-ideeën:
```
-- Nieuwe service-indicatoren via registry en proces
registry where registry.path:"HKLM\\SYSTEM\\CurrentControlSet\\Services\\*" and 
registry.value:(ImagePath or ServiceDll or Start)
then within 2m process where process.parent.name:services.exe
```

```
-- sc.exe / powershell New-Service met verdachte paden
process where process.name in (sc.exe, powershell.exe) and 
process.command_line:(*New-Service* or *create* or *config*) and 
process.command_line:(*\\AppData\\* or *\\Temp\\* or *\\Users\\*)
```

```
-- Binary drop gevolgd door service-wijziging
file where event.action:file_create and file.path:(*\\ProgramData\\* or *\\Users\\* or *\\Temp\\*)
then within 2m registry where registry.path:"HKLM\\SYSTEM\\CurrentControlSet\\Services\\*"
```

Ruisreductie:
- whitelist bekende installers en RMM-tools
- weeg signering en pad zwaarder, en let op vendorconsistentie

## 11.5 Misconfiguraties die aanvallers misbruiken
Misconfiguraties maken escalation of persistente executie makkelijker zonder complexe technieken.

Veelvoorkomende issues:
- onquoted service paths met spaties, kan leiden tot onverwachte padresolutie
- zwakke NTFS-permissies op service-mappen of binaries, standaardgebruikers kunnen schrijven
- zwakke registry-permissies op service-keys, niet-beheerders kunnen configuratie aanpassen
- service draait als LocalSystem terwijl de binary in gebruikersschrijfbare paden staat
- dll hijacking binnen service-startpaden of bij ServiceDll

Detectie- en triage-ideeën:
- file.write of file.rename naar service-binaries of -mappen gevolgd door service-restart
- registry.set op `ImagePath`, `ServiceDll` of `Start` voor bestaande services
- childprocessen van `services.exe` met ongewone paden of ongesigneerde binaries

Beperking ruis:
- vergelijk pad en eigenaar van de binary, `Program Files` hoort bij admin-installaties, `AppData` niet
- controleer of wijzigingen samengaan met legitieme updatecycli

## 11.6 Diagram, service lifecycle
Een vereenvoudigd overzicht.

```
Create/Config (installer, sc.exe, New-Service)
   |
   |  registry: HKLM\...\Services\<naam> (ImagePath/ServiceDll/Start)
   v
Binary op schijf (exe of DLL)
   |
   |  start via services.exe (of svchost.exe + ServiceDll)
   v
Running (proces, modules, threads)
   |
   |  stop/update/delete (registry + file)
   v
Elastic EDR: registry, process, file, dll_load
```

## Samenvatting
- Services draaien zonder userinteractie en starten via de Service Control Manager, configuratie staat onder `HKLM\\...\\Services`
- Verdachte creatie herken je aan parent, pad, signering en timing, vooral gebruikerspaden en ongetekende binaries
- Persistentie gaat via `ImagePath`, `ServiceDll` en `Start`, combineer registry, file en process-events
- Misconfiguraties zoals onquoted paths en zwakke permissies maken misbruik makkelijker, let op binary-writes gevolgd door service-restarts
- Gebruik sequences in Elastic om binary-drop, registry-wijziging en service-start te correleren en ruis te beperken

