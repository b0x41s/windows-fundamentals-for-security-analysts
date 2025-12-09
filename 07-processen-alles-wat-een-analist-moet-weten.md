# 7. Processen, alles wat een analist moet weten

## 7.1 Wat een proces eigenlijk is, praktisch uitgelegd
Een proces is de container waarin een programma draait. Het proces bezit een eigen adresruimte, een token met rechten, een handle-tabel naar resources, geladen modules en een of meer threads die de CPU werk laten doen. Jij beoordeelt gedrag door deze onderdelen in samenhang te bekijken.

Belangrijke eigenschappen:
- image en pad, welk uitvoerbaar bestand draait er
- command line en werkmap, hoe is het gestart en met welke parameters
- user en integriteitsniveau, onder welke identiteit en met welke macht
- code signing en hash, wie levert dit programma en is het gewijzigd
- ouderproces, welk proces heeft dit gestart en past dat bij de rol
- uptime en frequentie, eenmalige taak of terugkerende automatisering

Waarom dit telt voor detection, processen zijn het startpunt van vrijwel elke aanval, afwijkingen vallen hier het vroegst op.

## 7.2 Parent-child relaties interpreteren
De parent vertelt waar het initiatief vandaan komt. In normale ketens zie je, shell of gebruiker start app, app start helper, service start child onder dezelfde suite.

Let op deze patronen:
- Office of browser die een script of shell start, bijvoorbeeld powershell, cmd, wscript, cscript
- archiver of documentviewer die uitvoerbare bestanden start vanuit tijdelijke mappen
- service hosts die kindprocessen starten met afwijkende paden of gebruikerscontext
- installers of updaters die na afloop nog een schil achterlaten die netwerk opzet

Situaties die verwarren maar legitiem kunnen zijn:
- software met auto-update, een helper start kortstondig een installer en sluit weer
- beheeragents die via een service childprocessen draaien met verhoogde rechten
- security tooling die diagnostische subprocessen spawnt

Triagevragen:
- hoort deze parent bij de functie van het kindproces
- klopt de timing, gebeurt dit vaker op deze host of is het uniek
- is de parent gesigneerd door dezelfde vendor en uit een logisch pad

## 7.3 Process tree anomalies, Elastic visualisaties
In Elastic zie je procesbomen met tijdlijn. Het oog valt snel op outliers.

Anomalieën die je vaak ziet:
- burst, in korte tijd veel kinderen vanaf één parent, bijvoorbeeld script dat een kettingreactie veroorzaakt
- orphan of missing parent, het ouderproces ontbreekt of was zeer kortlevend, kan wijzen op maskeergedrag of snelle exit
- rolwissel, rustige applicatie start plotseling tools die niet passen, netwerk of crypto libraries
- langelevende shells of tools zonder UI die blijven hangen

Praktische checks in de boom:
- vergelijk met eerdere runs van hetzelfde programma, welke kinderen horen normaal
- klik door op code_signature en pad van parent en child, zoek mismatch
- beoordeel de volgorde, schrijf, laad, voer uit, de keten toont intentie

## 7.4 Suspicious process patterns, PowerShell, WMI, LOLBins
Sommige processen vragen standaard extra aandacht. Niet elk gebruik is kwaadaardig, context beslist.

PowerShell, signalen:
- EncodedCommand, lange Base64 parameters of verborgen download, combineer met netwerk en filestappen
- uitvoering buiten profiel, gestart door Office of vanuit gebruikerspaden met scripts
- AMSI, logs en telemetry uitschakelen, gevolgd door netwerk en childprocessen

WMI en beheer, signalen:
- wmic, powershell met WMI modules, of processen onder wmiprvse die onverwachte kinderen creëren
- remote uitvoering, childproces op systeemaccounts zonder bijpassende user activering

LOLBins, veelvoorkomende voorbeelden, beoordeel op pad, parameters en parent:
- rundll32, laadt DLL’s uit gebruikerspaden, onduidelijke exportnamen
- regsvr32, aanroepen van registratiefunctionaliteit voor niet standaard DLL’s
- mshta, uitvoeren van HTA of scripts uit ongebruikelijke locaties
- certutil of bitsadmin, gebruikt voor download of verplaatsen van bestanden
- installutil, scripthosts en andere tooling buiten hun normale beheercontext

Algemene richtlijn, één signaal is zelden genoeg, combineer parent, pad, parameters, signering en vervolgacties.

## 7.5 Hoe modules, memory en threads bij een proces horen
Een proces krijgt nieuwe mogelijkheden door modules te laden, door geheugen te wijzigen of door threads te starten. Samen vertellen ze of iets legitiem of verdacht is.

Koppelingen om te maken:
- dll_load, nieuwe capabilities, pad en signering zijn snelle filters
- memory_allocate en memory_protect, van RW naar RX, verhoogt risico, zeker met nieuwe thread
- create_remote_thread, uitvoering in een ander proces, vaak injectiepatroon

Triageaanpak:
- begin bij het proces, kijk daarna naar recente module, geheugen en thread events
- beoordeel de volgorde in seconden, alloceren, schrijven, beschermen, uitvoeren
- geef extra gewicht aan cross-process acties richting browser, LSASS of beveiligingsprocessen

## 7.6 Process events in Elastic, process.start, process.end, enzovoort
Elastic legt belangrijke levenscyclusmomenten vast. Je krijgt consistente categorieën en acties die in queries bruikbaar zijn.

Veelgebruikte velden:
- event.category en event.action, bijvoorbeeld process en process.start of process.end
- process.executable, name, args, command_line
- process.pid, process.ppid, process.entity_id voor correlatie
- user.name, user.domain, target.user bij impersonatiecases
- process.code_signature en process.hash.* voor herkomst en integriteit
- process.parent.* voor de keten
- process.integrity_level, session en logon context

Handige correlaties:
- sequence op process.entity_id om gedrag van één proces te volgen
- join op process.parent.entity_id om de keten te reconstrueren
- tijdvensters van seconden tot minuten om patronen te zien in snelle aanvallen

## 7.7 Praktische hunting queries
Conceptuele voorbeelden, pas aan op jouw datamodel en velden.

Office naar script of shell:
```
event.category:process and event.action:process_start and 
process.parent.name:(winword.exe excel.exe powerpnt.exe) and 
process.name:(powershell.exe pwsh.exe cmd.exe wscript.exe cscript.exe)
```

Ongetekend uit gebruikerspad met netwerkactiviteit kort erna:
```
process where code_signature.trusted:false and 
process.executable:(*\\\\Users\\\\*\\\\AppData\\\\* or *\\\\Temp\\\\* or *\\\\Downloads\\\\*)
then within 2m network where event.action:network_connection
```

Snel injectiepatroon richting hoogwaardig doelproces:
```
window by target.process.entity_id 2m
sequence: memory_allocate -> memory_write -> memory_protect -> create_remote_thread
filters: target.process.name in (lsass.exe, chrome.exe, msedge.exe)
```

Sideloading indicatie, module buiten systeempaden:
```
event.action:dll_load and 
not file.path:"C:\\\\Windows\\\\System32\\\\*" and 
file.path:(*\\\\AppData\\\\* or *\\\\Program Files\\\\* or *\\\\Temp\\\\*) and 
not code_signature.trusted:true
```

## Samenvatting
- Een proces is de kern van je analyse, image, parent, user, pad en signering vormen het eerste oordeel
- De procesboom in Elastic laat intentie zien, let op bursts, orphans, rolwissels en langelevende tools
- PowerShell, WMI en veelgebruikte LOLBins zijn contextgevoelig, combineer parent, pad en parameters
- Modules, geheugen en threads geven diepte, de volgorde van acties onthult injectie of sideloading
- Gebruik process.start, process.end en consistente velden voor betrouwbare correlatie en bouw hunts als sequences

