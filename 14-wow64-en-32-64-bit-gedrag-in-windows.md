# 14. WoW64 en 32/64-bit gedrag in Windows

## 14.1 Wat WoW64 is en waarom het soms verwarrend is
WoW64 is de compatibiliteitslaag die 32 bit programma’s laat draaien op een 64 bit Windows. Het zorgt ervoor dat 32 bit processen denken dat zij op een 32 bit systeem draaien, terwijl de kernel en 64 bit processen gewoon 64 bit zijn.

Belangrijke effecten voor analisten:
- Bestands-systeemredirectie, een 32 bit proces dat `C:\Windows\System32` opent, wordt omgeleid naar `C:\Windows\SysWOW64`
- Registry-redirectie, 32 bit processen zien en schrijven vaak onder `HKLM\SOFTWARE\WOW6432Node\...` in plaats van direct onder `HKLM\SOFTWARE\...`
- Dubbele binaries, er bestaan 32 en 64 bit varianten van veel systeemtools, bijvoorbeeld `rundll32.exe`, `cmd.exe`, `powershell.exe`

Waarom verwarrend, paden in events lijken op elkaar, maar verwijzen naar andere realiteit. Dit kan verkeerde aannames over herkomst, signering of capabilities geven als je niet naar de architectuur kijkt.

## 14.2 Waarom sommige processen 32 bit zijn op 64 bit systemen
Er zijn legitieme redenen waarom je 32 bit processen ziet op 64 bit hosts.

Veelvoorkomende oorzaken:
- Legacy of vendorsoftware die alleen 32 bit levert, inclusief plug-ins en extensies
- Bewuste installatie van 32 bit varianten van tools, compatibiliteit met specifieke add-ons
- Scripthosts en hulpprogramma’s hebben soms beide varianten, zowel in `System32` als `SysWOW64`

Praktische gevolgen voor triage:
- dezelfde bestandsnaam kan op twee plekken staan, met andere architectuur en soms andere signering
- 32 bit processen zien andere paden dan 64 bit processen, vooral onder `System32` en `SOFTWARE`
- modulecompatibiliteit, een 64 bit proces kan geen 32 bit DLL laden en andersom

## 14.3 Hoe EDR hiermee omgaat
EDR’s normaliseren velden zodat je verschillen kunt zien zonder alle details te onthouden.

Handige velden, conceptueel geformuleerd:
- process.pe.architecture of process.architecture, bijvoorbeeld amd64 of x86
- file.path, plus hints of de sensor redirectie detecteert, SysWOW64, System32 of Sysnative
- registry.path met of zonder `WOW6432Node`, plus context van het schrijvende proces
- module.architecture, om 32 of 64 bit libraries te onderscheiden

Triageaanpak in Elastic:
- controleer altijd de architectuur van bron en doel, vooral bij cross-process acties
- let op `SysWOW64`, `System32`, `Sysnative` en `WOW6432Node` in paden
- verwacht geen `dll_load` van 32 bit DLL in een 64 bit proces, inconsistenties wijzen op manual mapping of toolingfouten

## 14.4 Verdachte cross-architecture patronen
Aanvallers kunnen architectuurverschillen gebruiken om detectie te ontwijken of om naar gevoelige doelen te schrijven.

Patronen om te onderzoeken:
- 32 bit proces dat `open_process` en `memory_write` uitvoert richting 64 bit doelproces, legitiem zeldzaam
- Gebruik van `C:\Windows\Sysnative\...` door 32 bit processen om redirectie te omzeilen en echte `System32` te bereiken
- 32 bit `rundll32.exe` laadt een ongetekende 32 bit DLL uit `AppData` of `Temp` vlak voor netwerk of childprocessen
- Registry-writes onder `HKLM\SOFTWARE\WOW6432Node\...\Run` gecombineerd met file drops in gebruikerspaden
- Onverwachte padmismatch, een proces in `SysWOW64` dat modules laadt uit locaties die bij 64 bit horen

Contextvragen bij deze patronen:
- past het bij de rol van het bronproces en de vendor
- zijn er kort ervoor file.create of download events die de write verklaren
- zie je dezelfde activiteit ook in 64 bit varianten, of is dit een bewuste omzeiling

## 14.5 Indicatoren voor evasive behavior
Architectuurkeuzes en paden geven vaak weg dat een actor iets probeert te vermijden.

Indicatoren:
- expliciete `Sysnative` paden in command lines van 32 bit processen
- registry-writes specifiek onder `WOW6432Node` terwijl er ook 64 bit varianten aanwezig zijn
- herhaalde mislukte loads of toegang, gevolgd door een switch naar andere architectuur of pad
- gebruik van 32 bit scripthosts terwijl de 64 bit variant standaard is geïnstalleerd
- gelijknamige binaries in `SysWOW64` en `System32` waarvan alleen de 32 bit variant wordt aangesproken

Conceptuele query-ideeën:
```
-- 32 bit proces dat 64 bit doelproces aanvalt
event.action:open_process and process.pe.architecture:x86 and target.process.pe.architecture:amd64
```

```
-- Sysnative toegang door 32 bit proces
process.command_line:*Sysnative* and process.pe.architecture:x86
```

```
-- WOW6432Node persistentie vanuit gebruikerscontext
event.category:registry and event.action:registry_set and 
registry.path:*HKLM\\SOFTWARE\\WOW6432Node\\*\\Run* and 
process.user.name:* and not process.code_signature.trusted:true
```

Praktische ruisbeperking:
- whitelist bekende 32 bit applicaties in jouw omgeving die legitiem Sysnative of WOW6432Node gebruiken
- let op signering en vendorconsistentie, 32 of 64 bit van dezelfde suite hoort bij elkaar
- corrigeer voor installaties, updaters en softwaredistributies

## Samenvatting
- WoW64 laat 32 bit processen draaien op 64 bit Windows, met bestands- en registry-redirectie
- Kijk altijd naar architectuur, paden en `WOW6432Node` om verwarring te voorkomen
- EDR toont architectuur en padcontext, inconsistenties tussen 32 en 64 bit gedrag geven sterke signalen
- Verdacht zijn 32 naar 64 bit injecties, Sysnative gebruik door 32 bit processen, en Run keys onder WOW6432Node met gebruikerspaden
- Beperk ruis met whitelists voor bekende 32 bit software en let op vendorconsistentie en signering

