# 2. Windows Geheugen Begrijpen voor Threat Detection

## 2.1 Waarom geheugen een cruciaal onderdeel is van detection
Alle code die uitgevoerd wordt, leeft in geheugen. Aanvallers die detectie willen omzeilen, manipuleren vaak geheugen in plaats van alleen bestanden te droppen. Daarom zijn geheugenacties sterke signalen. Denk aan alloceren in een ander proces, payloads schrijven, of uitvoerrechten geven aan een nieuw geheugenblok. Wie begrijpt wat normaal is, herkent sneller patronen die niet kloppen.

Wat dit praktisch oplevert voor analisten:
- je ziet sneller het verschil tussen normaal laden van modules en injectie
- je herkent sequenties die niet passen bij legitieme software
- je koppelt geheugen-signalen aan proces, module en thread events
- je kunt beter onderscheiden, onschuldige JIT, beveiligingssoftware, ontwikkeltools versus echte injectie

## 2.2 Hoe Windows geheugen indeelt, simpel uitgelegd
Windows geeft elk proces een eigen virtuele adresruimte. Zie het als een kaart met pagina’s waarbinnen code en data leven. Belangrijk om te onthouden:

- Elk proces heeft een eigen kaart, isolatie is standaard
- Het systeem deelt geheugen op in pagina’s met toegangsrechten
- Reserveren, committen en vrijgeven zijn verschillende stappen

Wat dit betekent in de praktijk:
- een thread heeft een stack, groeit en krimpt, meestal RW
- een proces heeft een of meerdere heaps, RW voor dynamische data
- code van exe en DLL’s komt als image geheugen binnen, RX voor code, R voor data
- de kernel bewaakt rechten, een schrijfactie naar RX faalt tenzij rechten worden aangepast

## 2.3 Private memory, image memory, shared memory
Verschillende soorten geheugen helpen je gedrag te duiden.

- Private memory
  - Aangemaakt door het proces zelf, heap en stack
  - Voor data en tijdelijke buffers
  - Rechten veranderen hier soms legitiem, RWX blijft zeldzaam
- Image memory
  - Hoort bij een geladen exe of DLL
  - Codepagina’s zijn RX, data is R of RW
  - Schrijven naar codepagina’s wijst op patching of hooking
- Shared memory, secties
  - Deelbaar tussen processen via een section
  - Handig voor IPC en performance
  - Misbruik voor injectie zonder zichtbare WriteProcessMemory

Detectie-inzichten:
- uitvoerbare private of gedeelde pagina’s zijn verdachter dan image code
- writes naar image code duiden op inline hooking of patching
- section mapping die tegelijk in twee processen uitvoerbaar is, vraagt om extra aandacht

## 2.4 Memory permissions, R, W, X en waarom RWX verdacht is
Toegangsrechten bepalen wat er met een pagina mag gebeuren.

- R, lezen, code of data bekijken
- W, schrijven, data aanpassen
- X, uitvoeren, code laten lopen
- Combinaties, bijvoorbeeld RX of RW

Waarom RWX verdacht is:
- legitieme code heeft zelden tegelijk schrijf en uitvoerrechten nodig
- een gebruikelijk patroon voor injectie, eerst RW alloceren, data schrijven, daarna naar RX wijzigen en uitvoeren
- pagina’s die langdurig RWX blijven, zijn een sterke indicator

Let op uitzonderingen om ruis te voorkomen:
- JIT compilers, browsers, .NET runtime, soms kortstondig RW naar RX
- beveiligingssoftware en EDR-sensoren die code injecteren voor monitoring
- ontwikkeltools, debuggers, profilers

Praktische regel, focus op de sequentie, RW allocatie, write, protect naar RX, uitvoering, en doe een uitzondering voor bekende JIT processen en EDR processen.

## 2.5 Veelvoorkomende memory events die analisten zien
De exacte benamingen verschillen per product, het patroon is herkenbaar:

- allocate, reserveren of committen van nieuw geheugen, vaak met RW rechten
- protect, wijzigen van paginarechten, RW naar RX of toevoegen van X
- write, schrijven naar eigen of vreemd procesgeheugen
- free, vrijgeven van geheugen na gebruik
- map image of map section, koppelen aan een bestand of gedeelde sectie

Gerelateerde events die je erbij wil zien:
- CreateRemoteThread, starten van een thread in een ander proces
- QueueUserAPC, code plannen in een bestaande thread
- SetThreadContext of ResumeThread, contextwijziging of hervatten
- dll_load, module laden als onderdeel van een injectietechniek

Signalen die samen gewicht geven:
- write gevolgd door protect gevolgd door thread start, in enkele seconden
- write naar image code, vooral in beveiligde of systeemprocessen
- map section uitvoerbaar in bron en doel tegelijk

## 2.6 Injectiegedrag herkennen via memory changes
Veelvoorkomende patronen, in begrijpelijke volgorde.

- Classic remote thread
  1. OpenProcess op een doelproces met uitgebreide rechten
  2. Allocate in het doelproces, RW
  3. Write in het doelproces, payload of pad naar DLL
  4. Protect naar RX
  5. CreateRemoteThread, start in het nieuwe blok

- APC-based injectie
  - Zelfde geheugenstappen, uitvoering via geplande APC op een bestaande thread

- Section-based injectie, fileless
  - Gedeelde section aanmaken en mappen in bron en doel
  - Schrijven via bron, uitvoeren via doel, minder WriteProcessMemory zichtbaar

- Process hollowing, conceptueel
  - Doelproces in suspended state starten
  - Geheugen van de main image aanpassen, nieuwe image in geheugen plaatsen
  - Thread context bijwerken en hervatten

Waar je op let in Elastic-tijdlijnen:
- kruissprongen tussen processen, ongebruikelijke parent-child stromen
- RW allocatie, write, protect naar RX, gevolgd door thread start of APC
- writes naar image code of secties die horen bij systeemprocessen
- doelprocessen met hoge waarde, browser, LSASS, systeemservices, EDR proces

Praktische triagevragen:
- past het gedrag bij de rol van het bronproces
- is er voorafgaand verdacht bestand of netwerkmoment
- zijn er uitzonderingen zoals JIT, AV of EDR actief

## 2.7 Wat EDR registreert over geheugen, Elastic-specifiek
Elastic Security EDR correleert geheugenacties met procescontext. Verwacht in de praktijk de volgende informatie, afhankelijk van configuratie:

- bronproces en doelproces, PID, naam, pad, signering
- type operatie, allocatie, protect, write, map, free
- adresbereik en grootte van de regio
- oude en nieuwe bescherming, bijvoorbeeld RW naar RX
- bijkomende acties in de buurt, nieuwe thread, APC, DLL-load
- koppeling naar de parent chain en eerdere verdachtmakingen op hetzelfde proces

Korte KQL-achtige voorbeelden, conceptueel:
```
-- RW naar RX plus thread start in kort venster
event.category:process and 
event.action:("memory_protect" or "memory_allocate") and
process.name:* and 
process.pid:* 
| sort by @timestamp asc
| window by process.entity_id 5m
| where sequence has "memory_allocate" then "memory_write" then "memory_protect" then "create_remote_thread"
```

```
-- Write naar ander proces met hoge waarde
event.action:"memory_write" and 
target.process.name:("lsass.exe" "chrome.exe" "msedge.exe") and 
process.name:(-"MsMpEng.exe" -"Elastic*" -"Crowd*" -"Sentinel*")
```

Triage checklist:
- bevestig bron en doel, horen ze bij dezelfde vendor of suite
- bekijk volgorde in tijd, is er write, protect en daarna uitvoering
- controleer signering en pad van betrokken processen en modules
- corrigeer voor bekende uitzonderingen, JIT, AV, EDR, ontwikkeltools

## 2.8 Diagrammen, memory layout en suspicious patterns
Eenvoudige mentale modellen helpen tijdens triage.

Geheugenindeling in grote lijnen:
```
[ Image code RX ] [ Image data R ] [ Private RW ] [ Stack RW ] [ Heap RW ] [ Shared Section R/W ]
```

Typisch injectiepatroon, volgorde in één oogopslag:
```
OpenProcess -> Allocate(RW) -> Write -> Protect(RX) -> Start Thread/APC
```

Section-based injectie, minder zichtbare writes in doel:
```
Create Section -> Map (bron) -> Write (bron) -> Map (doel) -> Execute (doel)
```

## Samenvatting
- Geheugen is waar code leeft, geheugenacties zijn sterke signalen
- Onderscheid private, image en shared geheugen, afwijkende uitvoerrechten vallen op
- RWX is verdacht, sequentie RW naar RX plus uitvoering is doorslaggevend
- Combineer geheugen met proces, module, thread en toegangssignalen voor context
- Bouw detecties als sequences, alloceren, schrijven, beschermen, uitvoeren in kort tijdvenster, vooral richting een ander proces

