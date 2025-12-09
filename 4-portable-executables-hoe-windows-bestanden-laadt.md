# 4. Portable Executables, Hoe Windows bestanden laadt

## 4.1 Hoe Windows programma’s en DLL’s in geheugen plaatst
Wanneer je een exe of dll start of laadt, gebruikt Windows de PE-indeling, Portable Executable. De loader leest het bestand, maakt een geheugenbeeld van wat er op schijf staat en bereidt alles voor op uitvoering.

In grote lijnen gebeurt dit:
- bestand openen, de image wordt gemapt in geheugen
- secties worden op hun bedoelde adressen en rechten geplaatst, .text RX, .rdata R, .data RW
- relocaties toepassen als het niet op het voorkeursadres kan laden
- imports resolven, noodzakelijke DLL’s laden en functieadressen opzoeken
- TLS-initialisatie, indien aanwezig
- entry point aanroepen, voor exe de start van het programma, voor DLL DllMain bij process attach

Wat je in Elastic terugziet:
- dll_load events voor elke module die wordt geladen
- process.start voor het hoofdproces, gevolgd door image loads
- file events als het bestand vanaf schijf of netwerk wordt benaderd
- memory events die de uiteindelijke rechten laten zien, code is RX, data is R of RW

Waarom dit helpt bij triage:
- het normale laadprofiel van een proces is vrij stabiel
- afwijkingen, bijvoorbeeld een module uit een gebruikersmap, vallen op
- timing na start, snelle reeks van ongewone loads kan op sideloading wijzen

## 4.2 Wat elke analist moet weten over PE’s, zonder reverse engineering
Je hoeft een PE niet te dissassembleren. Enkele velden en concepten zijn genoeg om risico te duiden.

Waar je op let:
- architectuur, 32 of 64 bit, moet aansluiten op het proces en het platform
- subsysteem, console of GUI, context voor waar je het verwacht
- secties, .text, .rdata, .data, .rsrc, afwijkende namen kunnen iets zeggen over packers
- digitale handtekening, aanwezig en geldig, wie is de uitgever
- bestandsmetadata, CompanyName, ProductName, FileDescription, versies
- compile-tijdstempel, indicatief maar niet beslissend, kan gespoofd zijn
- pad en herkomst, system32, program files, gebruikersmap, netwerkpad

Praktische conclusies:
- een gesigneerde binary op een verwachte locatie met normaal sectieprofiel is meestal laag risico
- een ongesigneerde binary in een gebruikersmap met afwijkende secties verdient prioriteit

## 4.3 Imports, exports en waarom dit zichtbaar is in EDR-data
Imports vertellen welke functies een programma denkt nodig te hebben. Exports vertellen welke functies een DLL aan anderen aanbiedt.

Detectie-inzichten:
- zeer kleine importtabellen gecombineerd met dynamische resolutie, GetProcAddress, passen bij packers of evasive code
- imports voor netwerk of procesmanipulatie in processen die daar niet om bekend staan, onderzoeken
- exports met generieke namen in onverwachte DLL’s, bijvoorbeeld DllRegisterServer buiten COM-registratiecontext

In Elastic context:
- module naam en pad zijn altijd zichtbaar
- verrijkte artefacten, indien beschikbaar, kunnen imphash of importkenmerken tonen via integraties
- combineer module-informatie met gedrag, geheugen en netwerk om intentie te duiden

## 4.4 Verdachte PE-kenmerken, high entropy, rare sections
Bepaalde bestandskenmerken komen vaker voor bij gemaskeerde of ingepakte binaries.

Let op de combinatie van:
- hoge entropie in .text of ongewone secties, wijst op compressie of encryptie
- zeldzame sectienamen, .upx, .petite, .packed, of onlogische custom namen
- grote of misplaatste .rsrc met uitvoerbare inhoud
- RWX secties, schrijf en uitvoer tegelijk, zeldzaam bij legitieme software
- overlay data, bytes na het formele einde van de image
- afwijkende of ontbrekende digitale handtekening

Triage-aanpak:
- label als verdacht bij meerdere signalen tegelijk, niet op één kenmerk
- bekijk direct na start of er geheugenprotecties wijzigen, RW naar RX
- koppel aan netwerk of persistence acties om impact te schatten

## 4.5 DLL load events interpreteren
Een dll_load is een belangrijk moment, een proces breidt zijn mogelijkheden uit. Niet elke load is gelijkwaardig.

Waar je op let:
- pad, system32 en WinSxS zijn normaal, gebruikersmappen, tijdelijke paden en netwerkshares zijn risicovoller
- signering van de DLL en of die past bij het hostproces
- procesrol, laadt het proces modules die niet bij zijn taak passen, bijvoorbeeld crypto of netwerk in een offline tool
- duplicatie, dezelfde modulenaam maar andere schijfpadlocatie dan verwacht

Context en volgorde:
- vlak na process.start, een reeks niet-standaard loads uit de applicatiemap kan op sideloading wijzen
- late load van een ongebruikelijke DLL vlak voor netwerk of procesinjectie verhoogt het risico

Opmerking, de zoekvolgorde en hijackingmechanismen komen in het volgende hoofdstuk dieper aan bod, hier volstaat het om pad en signering kritisch te beoordelen.

## 4.6 Waarom packed executables verdacht zijn
Packers verpakken code om grootte te verkleinen of detectie te bemoeilijken. Gevolg, op schijf zie je weinig, in geheugen verschijnt de echte code.

Typische kenmerken:
- hoge entropie en kleine of lege importtabellen
- vroeg in de uitvoering, geheugen-allocaties, writes en protect-wijzigingen
- dynamische importresolutie, functies pas zoeken vlak voor gebruik

Waarom dit verdacht is voor detection:
- het verstoort file-based analyse en verbergt capabilities
- het dwingt je om op runtime-gedrag te letten, precies waar EDR goed in is

Praktische check:
- zie je direct na start, memory_allocate, memory_write en memory_protect, dan is unpacking aannemelijk
- combineer met ongesigneerde status en gebruikersmap, om prioriteit te bepalen

## 4.7 Hoe de loader werkt in relatie tot detection
De loader creëert een herkenbare eventstroom. Door die te kennen, zie je afwijkingen sneller.

Normaal patroon bij processtart:
```
file open exe
process.start
dll_load: ntdll, kernel32, user32/advapi32/ws2_32 afhankelijk van rol
dll_load: applicatiespecifieke modules
```

Signalen die opvallen:
- dll_load uit applicatiemap of gebruikersmap met dezelfde naam als een systeem-DLL
- image load van ongetekende modules in hoogwaardig proces
- plotselinge load van netwerk- of crypto-DLL’s gevolgd door uitgaand verkeer

Normaal patroon bij DLL-laden:
```
file open dll
map image, secties op RX/R/RW
resolve imports, mogelijk extra dll_loads
call DllMain, process attach
```

Detectie-aanwijzingen:
- extra dll_loads als gevolg van imports, let op de herkomstpaden
- mislukte loads of herhaalde probeerpaden, kan op hijackingpogingen of misconfig duiden

## 4.8 Diagrammen, PE simplified
Vereenvoudigd beeld van laden en observatiepunten.

```
Schijf (EXE/DLL)
   |
   |  open + map
   v
Geheugen (secties: .text RX, .rdata R, .data RW)
   |
   |  resolve imports -> extra dll_loads
   v
Entry point / DllMain
   |
   |  runtime gedrag -> geheugen, netwerk, bestanden
   v
Elastic EDR events (process, dll_load, file, memory, network)
```

Kleine checklist voor triage:
- klopt pad en signering van elke nieuw geladen module
- passen de geladen capabilities bij de rol van het proces
- zijn er runtime geheugenwijzigingen die unpacking of injectie suggereren

## Samenvatting
- PE-bestanden worden in geheugen gemapt met secties en rechten, de loader lost imports op en roept de entry aan
- Let op path hygiene, signering en timing van dll_loads om sideloading of hijacking te herkennen
- Verdachte PE-kenmerken, hoge entropie, zeldzame secties, RWX, overlay data, vragen om extra onderzoek
- Packed executables verplaatsen het probleem naar runtime, zoek naar alloceren, schrijven en protect-wijzigingen direct na start
- Koppel module-informatie aan proces, geheugen, bestand en netwerk om intentie te duiden

