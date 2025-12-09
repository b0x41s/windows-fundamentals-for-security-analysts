# 6. Hoe moderne EDR’s detecteren wat Windows doet

## 6.1 Signature-based detection
Signatures koppelen herkenbare artefacten aan bekende dreigingen. Dit kan op bestandsniveau, hash of eenvoudige regelsets die specifieke bytes of strings herkennen.

Sterke punten:
- snel en effectief tegen bekende varianten
- lage compute-kosten, duidelijke beslissingen
- geschikt voor preventie aan de rand van de keten

Beperkingen:
- breekbaar bij packers, encryptie en kleine wijzigingen
- geen zicht op gedrag of intentie
- hoge kans op omzeiling bij moderne aanvallen die fileless werken

In triage, gebruik signatures als indicator, niet als eindconclusie. Combineer altijd met context uit proces, geheugen en netwerk.

## 6.2 Heuristiek en gedragspatronen
Heuristiek kijkt naar patronen die vaak voorkomen bij misbruik. Dit is geen exacte match, maar een gewogen beoordeling van gedrag.

Voorbeelden van patronen:
- parent-child mismatches, Office start PowerShell of cmd met verdachte argumenten
- pad-hygiëne, uitvoer uit gebruikersschrijfbare paden richting systeemlocaties
- geheugen, RW naar RX plus nieuwe thread in hetzelfde segment
- modulegedrag, ongetekende of ongebruikelijke DLL’s in hoogwaardige processen
- netwerk, zeldzame domeinen of onlogische timing, direct na persistence

Waarom relevant:
- heuristiek vangt nieuwe varianten met dezelfde tactiek
- door meerdere zwakke signalen te combineren krijg je een sterk signaal

## 6.3 Wat Elastic EDR doet in User Mode en Kernel Mode
Elastic EDR observeert wat processen doen door in User Mode en Kernel Mode telemetrie te verzamelen en te correleren.

Conceptueel beeld:
- User Mode, zicht op API-grenzen, processtart, command line, module loads, netwerkinitiatie
- Kernel Mode, zicht op daadwerkelijke resource-acties, bestanden, registry, handles, geheugenbescherming
- Correlatie, samenbrengen tot tijdlijnen met enrichment, signering, hashes en parent chain

Wat dit oplevert voor analisten:
- consistente event.category en event.action, bruikbaar voor queries en rules
- sequences over meerdere processen en categorieën
- beter onderscheid tussen poging en geslaagde actie

## 6.4 Hooking en hoe aanvallers dit proberen te omzeilen
Veel EDR’s gebruiken vormen van hooking of inspectie op API-grenzen om gedrag vast te leggen. Aanvallers proberen die observatiepunten te mijden of te manipuleren.

Veelvoorkomende omzeilingen, conceptueel:
- directe syscalls, om user-mode hooks heen
- ntdll patching of syscall-stomping, om inspectie te verwarren
- manual mapping, DLL laden zonder LoadLibrary
- ETW-reductie, bronnen voor telemetry uitzetten of saboteren

Relevante observaties voor detection:
- side-effects blijven zichtbaar, geheugenprotecties, nieuwe threads, handles
- inconsistenties, user-mode call ontbreekt maar kernel-actie is zichtbaar
- patchpogingen, writes naar image code van ntdll of systeem-DLL’s

## 6.5 Indicatoren van EDR-bypass technieken
Wanneer een actor de EDR probeert weg te duwen, zie je vaak sporen in het systeemgedrag.

Indicatoren om op te letten:
- process access naar EDR-processen met uitgebreide rechten, open_process en write
- nieuwe threads in EDR-processen of suspends en resumes in korte tijd
- service stops of wijzigingen aan opstarttype van beveiligingsdiensten
- ongesigneerde of verdacht gesigneerde drivers die plotseling geladen worden
- ETW of registry-aanpassingen die logging reduceren
- plotselinge daling in telemetry, stille hosts waar je normaal veel ziet

Triagevragen:
- is er een legitieme onderhoudsactie of update gaande
- wat gebeurde er vlak vóór de verstoring, bestand, netwerk of privilege-wijziging
- is de afwijking beperkt tot één host of meerdere tegelijk

## 6.6 Sandboxing en automatische analyse
Moderne platforms detoneren bestanden in een gecontroleerde omgeving en scoren gedrag automatisch.

Waar je op let als analist:
- sandboxresultaten zijn aanvullend, bevestigen of ontkrachten een eerste indruk
- sandbox-aware malware kan vertragen of zich anders gedragen
- vergelijk runtime-signalen uit de sandbox met EDR-tijdlijnen op de host, zoek overeenkomsten

Beperkingen om te onthouden:
- korte runtime en beperkte internettoegang beïnvloeden gedrag
- omgeving verschilt van productie, false negatives zijn mogelijk

## 6.7 Waarom context belangrijker is dan losse events
Een enkel event bewijst zelden intentie. Context maakt het verschil tussen legitieme automatisering en kwaadaardig misbruik.

Hoe je context opbouwt:
- volgorde, schrijf, laad, voer uit, maakt intentie zichtbaar
- rechten, wie doet het, met welk token en integriteitsniveau
- herkomst en bestemming, paden, signering, domeinen, processen
- prevalentie, komt het vaker voor in jouw omgeving of is dit uniek

Praktisch voordeel:
- vermindert ruis, verhoogt betrouwbaarheid van alerts
- versnelt triage omdat je sneller tot een onderbouwd oordeel komt

## 6.8 Detection best practices voor analisten
Richtlijnen om rule-ontwikkeling en hunting effectief te maken en ruis te beperken.

Principes:
- werk met sequences, combineer zwakke signalen in een tijdvenster
- geef extra gewicht aan cross-process acties en gevoelige doelprocessen
- maak uitzonderingen expliciet, JIT, AV, EDR en ontwikkeltools
- gebruik pad-hygiëne, signering en uitgever als snelle filters
- toets rules op echte telemetrie, replay van bekende cases en simulaties, geen PoC-code
- evalueer performance, zorg dat queries schaalbaar en onderhoudbaar zijn

Conceptuele voorbeelden, beknopt:
```
-- Injectiesequentie binnen 2 minuten in één doelproces
window by target.process.entity_id 2m
sequence: memory_allocate -> memory_write -> memory_protect -> create_remote_thread
filters: exclude process.name in (MsMpEng.exe, Elastic*, Crowd*, Sentinel*)
```

```
-- Sideloading vanuit applicatiemap met userschrijfrechten
event.action:"dll_load" and 
not file.path:"C:\\Windows\\System32\\*" and 
file.path:("*\\AppData\\*" "*\\Temp\\*" "*\\Program Files\\*" ) and 
not code_signature.trusted:true
```

Operationaliseer je detecties:
- documenteer aannames en uitzonderingen bij elke rule
- monitor false positive ratio en herzie maandelijks
- koppel rules aan playbooks zodat triage consequent verloopt

## Samenvatting
- Signatures zijn nuttig tegen bekende dreigingen, gedrag vangt varianten
- Elastic combineert User Mode en Kernel Mode signalen tot contextrijke tijdlijnen
- Aanvallers mijden observatiepunten, side-effects blijven zichtbaar in geheugen, threads, handles en padkeuzes
- Context, volgorde en rechten zijn doorslaggevend bij beoordeling
- Bouw rules als sequences, documenteer uitzonderingen en toets continu op echte telemetrie

