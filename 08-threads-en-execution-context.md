# 8. Threads en Execution Context, zonder extreem low-level te worden

## 8.1 Wat een thread doet en waarom het relevant is voor detection
Een thread is de kleinste eenheid die de CPU werk laat doen. Een proces kan één of meerdere threads hebben. Threads delen hetzelfde procesgeheugen en dezelfde modules, maar hebben elk een eigen stack en instructiepointer. Voor analisten is dit belangrijk omdat veel aanvallen code willen laten uitvoeren in de context van een ander proces, en dat gaat via threads.

Wat je praktisch moet onthouden:
- een proces is de container, een thread is de uitvoering
- nieuwe functionaliteit komt via modules en geheugen, uitvoering start via threads
- injectietechnieken eindigen vaak met het starten of kapen van een thread

Signalen die opvallen in telemetrie:
- nieuwe thread in hetzelfde proces kort na geheugenwijzigingen
- thread in een ander proces met startadres in een onbekende regio
- suspends, resumes en contextwijzigingen rond kritieke processen

## 8.2 Remote thread creation als injectie
Remote thread creation betekent dat proces A een nieuwe thread start in proces B. Dit is een duidelijk injectiepatroon wanneer het gepaard gaat met geheugenmutaties in het doelproces.

Conceptuele volgorde die je vaak ziet:
1. OpenProcess op het doelproces met uitgebreide rechten
2. Memory allocate in doel, meestal RW
3. Memory write in doel, payload of pad naar DLL
4. Memory protect wijzigen naar RX
5. CreateRemoteThread in doel, start bij de payload of een loaderfunctie

Waar je op let in Elastic:
- event.action voor open_process, memory_allocate, memory_write, memory_protect, create_remote_thread
- target.process.name, gevoelige doelen zoals browser, LSASS, EDR-proces
- code_signature en pad van bron en doel, hoort dit bij elkaar
- timing, de sequentie gebeurt vaak binnen seconden

Ruisbeperking en uitzonderingen:
- ontwikkeltools, debuggers en sommige beveiligingsoplossingen kunnen legitiem vergelijkbaar gedrag tonen
- whitelisting voor bekende vendors en processen is essentieel

Snelle, conceptuele query-ideeën:
```
window by target.process.entity_id 2m
sequence: memory_allocate -> memory_write -> memory_protect -> create_remote_thread
filters: exclude process.name in (MsMpEng.exe, Elastic*, Crowd*, Sentinel*)
```

## 8.3 APC’s en thread hijacking op conceptueel niveau
APC staat voor Asynchronous Procedure Call. Het is een mechanisme om een functie te laten uitvoeren in de context van een bestaande thread. Aanvallers kunnen een APC in de wachtrij zetten voor een thread, zodat die code uitvoert wanneer de thread op een geschikt moment in een alertable state komt.

Belangrijk om te weten, conceptueel:
- QueueUserAPC voegt een oproep toe aan de wachtrij van een doelthread
- Early-bird APC, de APC wordt gepland voordat de thread volledig draait, zo valt het minder op
- Thread hijacking, in plaats van een nieuwe thread te maken, wordt een bestaande thread gestuurd of de context aangepast

Wat je in telemetrie zoekt:
- memory_allocate en memory_write in het doelproces, gevolgd door queue_user_apc of set_thread_context
- resume of alertable waits, waarna gedrag verandert, netwerk, bestand, nieuwe module
- geen klassieke create_remote_thread, maar wel dezelfde geheugenpatronen

Praktische beoordeling:
- dezelfde vragen als bij remote threads, past dit bij de rol van bron en doel
- extra gewicht voor gevoelige doelen en voor processen met veel privileges

## 8.4 TEB en PEB, wat analisten moeten weten, en wat niet
De TEB, Thread Environment Block, en de PEB, Process Environment Block, zijn datastructuren die Windows gebruikt om context over thread en proces bij te houden. Ze bevatten onder meer informatie over geladen modules, omgeving en status.

Wat je wel moet weten als analist:
- PEB bevat lijsten met modules die door de loader zijn geregistreerd
- manipulatie van de PEB kan moduleverbergtechnieken ondersteunen
- TEB bevat thread-specifieke gegevens zoals de pointer naar de PEB en de stackbasis

Wat je niet nodig hebt voor dagelijkse detection:
- offsets, velden en assemblydetails van TEB en PEB
- low-level inspectie zonder tooling levert zelden betrouwbare conclusies op

Detectie-inzicht, blijf bij observeerbare bijeffecten:
- ontbrekende dll_load events, maar functionaliteit die duidt op handmatig geladen code
- geheugenpagina’s met uitvoerrechten zonder backing file
- inconsistente module-informatie, pad en signering kloppen niet met gedrag

## 8.5 Elastic EDR indicators voor thread misbruik
Elastic EDR legt threadgerelateerd gedrag vast en koppelt dit aan procescontext. Je zoekt niet alleen het ene event, maar de samenhang.

Relevante indicatoren en velden, conceptueel:
- event.category: process of memory, met actions zoals create_remote_thread, queue_user_apc, set_thread_context
- process.name, target.process.name, en hun pad en signering
- process.entity_id en target.process.entity_id om over tijd te correleren
- memory_allocate, memory_write, memory_protect in hetzelfde doelproces
- open_process met uitgebreide rechten vlak vóór de threadactie

Triage-checklist:
- bevestig bron en doel, horen ze functioneel bij elkaar
- controleer timing, gebeurt allocate, write, protect en threadactie in kort tijdsbestek
- weeg privileges, integriteitsniveau en token van de bron mee
- sluit JIT, AV, EDR en ontwikkeltools uit op basis van signering en pad

Conceptuele query-ideeën:
```
-- Threadactie zonder bijbehorende dll_load, indicatie voor manual mapping
window by target.process.entity_id 5m
where create_remote_thread and not dll_load around @timestamp +/- 5s
```

```
-- APC-gebruik na geheugenwrites
window by target.process.entity_id 2m
sequence: memory_write -> queue_user_apc
```

## 8.6 Visualisatie, hoe een thread gestart wordt
Eenvoudige schema’s helpen tijdens triage.

Nieuwe thread in eigen proces:
```
CreateThread
   |
   v
Startadres in image code (RX)
```

Remote thread injectie:
```
OpenProcess -> Allocate(RW) -> Write -> Protect(RX) -> CreateRemoteThread
```

APC, uitvoering in bestaande thread:
```
QueueUserAPC -> Thread alertable -> Functie uitgevoerd in context van doelthread
```

## Samenvatting
- Threads voeren code uit, injecties draaien uiteindelijk via nieuwe of gekaapte threads
- Remote thread creation en APC’s zijn varianten met dezelfde bijeffecten, geheugenwrites en uitvoerrechten in het doel
- TEB en PEB bestaan, maar richt je op observeerbare bijeffecten zoals dll_load, geheugenrechten en inconsistente module-informatie
- Combineer thread-events met open_process en memory-sequenties, sluit legitieme uitzonderingen uit en geef extra gewicht aan gevoelige doelprocessen

