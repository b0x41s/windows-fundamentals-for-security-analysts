# 5. DLL’s en Module Loading, Gedrag dat analisten moeten herkennen

## 5.1 Wat is een DLL en waarom gebruikt Windows dit overal?
Een DLL is een bibliotheek met herbruikbare functies die door meerdere processen gebruikt kunnen worden. Windows zet zware functionaliteit in DLL’s zodat applicaties klein blijven, geheugen gedeeld kan worden en updates per component mogelijk zijn.

Belangrijke punten voor analisten:
- impliciet laden via de importtabel, de loader haalt de DLL op tijdens start
- expliciet laden via LoadLibrary, een proces vraagt zelf later een DLL op
- functionaliteit volgt de geladen modules, netwerkfuncties vragen netwerk-DLL’s, registryfuncties laden Advapi32, enzovoort

Waarom dit ertoe doet voor detection:
- elke extra DLL verandert de mogelijkheden van een proces
- afwijkende modules vertellen vaak eerder het verhaal dan losse events
- de herkomst en signering van de DLL geven een snelle risicobeoordeling

## 5.2 Normale vs. verdachte DLL patronen
Herken het normale profiel per applicatietype en vergelijk daar tegen.

Normaal gedrag:
- modules uit `C:\\Windows\\System32` of `WinSxS`, correct gesigneerd
- stabiele set van kern-DLL’s, aangevuld met applicatiespecifieke modules
- vroege loads tijdens process.start, daarna incidentele late loads voor specifieke features

Verdachte signalen:
- DLL’s uit gebruikersschrijfbare paden, `Temp`, `AppData`, applicatiemap met write-rechten, netwerkshares
- ongetekende of vreemd gesigneerde modules in hoogwaardige processen
- plotselinge laadpieken van netwerk of crypto-DLL’s in tools die daar niet om bekend staan
- snelle reeks loads vlak voor outbound verkeer of procesinjectie
- dezelfde modulenaam als een systeem-DLL, maar een ander pad

Triage-aanpak:
- controleer pad, signering en uitgever, past dit bij het hostproces
- vergelijk met het normale startprofiel in jouw omgeving
- verbind met voorafgaande file writes of recente downloads in dezelfde map

## 5.3 DLL search order en hijacking uitgelegd
Wanneer een proces een DLL-naam zonder volledig pad laadt, doorzoekt Windows in een vaste volgorde. In simpele termen:

- bekende systeem-DLL’s via KnownDLLs krijgen voorrang
- SafeDllSearchMode actief, systeemmappen (System32) wegen zwaar
- applicatiemap en huidige werkmap kunnen meedoen afhankelijk van context
- vervolgens Windows-map en mappen in `PATH`

Hoe hijacking werkt, conceptueel:
- een actor plaatst een gelijknamige DLL op een positie die eerder in de zoekvolgorde komt dan de bedoelde systeem-DLL
- de applicatie laadt de malafide DLL omdat de naam overeenkomt en het pad eerder gevonden wordt

Signalen voor detection:
- dll_load van bekende namen, maar met pad buiten `System32` of `WinSxS`
- dezelfde DLL-naam geladen uit de applicatiemap vlak na process.start
- herhaalde mislukte loads gevolgd door een load uit een ongebruikelijke map

Wat je beoordeelt:
- is het proces gevoelig voor relative path loads of ontbrekende manifests
- heeft de applicatiemap schrijf-rechten voor standaardgebruikers
- is er recent een bestand met dezelfde naam naar die map geschreven

## 5.4 Rundll32 als aanvalstechniek
Rundll32 is een legitiem Windows-programma dat een exportfunctie uit een DLL kan aanroepen. Het wordt gebruikt voor systeemtaken, maar ook misbruikt om code via een schijnbaar legitiem proces te draaien.

Legitiem vs. verdacht:
- legitiem, rundll32 met bekende systeem-DLL’s, met normale exporten, gestart door Windows-componenten
- verdacht, rundll32 die DLL’s uit `Temp` of `AppData` laadt, of onduidelijke exporten aanroept, gestart door Office of scripts

Waar je op let in Elastic:
- process.name `rundll32.exe` met pad naar DLL buiten `System32`
- command line met ongewone exportnamen of parameters die naar netwerk of scripts verwijzen
- parent-child keten, Office, browser of archiver als parent verhogen risico

Voorbeeld, conceptuele command line patronen:
```
rundll32.exe C:\\Users\\<user>\\AppData\\Local\\Temp\\x.dll,Start
rundll32.exe <pad>\\legit.dll,Control_RunDLL <verdachte-arg>
```

## 5.5 Verdachte module loads in Elastic herkennen
In Elastic zie je module-events als `dll_load`. Combineer deze met procescontext en recente bestandsactiviteiten.

Controlepunten bij `dll_load`:
- module.path, module.hash, code_signature.status en signer
- process.executable, parent, command_line en integriteitsniveau
- timing, direct na process.start of vlak voor opvallend gedrag

Handige correlaties:
- file.create of file.rename in dezelfde map kort vóór de `dll_load`
- network.outbound of dns naar een domein, gevolgd door download en `dll_load`
- memory events die wijzen op manual mapping, bijvoorbeeld uitvoerbare pagina’s zonder backing file

Conceptuele query-ideeën:
```
event.action:"dll_load" and not file.path: "C:\\\Windows\\\\System32\\\\*" 
and not code_signature.trusted: true
```

```
event.action:"dll_load" and process.name:("winword.exe" "excel.exe" "powerpnt.exe")
and file.path:("*\\\\AppData\\\\*" "*\\\\Temp\\\\*" "*\\\\Downloads\\\\*")
```

## 5.6 Misbruik van delay loading en API-resolutie
Delay loading betekent dat een DLL pas wordt geladen wanneer een functie voor het eerst wordt aangeroepen. Aanvallers kunnen dit benutten door het moment te kiezen waarop een verdacht moduleprofiel minder opvalt, of door dynamisch API’s te resolven met LoadLibrary en GetProcAddress.

Wat je ziet als analist:
- late `dll_load` van netwerk of crypto-DLL’s vlak voor data-exfiltratie
- wisselende sets modules tussen runs, omdat functies pas laat worden opgevraagd
- combinatie met string-obfuscatie en indirecte resolutie

Praktische beoordeling:
- context eerst, past de late load bij een gebruikersactie of feature
- geef extra gewicht aan late loads die voorafgegaan worden door ongewone file of registry-activiteiten
- correleer met geheugenprotectiewijzigingen en nieuwe threadstarts

## 5.7 Praktische detection tips per DLL-misbruikvorm
Samengevat per categorie, gericht op snelle triage en rule-ontwikkeling.

- Search order hijacking
  - zoeker, `dll_load` van bekende namen buiten `System32` of `WinSxS`
  - correlatie, file.create in dezelfde map net vóór de load
  - onderdrukking, bekende applicatie-extensies met legitieme private copies

- Sideloading bij applicaties
  - zoeker, `dll_load` uit applicatiemap met write-rechten voor users
  - context, parent is installer of Office, verhoogd risico
  - extra, check code_signature en uitgever mismatch met hostproces

- Rundll32-misbruik
  - zoeker, `process.name:rundll32.exe` en `dll_load` uit gebruikerspaden
  - context, parent van type Office, browser, archiver of scripting host
  - parameters, ongebruikelijke exportnamen of additionele URL/UNC-paden

- Manual mapping en fileless loads
  - zoeker, uitvoerbare geheugenpagina’s zonder bijbehorend bestandspad
  - correlatie, `memory_allocate` → `memory_write` → `memory_protect` → thread start
  - extra, `dll_load` ontbreekt terwijl functionaliteit zichtbaar verandert

- Delay loading en dynamische resolutie
  - zoeker, late load van netwerk, crypto, of procesmanipulatie-DLL’s
  - context, vlak voor exfiltratie, persistence of injectie
  - onderdrukking, JIT en bekende security tooling als uitzondering

## Samenvatting
- DLL’s bepalen welke capabilities een proces erbij krijgt, pad en signering zijn de snelste risicofilters
- Verdachte patronen, gebruikerspaden, ongetekende modules, naamconflicten en late loads voor gevoelige functionaliteit
- Begrijp de vereenvoudigde zoekvolgorde om search-order hijacking te herkennen en te prioriteren
- Rundll32 is legitiem, maar misbruik herken je aan pad, parent en ongewone exporten
- Combineer `dll_load` met file, memory en process-events om sideloading, manual mapping en delay loading te onderscheiden

