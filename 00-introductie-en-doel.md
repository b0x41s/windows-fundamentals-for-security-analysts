# 00. Introductie & Doel van deze training

## 00.1 Waarom Windows begrijpen essentieel is voor analisten
Windows produceert een groot deel van de signalen die een analist beoordeelt. Elastic levert wel agents voor Linux en macOS, maar de meeste triage- en hunting-cases draaien nog steeds om Windows-systemen. Door te begrijpen hoe Windows processen start, resources beheert en acties afdwingt, herken je sneller welk gedrag afwijkt van normaal. Die basis voorkomt dat telemetrie een rij losse gebeurtenissen blijft en versnelt het scheiden van legitiem gebruik, misconfiguraties en echte aanvallen.

**Wat bedoelen we met een paar kernbegrippen?**
- Endpoint Detection and Response (EDR): software die continu activiteiten op endpoints verzamelt, analyseert en corrigeert zodat verdachte acties snel zichtbaar en beheersbaar zijn.
- Telemetrie: meetgegevens over systeem- en gebruikersactiviteiten, zoals processtarts, bestandstoegang en netwerkverbindingen.
- Proces: container met geheugen, threads en een token dat identiteit en rechten bepaalt.
- Thread: uitvoerende context van de CPU binnen een proces.
- Module: DLL of executable die code of data levert aan een proces.
- Handle: verwijzing met rechten naar een object, zoals een bestand of registry-key.
- Token: identiteit, privileges en groepstoegang die bepalen welke acties een proces of thread mag uitvoeren.

**Kern van dit hoofdstuk**
- Je weet waarom Windows-kennis cruciaal is bij triage, hunting en incident response.
- Je kunt basisbegrippen duiden zonder voorkennis te veronderstellen.
- Je begrijpt dat de rest van het document verdieping geeft, maar deze sectie slechts de aanleiding schetst.

## 00.2 Hoe Elastic Security EDR naar Windows kijkt
Elastic Security EDR volgt de levensloop van processen en koppelt gebeurtenissen in een tijdlijn. Het kijkt mee in User Mode en Kernel Mode om processtart, moduleladers, bestandstoegang, registry-acties en netwerkcommunicatie vast te leggen. Die observaties worden verrijkt met command line, parent chain, hashes en context uit detections, zodat je kunt zien welke component een actie initieerde, welke resources zijn aangeraakt en welke regel een alert veroorzaakte.

### EDR versus traditionele antivirus
- **EDR**: richt zich op volledige context. Het registreert acties over tijd, correleert gebeurtenissen en ondersteunt onderzoek en respons (isoleren, killen, blokkeren).
- **Antivirus**: focust vooral op bekende malware en signaturen. Het beoordeelt veelal afzonderlijke bestanden of acties en biedt minder inzicht in de volledige keten.

## 00.3 Hoe dit document gebruikt kan worden
Gebruik dit document als referentiegids tijdens triage of threat hunting:
- Lees hoofdstukken lineair wanneer je je fundament wilt opbouwen.
- Spring naar specifieke onderwerpen, bijvoorbeeld geheugen, services of handles, tijdens een onderzoek.
- Combineer de uitleg met live queries in Elastic zodat theorie direct aan praktijkcases hangt.
- Gebruik de diagrammen en kernpunten voor kennisdeling binnen het SOC-team.
Het materiaal is geen deep-dive reverse engineering handboek, maar een vertaling van Windows-internals naar praktische detection inzichten.

Aanpak tijdens een onderzoek, kort stappenplan:
- Begin met de procesboom, bepaal herkomst en doel.
- Check recente module- en geheugenacties, zoek volgordes.
- Beoordeel paden, signering en rechten van betrokken objecten.
- Verbind met netwerk en registry om intentie te duiden.
- Sluit uit wat legitiem is, focus op wat overblijft.

## 00.4 Belangrijkste beveiligings- en detectieconcepten
Door de hoofdstukken heen komen steeds dezelfde principes terug:
- Context staat centraal; één event is zelden voldoende. Combineer procesketen, resourcegebruik en tijdsverloop.
- Toegangspaden zijn beslissend; wie een resource mag openen bepaalt of een actie legitiem is. Let op privileges, tokens en handles.
- Geheugen en modules verraden misbruik; onverwachte RWX-pagina’s of vreemde DLL’s zijn vaak de eerste indicator.
- API’s vormen de brug; ieder verdacht patroon vertaalt uiteindelijk naar ongebruikelijke API-calls of call-sequenties.
- Detection is correlatie; Elastic gebruikt regels, ML en sequences. Begrijp hoe observaties passen in MITRE ATT&CK.

## Samenvatting
- Windows-kennis maakt EDR-telemetrie begrijpelijk en versnelt triage.
- Elastic volgt processen end-to-end en levert contextrijke gebeurtenissen.
- Gebruik dit document als naslagwerk tijdens hunting en incident response.
- Focus op context, toegang, geheugen, API-gebruik en correlatie.
