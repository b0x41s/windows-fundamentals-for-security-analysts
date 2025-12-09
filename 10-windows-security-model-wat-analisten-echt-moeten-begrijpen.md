# 10. Windows Security Model, wat analisten echt moeten begrijpen

## 10.1 Tokens, gebruikerscontext, integriteitsniveaus
Windows beslist toegang op basis van het access token van een proces of thread. Het token bevat wie je bent, in welke groepen je zit, welke privileges je hebt en op welk integriteitsniveau je draait.

Kernbegrippen in praktische taal:
- Access token, identiteit en rechtenpakket van proces of thread
- User context, welke account en groepen zijn actief, lokaal of domein
- Integriteitsniveau, Low, Medium, High, System, bepaalt wat je mag aanraken, ook binnen dezelfde gebruiker
- Impersonatie, tijdelijk handelen als iemand anders op threadniveau

Waarom dit telt voor detection:
- dezelfde executable kan zich heel anders gedragen met een ander token
- elevation en impersonatie veranderen wat een proces mag, dit zie je terug in doelkeuzes en succesratio

Triagepunten in Elastic:
- process.user.name, process.integrity_level, process.code_signature en path
- afwijkingen, child met hoger integriteitsniveau dan de parent, tokenwisseling zonder duidelijke aanleiding
- target.object access errors, access denied, gevolgd door elevation en daarna succes

## 10.2 Privileges, SeDebugPrivilege en consorten
Privileges zijn speciale bevoegdheden in een token die acties mogelijk maken buiten normale ACL’s. Voorbeelden, processen debuggen, tijd instellen, services beheren.

Belangrijke privileges voor analisten, conceptueel:
- SeDebugPrivilege, inspecteren en manipuleren van andere processen
- SeImpersonatePrivilege, impersoneren van een ander token
- SeAssignPrimaryTokenPrivilege, een token toewijzen aan een nieuw proces
- SeTcbPrivilege, handelingen in de plaats van het besturingssysteem, zeldzaam buiten systeemcomponenten
- SeLoadDriverPrivilege, drivers laden, verhoogd risico
- SeBackupPrivilege en SeRestorePrivilege, brede toegang tot bestanden, relevant bij datadiefstal

Detectie-inzichten:
- privileges die plotseling actief worden in een proces dat ze normaal niet gebruikt, verhogen risico
- privilege enabling kort voor gevoelige acties, zoals process access of tokenmanipulatie

## 10.3 UAC en elevation
User Account Control scheidt dagelijkse taken, Medium, van beheerhandelingen, High. Elevation kan met consent prompt, door een beheerder of via administratieve hulpmiddelen.

Wat je praktisch ziet:
- parent op Medium start child op High, vaak via elevatiepad, consent.exe of shell elevation
- gebruikersactie, klik, gevolgd door elevation, of stille elevation via beheertools en geplande taken

Detectiepunten:
- procesparen met verschil in integriteitsniveau, vooral wanneer de parent geen legitiem beheerpad volgt
- elevation zonder zichtbare gebruikerstrigger, bijvoorbeeld via service of geplande taak buiten change window
- mislukte access gevolgd door elevation en daarna dezelfde actie met succes

Ruisbeperking:
- bekende beheertaken en softwaredistributies normaliseren
- onderscheid maken tussen lokale admin en standaardgebruikers, impact is anders

## 10.4 Authenticatie, basis, NTLM en Kerberos
Authenticatie bepaalt wie je bent richting het systeem of netwerk.

Kernpunten voor analisten:
- NTLM, challenge response, gevoelig voor relay en capture, zie je terug als aanmeldingen met NTLM-provider
- Kerberos, tickets, TGT en service tickets, veiliger en gangbaar in domeinen
- Logon types, interactive, network, service, batch, bepalen context van processen en toegang

Waar je op let in host-telemetry en context:
- nieuwe logon sessions vlak voor verdachte acties, bijvoorbeeld network logon gevolgd door processtart onder die sessie
- aanmeldingen met onverwachte providers of op ongebruikelijke tijden
- tokenkoppelingen aan services of scheduled tasks die niet passen bij normaal beheer

## 10.5 Waarom access tokens cruciaal zijn voor detection
Tokens koppelen identiteit aan actie. Ze leggen uit waarom iets wel of niet lukt.

Detectiewaarde van tokens in de praktijk:
- succes of mislukking is vaak verklaarbaar door het token, access denied vs. granted
- impersonatie of tokenwissel duidt op poging om rechten te krijgen zonder nieuwe logon
- privileges aan of uit zetten rond kritieke acties verraden escalatie

Triageaanpak:
- bekijk bij een verdacht proces altijd user, integriteitsniveau, privileges en recente tokenacties
- correleer open_process en tokenacties met het integriteitsniveau van bron en doel
- let op ketens, netwerk logon, service start, token duplicatie, processtart met nieuw token

## 10.6 Elastic indicators voor privilege escalation
Elastic legt meerdere signalen vast die samen een escalatieverhaal vormen.

Sterke combinaties:
- adjust_token_privileges gevolgd door open_process naar een hoogwaardig doel
- open_process_token en duplicate_token gevolgd door create_process_as_user of create_process_with_token
- childproces met hoger integriteitsniveau dan de parent zonder legitiem elevatiepad
- service create of change gevolgd door child op High of System

Conceptuele query-ideeën:
```
-- Privileges aanzetten gevolgd door gevoelige process access
sequence within 2m
event.action:adjust_token_privileges -> event.action:open_process
```

```
-- Duplicated token leidt tot nieuw elevated proces
window by process.entity_id 5m
sequence: open_process_token -> duplicate_token -> create_process_with_token
```

```
-- Child op High terwijl parent Medium is, zonder bekende elevatieparent
process where process.integrity_level:High and 
not process.parent.name in (consent.exe, services.exe, taskeng.exe)
```

Ruisreductie:
- whitelist bekende beheerpaden, installers, RMM tooling, softwaredistributies
- weeg signering en pad zwaarder bij twijfelgevallen

## 10.7 Praktische aanvallen en detectiepatronen
Samengevatte scenario’s met waar je op let, zonder offensieve details.

- Token impersonatie via service of named pipe
  - signalen, open_process naar serviceproces, open_process_token, duplicate_token, create_process_as_user
  - context, child draait onder ander account dan de gebruiker, vaak met hogere rechten

- UAC bypass via misconfiguratie of living off the land
  - signalen, child op High zonder consent pad, parent niet in whitelist, gevolgd door beheeracties
  - context, paden buiten Program Files, scripts of registry-instellingen die elevation beïnvloeden

- LSASS targeting voor credentials
  - signalen, open_process richting lsass.exe, memory_read of dump, en tokengerelateerde acties
  - context, bron is niet gesigneerd door securityvendor en draait op Medium of High

- Service misbruik voor persistentie en escalatie
  - signalen, service create of config change, gevolgd door child op System, nieuwe modules en netwerk
  - context, paden in gebruikersmappen of ongesigneerde binaries als services

Triagevragen bij deze scenario’s:
- past de identiteit en het integriteitsniveau bij de actie die je ziet
- is er een legitieme beheerreden op dat moment
- welke privileges zijn actief gezet en door wie

## Samenvatting
- Het access token bepaalt wie je bent, met welke privileges en op welk integriteitsniveau je draait, dat stuurt wat mogelijk is
- Privileges zoals SeDebugPrivilege en SeImpersonatePrivilege zijn krachtige indicatoren wanneer ze vlak voor gevoelige acties actief worden
- UAC en elevation leggen uit waarom een child hoger kan draaien dan de parent, let op afwijkende elevatiepaden
- Authenticatiecontext, NTLM en Kerberos, verklaart nieuwe sessies en rechten, relevant voor ketenanalyse
- Elastic signalen voor escalatie zijn combinaties van privilegewijzigingen, tokenacties en processtarts met hoger integriteitsniveau, bouw rules als sequences en maak uitzonderingen expliciet

