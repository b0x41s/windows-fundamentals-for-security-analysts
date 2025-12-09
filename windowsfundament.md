# **HOOFDSTUK 1 — Hoe Windows Werkt (Eenvoudige Intro voor Security Analisten)**

### *Voor mensen zonder Windows-internals achtergrond*

---

## 1.1 Waarom moet een analist Windows begrijpen?

Als je werkt met Elastic Security EDR, zie je dagelijks meldingen zoals:

* “Process created”
* “Thread created”
* “DLL loaded”
* “Memory modified”
* “Registry key changed”

Maar om te snappen **wat er echt gebeurt**, moet je een basisbeeld hebben van:

* hoe Windows programma’s draait
* hoe processen worden opgebouwd
* wat het verschil is tussen User Mode en Kernel Mode
* hoe applicaties acties uitvoeren (bestanden openen, netwerk, registry etc.)

Zonder dit fundament voelt EDR-telemetrie snel abstract.

---

## 1.2 Wat gebeurt er eigenlijk als je een programma opent?

Dit is de meest toegankelijke manier om naar Windows te kijken.

Wanneer je bijvoorbeeld *Chrome*, *PowerShell* of zelfs *malware.exe* opent, gebeurt het volgende:

1. **Windows start een nieuw proces**

   * Een proces is een “container” waarin een programma draait.
   * Het bevat: geheugen, modules (DLL’s), settings, threads.

2. **Windows maakt één of meerdere threads aan**

   * Een thread is waar de CPU echt werk uitvoert.
   * Een proces kan één of honderden threads hebben.

3. **Windows laadt modules (DLL’s) die het programma nodig heeft**
   Bijvoorbeeld:

   * Kernel32.dll → basis systeemfuncties
   * User32.dll → vensters en toetsenbord/muis
   * Advapi32.dll → registry, services
   * Ntdll.dll → laagste laag voor systeem-interacties

4. **Het programma start met uitvoeren van code**

   * Meestal via de entry point van het programma.

Voor een analist is vooral belangrijk:

➡ **Elk proces heeft een levenscyclus die te volgen is: start → modules laden → acties → eindigen.**
➡ **EDR ziet vrijwel elke stap hiervan en genereert telemetrie.**

---

## 1.3 De twee belangrijkste “werelden” in Windows

Windows werkt in twee beveiligingsniveaus:

### **User Mode**

* Hier draaien normale programma’s.
* Programma’s kunnen **niet direct** met hardware of kernel communiceren.
* Ze moeten alles via systeemfuncties doen.

Denk aan Chrome, Outlook, cmd.exe, malware, PowerShell, etc.

### **Kernel Mode**

* Hier draait de core van Windows: drivers, scheduler, memory manager.
* Kernel heeft volledige controle over het systeem.
* Alleen de kernel mag direct met hardware praten.

### Waarom dit belangrijk is voor analisten?

Veel alerts gaan over gedrag in **User Mode**, maar de impact hangt af van wat er **in de kernel gebeurt**.

**Bijvoorbeeld:**
Een programma roept “CreateFile” aan → Kernel opent een bestand → Elastic EDR ziet dat → analist beoordeelt het.

---

## 1.4 Hoe een programma een actie uitvoert (in begrijpelijke taal)

Stel dat PowerShell een bestand wil openen.

De volgorde is:

1. **PowerShell vraagt het aan Windows**
   via een bekende functie zoals `CreateFile`.

2. **Windows controleert of dit mag**
   permissies, policies, security rules.

3. **De kernel voert de actie uit**
   bestanden openen, netwerk, registry, geheugen.

4. **EDR registreert wat er is gebeurd**
   en stuurt telemetrie naar Elastic.

### Wat jij als analist hiervan moet onthouden:

✔ De kernel voert uiteindelijk de actie uit
✔ Maar de EDR ziet het **vóór en na** de kernel
✔ Daarom zie je in Elastic vaak:

* process event
* file event
* registry event
* dll load
* network event
* memory event

---

## 1.5 Waarom Windows zoveel DLL’s gebruikt

DLL’s zijn gedeelde onderdelen van Windows die programma’s nodig hebben.
Bijvoorbeeld:

* Kernel32.dll → basisfuncties
* Advapi32.dll → registry, services
* User32.dll → vensterbeheer
* Ws2_32.dll → netwerk
* Ntdll.dll → laagste systeemlaag

**Belangrijk voor analisten:**

Wanneer Elastic een melding toont als:

> “Unusual DLL loaded”
> “Unsigned DLL loaded in a system process”

Dan betekent dat:

⚠ Een programma gebruikt functionaliteit die niet standaard is
⚠ Mogelijk probeert malware functies te gebruiken die normaal niet bij dat proces horen

DLL-load events zijn dan ook essentieel bij threat hunting.

---

## 1.6 Hoe programma’s communiceren met Windows

Heel simpel:

**Programma → Windows-functie → Kernel → Resultaat → EDR Telemetry**

Je hoeft niet te weten hoe machine-instructies werken.
Je moet alleen begrijpen dat:

* Programma’s doen niks “magisch”
* Alles moet via Windows lopen
* Alles wat via Windows loopt, genereert telemetrie
* Elastic kijkt naar “wat het programma probeert te doen”

Dit is de basis van detection engineering.

---

## 1.7 Diagram — De eenvoudige weergave voor beginnende analisten

```
Programma (User Mode)
       |
       | Windows functies (DLL's)
       v
Windows Kernel (beveiligt en voert uit)
       |
       | Telemetrie over acties
       v
Elastic Security (EDR)
       |
       v
Analist beoordeelt gedrag
```

---

## 1.8 Wat je van dit hoofdstuk moet onthouden

Dit is de **samenvatting voor analisten**:

* Een proces = een programma dat draait, met geheugen + modules.
* Een thread = het onderdeel dat de CPU echt gebruikt.
* Programma’s draaien in User Mode → veilig afgescheiden.
* De kernel voert alle systeemacties uit.
* EDR’s zien gedrag door te monitoren wat een proces probeert te doen.
* Als je weet *hoe* Windows werkt, begrijp je waarom een actie verdacht is.
---

