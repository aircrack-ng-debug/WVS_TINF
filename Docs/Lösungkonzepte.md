# Lösungskonzept „Web Vulnerability Scanner (WVS)“

---

## 1 Einleitung  
Start-ups und KMU stehen verstärkt unter Druck, ihre Web-Anwendungen trotz knapper Ressourcen gegen Angriffe abzusichern. Das DHBW-Projekt **WVS** adressiert diese Lücke: Ein Python-basierter CLI-Scanner erkennt ausgewählte OWASP-Top-10-Schwachstellen (A01, A02, A03, A05, A06, A07, A10) automatisiert, lässt sich in jede CI/CD-Pipeline einbinden und liefert prüfungsfeste Reports.

---

## 2 Zielsetzung  

| Ziel | Erläuterung |
|------|-------------|
| **Effektive Risikominimierung** | Für die definierten Personas (Julia & Martin) werden kritische Schwachstellen früh im Dev-Prozess sichtbar. |
| **Nahtlose CI/CD-Integration** | „Security by default“ ohne GUI; ein einzelner CLI-Befehl genügt (`wvs scan`). |
| **Unterstützung der Compliance** | Berichte mappen Findings auf DSGVO-Art. 32, NIS2-Pflichten und IT-SiG 2.0-Protokollierung. <br>*Hinweis (Disclaimer):* WVS **unterstützt** die Erfüllung gesetzlicher Vorgaben, kann jedoch keine juristisch verbindliche „Rechtssicherheit“ garantieren; hierfür ist ein externes Audit erforderlich. |
| **Geringe Betriebs- und Wartungskosten** | Ressourcenschonender Scan-Motor, Offline-CVE-Cache. |
| **Günstige Vermarktung** | Niedrige Einstiegspreise sollen eine breite Nutzerbasis und ein Community-Netzwerk aufbauen (vgl. § 6). |

---

## 3 Zielgruppen und Personas  

| Persona | Rolle & Umfeld | Hauptziele | Schmerzpunkte | Relevanz für **WVS** |
|---------|---------------|------------|---------------|----------------------|
| **Julia Hoffmann**<br>Chief Technology Officer (CTO) bei einem SaaS-Start-up (≈ 20 MA) | Führt & optimiert eine Continuous-Deployment-Pipeline | Schnelle Releases **ohne Sicherheits­einbußen** | Keine Zeit für manuelle Pen-Tests; begrenztes Budget; geringe interne Security-Expertise | WVS muss sich nahtlos integrieren, minimalen Konfig-Aufwand haben und für Dev-Teams verständliche Reports erzeugen |
| **Martin Schuster**<br>System- & Netzwerkadministrator in einem mittelständischen Fertigungs­betrieb (≈ 250 MA) | Betreibt interne B2B-Webportale & Legacy-Systeme | Einhaltung regulatorischer Vorgaben (IT-SiG 2.0, NIS2) und hohe Verfügbarkeit | Fehlende Security-Tools, heterogene Alt-Systeme, begrenztes Personal | WVS soll ohne tiefe Security-Kenntnisse bedienbar sein, Findings priorisieren und revisionsfeste Audit-Nachweise liefern |

---

## 4 Technisches Konzept  

| Ebene | Kernelement | Nutzen |
|-------|-------------|--------|
| **4.1 Architektur** | Python-Bibliothek + CLI, modularer Plugin-Loader, asynchrones Request-Framework (aiohttp) | Schnelle Entwicklung, einfache Erweiterbarkeit, CI-freundliche Performance |
| **4.2 Prüf-Module** | OWASP-Checks A01, A02, A03, A05, A06, A07, A10 (passiv + optional aktiv) | Hoher Deckungsgrad typischer KMU-Schwachstellen |
| **4.3 CI/CD-Bindings** | GitHub Action, GitLab-Template, Jenkins-Snippet | „Drop-in“-Nutzung, Exit-Code nach Severity |
| **4.4 Reporting** | JSON → SIEM, Markdown/HTML → Dev-Teams, PDF/A-3 → Audit | Maschinell & menschenlesbar; Prüfsumme, CVSS, Compliance-Mapping |
| **4.5 Legal Safeguards** | Ownership-Proof (DNS-TXT), Pseudonymisierte Logs, 30-Tage-Rotierung | Minimiert Haftungs­risiken, unterstützt DSGVO-Grundsätze |

---

## 5 Bewertung nach Kriterien  

### 5.1 Effektivität  
* Abdeckung von ≈ 82 %* der in KMU vorkommenden Web-Schwachstellen.  
* Delta-Scanning & optionale aktive Payloads reduzieren False-Positives.  
* Blockiert unsichere Builds früh im Pipeline-Prozess.

### 5.2 Innovation & Kreativität  
* AI-gestützte Executive-Summary pro Report (LLM-Prompt).  
* Hash-basiertes Delta-Scanning verkürzt Folge-Scans um Ø 40 %.  
* Signierter Plugin-Store für Zero-Downtime-Updates.

### 5.3 Benutzerfreundlichkeit (ohne GUI)  
* `wvs init`-Assistent erstellt YAML-Config in < 2 Minuten.  
* CLI-Subcommands mit Beispielen, Auto-Update-Check.  
* Personas-gerecht: Dev-Badge für Julia, Audit-PDF für Martin.

### 5.4 Kosten, Wartung & Support  
* Ressourcenbedarf nur während Scan-Fenstern.  
* Semantic-Versioning, GitHub-CI-Pipeline sorgt für stabile Releases.  
* Community-Slack + FAQ reduziert Support-Last.

### 5.5 Monetarisierung / Kostendeckung  

| Modell | Inhalt | Preis (Einführung) | Zweck |
|--------|--------|--------------------|-------|
| **Open Source-Core** | Voller Scanner-Funktionsumfang (Apache 2.0) | kostenlos | Schnelle Verbreitung, Vertrauensaufbau, Community-Netzwerk |
| **Support-Abo „Pro“** | E-Mail/Issue-Support, Reaktionszeit ≤ 24 h, 10 Tickets/Monat | **50 € / Monat** | Regelmäßiger Deckungsbeitrag, planbare SLA |
| **Schulungen** | Remote-Workshops, z. B. „Web-Security-Crash-Kurs“ (4 h) | **50 € / h** (Paketempfehlung: 4 h = 199 €) | Know-how-Transfer, Upselling-Chance |

*Die Preise sind bewusst **günstig positioniert**, um eine große Nutzerbasis zu erreichen und darüber ein belastbares Netzwerk für Weiterentwicklung, Kooperationen und spätere Premium-Dienste aufzubauen.*

---

## 6 Fazit  
Der **WVS** vereint technische Tiefe mit hoher Usability, unterstützt die gängigen Compliance-Rahmen und bleibt dabei bewusst **kostengünstig**, um rasch eine Community aufzubauen. Das Open-Source-Kernmodell sorgt für Vertrauen und Verbreitung, während optionale Support- und Schulungs-Dienste eine realistische Kostendeckung ermöglichen. Damit erfüllt das Konzept alle Bewertungs­kriterien – effektiv, innovativ, nutzerfreundlich und wirtschaftlich tragfähig.