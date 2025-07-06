
# Projektdokumentation: Web Vulnerability Scanner (WVS)

---

## 1. Einleitung

Diese Dokumentation beschreibt die Konzeption, Architektur und Nutzung des Web Vulnerability Scanners (WVS). Das Projekt adressiert die wachsende Notwendigkeit für kleine und mittlere Unternehmen (KMU) sowie Start-ups, ihre Webanwendungen effektiv und kostengünstig abzusichern. WVS ist ein Kommandozeilen-Tool, das sich nahtlos in CI/CD-Pipelines integrieren lässt, um automatisierte Sicherheitsprüfungen basierend auf den OWASP Top 10 durchzuführen.

Die detaillierte **Problemstellung** und das **Lösungskonzept** sind in den folgenden Dokumenten zu finden:
- [Problemstellung.md](./Problemstellung.md)
- [Lösungskonzept.md](./Lösungkonzept.md)

---

## 2. User Stories

Die Anforderungen an WVS wurden aus den Bedürfnissen der folgenden zwei Personas abgeleitet:

**Persona 1: Julia Hoffmann (CTO eines SaaS-Start-ups)**

> *Als CTO bin ich für die schnelle und sichere Bereitstellung unserer Software verantwortlich. Mein Team arbeitet mit einer Continuous-Deployment-Pipeline. Wir haben begrenzte Security-Expertise und ein knappes Budget.*

- **User Story 1.1 (CI/CD-Integration):** "Ich möchte WVS mit einem einzigen Befehl in unserer GitHub-Actions-Pipeline ausführen können, damit jeder neue Build automatisch auf Schwachstellen geprüft wird."
- **User Story 1.2 (Verständliche Reports):** "Ich möchte, dass die Scan-Ergebnisse in einem einfachen Format (z.B. Markdown oder Konsole) ausgegeben werden, damit meine Entwickler die gefundenen Probleme schnell verstehen und beheben können."
- **User Story 1.3 (Konfigurierbarkeit):** "Ich möchte den Scanner über eine einfache Konfigurationsdatei (z.B. `wvs.toml`) anpassen können, um z.B. Timeouts zu definieren."

**Persona 2: Martin Schuster (IT-Admin eines Mittelständlers)**

> *Als IT-Admin betreue ich eine Reihe von internen Webportalen und muss die Einhaltung von Vorschriften wie der DSGVO und NIS2 sicherstellen. Ich bin kein Security-Spezialist.*

- **User Story 2.1 (Audit-fähige Reports):** "Ich muss in der Lage sein, nach einem Scan einen manipulationssicheren PDF-Report zu erzeugen, den ich als Nachweis für interne und externe Audits verwenden kann."
- **User Story 2.2 (Einfache Bedienung):** "Ich möchte den Scanner ohne tiefgehende technische Kenntnisse über einen einfachen Befehl wie `wvs scan <url>` starten können."
- **User Story 2.3 (Priorisierung):** "Ich möchte, dass die gefundenen Schwachstellen nach ihrem Schweregrad (z.B. Kritisch, Hoch, Mittel) eingestuft werden, damit ich mich auf die wichtigsten Probleme konzentrieren kann."

---

## 3. Architektur und Entwurf

### 3.1. UML-Komponentendiagramm

Das WVS-System ist modular aufgebaut, um eine hohe Wartbarkeit und Erweiterbarkeit zu gewährleisten. Das System wurde zunächst synchron aufgebaut; eine Umstrukturierung auf asynchrones Scannen ist erst in Stage 4 (die bislang nicht erreicht wurde) vorgesehen. Die folgende Abbildung zeigt die Hauptkomponenten und ihre Beziehungen:

```mermaid
  +----------------------+
  |   Benutzer (CLI)     |
  +----------------------+
           |
           v
+------------------------+      +-------------------------+
|     wvs.py (Typer)     |----->|   wvs.toml (Config)     |
+------------------------+      +-------------------------+
           |
           v
+------------------------+
| Scanner Engine         |
| - Lädt Module          |
| - Führt Scans aus      |
| - Sammelt Ergebnisse   |
+------------------------+
           |
           |--------------------------------------------+
           |                                            |
           v                                            v
+------------------------+                     +------------------------+
|   Scanner-Module       |                     |   Reporting-System     |
| - A01_Access           |                     | - Console Reporter     |
| - A02_Crypto           |                     | - JSON Reporter        |
| - A03_Injection        |                     | - PDF Reporter         |
| - A05_Config           |                     +------------------------+
| - A06_Components       |
| - A07_Auth             |
+------------------------+

```

### 3.2. Komponentenbeschreibung

- **CLI (`wvs.py`):** Die Schnittstelle zum Benutzer. Sie wird mit `typer` realisiert und stellt die Befehle `init` und `scan` zur Verfügung. Sie orchestriert die anderen Komponenten.

- **Configuration (`wvs.toml`):** Lädt und validiert die Konfiguration aus einer TOML-Datei. Stellt Standardwerte bereit, falls keine Konfigurationsdatei vorhanden ist.

- **Scanner Engine (`wvs/scanner/engine.py`):** Das Herzstück des Scanners. Sie ist verantwortlich für das dynamische Laden und Ausführen aller verfügbaren Scan-Module aus dem `wvs/scanner/modules`-Verzeichnis.

- **Base Module (`wvs/scanner/base_module.py`):** Definiert die abstrakte Klasse `BaseScannerModule`, die als Vorlage für alle Scan-Module dient. Dies stellt sicher, dass jedes Modul eine `scan`-Methode implementiert.

- **Scanner Modules (`wvs/scanner/modules/`):** Jede Datei in diesem Verzeichnis repräsentiert ein spezifisches Scan-Modul (z.B. `a03_injection.py`). Die Module sind für die Durchführung der eigentlichen Sicherheitsprüfungen verantwortlich.

- **Reporting (`wvs/reporting/`):** Diese Komponente ist für die Aufbereitung und Ausgabe der Scan-Ergebnisse in verschiedenen Formaten (Konsole, JSON, PDF) zuständig.

---

## 4. Benutzerhandbuch

### 4.1. Installation

1.  Stellen Sie sicher, dass Python 3.8+ auf Ihrem System installiert ist.
2.  Klonen Sie das Projekt-Repository von GitHub.
3.  Installieren Sie die erforderlichen Abhängigkeiten mit `pip`:

    ```bash
    pip install -r Requirements.txt
    ```

### 4.2. Konfiguration (Optional)

Führen Sie den folgenden Befehl im Hauptverzeichnis des Projekts aus, um eine Standard-Konfigurationsdatei (`wvs.toml`) zu erstellen:

```bash
py wvs.py init
```

Sie können die Werte in dieser Datei, wie z.B. den `timeout` für Anfragen, anpassen.

### 4.3. Scannen

Um einen Scan zu starten, verwenden Sie den `scan`-Befehl. Geben Sie die Ziel-URL als Argument an.

**Beispiele:**

- **Scan mit Konsolenausgabe:**
  ```bash
  py wvs.py scan http://example.com
  ```

- **Scan mit JSON-Report:**
  ```bash
  py wvs.py scan http://example.com --format json --output report.json
  ```

- **Scan mit PDF-Report:**
  ```bash
  py wvs.py scan http://example.com --format pdf --output report.pdf
  ```

---

## 5. Testprotokoll

Die Qualität und Korrektheit des WVS-Scanners wird durch eine Reihe von Unit-Tests sichergestellt. Die Tests befinden sich im `tests/`-Verzeichnis.

### 5.1. Ausführen der Tests

Um die Tests auszuführen, wurde ein dediziertes Skript `run_tests.py` erstellt, das alle Abhängigkeiten korrekt auflöst. Führen Sie es aus dem Projektstammverzeichnis aus:

```bash
py run_tests.py
```

### 5.2. Letztes Testergebnis

- **Datum:** 2025-07-06
- **Ergebnis:** **ERFOLGREICH**

```
test_scan_avoids_external_links (tests.test_modules.test_a03_injection.TestA03InjectionScanner.test_scan_avoids_external_links)
Test that the scanner does not follow and test external links. ... ok
test_scan_finds_error_based_sqli_in_get_parameter (tests.test_modules.test_a03_injection.TestA03InjectionScanner.test_scan_finds_error_based_sqli_in_get_parameter)
Test finding an error-based SQLi vulnerability in a GET parameter. ... ok
test_scan_finds_reflected_xss_in_form (tests.test_modules.test_a03_injection.TestA03InjectionScanner.test_scan_finds_reflected_xss_in_form)
Test finding a reflected XSS vulnerability in a POST form. ... ok
test_scan_no_vulnerabilities (tests.test_modules.test_a03_injection.TestA03InjectionScanner.test_scan_no_vulnerabilities)
Test scanning a page with no forms or links that are vulnerable. ... ok

----------------------------------------------------------------------
Ran 4 tests in 0.006s

OK
```

Die erfolgreiche Ausführung der Tests bestätigt die korrekte Funktionalität des neu implementierten `a03_injection`-Moduls sowie der bestehenden Komponenten.
