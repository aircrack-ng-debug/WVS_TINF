# Teamarbeit und Organisation im Projekt WVS_TINF

Dieses Dokument zeichnet die Entstehungsgeschichte des Projekts "Web Vulnerability Scanner (WVS)" nach. Es beleuchtet, wie die Teammitglieder – Aircrack (Maurice), Marius und Paul (LearningBirdi1212) – durch ihre individuellen Beiträge und ihre gemeinsame Koordination das Projekt von den ersten Schritten bis zum aktuellen Stand entwickelt haben. Die Darstellung orientiert sich an den Bewertungskriterien für Teamarbeit und Organisation aus der "Projektarbeit_Bewertungsmatrix.pdf".

## 1. Die Geburtsstunde des WVS: Initialisierung und Grundstruktur

Die Reise des WVS-Projekts begann mit **Aircrack (Maurice)**, der die grundlegende Infrastruktur schuf und die ersten Weichen stellte.

**Initialisierung und Hierarchie:** Das Projekt wurde mit einem "initial commit" gestartet, gefolgt von der Schaffung der grundlegenden Paket-Hierarchie (`wvs/`, `wvs/scanner/`, `wvs/reporting/` etc.) und der Integration erster Projekt-PDFs in den `Docs`-Ordner. Dies legte das Fundament für alle zukünftigen Entwicklungen und definierte die anfängliche Struktur des Projekts.
**Frühe Dokumentation:** Parallel zur Code-Struktur begann Aircrack mit der Erstellung wichtiger Projektdokumente wie der Problemstellung (`Problemstellung.md`) und erster Lösungsansätze (`Loesungskonzept_v1.md`). Dies zeigt eine frühe Priorisierung der Dokumentation und des Verständnisses der Projektziele.

## 2. Erste Feature-Entwicklung und die Rolle des Code Reviews

Nach der initialen Strukturierung begann die Implementierung erster funktionaler Module, wobei die Zusammenarbeit und Koordination durch Pull Requests und Code Reviews eine zentrale Rolle spielten.

**OWASP-Integration und Modul-Anfänge:** Aircrack begann mit der Integration von OWASP-relevanten Scans, insbesondere im Bereich Kryptographie (`a02_crypto.py`). Hierbei wurden auch erste Testdateien angelegt und grundlegende Python-Paketstrukturen korrigiert (`_init_.py` zu `__init__.py`).
**Pauls Rolle als Integrator und Qualitätssicherer:** In dieser Phase wurde **Paul (LearningBirdi1212)** als derjenige sichtbar, der die von Aircrack entwickelten Features über Pull Requests in den `main`-Branch integrierte. Jeder dieser Merge-Commits steht für einen abgeschlossenen Entwicklungszyklus, in dem Paul die Qualität des Codes sicherstellte und die Kohärenz des Gesamtprojekts bewahrte. Dies unterstreicht seine Rolle in der **effektiven Zusammenarbeit im Team** und der **Kommunikation und Koordination während des Projekts** durch den Einsatz eines strukturierten Git-Workflows.

## 3. Aufbau des Kern-Frameworks und erste gemeinsame Code-Beiträge

Die Entwicklung schritt voran mit dem Aufbau der zentralen Scanner-Engine und der Kommandozeilen-Schnittstelle. Hier zeigen sich auch die ersten direkten Code-Beiträge von Marius.

**Das Herzstück des Scanners:** Aircrack implementierte das "foundational framework" des WVS. Dies umfasste die `ScannerEngine` (verantwortlich für das dynamische Laden von Modulen), den `ConsoleReporter` für die Ausgabe der Ergebnisse und die `typer`-basierte Kommandozeilen-Schnittstelle (`wvs.py`). Dieser Commit war ein Meilenstein, der die Kernfunktionalität des Scanners etablierte.
**Marius' erster Bugfix:** Kurz nach der Implementierung des Kern-Frameworks leistete **Marius** seinen ersten direkten Code-Beitrag, indem er einen Fehler in `wvs/scanner/modules/a02_crypto.py` behob, der mit der `requests` Bibliothek zusammenhing. Dies zeigt Marius' Rolle im **Bugfixing** und seine Fähigkeit, sich schnell in die bestehende Codebasis einzuarbeiten. Die schnelle Behebung eines Problems, das die Funktionalität beeinträchtigen könnte, ist ein Beispiel für **effektive Zusammenarbeit im Team**.
**Integration des Kern-Frameworks:** Paul integrierte die umfangreichen Änderungen des Kern-Frameworks und Marius' Bugfix. Die Commit-Nachricht "passt!" in einem dieser Merges deutet auf eine erfolgreiche Überprüfung und Abnahme der Änderungen hin, was die **Kommunikation und Koordination** im Team weiter festigt.

## 4. Refactoring, Modul-Erweiterung und kontinuierlicher Fortschritt

Mit einem stabilen Kern-Framework konzentrierte sich die Entwicklung auf die Verbesserung der Modulstruktur und die Erweiterung der Scan-Fähigkeiten.

**Standardisierung der Scanner-Module:** Aircrack führte ein umfassendes Refactoring durch, indem er die abstrakte Klasse `BaseScannerModule` erstellte und bestehende Module (`a02_crypto.py`, `a05_config.py`, `a06_components.py`) an diese neue Struktur anpasste. Dies verbesserte die Wartbarkeit und Erweiterbarkeit des Scanners erheblich. Die Commit-Nachricht enthielt auch eine direkte Ansprache an Paul ("Hoffe du bist zufrieden @Paul"), was die **Kommunikation und Koordination** im Team und die Erwartung eines Code Reviews unterstreicht.
**Marius' fortlaufende Beiträge:** Marius setzte seine Arbeit an der Codebasis fort, wie sein Commit "Hier einige Änderungen und mein Progress" zeigt. Dies deutet auf eine kontinuierliche Entwicklung und Anpassung von Modulen hin, was seine Rolle im **Coding** und der **Verteilung von Aufgaben und Verantwortlichkeiten** festigt.
**Integration des Refactorings und Marius' Fortschritt:** Paul integrierte die Refactoring-Änderungen und Marius' Fortschritte. Diese Merges sind ein Beleg für die **effektive Zusammenarbeit im Team**, da sie die erfolgreiche Zusammenführung komplexer Code-Änderungen aus verschiedenen Entwicklungssträngen darstellen.

## 5. Umfassende Berichterstattung und neue Scanner-Fähigkeiten

Die jüngsten Entwicklungen konzentrierten sich auf die Verbesserung der Ausgabe und die Erweiterung der Scan-Fähigkeiten.

**Erweiterte Berichtsfunktionen und A03 Injection:** Der jüngste große Beitrag von Aircrack umfasste die Implementierung umfassender Berichtsfunktionen (JSON- und PDF-Reporter) und die Einführung des `A03InjectionScanner` mit dedizierten Tests. Dies zeigt die kontinuierliche Weiterentwicklung des Projekts und die Fokussierung auf die Bereitstellung audit-fähiger Ergebnisse. Die Integration der `Requirements.txt` und des `run_tests.py`-Skripts in diesem Commit unterstreicht die Professionalisierung der Projektinfrastruktur.

## 6. Meilensteine und Projekt-Roadmap

Die Entwicklung des WVS-Projekts erfolgte in mehreren klar definierten Phasen, die sich im Git-Verlauf widerspiegeln. Diese Roadmap zeigt die wichtigsten Meilensteine und ihre zeitliche Einordnung:

**06. Juni 2025: Projektstart und Grundstruktur**
    Initialer Commit und Erstellung der grundlegenden Paket-Hierarchie.
    Beginn der Projektdokumentation (Problemstellung, erste Lösungsansätze).

**10. Juni 2025: Kern-Framework und erste Bugfixes**
    Implementierung der `ScannerEngine`, des `ConsoleReporter` und der `typer`-basierten CLI.
    Erster Bugfix durch Marius zur Behebung eines Problems mit HTTP-Headern.

**04. Juli 2025: Modul-Standardisierung und fortlaufende Entwicklung**
    Umfassendes Refactoring zur Einführung der `BaseScannerModule` und Anpassung bestehender Scanner-Module.
    Marius' fortlaufende Beiträge zur Codebasis und Modulanpassungen.

**06. Juli 2025: Umfassende Berichterstattung und neue Scanner-Module**
    Implementierung von JSON- und PDF-Berichtsfunktionen.
    Einführung des `A03InjectionScanner` mit zugehörigen Unit-Tests.
    Integration der `Requirements.txt` und des `run_tests.py`-Skripts.

Diese Meilensteine zeigen einen kontinuierlichen und strukturierten Entwicklungsprozess, der durch die effektive Zusammenarbeit des Teams ermöglicht wurde.

## 7. Teamarbeit und Organisation:

### 7.1. Effektive Zusammenarbeit im Team

Die effektive Zusammenarbeit im Team war ein zentraler Pfeiler des Projekterfolgs:

**Komplementäre Rollen:** Die klare, aber flexible Rollenverteilung zwischen Aircrack (Architektur, Hauptentwicklung, Dokumentation), Marius (Bugfixing, spezifische Implementierungen) und Paul (Organisation, Code Review, Integration) ermöglichte es jedem Teammitglied, seine Stärken optimal einzusetzen.
**Strukturierter Workflow:** Die konsequente Nutzung von Git-Branches und Pull Requests, orchestriert durch Paul, sorgte für einen geordneten Entwicklungsprozess. Dies minimierte Konflikte und stellte sicher, dass Code-Änderungen gründlich geprüft wurden, bevor sie in den Hauptzweig gelangten.
**Gegenseitige Unterstützung:** Marius' schnelle Behebung eines Fehlers im Kern-Framework und Aircracks direkte Ansprache an Paul in Commit-Nachrichten sind Beispiele für die gegenseitige Unterstützung und das offene Kommunikationsklima im Team.

### 7.2. Verteilung von Aufgaben und Verantwortlichkeiten und Dokumentation dieser

Die Verteilung der Aufgaben war klar definiert und wurde implizit durch den Git-Verlauf dokumentiert:

**Aircrack:** Übernahm die Verantwortung für die initiale Projektstruktur, die Entwicklung des Kern-Frameworks, die Implementierung großer Features (z.B. Reporting, A03 Injection) und die Erstellung der umfassenden Projektdokumentation. Seine Commits zeigen eine durchgängige Führung in der Code-Entwicklung und Architektur.
**Marius:** Konzentrierte sich auf die Behebung spezifischer Code-Probleme und trug kontinuierlich zur Implementierung und Anpassung von Modulen bei. Seine Beiträge waren entscheidend für die Stabilität und Funktionalität des Scanners.
**Paul:** War der primäre Koordinator und Qualitätssicherer. Seine Rolle bei der Integration von Code-Änderungen und der Sicherstellung der Code-Qualität war unerlässlich für den reibungslosen Fortschritt des Projekts. Die Merge-Commits sind die direkte Dokumentation seiner Verantwortlichkeiten.

Die Git-Historie selbst dient als detailliertes Protokoll der Aufgabenverteilung, da jeder Commit den Autor, die vorgenommenen Änderungen und den Zeitpunkt der Ausführung festhält.

### 7.3. Kommunikation und Koordination während des Projekts

Die Kommunikation und Koordination waren durch Transparenz und Effizienz geprägt:

**Discord-basierter Austausch:** Der Discord war das primäre Medium für die Kommunikation über Code-Änderungen. Diskussionen und Feedback fanden hier statt, bevor Code integriert wurde.
**Klare Branching-Strategie:** Die Verwendung von `feature/` und `stage/` Branches ermöglichte eine parallele Entwicklung und eine klare Abgrenzung von Arbeitsbereichen. Dies erforderte und förderte eine präzise Koordination, um sicherzustellen, dass die verschiedenen Entwicklungsstränge am Ende zusammenpassten.
**Implizite und explizite Kommunikation:** Während viele Interaktionen durch den Git-Workflow impliziert sind (z.B. Pauls Merges nach Aircracks Commits), gab es auch explizite Kommunikationshinweise in den Commit-Nachrichten, die auf direkte Absprachen und Feedback-Schleifen hindeuten.





