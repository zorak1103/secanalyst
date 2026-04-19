# **Product Requirements Document: Security Scanner Agent**

## **1\. Produktübersicht**

Das Produkt ist ein System für die Prüfung von Softwareprojekten auf Sicherheitslücken. Da Entwickler Sicherheitsüberprüfungen oft ignorieren, automatisiert dieses System den Prozess. Das System analysiert Quellcode auf Schwachstellen und erstellt Berichte mit Lösungsansätzen.

## **2\. Eingabeanforderungen**

Das System erfordert einen Startpunkt für die Analyse. Es akzeptiert drei Arten von Eingaben:

* Ein lokales Projektverzeichnis.  
* Eine URL zu einem **GitHub-Repository**. Das System nutzt die **GitHub CLI**, um das **Repository** in einen lokalen Ordner zu klonen.  
* Eine URL zu einem **GitLab-Repository**. Das System nutzt **glab**, um das **Repository** in einen lokalen Ordner zu klonen.

## **3\. Funktionsumfang der Analyse**

Die Sicherheitsprüfung stützt sich auf Branchenstandards. Die Hauptreferenz für die Prüfung bilden die **OWASP Top 10**.  
Das System sucht nach folgenden Schwachstellen:

* Fest im Code hinterlegte Geheimnisse.  
* **SQL Injection**.  
* **OS Command Injection**.  
* Arbiträre Codeausführung.  
* Kryptografische Fehler.  
* Fehlerhafte Zugriffskontrollen.  
* Unsicheres Design.

Das System gleicht Projektabhängigkeiten mit einer Datenbank für bekannte Sicherheitslücken ab.

## **4\. Systemarchitektur**

Die Lösung trennt das Fachwissen von der Logik für die Analyse. Sie besteht aus vier Kernkomponenten:

### **4.1 Security Scanner Skill**

Der **Skill** kapselt das Wissen für die Sicherheitsprüfung. Er verweist auf separate Referenzdokumente für jede der **OWASP Top 10**\-Kategorien. Jedes dieser Dokumente beschreibt das Problem, Präventionsmaßnahmen und typische Angriffsszenarien. Der **Skill** definiert den Ausführungsfluss für die Analyse. Er lässt sich in unterschiedlichen **LLM-Systemen** wiederverwenden.

### **4.2 Security Sub-Agent**

Der **Security Sub-Agent** ruft den **Skill** auf und koordiniert die Überprüfung des Codes. Er hat keine Berechtigung für Codeänderungen. Identifiziert diese Instanz eine mögliche Schwachstelle, leitet sie die Informationen an den **Challenger Agent** weiter.

### **4.3 Challenger Agent**

Der **Challenger Agent** hat die Aufgabe, die gemeldeten Funde zu hinterfragen. Beide Instanzen treten in einen iterativen Diskurs. Sie analysieren den Kontext der Code-Stelle und diskutieren die Validität der Schwachstelle. Dieser Austausch endet, wenn beide Instanzen den Fehler einstimmig bestätigen oder als **False Positive** verwerfen.

### **4.4 Exploit Agent**

Bestätigen die beiden Prüfinstanzen eine Schwachstelle, greift der **Exploit Agent** ein. Er versucht, einen konkreten **Exploit** für das Problem zu programmieren. Gelingt der Versuch, gilt die Lücke als praktisch ausnutzbar.

## **5\. Ausgabe und Berichterstattung**

Die Ergebnisse der Analyse fließen in einen Bericht. Das System legt diesen Bericht im Projektverzeichnis ab. Die Ordnerstruktur folgt dem Muster /audit/\[aktuelles Datum\]/.  
Der Bericht enthält:

* Eine Auflistung aller verifizierten Schwachstellen.  
* Einen Gesamt-**Risk Score**.  
* Die Einteilung der Funde in Schweregrade.  
* Konkrete Lösungsvorschläge für jede Lücke.  
* Den Code des erfolgreichen **Exploit**\-Versuchs zur Demonstration der Ausnutzbarkeit.