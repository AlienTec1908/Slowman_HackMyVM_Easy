# Slowman - HackMyVM (Easy)

![Slowman.png](Slowman.png)

## Übersicht

*   **VM:** Slowman
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Slowman)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2023-12-04
*   **Original-Writeup:** [https://alientec1908.github.io/Slowman_HackMyVM_Easy/](https://alientec1908.github.io/Slowman_HackMyVM_Easy/)
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, sowohl die User- als auch die Root-Flag auf der virtuellen Maschine "Slowman" zu erlangen. Der Lösungsweg umfasste initiales Netzwerk-Scanning und Web-Enumeration, gefolgt von der Ausnutzung eines Informationslecks im FTP-Dienst, das zu MySQL-Zugangsdaten führte. Nach dem Knacken des MySQL-Passworts wurden in der Datenbank weitere Zugangsdaten und ein Hinweis auf eine versteckte ZIP-Datei gefunden. Das Passwort dieser ZIP-Datei wurde geknackt, was zu einem SSH-Passwort-Hash führte. Nach dem Knacken dieses Hashes konnte der initiale Zugriff als Benutzer `trainerjean` erlangt werden. Die Privilegieneskalation zu Root erfolgte durch Ausnutzung einer falsch konfigurierten Linux-Capability (`cap_setuid`) der Python3.10-Binärdatei.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `vi`
*   `nikto`
*   `nmap`
*   `gobuster`
*   `curl`
*   `mysql`
*   `ftp`
*   `cat`
*   `ssh-username-enum.py`
*   `dirb`
*   `hydra`
*   `wget`
*   `zip2john`
*   `john` (John the Ripper)
*   `unzip`
*   `echo`
*   `ssh`
*   `sudo` (zur Überprüfung von Rechten)
*   `ss`
*   `find`
*   `msfconsole` (für Shell-Handling, nicht für den finalen Exploit)
*   `rm`
*   `mkfifo`
*   `nc` (Netcat)
*   `python3`
*   `chmod`
*   `pspy64`
*   `linpeas.sh`
*   `getcap`
*   `setcap` (Versuch, nicht erfolgreich)
*   `grep`
*   `ssh-agent` (Versuch, nicht erfolgreich)
*   `su` (Versuch, nicht erfolgreich)
*   Standard Linux-Befehle (`ls`, `id`, etc.)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Slowman" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Adresse (`192.168.2.113`) via `arp-scan` identifiziert.
    *   `nmap`-Scan ergab offene Ports: 21 (FTP - vsftpd 3.0.5, anonymer Login), 22 (SSH - OpenSSH 8.9p1), 80 (HTTP - Apache 2.4.52), 3306 (MySQL - 8.0.35).
    *   `nikto`-Scan auf Port 80 zeigte fehlende Sicherheitsheader, Directory Indexing für `/css/` & `/images/` und die ungewöhnliche HTTP-Methode `PTINS`.

2.  **FTP & Web Enumeration (Fund von MySQL-Nutzer):**
    *   Anonymer FTP-Login auf Port 21. Die Datei `allowedusersmysql.txt` wurde gefunden und enthielt den Benutzernamen `trainerjeff`.
    *   Verzeichnis-Bruteforce (`gobuster`, `dirb`) auf dem Webserver offenbarte Standardseiten sowie die Verzeichnisse `/secretLGIN/` und `/secretgym/`.

3.  **Initial Access (MySQL kompromittieren -> SSH als `trainerjean`):**
    *   Mittels `hydra` wurde das MySQL-Passwort für `trainerjeff` (`soccer1`) auf Port 3306 gebruteforced.
    *   Login in die MySQL-Datenbank als `trainerjeff`. Die Tabelle `trainers_db.users` enthielt Zugangsdaten für `gonzalo` (`tH1sS2stH3g0nz4l0pAsSWW0rDD!!`) und den Pfad `/secretLGIN/login.html`.
    *   Im Webverzeichnis `/secretgym/serverSHARE/` wurde die Datei `credentials.zip` gefunden und heruntergeladen.
    *   Der Hash der ZIP-Datei wurde mit `zip2john` extrahiert und mit `john` und `rockyou.txt` geknackt: Passwort `spongebob1`.
    *   Die ZIP-Datei enthielt `passwords.txt` mit den Daten: `$USERS: trainerjean`, `$PASSWRD: $2y$10$DBFBehmb6ktnyGyAtQZNeV/kiNAE.Y3He8cJsvpRxIFEhRAUe1kq`.
    *   Der bcrypt-Hash für `trainerjean` wurde mit `john` und `rockyou.txt` geknackt: Passwort `tweety1`.
    *   Erfolgreicher SSH-Login als `trainerjean` mit dem Passwort `tweety1`. Die User-Flag wurde in `/home/trainerjean/user.txt` gefunden.

4.  **Privilege Escalation (von `trainerjean` zu `root`):**
    *   Nach dem Login als `trainerjean` wurde mit `linpeas.sh` und `getcap -r / 2>/dev/null` enumeriert.
    *   Es wurde festgestellt, dass `/usr/bin/python3.10` die Linux-Capability `cap_setuid=ep` besitzt.
    *   Ausnutzung dieser Capability mit dem Befehl: `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'`.
    *   Dies gewährte eine Shell mit `uid=0(root)`. Die Root-Flag wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Informationsleck durch anonymen FTP-Zugriff:** Die Datei `allowedusersmysql.txt` auf dem FTP-Server enthielt einen gültigen MySQL-Benutzernamen.
*   **Schwache Passwörter & Passwort-Cracking:** Das MySQL-Passwort (`soccer1`), das ZIP-Passwort (`spongebob1`) und das SSH-Passwort (`tweety1` aus einem bcrypt-Hash) waren schwach und konnten mittels Brute-Force (`hydra`) bzw. Hash-Cracking (`john`) ermittelt werden.
*   **Speicherung von Zugangsdaten im Klartext/schwach geschützt:** Das Passwort für `gonzalo` war im Klartext in der MySQL-Datenbank. Der Hash für `trainerjean` befand sich in einer nur schwach passwortgeschützten ZIP-Datei.
*   **Fehlkonfigurierte Linux Capabilities (Privilege Escalation):** Die Python3.10-Binärdatei `/usr/bin/python3.10` hatte die `cap_setuid=ep` Capability gesetzt, was es einem niedrig privilegierten Benutzer ermöglichte, seine UID auf 0 (root) zu ändern und volle Systemkontrolle zu erlangen.
*   **Versteckte Web-Verzeichnisse/Dateien:** Das Auffinden von `/secretgym/serverSHARE/credentials.zip` war ein wichtiger Schritt.

## Flags

*   **User Flag (`/home/trainerjean/user.txt`):** `YU9et7HEpA$SwordofS10wMan!!`
*   **Root Flag (`/root/root.txt`):** `Y0UGE23t7hE515roo7664pa5$WoRDFSlowmaN!!`

## Tags

`HackMyVM`, `Slowman`, `Easy`, `FTP`, `MySQL`, `Password Cracking`, `JohnTheRipper`, `Hydra`, `Linux Capabilities`, `Python`, `Web Enumeration`, `Privilege Escalation`, `Linux`
