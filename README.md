1. Importul proiectului din GitHub
1.1 Deschide un terminal (PowerShell, Windows Terminal sau VS Code).
1.2 Clonează repository-ul:
git clone https://github.com/VladBeX2/tls-scanner.git
cd tls-scanner

2. Necesități pentru rulare (WSL + Docker)

2.1 Instalare WSL (dacă nu este instalat)
Deschide PowerShell ca administrator și rulează:
wsl --install
Apoi repornește calculatorul.

Verifică:
wsl -l -v

2.2 Activarea serviciului Docker în WSL
În WSL, pornește daemon-ul Docker:
sudo dockerd
Această comandă trebuie lăsată să ruleze în acel terminal.
În paralel, deschide un alt terminal WSL pentru comenzi Docker.

3. Construirea imaginii Docker
În folderul proiectului:
docker build -t tls-scanner .

4. Rularea scannerului
docker run --rm tls-scanner

5. Modificarea codului
Fișierele sunt în app/scanner.py
După orice modificare:
docker build -t tls-scanner .
docker run --rm tls-scanner
