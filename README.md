
# Port-Scanner

> **Résumé rapide :**  
> Ce dépôt contient un port scanner pédagogique (TCP multithread) avec banner grabbing, fingerprint HTTP, parsing de banner SSH, export JSON/CSV, historisation SQLite (détection de changements — diff opened/closed) et un mini-dashboard Flask pour visualiser l’historique. Des scripts de test automatisés (HTTP + SSH via Docker) sont fournis.

> **Important (légal/éthique)** : n’effectuez des scans que sur des machines que vous contrôlez ou pour lesquelles vous avez une autorisation explicite. Les exemples fournis utilisent `127.0.0.1` (localhost) et des conteneurs Docker.

---

## Arborescence (attendue)
```
port-scanner/
├── scanner.py
├── dashboard.py
├── requirements.txt
├── README.md
├── .gitignore
├── tests/
│   ├── test_auto.sh
│   └── test_auto_docker.sh
└── examples/
    └── scan_example.json
```

---

## Prérequis (généraux)
- **Python 3.8+** installé (macOS, Linux, Windows).
- `pip` (fourni avec Python).
- (Optionnel mais recommandé) **Git** pour versionner.
- (Optionnel) **Docker Desktop** pour les tests SSH automatisés.
- Terminal / PowerShell / Windows Terminal.

> Nous utilisons un environnement virtuel Python (`.venv`) par projet pour isoler les dépendances.

---

## Installation (pas à pas — multiplateforme)

### macOS / Linux (bash / zsh)
```bash
# 1) clone (optionnel) / aller dans le dossier projet
cd ~/Developer
git clone <URL_REPO> port-scanner || true
cd port-scanner

# 2) créer et activer un venv
python3 -m venv .venv
source .venv/bin/activate

# 3) installer dépendances
pip install --upgrade pip
pip install -r requirements.txt
```

### Windows (PowerShell)
```powershell
# 1) clone (optionnel) / aller dans le dossier projet
cd $HOME\Developer
git clone <URL_REPO> port-scanner
cd port-scanner

# 2) créer et activer venv
python -m venv .venv
# activer
.venv\Scripts\Activate.ps1    # ou Activate.bat selon shell

# 3) installer dépendances
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## Structure des fichiers et rôle
- `scanner.py` : script principal — scan TCP, banner grabbing, fingerprint HTTP, parsing SSH, options CLI (`--json`, `--csv`, `--db`, `--diff`, `--show-open`).
- `dashboard.py` : mini-app Flask pour visualiser l’historique et diffs.
- `requirements.txt` : dépendances Python (`tqdm`, `colorama`, `Flask`).
- `tests/test_auto.sh` : script de tests automatiques (HTTP local et, si Docker disponible, SSH via container).
- `tests/test_auto_docker.sh` : test Docker SSH multi-arch (fallback).
- `examples/scan_example.json` : exemple de sortie JSON.
- `.gitignore` : fichiers à ignorer.

---

## Utilisation — commandes utiles

### Scanner local (exemples)
Activer venv (si pas déjà fait) :
```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1
```

Scan des 1-1024 premiers ports et affichage complet :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024
```

Afficher uniquement les ports ouverts :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024 --show-open
```

Sauvegarder en JSON et CSV :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024 --json scan.json --csv scan.csv
```

Sauvegarder en base SQLite (historiser) :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024 --db
```

Comparer avec le dernier scan (nécessite `--db`) :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024 --db --diff
```

---

## Tester automatiquement (HTTP)

Un script ready-to-use démarre un `http.server` local, lance le scanner et arrête :
```bash
chmod +x tests/test_auto.sh
./tests/test_auto.sh
```

Sortie attendue (extrait) :
```
[OPEN] Port 8000 ... | HTTP: SimpleHTTP/0.6 Python/3.x.x
Résultats sauvegardés en JSON: tests/scan_test_8000.json
Scan sauvegardé dans la base: id=...
```

---

## Tester SSH avec Docker (automatique)

Si Docker est installé et démarré, lance le test Docker (script essaie une image et bascule sur un fallback multi-arch si nécessaire) :
```bash
# rendre exécutable
chmod +x tests/test_auto_docker.sh
# lancer
./tests/test_auto_docker.sh
```

Sortie attendue (extrait) :
```
[docker] launched rastasheep image mapping 22->2222
[scan] Scanning 127.0.0.1:2222
[OPEN] Port 2222 (ssh (OpenSSH_X.Y)) - SSH-2.0-OpenSSH_X.Y ...
Résultats sauvegardés en JSON: tests/scan_test_ssh.json
Scan sauvegardé dans la base: id=...
```

**Si Docker n’est pas installé** : tu peux tester SSH local en activant Remote Login (macOS) ou en lançant `sshd` temporaire sur un port non privilégié (Linux/*nix).

---

## Dashboard web — visualiser l’historique et diffs

1. Lancer le dashboard (avec venv activé) :
```bash
export FLASK_APP=dashboard.py      # macOS / Linux
# Windows PowerShell: $env:FLASK_APP = 'dashboard.py'

# lancer (macOS / Linux / Windows)
flask run --host=0.0.0.0 --port=5001
```

2. Ouvrir un navigateur : `http://127.0.0.1:5001`  
- La page liste les scans (id, target, ip, date).  
- Cliquer sur **view** pour voir le détail d’un scan et le diff vs scan précédent (si existant).

---

## Forcer un **diff** (exemples pas-à-pas)

### FerMÉ → OuVERT (fermé puis ouvrir)
1. Assure-toi qu'aucun serveur n'écoute sur 8000 :
```bash
lsof -nP -iTCP:8000 -sTCP:LISTEN || echo "rien sur 8000"
```

2. Scan initial (port fermé) :
```bash
python3 scanner.py -t 127.0.0.1 -p 8000 --db --diff --json scan_step1.json
```

3. Démarre le serveur HTTP dans un autre terminal :
```bash
python3 -m http.server 8000
```

4. Scan après démarrage (port ouvert) :
```bash
python3 scanner.py -t 127.0.0.1 -p 8000 --db --diff --show-open --json scan_step2.json
```

Résultat attendu : `Ports nouvellement ouverts: [8000]`.

### OuVERT → FerMÉ (ouvrir puis fermer)
1. Avec `http.server` lancé, lance un scan (open), arrête `http.server` (Ctrl+C) puis relance le scan : tu verras `Ports fermés depuis le dernier scan: [8000]`.

---

## Lecture des résultats (JSON / SQLite)
- JSON : `python3 -m json.tool tests/scan_test_8000.json`  
- SQLite (exemples) :
```bash
# liste derniers scans
sqlite3 scans_history.db "SELECT id,target,ip,ports_scanned,scan_time FROM scans ORDER BY id DESC LIMIT 10;"

# voir résultats d'un scan id=11
sqlite3 scans_history.db "SELECT port,state,service,banner FROM scan_results WHERE scan_id=11 ORDER BY port;"
```

---

## Dépannage (issues courantes & solutions)

### 1. `ModuleNotFoundError: No module named 'tqdm'`
Tu n’as pas activé le venv ou les dépendances ne sont pas installées.  
Solution :
```bash
source .venv/bin/activate   # ou .venv\Scripts\Activate.ps1 (Windows)
pip install -r requirements.txt
```

### 2. `docker: command not found`
Docker Desktop n’est pas lancé ou `docker` n’est pas dans le PATH.  
- Démarre Docker Desktop (GUI).  
- Vérifie : `docker --version` et `docker info`.  
- Si besoin : `open -a Docker` (macOS) puis attends que Docker soit prêt.

### 3. `Address already in use` (Flask)
Le port (5000/5001) est occupé. Lance Flask sur un autre port :
```bash
flask run --host=0.0.0.0 --port=5002
```

### 4. macOS : `setremotelogin` / Full Disk Access
Si tu utilises `systemsetup` ou `sshd`, macOS peut demander des permissions (Full Disk Access) pour Terminal. Ajoute Terminal à `Préférences Système → Confidentialité et sécurité` si nécessaire.

### 5. `getservbyport` retourne un service étrange (ex. `irdmi`)
Certains ports ont des mappings système (ex. 8000 → `irdmi`). C’est purement un label système : la vraie information utile est le `banner` / fingerprint HTTP.

---

## Sécurité, éthique & mentions légales
- **Ne scannez que ce que vous possédez** ou pour lequel vous avez une autorisation.  
- Documentez dans votre portfolio que vos scans d’exemple ont été effectués sur des environnements locaux / VM / conteneurs.  
- Le dashboard Flask fourni est un serveur **de développement**, non sécurisé pour une exposition publique.

---

## Conseils pour ton portfolio (suggestions)
- Ajoute dans le repo :  
  - `examples/scan_example.json` (déjà fourni).  
  - `screenshots/terminal_scan_open.png` et `screenshots/dashboard_view.png` (captures montrant `[OPEN]` + fingerprint et la page `view` du dashboard).  
- Dans README, ajoute une courte démo GIF (optionnel) ou un lien vers une vidéo de 30s montrant le scénario `closed→open→diff`.  
- Ajoute dans README une section « How it works » (1 paragraphe) expliquant que tu utilises sockets TCP, `connect_ex`, lecture de banners, heuristiques HTTP/SSH, puis stockage SQLite et une vue Flask.

---

## Commandes utiles résumé (copier-coller)

### Préparer & installer
```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```

### Tests rapides
```bash
chmod +x tests/test_auto.sh
./tests/test_auto.sh             # teste HTTP (+ SSH si docker dispo)
chmod +x tests/test_auto_docker.sh
./tests/test_auto_docker.sh      # test SSH via Docker (multi-arch)
```

### Dashboard
```bash
export FLASK_APP=dashboard.py     # Windows PowerShell: $env:FLASK_APP='dashboard.py'
flask run --host=0.0.0.0 --port=5001
# ouvre http://127.0.0.1:5001
```

### Nettoyer
```bash
rm -f scans_history.db tests/scan_test_*.json scan_demo_*.json
```

---

## FAQ rapide
**Q : Puis-je exécuter ce projet sur Windows ?**  
Oui — Python + venv + pip fonctionnent sur Windows. Les scripts bash `tests/*.sh` sont pensés pour macOS/Linux ; tu peux exécuter les mêmes commandes manuellement sous PowerShell. `tests/test_auto_docker.sh` nécessite Docker Desktop pour Windows.

**Q : Puis-je utiliser ce scanner “en production” ?**  
Non — c’est un outil pédagogique. Pour usages avancés/professionnels, utilise `nmap` ou solutions éprouvées.

---

## Licence
```
MIT License
(c) Atchekzai Léo 2025
```

---
# port-scanner
