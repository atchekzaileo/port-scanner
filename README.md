# Port Scanner — Network Recon Tool (TCP)

Outil de reconnaissance réseau écrit en Python.  
Il réalise un scan TCP multithread, collecte des informations de service (banner, HTTP, SSH) et conserve un historique des scans afin de détecter les changements dans le temps (ports ouverts / fermés).

Le projet est conçu pour être utilisé sur des environnements locaux (localhost, VM, conteneurs) et à des fins pédagogiques.

---

## Fonctionnalités principales
- Scan TCP (`connect_ex`) multithread
- Gestion des timeouts
- Banner grabbing
- Fingerprinting HTTP (Server / status line)
- Parsing de banner SSH
- Export des résultats (JSON, CSV)
- Historisation des scans (SQLite)
- Détection des changements entre deux scans successifs
- Mini dashboard Flask pour visualiser l’historique

---

## Structure du projet

<p align="center">
  <img
    src="https://github.com/user-attachments/assets/05bd9fd9-1912-48e4-b70f-9974193de957"
    alt="Terminal scan"
    width="800"
    style="filter: brightness(0) invert(1);"
  />
</p>


---

## Prérequis
- Python 3.8+
- pip
- (Optionnel) Docker pour les tests SSH automatisés

Il est recommandé d’utiliser un environnement virtuel Python.

---

## Installation
```bash
python3 -m venv .venv
source .venv/bin/activate        # Windows : .venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install -r requirements.txt
```
## Utilisation

Pour voir des ports ouverts, il faut qu’un service écoute réellement sur la machine cible.
Si aucun service n’est actif, le scanner affichera uniquement des ports closed, ce qui est un comportement normal.

## Exemple simple (HTTP local)

Dans un premier terminal :
```bash
python3 -m http.server 8000
```

Dans un second terminal (avec le venv activé) :
```bash
python3 scanner.py -t 127.0.0.1 -p 8000 --show-open --db --diff
```

Scan simple sur localhost :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024
```

Afficher uniquement les ports ouverts :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024 --show-open
```

Exporter les résultats :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024 --json scan.json --csv scan.csv
```

Sauvegarder le scan dans la base d’historique :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024 --db
```

Comparer avec le scan précédent :
```bash
python3 scanner.py -t 127.0.0.1 -p 1-1024 --db --diff
```
## Historisation et détection des changements

Les scans sauvegardés en base SQLite permettent d’identifier :
- les ports nouvellement ouverts
- les ports fermés depuis le dernier scan

Cette fonctionnalité est utile pour observer l’évolution d’un service ou d’un environnement dans le temps.

## Dashboard

Une application Flask minimale permet de :
- lister les scans enregistrés
- consulter le détail d’un scan
- visualiser les différences avec le scan précédent

Le dashboard nécessite au moins un scan exécuté avec l’option --db.

Lancement :
```bash
export FLASK_APP=dashboard.py    # Windows PowerShell : $env:FLASK_APP='dashboard.py'
flask run --host=0.0.0.0 --port=5001
```

Puis ouvrir dans un navigateur :
```bash
http://127.0.0.1:5001
```
## Tests

Des scripts sont fournis pour tester automatiquement :
- un service HTTP local
- un service SSH via conteneur Docker
```bash  
chmod +x tests/test_auto.sh
./tests/test_auto.sh
```

⚠️ Le test SSH nécessite que Docker Desktop soit installé et démarré.
Si Docker n’est pas disponible, le test SSH est simplement ignoré.

## Limitations
- Scanner TCP de type connect (pas de SYN scan)
- Outil pédagogique, non destiné à un usage de production
- Dashboard Flask non sécurisé (serveur de développement)

## Sécurité et éthique
Ce projet doit être utilisé uniquement sur des machines ou réseaux pour lesquels une autorisation explicite a été donnée.
Les exemples fournis utilisent exclusivement des environnements locaux.

## Licence

MIT License
© 2025 — Léo Atchekzai
