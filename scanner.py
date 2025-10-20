#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Port Scanner amélioré - TCP multithread + banner grabbing + HTTP fingerprinting + SSH parsing
+ Historisation (SQLite) pour détecter changements entre scans
Usage: python3 scanner.py -t 127.0.0.1 -p 1-1024 --json out.json
"""
import argparse
import socket
import threading
import json
import csv
import sqlite3
import os
from queue import Queue, Empty
from datetime import datetime
from tqdm import tqdm
from colorama import Fore, Style, init as colorama_init

colorama_init(autoreset=True)

DEFAULT_TIMEOUT = 0.8
DEFAULT_THREADS = 100
BANNER_RECV_BYTES = 4096
DB_FILE = "scans_history.db"

# ---------------------------
# Utilities & DB helpers
# ---------------------------
def parse_ports(port_str):
    ports = set()
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            ports.update(range(a, b + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)

def ensure_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT,
        ip TEXT,
        ports_scanned TEXT,
        count INTEGER,
        timeout REAL,
        threads INTEGER,
        scan_time TEXT
    )""")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS scan_results (
        scan_id INTEGER,
        port INTEGER,
        state TEXT,
        service TEXT,
        banner TEXT,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )""")
    conn.commit()
    conn.close()

def save_scan_to_db(meta, results):
    ensure_db()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO scans(target, ip, ports_scanned, count, timeout, threads, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (meta['target'], meta['ip'], meta['ports_scanned'], meta['count'],
          meta['timeout'], meta['threads'], meta['scan_time']))
    scan_id = cur.lastrowid
    rows = [(scan_id, r['port'], r['state'], r.get('service') or '', r.get('banner') or '') for r in results]
    cur.executemany("INSERT INTO scan_results(scan_id, port, state, service, banner) VALUES (?, ?, ?, ?, ?)", rows)
    conn.commit()
    conn.close()
    return scan_id

def get_last_scan_id_for_target(target, ip):
    ensure_db()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT id FROM scans WHERE target=? AND ip=? ORDER BY id DESC LIMIT 1", (target, ip))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else None

def get_results_by_scan(scan_id):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT port, state FROM scan_results WHERE scan_id=?", (scan_id,))
    res = {row[0]: row[1] for row in cur.fetchall()}
    conn.close()
    return res

# ---------------------------
# Network helpers
# ---------------------------
def banner_grab_tcp(host, port, timeout):
    """Try to read immediate bytes from service (banner)"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            try:
                data = s.recv(BANNER_RECV_BYTES)
                if data:
                    return data.decode(errors='replace').strip()
            except Exception:
                return ""
    except Exception:
        return None
    return ""

def http_fingerprint(host, port, timeout):
    """
    Send minimal GET and try to extract Server: header or HTTP status line.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            try:
                req = b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
                s.sendall(req)
            except Exception:
                pass
            try:
                data = s.recv(BANNER_RECV_BYTES)
                if not data:
                    return ""
                txt = data.decode(errors="replace")
                for line in txt.splitlines():
                    if line.lower().startswith("server:"):
                        return line.split(":", 1)[1].strip()
                first = txt.splitlines()[0] if txt.splitlines() else ""
                return first.strip()
            except Exception:
                return ""
    except Exception:
        return None

def parse_ssh_banner(banner_text):
    if not banner_text:
        return ""
    for line in banner_text.splitlines():
        if line.startswith("SSH-"):
            parts = line.split('-')
            if len(parts) >= 3:
                return parts[2].strip().split()[0]
            else:
                return line.strip()
    return ""

# ---------------------------
# Worker & scan
# ---------------------------
def worker_tcp(host, q, results, timeout, pbar):
    while True:
        try:
            port = q.get_nowait()
        except Empty:
            return
        res = {"port": port, "state": "closed", "service": None, "banner": None}
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                err = s.connect_ex((host, port))
                if err == 0:
                    res["state"] = "open"
                    banner = banner_grab_tcp(host, port, timeout)
                    if banner is None:
                        res["banner"] = ""
                    else:
                        res["banner"] = banner

                    # detect SSH banner
                    if isinstance(res.get("banner"), str) and "ssh-" in (res.get("banner") or "").lower():
                        ssh_ver = parse_ssh_banner(res.get("banner"))
                        if ssh_ver:
                            res["service"] = f"ssh ({ssh_ver})"
                        else:
                            res["service"] = "ssh"
                    else:
                        try:
                            svc = socket.getservbyport(port)
                            res["service"] = svc
                        except Exception:
                            res["service"] = None

                    # HTTP heuristic
                    if port in (80, 8080, 8000, 3000, 5000) or ("http" in (res.get("banner") or "").lower()):
                        http_info = http_fingerprint(host, port, timeout)
                        if http_info not in (None, ""):
                            res["service"] = res.get("service") or "http"
                            res["banner"] = (res.get("banner") or "") + (" | HTTP: " + http_info)
                else:
                    res["state"] = "closed"
        except Exception as e:
            res["state"] = "error"
            res["banner"] = str(e)
        results.append(res)
        q.task_done()
        if pbar is not None:
            pbar.update(1)

def scan_tcp(host, ports, timeout=DEFAULT_TIMEOUT, threads=DEFAULT_THREADS):
    q = Queue()
    for p in ports:
        q.put(p)
    results = []
    pbar = tqdm(total=len(ports), desc=f"Scanning {host}", unit="port")
    workers = []
    for _ in range(min(threads, len(ports))):
        t = threading.Thread(target=worker_tcp, args=(host, q, results, timeout, pbar), daemon=True)
        t.start()
        workers.append(t)
    q.join()
    pbar.close()
    results.sort(key=lambda x: x['port'])
    return results

# ---------------------------
# Exports & diff
# ---------------------------
def save_json(results, filename, metadata=None):
    data = {"metadata": metadata or {}, "results": results}
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def save_csv(results, filename, metadata=None):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["port", "state", "service", "banner"])
        for r in results:
            writer.writerow([r.get("port"), r.get("state"), r.get("service") or "", r.get("banner") or ""])

# ---------------------------
# CLI
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Port Scanner + fingerprint (HTTP/SSH) + historisation SQLite")
    parser.add_argument("-t", "--target", required=True, help="Host ou IP cible")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports: e.g. 22,80,443 or 1-1024,8000-8100")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout par connexion (s)")
    parser.add_argument("--threads", "-T", type=int, default=DEFAULT_THREADS, help="Nombre de threads")
    parser.add_argument("--json", help="Enregistrer les résultats en JSON")
    parser.add_argument("--csv", help="Enregistrer les résultats en CSV")
    parser.add_argument("--show-open", action="store_true", help="Afficher uniquement les ports ouverts")
    parser.add_argument("--db", action="store_true", help="Sauvegarder le scan dans la base historique (scans_history.db)")
    parser.add_argument("--diff", action="store_true", help="Afficher les changements par rapport au dernier scan (nécessite --db)")
    args = parser.parse_args()

    target = args.target
    try:
        ip = socket.gethostbyname(target)
    except Exception as e:
        print(f"{Fore.RED}Erreur résolution DNS pour {target}: {e}{Style.RESET_ALL}")
        return

    ports = parse_ports(args.ports)
    if not ports:
        print(f"{Fore.RED}Aucun port valide fourni.{Style.RESET_ALL}")
        return

    meta = {
        "target": target,
        "ip": ip,
        "ports_scanned": f"{ports[0]}-{ports[-1]}" if len(ports) > 1 else str(ports[0]),
        "count": len(ports),
        "timeout": args.timeout,
        "threads": args.threads,
        "scan_time": datetime.utcnow().isoformat() + "Z"
    }
    print(f"Scan de {target} ({ip}) - {len(ports)} ports - timeout={args.timeout}s - threads={args.threads}")

    results = scan_tcp(ip, ports, timeout=args.timeout, threads=args.threads)

    open_ports = [r for r in results if r["state"] == "open"]
    if args.show_open:
        for r in open_ports:
            svc = f" ({r['service']})" if r.get("service") else ""
            banner = f" - { (r.get('banner') or '')[:300] }" if r.get('banner') else ""
            print(f"{Fore.GREEN}[OPEN] Port {r['port']}{svc}{Style.RESET_ALL}{banner}")
    else:
        for r in results:
            if r["state"] == "open":
                print(f"{Fore.GREEN}[OPEN] Port {r['port']} - svc={r.get('service')} - banner={ (r.get('banner') or '')[:200] }{Style.RESET_ALL}")
            elif r["state"] == "closed":
                print(f"{Fore.WHITE}[closed] Port {r['port']}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[{r['state']}] Port {r['port']} - {r.get('banner')}{Style.RESET_ALL}")

    if args.json:
        save_json(results, args.json, metadata=meta)
        print(f"Résultats sauvegardés en JSON: {args.json}")
    if args.csv:
        save_csv(results, args.csv, metadata=meta)
        print(f"Résultats sauvegardés en CSV: {args.csv}")

    if args.db:
        prev_id = get_last_scan_id_for_target(target, ip)
        scan_id = save_scan_to_db(meta, results)
        print(f"Scan sauvegardé dans la base: id={scan_id} (fichier {DB_FILE})")

        if args.diff:
            if prev_id is None:
                print("Aucun scan précédent pour faire la comparaison.")
            else:
                prev_map = get_results_by_scan(prev_id)
                current_map = {r['port']: r['state'] for r in results}
                opened = [p for p in current_map if current_map[p] == 'open' and prev_map.get(p) != 'open']
                closed = [p for p in prev_map if prev_map[p] == 'open' and current_map.get(p) != 'open']
                print(f"Comparaison vs scan id={prev_id}:")
                if opened:
                    print(f"{Fore.GREEN}Ports nouvellement ouverts: {sorted(opened)}{Style.RESET_ALL}")
                else:
                    print("Aucun nouveau port ouvert.")
                if closed:
                    print(f"{Fore.RED}Ports fermés depuis le dernier scan: {sorted(closed)}{Style.RESET_ALL}")
                else:
                    print("Aucun port fermé depuis le dernier scan.")
    else:
        if args.diff:
            print("Option --diff nécessite --db pour avoir une base d'historique.")

if __name__ == "__main__":
    main()
