#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import json
import os
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from colorama import Fore, Style, init as colorama_init
from tqdm import tqdm

colorama_init(autoreset=True)

DB_FILE = "scans_history.db"

DEFAULT_TIMEOUT = 0.8
DEFAULT_THREADS = 100
BANNER_RECV_BYTES = 4096

HTTP_PORTS = {80, 8080, 8000, 3000, 5000, 5001}


def parse_ports(expr: str) -> list[int]:
    ports: set[int] = set()
    for part in (p.strip() for p in expr.split(",")):
        if not part:
            continue
        if "-" in part:
            a_str, b_str = part.split("-", 1)
            a, b = int(a_str), int(b_str)
            if a > b:
                a, b = b, a
            for p in range(a, b + 1):
                if 0 < p < 65536:
                    ports.add(p)
        else:
            p = int(part)
            if 0 < p < 65536:
                ports.add(p)
    return sorted(ports)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_db(db_path: str = DB_FILE) -> None:
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                ip TEXT NOT NULL,
                ports_scanned TEXT NOT NULL,
                count INTEGER NOT NULL,
                timeout REAL NOT NULL,
                threads INTEGER NOT NULL,
                scan_time TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                scan_id INTEGER NOT NULL,
                port INTEGER NOT NULL,
                state TEXT NOT NULL,
                service TEXT,
                banner TEXT,
                FOREIGN KEY(scan_id) REFERENCES scans(id)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_target_ip ON scans(target, ip, id)")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_results_scan ON scan_results(scan_id, port)")
        conn.commit()


def save_scan_to_db(meta: dict, results: list[dict], db_path: str = DB_FILE) -> int:
    ensure_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO scans(target, ip, ports_scanned, count, timeout, threads, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                meta["target"],
                meta["ip"],
                meta["ports_scanned"],
                meta["count"],
                meta["timeout"],
                meta["threads"],
                meta["scan_time"],
            ),
        )
        scan_id = cur.lastrowid

        rows = [
            (scan_id, r["port"], r["state"], r.get("service") or "", r.get("banner") or "")
            for r in results
        ]
        cur.executemany(
            "INSERT INTO scan_results(scan_id, port, state, service, banner) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        return int(scan_id)


def get_last_scan_id_for_target(target: str, ip: str, db_path: str = DB_FILE) -> int | None:
    ensure_db(db_path)
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id FROM scans WHERE target=? AND ip=? ORDER BY id DESC LIMIT 1",
            (target, ip),
        )
        row = cur.fetchone()
        return int(row[0]) if row else None


def get_results_by_scan(scan_id: int, db_path: str = DB_FILE) -> dict[int, str]:
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        cur.execute("SELECT port, state FROM scan_results WHERE scan_id=?", (scan_id,))
        return {int(p): str(s) for (p, s) in cur.fetchall()}


def try_recv_banner(host: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                data = s.recv(BANNER_RECV_BYTES)
            except Exception:
                return ""
            if not data:
                return ""
            return data.decode(errors="replace").strip()
    except Exception:
        return None


def http_fingerprint(host: str, port: int, timeout: float) -> str | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            req = f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode()
            try:
                s.sendall(req)
            except Exception:
                pass

            try:
                data = s.recv(BANNER_RECV_BYTES)
            except Exception:
                return ""
            if not data:
                return ""
            txt = data.decode(errors="replace")
            for line in txt.splitlines():
                if line.lower().startswith("server:"):
                    return line.split(":", 1)[1].strip()
            lines = txt.splitlines()
            return lines[0].strip() if lines else ""
    except Exception:
        return None


def parse_ssh_version(text: str) -> str:
    if not text:
        return ""
    for line in text.splitlines():
        if line.startswith("SSH-"):
            parts = line.split("-", 2)
            if len(parts) >= 3:
                return parts[2].split()[0].strip()
            return line.strip()
    return ""


def detect_service(port: int, banner: str | None) -> str | None:
    b = (banner or "").lower()

    if "ssh-" in b:
        ver = parse_ssh_version(banner or "")
        return f"ssh ({ver})" if ver else "ssh"

    try:
        return socket.getservbyport(port)
    except Exception:
        return None


def scan_one_port(host: str, port: int, timeout: float) -> dict:
    res = {"port": port, "state": "closed", "service": None, "banner": None}
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            err = s.connect_ex((host, port))
            if err != 0:
                return res

        res["state"] = "open"
        banner = try_recv_banner(host, port, timeout)
        res["banner"] = "" if banner is None else banner
        res["service"] = detect_service(port, res["banner"])

        if port in HTTP_PORTS or "http" in (res["banner"] or "").lower():
            http_info = http_fingerprint(host, port, timeout)
            if http_info not in (None, ""):
                res["service"] = res["service"] or "http"
                base = res["banner"] or ""
                res["banner"] = f"{base} | HTTP: {http_info}".strip(" |")
        return res
    except Exception as e:
        res["state"] = "error"
        res["banner"] = str(e)
        return res


def scan_tcp(host: str, ports: list[int], timeout: float, threads: int) -> list[dict]:
    results: list[dict] = []
    if not ports:
        return results

    workers = min(max(1, threads), len(ports))
    pbar = tqdm(total=len(ports), desc=f"Scanning {host}", unit="port")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(scan_one_port, host, p, timeout) for p in ports]
        for fut in as_completed(futures):
            results.append(fut.result())
            pbar.update(1)

    pbar.close()
    results.sort(key=lambda x: x["port"])
    return results


def save_json(results: list[dict], filename: str, metadata: dict | None = None) -> None:
    payload = {"metadata": metadata or {}, "results": results}
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def save_csv(results: list[dict], filename: str) -> None:
    with open(filename, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["port", "state", "service", "banner"])
        for r in results:
            w.writerow([r.get("port"), r.get("state"), r.get("service") or "", r.get("banner") or ""])


def print_results(results: list[dict], show_open_only: bool) -> None:
    for r in results:
        if show_open_only and r["state"] != "open":
            continue

        port = r["port"]
        state = r["state"]
        svc = f" ({r['service']})" if r.get("service") else ""

        if state == "open":
            banner = (r.get("banner") or "")[:300]
            extra = f" - {banner}" if banner else ""
            print(f"{Fore.GREEN}[OPEN]{Style.RESET_ALL} Port {port}{svc}{extra}")
        elif state == "closed":
            if not show_open_only:
                print(f"{Fore.WHITE}[closed]{Style.RESET_ALL} Port {port}")
        else:
            msg = r.get("banner") or ""
            print(f"{Fore.YELLOW}[{state}]{Style.RESET_ALL} Port {port} - {msg}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TCP port scanner (multithread) + banner/fingerprint + SQLite history"
    )
    parser.add_argument("-t", "--target", required=True, help="Host ou IP cible")
    parser.add_argument("-p", "--ports", default="1-1024", help="Ports: 22,80,443 ou 1-1024")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout par connexion (s)")
    parser.add_argument("-T", "--threads", type=int, default=DEFAULT_THREADS, help="Nombre de threads")
    parser.add_argument("--json", help="Exporter en JSON")
    parser.add_argument("--csv", help="Exporter en CSV")
    parser.add_argument("--show-open", action="store_true", help="Afficher uniquement les ports ouverts")
    parser.add_argument("--db", action="store_true", help=f"Sauvegarder dans {DB_FILE}")
    parser.add_argument("--diff", action="store_true", help="Comparer au dernier scan (nécessite --db)")
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
        "timeout": float(args.timeout),
        "threads": int(args.threads),
        "scan_time": utc_now_iso(),
    }

    print(f"Scan de {target} ({ip}) - {len(ports)} ports - timeout={args.timeout}s - threads={args.threads}")

    results = scan_tcp(ip, ports, timeout=args.timeout, threads=args.threads)
    print_results(results, show_open_only=args.show_open)

    if args.json:
        save_json(results, args.json, metadata=meta)
        print(f"Résultats sauvegardés en JSON: {args.json}")

    if args.csv:
        save_csv(results, args.csv)
        print(f"Résultats sauvegardés en CSV: {args.csv}")

    if args.diff and not args.db:
        print("Option --diff nécessite --db.")
        return

    if args.db:
        prev_id = get_last_scan_id_for_target(target, ip)
        scan_id = save_scan_to_db(meta, results)
        print(f"Scan sauvegardé: id={scan_id} ({DB_FILE})")

        if args.diff:
            if prev_id is None:
                print("Aucun scan précédent pour comparaison.")
                return

            prev_map = get_results_by_scan(prev_id)
            curr_map = {r["port"]: r["state"] for r in results}

            opened = [p for p, st in curr_map.items() if st == "open" and prev_map.get(p) != "open"]
            closed = [p for p, st in prev_map.items() if st == "open" and curr_map.get(p) != "open"]

            print(f"Comparaison vs scan id={prev_id}:")
            if opened:
                print(f"{Fore.GREEN}Ports nouvellement ouverts: {sorted(opened)}{Style.RESET_ALL}")
            else:
                print("Aucun nouveau port ouvert.")
            if closed:
                print(f"{Fore.RED}Ports fermés depuis le dernier scan: {sorted(closed)}{Style.RESET_ALL}")
            else:
                print("Aucun port fermé depuis le dernier scan.")


if __name__ == "__main__":
    main()
