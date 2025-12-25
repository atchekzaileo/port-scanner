#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sqlite3
from flask import Flask, render_template_string, redirect, url_for, abort

DB_FILE = "scans_history.db"
app = Flask(__name__)

TEMPLATE_INDEX = """
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <title>Port Scanner - Dashboard</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
    table { border-collapse: collapse; width: 100%; max-width: 1100px; }
    th, td { border: 1px solid #ddd; padding: 10px; font-size: 14px; }
    th { background: #f6f6f6; text-align: left; }
    a { color: #0b57d0; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .top { display:flex; align-items:center; justify-content:space-between; max-width:1100px; }
    .muted { color:#666; font-size: 13px; }
  </style>
</head>
<body>
  <div class="top">
    <h1>Historique des scans</h1>
    <p><a href="{{ url_for('refresh') }}">Refresh</a></p>
  </div>

  {% if not scans %}
    <p class="muted">Aucun scan enregistré.</p>
  {% else %}
  <table>
    <tr>
      <th>id</th><th>target</th><th>ip</th><th>ports</th><th>count</th><th>scan_time</th><th></th>
    </tr>
    {% for s in scans %}
    <tr>
      <td>{{ s['id'] }}</td>
      <td>{{ s['target'] }}</td>
      <td>{{ s['ip'] }}</td>
      <td>{{ s['ports_scanned'] }}</td>
      <td>{{ s['count'] }}</td>
      <td>{{ s['scan_time'] }}</td>
      <td><a href="{{ url_for('view_scan', scan_id=s['id']) }}">view</a></td>
    </tr>
    {% endfor %}
  </table>
  {% endif %}
</body>
</html>
"""

TEMPLATE_VIEW = """
<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <title>Scan {{ scan_id }}</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 24px; }
    table { border-collapse: collapse; width: 100%; max-width: 1100px; }
    th, td { border: 1px solid #ddd; padding: 10px; font-size: 14px; vertical-align: top; }
    th { background: #f6f6f6; text-align: left; }
    a { color: #0b57d0; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .muted { color:#666; font-size: 13px; }
    pre { white-space: pre-wrap; margin: 0; }
    .box { max-width:1100px; }
  </style>
</head>
<body>
  <div class="box">
    <p><a href="{{ url_for('index') }}">← Back</a></p>
    <h1>Scan #{{ scan_id }} — {{ scan['target'] }} ({{ scan['ip'] }})</h1>
    <p class="muted">ports: {{ scan['ports_scanned'] }} • count: {{ scan['count'] }} • {{ scan['scan_time'] }}</p>

    {% if diff %}
      <h2>Diff vs scan #{{ diff['prev_scan_id'] }}</h2>
      <p>Opened: {{ diff['opened'] }}</p>
      <p>Closed: {{ diff['closed'] }}</p>
    {% endif %}

    <h2>Résultats</h2>
    <table>
      <tr><th>port</th><th>state</th><th>service</th><th>banner</th></tr>
      {% for r in results %}
      <tr>
        <td>{{ r['port'] }}</td>
        <td>{{ r['state'] }}</td>
        <td>{{ r['service'] }}</td>
        <td><pre>{{ r['banner'] }}</pre></td>
      </tr>
      {% endfor %}
    </table>
  </div>
</body>
</html>
"""


def get_db():
    if not os.path.exists(DB_FILE):
        return None
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    conn = get_db()
    if conn is None:
        return "<p>No database found. Run <code>scanner.py --db</code> first.</p>"

    cur = conn.cursor()
    cur.execute("SELECT id,target,ip,ports_scanned,count,scan_time FROM scans ORDER BY id DESC")
    scans = [dict(r) for r in cur.fetchall()]
    conn.close()
    return render_template_string(TEMPLATE_INDEX, scans=scans)


@app.route("/scan/<int:scan_id>")
def view_scan(scan_id: int):
    conn = get_db()
    if conn is None:
        return "<p>No database found.</p>"

    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        abort(404)

    scan = dict(row)

    cur.execute(
        "SELECT port,state,service,banner FROM scan_results WHERE scan_id=? ORDER BY port",
        (scan_id,),
    )
    results = [dict(r) for r in cur.fetchall()]

    cur.execute(
        "SELECT id FROM scans WHERE target=? AND ip=? AND id<? ORDER BY id DESC LIMIT 1",
        (scan["target"], scan["ip"], scan_id),
    )
    prev = cur.fetchone()

    diff = None
    if prev:
        prev_id = int(prev["id"])
        cur.execute("SELECT port,state FROM scan_results WHERE scan_id=?", (prev_id,))
        prev_map = {int(p): str(s) for (p, s) in cur.fetchall()}
        curr_map = {int(r["port"]): str(r["state"]) for r in results}

        opened = [p for p, st in curr_map.items() if st == "open" and prev_map.get(p) != "open"]
        closed = [p for p, st in prev_map.items() if st == "open" and curr_map.get(p) != "open"]

        diff = {"prev_scan_id": prev_id, "opened": sorted(opened), "closed": sorted(closed)}

    conn.close()
    return render_template_string(
        TEMPLATE_VIEW, scan_id=scan_id, scan=scan, results=results, diff=diff
    )


@app.route("/refresh")
def refresh():
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=False)
