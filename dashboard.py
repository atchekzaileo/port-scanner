#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Flask dashboard minimal pour visualiser les scans enregistrés dans scans_history.db
Affiche la liste des scans et permet de voir le détail + diff vs scan précédent.
"""
from flask import Flask, render_template_string, redirect, url_for
import sqlite3
import os

DB_FILE = "scans_history.db"
app = Flask(__name__)

TEMPLATE_INDEX = """
<!doctype html>
<title>Port Scanner - Dashboard</title>
<h1>Historique des scans</h1>
<p><a href="{{ url_for('refresh') }}">Refresh</a></p>
<table border="1" cellpadding="6" cellspacing="0">
<tr><th>id</th><th>target</th><th>ip</th><th>ports</th><th>count</th><th>scan_time</th><th>action</th></tr>
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
"""

TEMPLATE_VIEW = """
<!doctype html>
<title>Scan {{ scan_id }}</title>
<h1>Scan id={{ scan_id }} - {{ scan['target'] }} ({{ scan['ip'] }})</h1>
<p><a href="{{ url_for('index') }}">Back</a></p>
<h2>Results</h2>
<table border="1" cellpadding="6">
<tr><th>port</th><th>state</th><th>service</th><th>banner</th></tr>
{% for r in results %}
<tr>
  <td>{{ r['port'] }}</td>
  <td>{{ r['state'] }}</td>
  <td>{{ r['service'] }}</td>
  <td><pre style="white-space:pre-wrap;max-width:800px">{{ r['banner'] }}</pre></td>
</tr>
{% endfor %}
</table>
{% if diff %}
<h2>Diff vs scan id={{ diff.prev_scan_id }}</h2>
<p>Opened: {{ diff.opened }}</p>
<p>Closed: {{ diff.closed }}</p>
{% endif %}
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
        return "<p>No DB found. Run a scan with --db first.</p>"
    cur = conn.cursor()
    cur.execute("SELECT id,target,ip,ports_scanned,count,scan_time FROM scans ORDER BY id DESC")
    scans = [dict(r) for r in cur.fetchall()]
    conn.close()
    return render_template_string(TEMPLATE_INDEX, scans=scans)

@app.route("/scan/<int:scan_id>")
def view_scan(scan_id):
    conn = get_db()
    if conn is None:
        return "<p>No DB found.</p>"
    cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    s = cur.fetchone()
    if not s:
        return "Scan not found", 404
    scan = dict(s)
    cur.execute("SELECT port,state,service,banner FROM scan_results WHERE scan_id=? ORDER BY port", (scan_id,))
    results = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT id FROM scans WHERE target=? AND ip=? AND id<? ORDER BY id DESC LIMIT 1", (scan['target'], scan['ip'], scan_id))
    prev = cur.fetchone()
    diff = None
    if prev:
        prev_id = prev['id']
        cur.execute("SELECT port,state FROM scan_results WHERE scan_id=?", (prev_id,))
        prev_map = {row[0]: row[1] for row in cur.fetchall()}
        curr_map = {r['port']: r['state'] for r in results}
        opened = [p for p in curr_map if curr_map[p]=='open' and prev_map.get(p)!='open']
        closed = [p for p in prev_map if prev_map[p]=='open' and curr_map.get(p)!='open']
        diff = type("D", (), {"opened": opened, "closed": closed, "prev_scan_id": prev_id})
    conn.close()
    return render_template_string(TEMPLATE_VIEW, scan_id=scan_id, scan=scan, results=results, diff=diff)

@app.route("/refresh")
def refresh():
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
