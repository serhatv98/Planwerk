from flask import Flask, request, jsonify, send_from_directory
import sqlite3, os, hashlib, secrets
from datetime import datetime

import os as _os
_base = _os.path.dirname(_os.path.abspath(__file__))
_static = _os.path.join(_base, 'public') if _os.path.exists(_os.path.join(_base, 'public', 'index.html')) else _base
app = Flask(__name__, static_folder=_static, static_url_path='')

DB_DIR = os.environ.get('DB_DIR', os.path.join(os.path.dirname(__file__), 'db'))
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, 'planwerk.db')

ADMIN_PW = 'SBG1234'

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user',
            password_hash TEXT,
            must_change_pw INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, desc TEXT,
            owner TEXT, deadline TEXT, color TEXT DEFAULT '#00897b',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS aufgaben (
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
            name TEXT NOT NULL, owner TEXT, dept TEXT, abh TEXT,
            created_by TEXT, created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS versionen (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aufgabe_id TEXT NOT NULL, ver INTEGER NOT NULL,
            status TEXT DEFAULT 'Offen', soll REAL DEFAULT 0,
            ist REAL DEFAULT 0, termin TEXT, notes TEXT, grund TEXT,
            created_by TEXT, created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS inputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, version_id INTEGER NOT NULL,
            name TEXT, von TEXT, abt TEXT, datum TEXT
        );
        CREATE TABLE IF NOT EXISTS outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, version_id INTEGER NOT NULL,
            name TEXT, ziel TEXT, abt TEXT, datum TEXT
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name TEXT NOT NULL, message TEXT NOT NULL,
            aufgabe_id TEXT, project_id TEXT, read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        ''')
        conn.commit()

init_db()

def row_to_dict(row):
    return dict(row) if row else None

def rows_to_list(rows):
    return [dict(r) for r in rows]

def get_full_project(pid):
    with get_db() as conn:
        proj = row_to_dict(conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone())
        if not proj: return None
        aufgaben = rows_to_list(conn.execute("SELECT * FROM aufgaben WHERE project_id=? ORDER BY created_at", (pid,)).fetchall())
        for a in aufgaben:
            vers = rows_to_list(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver", (a['id'],)).fetchall())
            for v in vers:
                v['inputs'] = rows_to_list(conn.execute("SELECT * FROM inputs WHERE version_id=?", (v['id'],)).fetchall())
                v['outputs'] = rows_to_list(conn.execute("SELECT * FROM outputs WHERE version_id=?", (v['id'],)).fetchall())
            a['versionen'] = vers
        proj['aufgaben'] = aufgaben
        return proj

def send_notif(conn, user_name, message, aufgabe_id, project_id):
    # Kullanıcı sistemde kayıtlı mı kontrol et
    user = conn.execute("SELECT id FROM users WHERE name=?", (user_name,)).fetchone()
    if user:
        conn.execute("INSERT INTO notifications (user_name, message, aufgabe_id, project_id) VALUES (?,?,?,?)",
                     (user_name, message, aufgabe_id, project_id))

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

# ── AUTH ──────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    name = data.get('name','').strip()
    password = data.get('password','')
    if not name or not password:
        return jsonify({'error':'Name und Passwort erforderlich'}), 400
    if name == 'Admin':
        if password != ADMIN_PW:
            return jsonify({'error':'Falsches Passwort'}), 401
        return jsonify({'name':'Admin','role':'admin','must_change_pw':False})
    with get_db() as conn:
        user = row_to_dict(conn.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone())
        if not user:
            return jsonify({'error':'Benutzer nicht gefunden'}), 401
        if user['password_hash'] != hash_pw(password):
            return jsonify({'error':'Falsches Passwort'}), 401
        return jsonify({'name':user['name'],'role':user['role'],'must_change_pw':bool(user['must_change_pw'])})

@app.route('/api/change_password', methods=['POST'])
def change_password():
    data = request.json
    name = data.get('name','')
    old_pw = data.get('old_password','')
    new_pw = data.get('new_password','')
    if not new_pw or len(new_pw) < 4:
        return jsonify({'error':'Passwort zu kurz (min. 4 Zeichen)'}), 400
    with get_db() as conn:
        user = row_to_dict(conn.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone())
        if not user: return jsonify({'error':'Nicht gefunden'}), 404
        if user['password_hash'] != hash_pw(old_pw):
            return jsonify({'error':'Altes Passwort falsch'}), 401
        conn.execute("UPDATE users SET password_hash=?, must_change_pw=0 WHERE name=?", (hash_pw(new_pw), name))
        conn.commit()
    return jsonify({'ok':True})

# ── USER MANAGEMENT (Admin) ────────────────────────
@app.route('/api/users', methods=['GET'])
def get_users():
    with get_db() as conn:
        users = rows_to_list(conn.execute("SELECT id, name, role, must_change_pw, created_at FROM users ORDER BY name").fetchall())
        return jsonify(users)

@app.route('/api/users', methods=['POST'])
def create_user():
    d = request.json
    name = d.get('name','').strip()
    pw = d.get('password','')
    role = d.get('role','user')
    if not name or not pw:
        return jsonify({'error':'Name und Passwort erforderlich'}), 400
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE name=?", (name,)).fetchone()
        if existing: return jsonify({'error':'Benutzer existiert bereits'}), 409
        conn.execute("INSERT INTO users (name, role, password_hash, must_change_pw) VALUES (?,?,?,1)",
                     (name, role, hash_pw(pw)))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/users/<name>', methods=['DELETE'])
def delete_user(name):
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE name=?", (name,))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/users/<name>/reset_password', methods=['POST'])
def reset_password(name):
    d = request.json
    new_pw = d.get('password','')
    if not new_pw: return jsonify({'error':'Passwort erforderlich'}), 400
    with get_db() as conn:
        conn.execute("UPDATE users SET password_hash=?, must_change_pw=1 WHERE name=?", (hash_pw(new_pw), name))
        conn.commit()
    return jsonify({'ok':True})

# ── PROJECTS ──────────────────────────────────────
@app.route('/api/projects', methods=['GET'])
def get_projects():
    with get_db() as conn:
        return jsonify(rows_to_list(conn.execute("SELECT * FROM projects ORDER BY created_at").fetchall()))

@app.route('/api/projects', methods=['POST'])
def create_project():
    d = request.json
    with get_db() as conn:
        conn.execute("INSERT INTO projects (id,name,desc,owner,deadline,color) VALUES (?,?,?,?,?,?)",
                     (d['id'],d['name'],d.get('desc',''),d.get('owner',''),d.get('deadline',''),d.get('color','#00897b')))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/projects/<pid>', methods=['GET'])
def get_project(pid):
    proj = get_full_project(pid)
    if not proj: return jsonify({'error':'Nicht gefunden'}), 404
    return jsonify(proj)

@app.route('/api/projects/<pid>', methods=['PUT'])
def update_project(pid):
    d = request.json
    with get_db() as conn:
        conn.execute("UPDATE projects SET name=?,desc=?,owner=?,deadline=? WHERE id=?",
                     (d['name'],d.get('desc',''),d.get('owner',''),d.get('deadline',''),pid))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/projects/<pid>', methods=['DELETE'])
def delete_project(pid):
    with get_db() as conn:
        aufgaben = rows_to_list(conn.execute("SELECT id FROM aufgaben WHERE project_id=?", (pid,)).fetchall())
        for a in aufgaben:
            vers = rows_to_list(conn.execute("SELECT id FROM versionen WHERE aufgabe_id=?", (a['id'],)).fetchall())
            for v in vers:
                conn.execute("DELETE FROM inputs WHERE version_id=?", (v['id'],))
                conn.execute("DELETE FROM outputs WHERE version_id=?", (v['id'],))
            conn.execute("DELETE FROM versionen WHERE aufgabe_id=?", (a['id'],))
        conn.execute("DELETE FROM aufgaben WHERE project_id=?", (pid,))
        conn.execute("DELETE FROM projects WHERE id=?", (pid,))
        conn.commit()
    return jsonify({'ok':True})

# ── AUFGABEN ──────────────────────────────────────
@app.route('/api/aufgaben', methods=['POST'])
def create_aufgabe():
    d = request.json
    v = d.get('version',{})
    with get_db() as conn:
        conn.execute("INSERT INTO aufgaben (id,project_id,name,owner,dept,abh,created_by) VALUES (?,?,?,?,?,?,?)",
                     (d['id'],d['project_id'],d['name'],d.get('owner',''),d.get('dept',''),d.get('abh',''),d.get('created_by','')))
        r = conn.execute("INSERT INTO versionen (aufgabe_id,ver,status,soll,ist,termin,notes,grund,created_by) VALUES (?,1,?,?,?,?,?,?,?)",
                         (d['id'],v.get('status','Offen'),v.get('soll',0),v.get('ist',0),v.get('termin',''),v.get('notes',''),'',d.get('created_by','')))
        vid = r.lastrowid
        for inp in v.get('inputs',[]):
            conn.execute("INSERT INTO inputs (version_id,name,von,abt,datum) VALUES (?,?,?,?,?)",
                         (vid,inp.get('name',''),inp.get('von',''),inp.get('abt',''),inp.get('datum','')))
        for out in v.get('outputs',[]):
            conn.execute("INSERT INTO outputs (version_id,name,ziel,abt,datum) VALUES (?,?,?,?,?)",
                         (vid,out.get('name',''),out.get('ziel',''),out.get('abt',''),out.get('datum','')))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/aufgaben/<aid>', methods=['PUT'])
def update_aufgabe(aid):
    d = request.json
    v = d.get('version',{})
    with get_db() as conn:
        conn.execute("UPDATE aufgaben SET name=?,owner=?,dept=?,abh=? WHERE id=?",
                     (d['name'],d.get('owner',''),d.get('dept',''),d.get('abh',''),aid))
        ver = row_to_dict(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver DESC LIMIT 1",(aid,)).fetchone())
        if ver and v:
            old_status = ver['status']
            conn.execute("UPDATE versionen SET status=?,soll=?,ist=?,termin=?,notes=? WHERE id=?",
                         (v.get('status','Offen'),v.get('soll',0),v.get('ist',0),v.get('termin',''),v.get('notes',''),ver['id']))
            conn.execute("DELETE FROM inputs WHERE version_id=?", (ver['id'],))
            conn.execute("DELETE FROM outputs WHERE version_id=?", (ver['id'],))
            for inp in v.get('inputs',[]):
                conn.execute("INSERT INTO inputs (version_id,name,von,abt,datum) VALUES (?,?,?,?,?)",
                             (ver['id'],inp.get('name',''),inp.get('von',''),inp.get('abt',''),inp.get('datum','')))
            for out in v.get('outputs',[]):
                conn.execute("INSERT INTO outputs (version_id,name,ziel,abt,datum) VALUES (?,?,?,?,?)",
                             (ver['id'],out.get('name',''),out.get('ziel',''),out.get('abt',''),out.get('datum','')))
            if v.get('status') == 'Abgeschlossen' and old_status != 'Abgeschlossen':
                aufg = row_to_dict(conn.execute("SELECT * FROM aufgaben WHERE id=?",(aid,)).fetchone())
                proj = row_to_dict(conn.execute("SELECT * FROM projects WHERE id=?",(aufg['project_id'],)).fetchone())
                outs = rows_to_list(conn.execute("SELECT * FROM outputs WHERE version_id=?",(ver['id'],)).fetchall())
                for out in outs:
                    if out.get('ziel'):
                        send_notif(conn, out['ziel'], '"'+ aufg['name']+'" wurde abgeschlossen. Du kannst jetzt beginnen! (Projekt: '+proj['name']+')', aid, aufg['project_id'])
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/aufgaben/<aid>/status', methods=['PATCH'])
def quick_status(aid):
    d = request.json
    status = d.get('status')
    user = d.get('user','')
    with get_db() as conn:
        ver = row_to_dict(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver DESC LIMIT 1",(aid,)).fetchone())
        if not ver: return jsonify({'error':'Nicht gefunden'}), 404
        old_status = ver['status']
        conn.execute("UPDATE versionen SET status=? WHERE id=?",(status,ver['id']))
        if status == 'Abgeschlossen' and old_status != 'Abgeschlossen':
            aufg = row_to_dict(conn.execute("SELECT * FROM aufgaben WHERE id=?",(aid,)).fetchone())
            proj = row_to_dict(conn.execute("SELECT * FROM projects WHERE id=?",(aufg['project_id'],)).fetchone())
            outs = rows_to_list(conn.execute("SELECT * FROM outputs WHERE version_id=?",(ver['id'],)).fetchall())
            for out in outs:
                if out.get('ziel') and out['ziel'] != user:
                    send_notif(conn, out['ziel'], '"'+ aufg['name']+'" wurde abgeschlossen. Du kannst jetzt beginnen! (Projekt: '+proj['name']+')', aid, aufg['project_id'])
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/aufgaben/<aid>/version/latest', methods=['DELETE'])
def delete_latest_version(aid):
    with get_db() as conn:
        vers = rows_to_list(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver",(aid,)).fetchall())
        if len(vers) <= 1: return jsonify({'error':'Nur eine Version'}), 400
        last = vers[-1]
        conn.execute("DELETE FROM inputs WHERE version_id=?", (last['id'],))
        conn.execute("DELETE FROM outputs WHERE version_id=?", (last['id'],))
        conn.execute("DELETE FROM versionen WHERE id=?", (last['id'],))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/versionen/<int:vid>', methods=['DELETE'])
def delete_version(vid):
    with get_db() as conn:
        conn.execute("DELETE FROM inputs WHERE version_id=?", (vid,))
        conn.execute("DELETE FROM outputs WHERE version_id=?", (vid,))
        conn.execute("DELETE FROM versionen WHERE id=?", (vid,))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/aufgaben/<aid>', methods=['DELETE'])
def delete_aufgabe(aid):
    with get_db() as conn:
        vers = rows_to_list(conn.execute("SELECT id FROM versionen WHERE aufgabe_id=?",(aid,)).fetchall())
        for v in vers:
            conn.execute("DELETE FROM inputs WHERE version_id=?", (v['id'],))
            conn.execute("DELETE FROM outputs WHERE version_id=?", (v['id'],))
        conn.execute("DELETE FROM versionen WHERE aufgabe_id=?", (aid,))
        conn.execute("DELETE FROM aufgaben WHERE id=?", (aid,))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/aufgaben/<aid>/revision', methods=['POST'])
def create_revision(aid):
    d = request.json
    with get_db() as conn:
        vers = rows_to_list(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver",(aid,)).fetchall())
        prev = vers[-1]
        new_ver = len(vers) + 1
        conn.execute("INSERT INTO versionen (aufgabe_id,ver,status,soll,ist,termin,notes,grund,created_by) VALUES (?,?,?,?,0,?,?,?,?)",
                     (aid,new_ver,'In Bearbeitung',d.get('soll',prev['soll']),d.get('termin',prev['termin']),'',d.get('grund',''),d.get('created_by','')))
        conn.commit()
    return jsonify({'ok':True})

# ── BİLDİRİMLER ───────────────────────────────────
@app.route('/api/notifications/<user>')
def get_notifications(user):
    with get_db() as conn:
        return jsonify(rows_to_list(conn.execute("SELECT * FROM notifications WHERE user_name=? ORDER BY created_at DESC LIMIT 30",(user,)).fetchall()))

@app.route('/api/notifications/<int:nid>/read', methods=['PATCH'])
def mark_read(nid):
    with get_db() as conn:
        conn.execute("UPDATE notifications SET read=1 WHERE id=?", (nid,))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/notifications/readall/<user>', methods=['PATCH'])
def mark_all_read(user):
    with get_db() as conn:
        conn.execute("UPDATE notifications SET read=1 WHERE user_name=?", (user,))
        conn.commit()
    return jsonify({'ok':True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=port)
