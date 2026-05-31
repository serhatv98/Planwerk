from flask import Flask, request, jsonify, send_from_directory
import sqlite3, os, hashlib
from datetime import datetime

import os as _os
_base = _os.path.dirname(_os.path.abspath(__file__))
_static = _os.path.join(_base, 'public') if _os.path.exists(_os.path.join(_base, 'public', 'index.html')) else _base
app = Flask(__name__, static_folder=_static, static_url_path='')

DB_DIR = os.environ.get('DB_DIR', os.path.join(os.path.dirname(__file__), 'db'))
os.makedirs(DB_DIR, exist_ok=True)
DB_PATH = os.path.join(DB_DIR, 'planwerk.db')
ADMIN_PW = 'SBG1234'

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

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
            name TEXT UNIQUE NOT NULL, role TEXT DEFAULT 'user',
            password_hash TEXT, must_change_pw INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS abteilungen (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );
        CREATE TABLE IF NOT EXISTS abteilung_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            abteilung_id INTEGER NOT NULL, user_name TEXT NOT NULL,
            UNIQUE(abteilung_id, user_name)
        );
        CREATE TABLE IF NOT EXISTS projects (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, desc TEXT,
            owner TEXT, deadline TEXT, color TEXT DEFAULT '#00897b',
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS project_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id TEXT NOT NULL, user_name TEXT NOT NULL,
            can_edit INTEGER DEFAULT 0, can_delete INTEGER DEFAULT 0,
            UNIQUE(project_id, user_name)
        );
        CREATE TABLE IF NOT EXISTS aufgaben (
            id TEXT PRIMARY KEY, project_id TEXT NOT NULL,
            name TEXT NOT NULL,
            abteilung TEXT,
            bearbeiter TEXT, pruefer TEXT, freigabe TEXT,
            depends_on TEXT,
            status TEXT DEFAULT 'Ausstehend',
            accepted_by TEXT, accepted_at TEXT,
            est_finish TEXT,
            created_by TEXT, created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            aufgabe_id TEXT NOT NULL,
            old_status TEXT, new_status TEXT,
            changed_by TEXT,
            changed_at TEXT DEFAULT (datetime('now'))
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
            name TEXT, von_aufgabe_id TEXT, von_abt TEXT, fertig INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS outputs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, version_id INTEGER NOT NULL,
            name TEXT, fuer_aufgabe_id TEXT, fuer_abt TEXT,
            abgeschlossen_at TEXT
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_name TEXT NOT NULL, message TEXT NOT NULL,
            aufgabe_id TEXT, project_id TEXT, type TEXT DEFAULT 'info',
            read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        );
        ''')
        conn.commit()

init_db()

def row_to_dict(row): return dict(row) if row else None
def rows_to_list(rows): return [dict(r) for r in rows]

def send_notif(conn, user_name, message, aufgabe_id=None, project_id=None, ntype='info'):
    if not user_name: return
    user = conn.execute("SELECT id FROM users WHERE name=?", (user_name,)).fetchone()
    if user:
        conn.execute("INSERT INTO notifications (user_name,message,aufgabe_id,project_id,type) VALUES (?,?,?,?,?)",
                     (user_name, message, aufgabe_id, project_id, ntype))

def send_notif_to_abt(conn, abt_name, message, aufgabe_id=None, project_id=None, ntype='info', exclude=None):
    members = rows_to_list(conn.execute(
        "SELECT am.user_name FROM abteilung_members am JOIN abteilungen a ON a.id=am.abteilung_id WHERE a.name=?",
        (abt_name,)).fetchall())
    for m in members:
        if m['user_name'] != exclude:
            send_notif(conn, m['user_name'], message, aufgabe_id, project_id, ntype)

def get_full_project(pid):
    with get_db() as conn:
        proj = row_to_dict(conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone())
        if not proj: return None
        proj['members'] = rows_to_list(conn.execute("SELECT * FROM project_members WHERE project_id=?", (pid,)).fetchall())
        aufgaben = rows_to_list(conn.execute("SELECT * FROM aufgaben WHERE project_id=? ORDER BY created_at", (pid,)).fetchall())
        for a in aufgaben:
            vers = rows_to_list(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver", (a['id'],)).fetchall())
            for v in vers:
                v['inputs'] = rows_to_list(conn.execute("SELECT * FROM inputs WHERE version_id=?", (v['id'],)).fetchall())
                v['outputs'] = rows_to_list(conn.execute("SELECT * FROM outputs WHERE version_id=?", (v['id'],)).fetchall())
            a['versionen'] = vers
            a['status_history'] = rows_to_list(conn.execute(
                "SELECT * FROM status_history WHERE aufgabe_id=? ORDER BY changed_at", (a['id'],)).fetchall())
        proj['aufgaben'] = aufgaben
        return proj

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

# ── AUTH ──────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    d = request.json
    name = d.get('name','').strip()
    pw = d.get('password','')
    if not name or not pw: return jsonify({'error':'Name und Passwort erforderlich'}), 400
    if name == 'Admin':
        if pw != ADMIN_PW: return jsonify({'error':'Falsches Passwort'}), 401
        return jsonify({'name':'Admin','role':'admin','must_change_pw':False})
    with get_db() as conn:
        user = row_to_dict(conn.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone())
        if not user: return jsonify({'error':'Benutzer nicht gefunden'}), 401
        if user['password_hash'] != hash_pw(pw): return jsonify({'error':'Falsches Passwort'}), 401
        return jsonify({'name':user['name'],'role':user['role'],'must_change_pw':bool(user['must_change_pw'])})

@app.route('/api/change_password', methods=['POST'])
def change_password():
    d = request.json
    name = d.get('name','')
    old_pw = d.get('old_password','')
    new_pw = d.get('new_password','')
    if len(new_pw) < 4: return jsonify({'error':'Min. 4 Zeichen'}), 400
    with get_db() as conn:
        user = row_to_dict(conn.execute("SELECT * FROM users WHERE name=?", (name,)).fetchone())
        if not user: return jsonify({'error':'Nicht gefunden'}), 404
        if user['password_hash'] != hash_pw(old_pw): return jsonify({'error':'Altes Passwort falsch'}), 401
        conn.execute("UPDATE users SET password_hash=?,must_change_pw=0 WHERE name=?", (hash_pw(new_pw),name))
        conn.commit()
    return jsonify({'ok':True})

# ── USERS ─────────────────────────────────────────
@app.route('/api/users', methods=['GET'])
def get_users():
    with get_db() as conn:
        return jsonify(rows_to_list(conn.execute("SELECT id,name,role,must_change_pw,created_at FROM users ORDER BY name").fetchall()))

@app.route('/api/users', methods=['POST'])
def create_user():
    d = request.json
    name = d.get('name','').strip()
    pw = d.get('password','')
    if not name or not pw: return jsonify({'error':'Name und Passwort erforderlich'}), 400
    with get_db() as conn:
        if conn.execute("SELECT id FROM users WHERE name=?", (name,)).fetchone():
            return jsonify({'error':'Benutzer existiert bereits'}), 409
        conn.execute("INSERT INTO users (name,role,password_hash,must_change_pw) VALUES (?,?,?,1)",
                     (name,d.get('role','user'),hash_pw(pw)))
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
    pw = d.get('password','')
    if not pw: return jsonify({'error':'Passwort erforderlich'}), 400
    with get_db() as conn:
        conn.execute("UPDATE users SET password_hash=?,must_change_pw=1 WHERE name=?", (hash_pw(pw),name))
        conn.commit()
    return jsonify({'ok':True})

# ── ABTEİLUNGEN ───────────────────────────────────
@app.route('/api/abteilungen', methods=['GET'])
def get_abteilungen():
    with get_db() as conn:
        return jsonify(rows_to_list(conn.execute("SELECT * FROM abteilungen ORDER BY name").fetchall()))

@app.route('/api/abteilungen/with_members', methods=['GET'])
def get_abteilungen_with_members():
    with get_db() as conn:
        abts = rows_to_list(conn.execute("SELECT * FROM abteilungen ORDER BY name").fetchall())
        for a in abts:
            a['members'] = rows_to_list(conn.execute("SELECT * FROM abteilung_members WHERE abteilung_id=?", (a['id'],)).fetchall())
        return jsonify(abts)

@app.route('/api/abteilungen', methods=['POST'])
def create_abteilung():
    name = request.json.get('name','').strip()
    if not name: return jsonify({'error':'Name erforderlich'}), 400
    with get_db() as conn:
        if conn.execute("SELECT id FROM abteilungen WHERE name=?", (name,)).fetchone():
            return jsonify({'error':'Existiert bereits'}), 409
        conn.execute("INSERT INTO abteilungen (name) VALUES (?)", (name,))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/abteilungen/<int:aid>', methods=['DELETE'])
def delete_abteilung(aid):
    with get_db() as conn:
        conn.execute("DELETE FROM abteilungen WHERE id=?", (aid,))
        conn.execute("DELETE FROM abteilung_members WHERE abteilung_id=?", (aid,))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/abteilungen/<int:aid>/members', methods=['POST'])
def add_abt_member(aid):
    user_name = request.json.get('user_name','').strip()
    if not user_name: return jsonify({'error':'Name erforderlich'}), 400
    with get_db() as conn:
        conn.execute("INSERT OR IGNORE INTO abteilung_members (abteilung_id,user_name) VALUES (?,?)", (aid,user_name))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/abteilungen/<int:aid>/members/<user_name>', methods=['DELETE'])
def remove_abt_member(aid, user_name):
    with get_db() as conn:
        conn.execute("DELETE FROM abteilung_members WHERE abteilung_id=? AND user_name=?", (aid,user_name))
        conn.commit()
    return jsonify({'ok':True})

# ── PROJECTS ──────────────────────────────────────
@app.route('/api/projects', methods=['GET'])
def get_projects():
    user_name = request.args.get('user','')
    role = request.args.get('role','')
    with get_db() as conn:
        if role == 'admin':
            projs = rows_to_list(conn.execute("SELECT * FROM projects ORDER BY created_at").fetchall())
        else:
            projs = rows_to_list(conn.execute(
                "SELECT p.* FROM projects p JOIN project_members pm ON p.id=pm.project_id WHERE pm.user_name=? ORDER BY p.created_at",
                (user_name,)).fetchall())
        for p in projs:
            p['members'] = rows_to_list(conn.execute("SELECT * FROM project_members WHERE project_id=?", (p['id'],)).fetchall())
        return jsonify(projs)

@app.route('/api/projects', methods=['POST'])
def create_project():
    d = request.json
    with get_db() as conn:
        conn.execute("INSERT INTO projects (id,name,desc,owner,deadline,color) VALUES (?,?,?,?,?,?)",
                     (d['id'],d['name'],d.get('desc',''),d.get('owner',''),d.get('deadline',''),d.get('color','#00897b')))
        if d.get('created_by') and d.get('created_by') != 'Admin':
            conn.execute("INSERT OR IGNORE INTO project_members (project_id,user_name,can_edit,can_delete) VALUES (?,?,1,1)",
                         (d['id'],d['created_by']))
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
            conn.execute("DELETE FROM status_history WHERE aufgabe_id=?", (a['id'],))
        conn.execute("DELETE FROM aufgaben WHERE project_id=?", (pid,))
        conn.execute("DELETE FROM project_members WHERE project_id=?", (pid,))
        conn.execute("DELETE FROM projects WHERE id=?", (pid,))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/projects/<pid>/members', methods=['POST'])
def add_member(pid):
    d = request.json
    user_name = d.get('user_name','')
    can_edit = 1 if d.get('can_edit') else 0
    can_delete = 1 if d.get('can_delete') else 0
    with get_db() as conn:
        conn.execute("INSERT OR REPLACE INTO project_members (project_id,user_name,can_edit,can_delete) VALUES (?,?,?,?)",
                     (pid,user_name,can_edit,can_delete))
        proj = row_to_dict(conn.execute("SELECT * FROM projects WHERE id=?", (pid,)).fetchone())
        send_notif(conn, user_name, 'Du wurdest zum Projekt "'+proj['name']+'" hinzugefuegt.', None, pid, 'project')
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/projects/<pid>/members/<user_name>', methods=['DELETE'])
def remove_member(pid, user_name):
    with get_db() as conn:
        conn.execute("DELETE FROM project_members WHERE project_id=? AND user_name=?", (pid,user_name))
        conn.commit()
    return jsonify({'ok':True})

# ── AUFGABEN ──────────────────────────────────────
@app.route('/api/aufgaben', methods=['POST'])
def create_aufgabe():
    d = request.json
    now = datetime.now().isoformat()
    with get_db() as conn:
        conn.execute("""INSERT INTO aufgaben 
            (id,project_id,name,abteilung,bearbeiter,pruefer,freigabe,depends_on,status,est_finish,created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (d['id'],d['project_id'],d['name'],d.get('abteilung',''),
             d.get('bearbeiter',''),d.get('pruefer',''),d.get('freigabe',''),
             d.get('depends_on',''),d.get('status','Ausstehend'),
             d.get('est_finish',''),d.get('created_by','')))
        
        # Status history
        conn.execute("INSERT INTO status_history (aufgabe_id,old_status,new_status,changed_by) VALUES (?,?,?,?)",
                     (d['id'],'',d.get('status','Ausstehend'),d.get('created_by','')))
        
        # Versiyon oluştur
        r = conn.execute("INSERT INTO versionen (aufgabe_id,ver,status,soll,ist,termin,notes,grund,created_by) VALUES (?,1,?,?,?,?,?,?,?)",
                         (d['id'],d.get('status','Ausstehend'),d.get('soll',0),0,d.get('est_finish',''),'','',d.get('created_by','')))
        vid = r.lastrowid
        
        # Inputlar
        for inp in d.get('inputs',[]):
            conn.execute("INSERT INTO inputs (version_id,name,von_aufgabe_id,von_abt,fertig) VALUES (?,?,?,?,0)",
                         (vid,inp.get('name',''),inp.get('von_aufgabe_id',''),inp.get('von_abt','')))
        
        # Outputlar
        for out in d.get('outputs',[]):
            conn.execute("INSERT INTO outputs (version_id,name,fuer_aufgabe_id,fuer_abt) VALUES (?,?,?,?)",
                         (vid,out.get('name',''),out.get('fuer_aufgabe_id',''),out.get('fuer_abt','')))

        proj = row_to_dict(conn.execute("SELECT * FROM projects WHERE id=?", (d['project_id'],)).fetchone())
        
        # Depends_on olan abteilung'a bildirim
        if d.get('depends_on'):
            dep_aufg = row_to_dict(conn.execute("SELECT * FROM aufgaben WHERE id=?", (d['depends_on'],)).fetchone())
            if dep_aufg and dep_aufg.get('abteilung'):
                msg = '"'+d['name']+'" goerevi icin "'+dep_aufg['name']+'" gereklidir. Bitte bestaetigen. (Projekt: '+proj['name']+')'
                send_notif_to_abt(conn, dep_aufg['abteilung'], msg, d['id'], d['project_id'], 'request', d.get('created_by'))

        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/aufgaben/<aid>', methods=['PUT'])
def update_aufgabe(aid):
    d = request.json
    with get_db() as conn:
        old = row_to_dict(conn.execute("SELECT * FROM aufgaben WHERE id=?", (aid,)).fetchone())
        conn.execute("""UPDATE aufgaben SET name=?,abteilung=?,bearbeiter=?,pruefer=?,freigabe=?,
                     depends_on=?,est_finish=? WHERE id=?""",
                     (d['name'],d.get('abteilung',''),d.get('bearbeiter',''),
                      d.get('pruefer',''),d.get('freigabe',''),
                      d.get('depends_on',''),d.get('est_finish',''),aid))
        
        # Versiyon güncelle
        ver = row_to_dict(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver DESC LIMIT 1",(aid,)).fetchone())
        if ver:
            conn.execute("UPDATE versionen SET soll=?,termin=?,notes=? WHERE id=?",
                         (d.get('soll',0),d.get('est_finish',''),d.get('notes',''),ver['id']))
            conn.execute("DELETE FROM inputs WHERE version_id=?", (ver['id'],))
            conn.execute("DELETE FROM outputs WHERE version_id=?", (ver['id'],))
            for inp in d.get('inputs',[]):
                conn.execute("INSERT INTO inputs (version_id,name,von_aufgabe_id,von_abt,fertig) VALUES (?,?,?,?,0)",
                             (ver['id'],inp.get('name',''),inp.get('von_aufgabe_id',''),inp.get('von_abt','')))
            for out in d.get('outputs',[]):
                conn.execute("INSERT INTO outputs (version_id,name,fuer_aufgabe_id,fuer_abt) VALUES (?,?,?,?)",
                             (ver['id'],out.get('name',''),out.get('fuer_aufgabe_id',''),out.get('fuer_abt','')))
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/aufgaben/<aid>/accept', methods=['POST'])
def accept_aufgabe(aid):
    d = request.json
    now = datetime.now().isoformat()
    with get_db() as conn:
        aufg = row_to_dict(conn.execute("SELECT * FROM aufgaben WHERE id=?", (aid,)).fetchone())
        if not aufg: return jsonify({'error':'Nicht gefunden'}), 404
        
        conn.execute("""UPDATE aufgaben SET status='In Bearbeitung',accepted_by=?,accepted_at=?,
                     bearbeiter=?,pruefer=?,freigabe=?,est_finish=? WHERE id=?""",
                     (d.get('accepted_by',''),now,
                      d.get('bearbeiter',''),d.get('pruefer',''),d.get('freigabe',''),
                      d.get('est_finish',''),aid))
        
        conn.execute("INSERT INTO status_history (aufgabe_id,old_status,new_status,changed_by) VALUES (?,?,?,?)",
                     (aid,aufg['status'],'In Bearbeitung',d.get('accepted_by','')))
        
        proj = row_to_dict(conn.execute("SELECT * FROM projects WHERE id=?", (aufg['project_id'],)).fetchone())
        
        # Görevi isteyen abteilung'a bildirim
        # O görevin depend eden görevi bul
        dep_aufgaben = rows_to_list(conn.execute("SELECT * FROM aufgaben WHERE depends_on=?", (aid,)).fetchall())
        for dep in dep_aufgaben:
            if dep.get('abteilung'):
                msg = '"'+aufg['name']+'" kabul edildi. Bearbeiter: '+d.get('bearbeiter','')+', Tahmini bitis: '+d.get('est_finish','—')+'  (Projekt: '+proj['name']+')'
                send_notif_to_abt(conn, dep['abteilung'], msg, aid, aufg['project_id'], 'accepted')
        
        conn.commit()
    return jsonify({'ok':True})

@app.route('/api/aufgaben/<aid>/status', methods=['PATCH'])
def quick_status(aid):
    d = request.json
    new_status = d.get('status')
    changed_by = d.get('user','')
    now = datetime.now().isoformat()
    with get_db() as conn:
        aufg = row_to_dict(conn.execute("SELECT * FROM aufgaben WHERE id=?", (aid,)).fetchone())
        if not aufg: return jsonify({'error':'Nicht gefunden'}), 404
        old_status = aufg['status']
        
        conn.execute("UPDATE aufgaben SET status=? WHERE id=?", (new_status,aid))
        conn.execute("INSERT INTO status_history (aufgabe_id,old_status,new_status,changed_by) VALUES (?,?,?,?)",
                     (aid,old_status,new_status,changed_by))
        
        # Versiyonu da güncelle
        ver = row_to_dict(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver DESC LIMIT 1",(aid,)).fetchone())
        if ver:
            conn.execute("UPDATE versionen SET status=? WHERE id=?", (new_status,ver['id']))

        proj = row_to_dict(conn.execute("SELECT * FROM projects WHERE id=?", (aufg['project_id'],)).fetchone())
        
        if new_status == 'Abgeschlossen' and old_status != 'Abgeschlossen':
            # Output tarihlerini güncelle
            ver = row_to_dict(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver DESC LIMIT 1",(aid,)).fetchone())
            if ver:
                conn.execute("UPDATE outputs SET abgeschlossen_at=? WHERE version_id=?", (now,ver['id']))
                
                # Bağımlı görevlerin inputlarını güncelle
                outs = rows_to_list(conn.execute("SELECT * FROM outputs WHERE version_id=?", (ver['id'],)).fetchall())
                dep_aufgaben = rows_to_list(conn.execute("SELECT * FROM aufgaben WHERE depends_on=?", (aid,)).fetchall())
                
                for dep in dep_aufgaben:
                    # O görevin inputlarını hazır işaretle
                    dep_ver = row_to_dict(conn.execute("SELECT * FROM versionen WHERE aufgabe_id=? ORDER BY ver DESC LIMIT 1",(dep['id'],)).fetchone())
                    if dep_ver:
                        conn.execute("UPDATE inputs SET fertig=1 WHERE version_id=? AND von_aufgabe_id=?", (dep_ver['id'],aid))
                    
                    # Bildirim gönder
                    if dep.get('abteilung'):
                        msg = '"'+aufg['name']+'" abgeschlossen! "'+dep['name']+'" kann jetzt beginnen. (Projekt: '+proj['name']+')'
                        send_notif_to_abt(conn, dep['abteilung'], msg, dep['id'], aufg['project_id'], 'ready')
                    
                    # Direkt kişilere de bildirim
                    for person in [dep.get('bearbeiter'),dep.get('pruefer')]:
                        if person and person != changed_by:
                            send_notif(conn, person, '"'+aufg['name']+'" abgeschlossen! "'+dep['name']+'" kann jetzt beginnen. (Projekt: '+proj['name']+')', dep['id'], aufg['project_id'], 'ready')
        
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
        conn.execute("UPDATE aufgaben SET status='In Bearbeitung' WHERE id=?", (aid,))
        conn.execute("INSERT INTO status_history (aufgabe_id,old_status,new_status,changed_by) VALUES (?,?,?,?)",
                     (aid,'Abgeschlossen','In Bearbeitung (Revision)',d.get('created_by','')))
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

@app.route('/api/aufgaben/<aid>', methods=['DELETE'])
def delete_aufgabe(aid):
    with get_db() as conn:
        vers = rows_to_list(conn.execute("SELECT id FROM versionen WHERE aufgabe_id=?",(aid,)).fetchall())
        for v in vers:
            conn.execute("DELETE FROM inputs WHERE version_id=?", (v['id'],))
            conn.execute("DELETE FROM outputs WHERE version_id=?", (v['id'],))
        conn.execute("DELETE FROM versionen WHERE aufgabe_id=?", (aid,))
        conn.execute("DELETE FROM status_history WHERE aufgabe_id=?", (aid,))
        conn.execute("DELETE FROM aufgaben WHERE id=?", (aid,))
        conn.commit()
    return jsonify({'ok':True})

# ── BİLDİRİMLER ───────────────────────────────────
@app.route('/api/notifications/<user>')
def get_notifications(user):
    with get_db() as conn:
        return jsonify(rows_to_list(conn.execute(
            "SELECT * FROM notifications WHERE user_name=? ORDER BY created_at DESC LIMIT 50",(user,)).fetchall()))

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
