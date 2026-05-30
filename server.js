const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// DB yolu - Render'da /data klasörü kalıcı
const DB_DIR = process.env.DB_DIR || path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(path.join(DB_DIR, 'planwerk.db'));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── DB KURULUM ─────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    role TEXT DEFAULT 'user',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    desc TEXT,
    owner TEXT,
    deadline TEXT,
    color TEXT DEFAULT '#00897b',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS aufgaben (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    name TEXT NOT NULL,
    owner TEXT,
    dept TEXT,
    abh TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );

  CREATE TABLE IF NOT EXISTS versionen (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    aufgabe_id TEXT NOT NULL,
    ver INTEGER NOT NULL,
    status TEXT DEFAULT 'Offen',
    soll REAL DEFAULT 0,
    ist REAL DEFAULT 0,
    termin TEXT,
    notes TEXT,
    grund TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (aufgabe_id) REFERENCES aufgaben(id)
  );

  CREATE TABLE IF NOT EXISTS inputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL,
    name TEXT,
    von TEXT,
    abt TEXT,
    datum TEXT,
    FOREIGN KEY (version_id) REFERENCES versionen(id)
  );

  CREATE TABLE IF NOT EXISTS outputs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    version_id INTEGER NOT NULL,
    name TEXT,
    ziel TEXT,
    abt TEXT,
    datum TEXT,
    FOREIGN KEY (version_id) REFERENCES versionen(id)
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_name TEXT NOT NULL,
    message TEXT NOT NULL,
    aufgabe_id TEXT,
    project_id TEXT,
    read INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// Admin kullanıcıyı ekle
const adminExists = db.prepare('SELECT id FROM users WHERE name = ?').get('Admin');
if (!adminExists) {
  db.prepare('INSERT INTO users (name, role) VALUES (?, ?)').run('Admin', 'admin');
}

// ── HELPER ─────────────────────────────────────────────────
function getFullProject(projectId) {
  const proj = db.prepare('SELECT * FROM projects WHERE id = ?').get(projectId);
  if (!proj) return null;

  const aufgaben = db.prepare('SELECT * FROM aufgaben WHERE project_id = ? ORDER BY created_at').all(projectId);

  proj.aufgaben = aufgaben.map(a => {
    const versionen = db.prepare('SELECT * FROM versionen WHERE aufgabe_id = ? ORDER BY ver').all(a.id);
    const fullVers = versionen.map(v => {
      v.inputs = db.prepare('SELECT * FROM inputs WHERE version_id = ?').all(v.id);
      v.outputs = db.prepare('SELECT * FROM outputs WHERE version_id = ?').all(v.id);
      return v;
    });
    return { ...a, versionen: fullVers };
  });

  return proj;
}

// ── AUTH ───────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { name, password } = req.body;
  if (!name) return res.status(400).json({ error: 'Name erforderlich' });

  // Admin kontrolü
  if (name === 'Admin') {
    if (password !== 'Serhat1133.') return res.status(401).json({ error: 'Falsches Passwort' });
    return res.json({ name: 'Admin', role: 'admin' });
  }

  // Normal kullanıcı - yoksa oluştur
  let user = db.prepare('SELECT * FROM users WHERE name = ?').get(name);
  if (!user) {
    db.prepare('INSERT INTO users (name, role) VALUES (?, ?)').run(name, 'user');
    user = db.prepare('SELECT * FROM users WHERE name = ?').get(name);
  }
  res.json({ name: user.name, role: user.role });
});

// ── USERS ──────────────────────────────────────────────────
app.get('/api/users', (req, res) => {
  const users = db.prepare('SELECT name, role FROM users ORDER BY name').all();
  res.json(users);
});

// ── PROJECTS ───────────────────────────────────────────────
app.get('/api/projects', (req, res) => {
  const projects = db.prepare('SELECT * FROM projects ORDER BY created_at').all();
  res.json(projects);
});

app.post('/api/projects', (req, res) => {
  const { id, name, desc, owner, deadline, color } = req.body;
  db.prepare('INSERT INTO projects (id, name, desc, owner, deadline, color) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, name, desc || '', owner || '', deadline || '', color || '#00897b');
  res.json({ ok: true });
});

app.get('/api/projects/:id', (req, res) => {
  const proj = getFullProject(req.params.id);
  if (!proj) return res.status(404).json({ error: 'Nicht gefunden' });
  res.json(proj);
});

// ── AUFGABEN ───────────────────────────────────────────────
app.post('/api/aufgaben', (req, res) => {
  const { id, project_id, name, owner, dept, abh, created_by, version } = req.body;

  db.prepare('INSERT INTO aufgaben (id, project_id, name, owner, dept, abh, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(id, project_id, name, owner || '', dept || '', abh || '', created_by || '');

  // İlk versiyon
  const vRes = db.prepare('INSERT INTO versionen (aufgabe_id, ver, status, soll, ist, termin, notes, grund, created_by) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?)')
    .run(id, version.status || 'Offen', version.soll || 0, version.ist || 0, version.termin || '', version.notes || '', '', created_by || '');

  const vId = vRes.lastInsertRowid;
  (version.inputs || []).forEach(inp => {
    db.prepare('INSERT INTO inputs (version_id, name, von, abt, datum) VALUES (?, ?, ?, ?, ?)').run(vId, inp.name, inp.von, inp.abt, inp.datum);
  });
  (version.outputs || []).forEach(out => {
    db.prepare('INSERT INTO outputs (version_id, name, ziel, abt, datum) VALUES (?, ?, ?, ?, ?)').run(vId, out.name, out.ziel, out.abt, out.datum);
  });

  res.json({ ok: true });
});

app.put('/api/aufgaben/:id', (req, res) => {
  const { name, owner, dept, abh, version } = req.body;
  db.prepare('UPDATE aufgaben SET name=?, owner=?, dept=?, abh=? WHERE id=?')
    .run(name, owner || '', dept || '', abh || '', req.params.id);

  // Aktif versiyonu güncelle
  const v = db.prepare('SELECT * FROM versionen WHERE aufgabe_id = ? ORDER BY ver DESC LIMIT 1').get(req.params.id);
  if (v && version) {
    db.prepare('UPDATE versionen SET status=?, soll=?, ist=?, termin=?, notes=? WHERE id=?')
      .run(version.status, version.soll || 0, version.ist || 0, version.termin || '', version.notes || '', v.id);

    db.prepare('DELETE FROM inputs WHERE version_id = ?').run(v.id);
    db.prepare('DELETE FROM outputs WHERE version_id = ?').run(v.id);
    (version.inputs || []).forEach(inp => {
      db.prepare('INSERT INTO inputs (version_id, name, von, abt, datum) VALUES (?, ?, ?, ?, ?)').run(v.id, inp.name, inp.von, inp.abt, inp.datum);
    });
    (version.outputs || []).forEach(out => {
      db.prepare('INSERT INTO outputs (version_id, name, ziel, abt, datum) VALUES (?, ?, ?, ?, ?)').run(v.id, out.name, out.ziel, out.abt, out.datum);
    });

    // Abgeschlossen yapılınca bildirim gönder
    if (version.status === 'Abgeschlossen') {
      const aufg = db.prepare('SELECT * FROM aufgaben WHERE id = ?').get(req.params.id);
      const proj = db.prepare('SELECT * FROM projects WHERE id = ?').get(aufg.project_id);
      const outputs = db.prepare('SELECT * FROM outputs WHERE version_id = ?').all(v.id);
      outputs.forEach(out => {
        if (out.ziel) {
          db.prepare('INSERT INTO notifications (user_name, message, aufgabe_id, project_id) VALUES (?, ?, ?, ?)')
            .run(out.ziel, aufg.name + ' wurde abgeschlossen. Projekt: ' + proj.name, aufg.id, aufg.project_id);
        }
      });
    }
  }

  res.json({ ok: true });
});

// Status hızlı güncelle
app.patch('/api/aufgaben/:id/status', (req, res) => {
  const { status, user } = req.body;
  const v = db.prepare('SELECT * FROM versionen WHERE aufgabe_id = ? ORDER BY ver DESC LIMIT 1').get(req.params.id);
  if (!v) return res.status(404).json({ error: 'Version nicht gefunden' });

  db.prepare('UPDATE versionen SET status = ? WHERE id = ?').run(status, v.id);

  // Abgeschlossen → bildirim
  if (status === 'Abgeschlossen') {
    const aufg = db.prepare('SELECT * FROM aufgaben WHERE id = ?').get(req.params.id);
    const proj = db.prepare('SELECT * FROM projects WHERE id = ?').get(aufg.project_id);
    const outputs = db.prepare('SELECT * FROM outputs WHERE version_id = ?').all(v.id);
    outputs.forEach(out => {
      if (out.ziel && out.ziel !== user) {
        db.prepare('INSERT INTO notifications (user_name, message, aufgabe_id, project_id) VALUES (?, ?, ?, ?)')
          .run(out.ziel, '"' + aufg.name + '" wurde abgeschlossen. Du kannst jetzt beginnen! (Projekt: ' + proj.name + ')', aufg.id, aufg.project_id);
      }
    });
  }

  res.json({ ok: true });
});

// Aktif versiyonu sil
app.delete('/api/aufgaben/:id/version/latest', (req, res) => {
  const vers = db.prepare('SELECT * FROM versionen WHERE aufgabe_id = ? ORDER BY ver').all(req.params.id);
  if (vers.length <= 1) return res.status(400).json({ error: 'Nur eine Version vorhanden' });
  const last = vers[vers.length - 1];
  db.prepare('DELETE FROM inputs WHERE version_id = ?').run(last.id);
  db.prepare('DELETE FROM outputs WHERE version_id = ?').run(last.id);
  db.prepare('DELETE FROM versionen WHERE id = ?').run(last.id);
  res.json({ ok: true });
});

// Arşiv versiyonu sil (sadece admin)
app.delete('/api/versionen/:id', (req, res) => {
  db.prepare('DELETE FROM inputs WHERE version_id = ?').run(req.params.id);
  db.prepare('DELETE FROM outputs WHERE version_id = ?').run(req.params.id);
  db.prepare('DELETE FROM versionen WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Tüm görevi sil (sadece admin)
app.delete('/api/aufgaben/:id', (req, res) => {
  const vers = db.prepare('SELECT id FROM versionen WHERE aufgabe_id = ?').all(req.params.id);
  vers.forEach(v => {
    db.prepare('DELETE FROM inputs WHERE version_id = ?').run(v.id);
    db.prepare('DELETE FROM outputs WHERE version_id = ?').run(v.id);
  });
  db.prepare('DELETE FROM versionen WHERE aufgabe_id = ?').run(req.params.id);
  db.prepare('DELETE FROM aufgaben WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Revizyon ekle
app.post('/api/aufgaben/:id/revision', (req, res) => {
  const { soll, termin, grund, created_by } = req.body;
  const vers = db.prepare('SELECT * FROM versionen WHERE aufgabe_id = ? ORDER BY ver').all(req.params.id);
  const newVer = vers.length + 1;
  const prev = vers[vers.length - 1];
  db.prepare('INSERT INTO versionen (aufgabe_id, ver, status, soll, ist, termin, notes, grund, created_by) VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?)')
    .run(req.params.id, newVer, 'In Bearbeitung', soll || prev.soll, termin || prev.termin, '', grund || '', created_by || '');
  res.json({ ok: true });
});

// ── BİLDİRİMLER ────────────────────────────────────────────
app.get('/api/notifications/:user', (req, res) => {
  const notifs = db.prepare('SELECT * FROM notifications WHERE user_name = ? ORDER BY created_at DESC LIMIT 20').all(req.params.user);
  res.json(notifs);
});

app.patch('/api/notifications/:id/read', (req, res) => {
  db.prepare('UPDATE notifications SET read = 1 WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.patch('/api/notifications/readall/:user', (req, res) => {
  db.prepare('UPDATE notifications SET read = 1 WHERE user_name = ?').run(req.params.user);
  res.json({ ok: true });
});

// ── START ──────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log('Planwerk läuft auf Port ' + PORT);
});
