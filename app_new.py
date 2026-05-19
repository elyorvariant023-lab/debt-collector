from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
from datetime import datetime
import hashlib
import os
import secrets

app = Flask(__name__, template_folder='.')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
DB_PATH = 'debt_collector.db'

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT DEFAULT 'employee',
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS debtors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            contract_number TEXT NOT NULL UNIQUE,
            debt_amount REAL NOT NULL,
            paid_amount REAL DEFAULT 0,
            due_date TEXT,
            status TEXT DEFAULT 'unpaid',
            comment TEXT,
            created_by INTEGER,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS contact_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            debtor_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            note TEXT NOT NULL,
            ptp_datetime TEXT,
            ptp_done INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (debtor_id) REFERENCES debtors(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            debtor_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            phone TEXT NOT NULL,
            message_text TEXT NOT NULL,
            sent_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (debtor_id) REFERENCES debtors(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS message_templates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE TABLE IF NOT EXISTS activity_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')

    # Create default admin
    cur = conn.execute('SELECT COUNT(*) FROM users WHERE role="admin"')
    if cur.fetchone()[0] == 0:
        conn.execute('''INSERT INTO users (username, password, full_name, role)
                        VALUES (?, ?, ?, ?)''',
                     ('admin', hash_password('admin123'), 'Administrator', 'admin'))

    # Default templates
    cur = conn.execute('SELECT COUNT(*) FROM message_templates')
    if cur.fetchone()[0] == 0:
        conn.execute('INSERT INTO message_templates (name, text) VALUES (?, ?)', (
            'Standart eslatma',
            'Hurmatli {full_name}! {contract_number}-sonli shartnoma boyicha {debt_amount} som qarzingiz mavjud. Iltimos, tolovni amalga oshiring.'
        ))
        conn.execute('INSERT INTO message_templates (name, text) VALUES (?, ?)', (
            'PTP eslatma',
            'Hurmatli {full_name}! Siz {contract_number}-sonli shartnoma boyicha {debt_amount} som tolab berishingizni vaoda qilgansiz. Iltimos, bugun tolovni amalga oshiring.'
        ))

    conn.commit()
    conn.close()

# ─── AUTH ─────────────────────────────────────────────────────────────────────

def current_user():
    if 'user_id' not in session:
        return None
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE id=? AND is_active=1', (session['user_id'],)).fetchone()
    conn.close()
    return dict(user) if user else None

def require_login(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            return jsonify({'error': 'unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        u = current_user()
        if not u or u['role'] != 'admin':
            return jsonify({'error': 'forbidden'}), 403
        return f(*args, **kwargs)
    return decorated

def log_activity(user_id, action, details=None):
    conn = get_db()
    conn.execute('INSERT INTO activity_log (user_id, action, details) VALUES (?, ?, ?)',
                 (user_id, action, details))
    conn.commit()
    conn.close()

# ─── PAGES ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if not current_user():
        return render_template('login.html')
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username=? AND password=? AND is_active=1',
                        (data['username'], hash_password(data['password']))).fetchone()
    conn.close()
    if user:
        session['user_id'] = user['id']
        log_activity(user['id'], 'login', f"Kirdi: {user['full_name']}")
        return jsonify({'success': True, 'user': {'id': user['id'], 'full_name': user['full_name'], 'role': user['role'], 'username': user['username']}})
    return jsonify({'success': False, 'error': 'Noto\'g\'ri login yoki parol'})

@app.route('/logout', methods=['POST'])
def logout():
    u = current_user()
    if u:
        log_activity(u['id'], 'logout', f"Chiqdi: {u['full_name']}")
    session.clear()
    return jsonify({'success': True})

@app.route('/api/me')
def me():
    u = current_user()
    if not u:
        return jsonify({'error': 'unauthorized'}), 401
    return jsonify(u)

# ─── USERS (admin only) ───────────────────────────────────────────────────────

@app.route('/api/users', methods=['GET'])
@require_admin
def get_users():
    conn = get_db()
    users = conn.execute('''
        SELECT u.*, COUNT(d.id) as debtor_count
        FROM users u
        LEFT JOIN debtors d ON d.created_by = u.id
        GROUP BY u.id ORDER BY u.created_at DESC
    ''').fetchall()
    conn.close()
    return jsonify([{k: v for k, v in dict(u).items() if k != 'password'} for u in users])

@app.route('/api/users', methods=['POST'])
@require_admin
def add_user():
    data = request.json
    conn = get_db()
    try:
        conn.execute('''INSERT INTO users (username, password, full_name, role)
                        VALUES (?, ?, ?, ?)''',
                     (data['username'], hash_password(data['password']),
                      data['full_name'], data.get('role', 'employee')))
        conn.commit()
        u = current_user()
        log_activity(u['id'], 'add_user', f"Yangi foydalanuvchi: {data['full_name']}")
        conn.close()
        return jsonify({'success': True})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': 'Bu username allaqachon mavjud'}), 400

@app.route('/api/users/<int:uid>', methods=['PUT'])
@require_admin
def update_user(uid):
    data = request.json
    conn = get_db()
    if data.get('password'):
        conn.execute('UPDATE users SET full_name=?, role=?, is_active=?, password=? WHERE id=?',
                     (data['full_name'], data.get('role','employee'), data.get('is_active',1), hash_password(data['password']), uid))
    else:
        conn.execute('UPDATE users SET full_name=?, role=?, is_active=? WHERE id=?',
                     (data['full_name'], data.get('role','employee'), data.get('is_active',1), uid))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/users/<int:uid>', methods=['DELETE'])
@require_admin
def delete_user(uid):
    u = current_user()
    if uid == u['id']:
        return jsonify({'success': False, 'error': 'O\'zingizni o\'chira olmaysiz'}), 400
    conn = get_db()
    conn.execute('UPDATE users SET is_active=0 WHERE id=?', (uid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ─── ACTIVITY LOG ─────────────────────────────────────────────────────────────

@app.route('/api/activity', methods=['GET'])
@require_admin
def get_activity():
    conn = get_db()
    logs = conn.execute('''
        SELECT a.*, u.full_name, u.username FROM activity_log a
        JOIN users u ON a.user_id = u.id
        ORDER BY a.created_at DESC LIMIT 200
    ''').fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])

# ─── DEBTORS ──────────────────────────────────────────────────────────────────

@app.route('/api/debtors', methods=['GET'])
@require_login
def get_debtors():
    conn = get_db()
    search = request.args.get('search', '')
    status = request.args.get('status', '')
    ptp_today = request.args.get('ptp_today', '')
    user_filter = request.args.get('user_id', '')

    if ptp_today:
        now = datetime.now().strftime('%Y-%m-%d %H:%M')
        rows = conn.execute('''
            SELECT d.*, cl.id as log_id, cl.note, cl.ptp_datetime, cl.ptp_done,
                   u.full_name as created_by_name
            FROM debtors d
            JOIN contact_logs cl ON cl.debtor_id = d.id
            LEFT JOIN users u ON d.created_by = u.id
            WHERE cl.ptp_done = 0 AND cl.ptp_datetime IS NOT NULL AND cl.ptp_datetime <= ?
              AND cl.id = (SELECT MAX(id) FROM contact_logs WHERE debtor_id=d.id AND ptp_done=0 AND ptp_datetime IS NOT NULL)
            ORDER BY cl.ptp_datetime ASC
        ''', (now,)).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])

    query = '''
        SELECT d.*,
          u.full_name as created_by_name,
          (SELECT note FROM contact_logs WHERE debtor_id=d.id ORDER BY id DESC LIMIT 1) as last_note,
          (SELECT cl2.created_at FROM contact_logs cl2 WHERE cl2.debtor_id=d.id ORDER BY cl2.id DESC LIMIT 1) as last_contact_at,
          (SELECT u2.full_name FROM contact_logs cl3 JOIN users u2 ON cl3.user_id=u2.id WHERE cl3.debtor_id=d.id ORDER BY cl3.id DESC LIMIT 1) as last_contact_by,
          (SELECT ptp_datetime FROM contact_logs WHERE debtor_id=d.id AND ptp_done=0 AND ptp_datetime IS NOT NULL ORDER BY id DESC LIMIT 1) as next_ptp
        FROM debtors d LEFT JOIN users u ON d.created_by = u.id WHERE 1=1
    '''
    params = []
    if search:
        query += ' AND (d.full_name LIKE ? OR d.contract_number LIKE ? OR d.phone LIKE ?)'
        s = f'%{search}%'; params += [s, s, s]
    if status:
        query += ' AND d.status = ?'; params.append(status)
    if user_filter:
        query += ' AND d.created_by = ?'; params.append(int(user_filter))
    query += ' ORDER BY d.created_at DESC'

    debtors = conn.execute(query, params).fetchall()
    conn.close()
    return jsonify([dict(d) for d in debtors])

@app.route('/api/debtors', methods=['POST'])
@require_login
def add_debtor():
    data = request.json
    u = current_user()
    conn = get_db()
    try:
        conn.execute('''INSERT INTO debtors (full_name, phone, contract_number, debt_amount, paid_amount, due_date, comment, created_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                     (data['full_name'], data['phone'], data['contract_number'],
                      float(data['debt_amount']), float(data.get('paid_amount', 0)),
                      data.get('due_date', ''), data.get('comment', ''), u['id']))
        conn.commit()
        new_id = conn.execute('SELECT last_insert_rowid()').fetchone()[0]
        log_activity(u['id'], 'add_debtor', f"{data['full_name']} - {data['contract_number']}")
        debtor = conn.execute('''
            SELECT d.*, u.full_name as created_by_name, NULL as last_note, NULL as next_ptp, NULL as last_contact_at, NULL as last_contact_by
            FROM debtors d LEFT JOIN users u ON d.created_by=u.id WHERE d.id=?
        ''', (new_id,)).fetchone()
        conn.close()
        return jsonify({'success': True, 'debtor': dict(debtor)})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': 'Bu shartnoma raqami allaqachon mavjud'}), 400

@app.route('/api/debtors/<int:did>', methods=['PUT'])
@require_login
def update_debtor(did):
    data = request.json
    u = current_user()
    conn = get_db()
    debt = float(data.get('debt_amount', 0))
    paid = float(data.get('paid_amount', 0))
    status = 'paid' if paid >= debt else ('partial' if paid > 0 else 'unpaid')
    conn.execute('''UPDATE debtors SET full_name=?, phone=?, contract_number=?, debt_amount=?,
                    paid_amount=?, due_date=?, status=?, comment=?, updated_at=datetime('now','localtime')
                    WHERE id=?''',
                 (data['full_name'], data['phone'], data['contract_number'],
                  debt, paid, data.get('due_date',''), status, data.get('comment',''), did))
    conn.commit()
    log_activity(u['id'], 'edit_debtor', f"{data['full_name']} - {data['contract_number']}")
    debtor = conn.execute('''
        SELECT d.*, u.full_name as created_by_name,
          (SELECT note FROM contact_logs WHERE debtor_id=d.id ORDER BY id DESC LIMIT 1) as last_note,
          (SELECT ptp_datetime FROM contact_logs WHERE debtor_id=d.id AND ptp_done=0 AND ptp_datetime IS NOT NULL ORDER BY id DESC LIMIT 1) as next_ptp,
          NULL as last_contact_at, NULL as last_contact_by
        FROM debtors d LEFT JOIN users u ON d.created_by=u.id WHERE d.id=?
    ''', (did,)).fetchone()
    conn.close()
    return jsonify({'success': True, 'debtor': dict(debtor)})

@app.route('/api/debtors/<int:did>', methods=['DELETE'])
@require_login
def delete_debtor(did):
    u = current_user()
    conn = get_db()
    d = conn.execute('SELECT * FROM debtors WHERE id=?', (did,)).fetchone()
    if u['role'] != 'admin' and d['created_by'] != u['id']:
        conn.close()
        return jsonify({'success': False, 'error': 'Ruxsat yo\'q'}), 403
    conn.execute('DELETE FROM messages WHERE debtor_id=?', (did,))
    conn.execute('DELETE FROM contact_logs WHERE debtor_id=?', (did,))
    conn.execute('DELETE FROM debtors WHERE id=?', (did,))
    conn.commit()
    log_activity(u['id'], 'delete_debtor', f"Shartnoma ID: {did}")
    conn.close()
    return jsonify({'success': True})

# ─── CONTACT LOGS ─────────────────────────────────────────────────────────────

@app.route('/api/debtors/<int:did>/logs', methods=['GET'])
@require_login
def get_logs(did):
    conn = get_db()
    logs = conn.execute('''
        SELECT cl.*, u.full_name as user_name FROM contact_logs cl
        JOIN users u ON cl.user_id = u.id
        WHERE cl.debtor_id=? ORDER BY cl.id DESC
    ''', (did,)).fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])

@app.route('/api/debtors/<int:did>/logs', methods=['POST'])
@require_login
def add_log(did):
    data = request.json
    u = current_user()
    conn = get_db()
    conn.execute('INSERT INTO contact_logs (debtor_id, user_id, note, ptp_datetime) VALUES (?, ?, ?, ?)',
                 (did, u['id'], data['note'], data.get('ptp_datetime')))
    conn.commit()
    log_activity(u['id'], 'add_log', f"Debtor ID: {did} - PTP: {data.get('ptp_datetime','yo\'q')}")
    conn.close()
    return jsonify({'success': True})

@app.route('/api/logs/<int:log_id>/ptp_done', methods=['PATCH'])
@require_login
def ptp_done(log_id):
    u = current_user()
    conn = get_db()
    conn.execute('UPDATE contact_logs SET ptp_done=1 WHERE id=?', (log_id,))
    conn.commit()
    log_activity(u['id'], 'ptp_done', f"Log ID: {log_id}")
    conn.close()
    return jsonify({'success': True})

# ─── MESSAGES ─────────────────────────────────────────────────────────────────

@app.route('/api/messages', methods=['GET'])
@require_login
def get_messages():
    conn = get_db()
    msgs = conn.execute('''
        SELECT m.*, d.full_name, u.full_name as sent_by FROM messages m
        JOIN debtors d ON m.debtor_id=d.id
        JOIN users u ON m.user_id=u.id
        ORDER BY m.sent_at DESC LIMIT 200
    ''').fetchall()
    conn.close()
    return jsonify([dict(m) for m in msgs])

@app.route('/api/messages/log', methods=['POST'])
@require_login
def log_message():
    data = request.json
    u = current_user()
    conn = get_db()
    conn.execute('INSERT INTO messages (debtor_id, user_id, phone, message_text) VALUES (?, ?, ?, ?)',
                 (data['debtor_id'], u['id'], data['phone'], data['message_text']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ─── TEMPLATES ────────────────────────────────────────────────────────────────

@app.route('/api/templates', methods=['GET'])
@require_login
def get_templates():
    conn = get_db()
    t = conn.execute('SELECT * FROM message_templates ORDER BY id').fetchall()
    conn.close()
    return jsonify([dict(x) for x in t])

@app.route('/api/templates', methods=['POST'])
@require_login
def add_template():
    data = request.json
    conn = get_db()
    conn.execute('INSERT INTO message_templates (name, text) VALUES (?, ?)', (data['name'], data['text']))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/templates/<int:tid>', methods=['PUT'])
@require_login
def update_template(tid):
    data = request.json
    conn = get_db()
    conn.execute('UPDATE message_templates SET name=?, text=? WHERE id=?', (data['name'], data['text'], tid))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/templates/<int:tid>', methods=['DELETE'])
@require_login
def delete_template(tid):
    conn = get_db()
    conn.execute('DELETE FROM message_templates WHERE id=?', (tid,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# ─── STATS ────────────────────────────────────────────────────────────────────

@app.route('/api/stats', methods=['GET'])
@require_login
def get_stats():
    conn = get_db()
    now = datetime.now().strftime('%Y-%m-%d %H:%M')
    total = conn.execute('SELECT COUNT(*) FROM debtors').fetchone()[0]
    paid = conn.execute("SELECT COUNT(*) FROM debtors WHERE status='paid'").fetchone()[0]
    unpaid = conn.execute("SELECT COUNT(*) FROM debtors WHERE status='unpaid'").fetchone()[0]
    partial = conn.execute("SELECT COUNT(*) FROM debtors WHERE status='partial'").fetchone()[0]
    total_debt = conn.execute('SELECT COALESCE(SUM(debt_amount),0) FROM debtors').fetchone()[0]
    total_paid = conn.execute('SELECT COALESCE(SUM(paid_amount),0) FROM debtors').fetchone()[0]
    ptp_due = conn.execute('''SELECT COUNT(DISTINCT debtor_id) FROM contact_logs
                              WHERE ptp_done=0 AND ptp_datetime IS NOT NULL AND ptp_datetime <= ?''', (now,)).fetchone()[0]
    msgs_today = conn.execute("SELECT COUNT(*) FROM messages WHERE date(sent_at)=date('now','localtime')").fetchone()[0]

    # Per-user stats (admin only)
    user_stats = []
    u = current_user()
    if u and u['role'] == 'admin':
        user_stats = conn.execute('''
            SELECT u.id, u.full_name, u.username,
              COUNT(DISTINCT d.id) as debtors_added,
              COUNT(DISTINCT cl.id) as contacts_made,
              COUNT(DISTINCT m.id) as sms_sent
            FROM users u
            LEFT JOIN debtors d ON d.created_by=u.id
            LEFT JOIN contact_logs cl ON cl.user_id=u.id
            LEFT JOIN messages m ON m.user_id=u.id
            WHERE u.is_active=1
            GROUP BY u.id ORDER BY debtors_added DESC
        ''').fetchall()
        user_stats = [dict(x) for x in user_stats]

    conn.close()
    return jsonify({
        'total': total, 'paid': paid, 'unpaid': unpaid, 'partial': partial,
        'total_debt': total_debt, 'total_paid': total_paid,
        'ptp_due': ptp_due, 'msgs_today': msgs_today, 'user_stats': user_stats
    })

if __name__ == '__main__':
    init_db()
    print("✅ Tizim ishga tushdi: http://localhost:5000")
    print("👑 Admin: login=admin, parol=admin123")
    app.run(debug=True, host='0.0.0.0', port=5000)
