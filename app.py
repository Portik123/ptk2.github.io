from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(32))
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['SESSION_COOKIE_SECURE'] = False  # Отключено для локального тестирования
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Проверка расширения файла
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Проверка блокировки
def is_user_banned(user_id):
    conn = sqlite3.connect('portik.db')
    c = conn.cursor()
    c.execute('SELECT expires_at FROM bans WHERE user_id = ? AND (expires_at IS NULL OR expires_at > ?)', 
              (user_id, datetime.now().isoformat()))
    ban = c.fetchone()
    conn.close()
    return ban is not None

# Инициализация базы данных с миграцией
def init_db():
    conn = sqlite3.connect('portik.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS profiles (
        user_id INTEGER PRIMARY KEY,
        avatar TEXT,
        custom_tag TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    try:
        c.execute('ALTER TABLE profiles ADD COLUMN balance INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    c.execute('''CREATE TABLE IF NOT EXISTS addons (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        link TEXT,
        type TEXT,
        tags TEXT,
        user_id INTEGER,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    try:
        c.execute('ALTER TABLE addons ADD COLUMN user_id INTEGER')
    except sqlite3.OperationalError:
        pass
    c.execute('''CREATE TABLE IF NOT EXISTS forum (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id TEXT,
        receiver_id TEXT,
        content TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS badges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        description TEXT,
        color TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS user_badges (
        user_id INTEGER,
        badge_id INTEGER,
        PRIMARY KEY(user_id, badge_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(badge_id) REFERENCES badges(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS shop_badges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        description TEXT,
        price INTEGER,
        image TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS user_purchased_badges (
        user_id INTEGER,
        badge_id INTEGER,
        PRIMARY KEY(user_id, badge_id),
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(badge_id) REFERENCES shop_badges(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS warnings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS bans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        reason TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT
    )''')
    conn.commit()
    conn.close()

# Главная страница
@app.route('/')
def index():
    conn = sqlite3.connect('portik.db')
    c = conn.cursor()
    c.execute('SELECT title, link, type, tags FROM addons')
    addons = c.fetchall()
    conn.close()
    return render_template('index.html', addons=addons, user=session.get('user'), lang=session.get('lang', 'en'))

# Переключение языка
@app.route('/language/<lang>')
def switch_language(lang):
    if lang in ['en', 'ru']:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

# Авторизация и регистрация
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        print(f"POST request: username={username}, action={'register' if 'submit_register' in request.form else 'login'}")
        if not username or not password:
            flash('Username and password are required.', 'error')
            return render_template('login.html', lang=session.get('lang', 'en'))
        if len(username) > 50 or len(password) > 128:
            flash('Username or password is too long.', 'error')
            return render_template('login.html', lang=session.get('lang', 'en'))
        action = 'register' if 'submit_register' in request.form else 'login'
        conn = sqlite3.connect('portik.db')
        c = conn.cursor()
        if action == 'register':
            try:
                hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                user_id = c.lastrowid
                c.execute('INSERT INTO profiles (user_id, avatar, custom_tag, balance) VALUES (?, ?, ?, ?)', 
                         (user_id, 'default.png', '', 0))
                conn.commit()
                print(f"Registration successful for {username}")
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                print(f"Registration failed: Username {username} already taken")
                flash('Username already taken.', 'error')
            except sqlite3.Error as e:
                print(f"Database error during registration: {str(e)}")
                flash(f'Database error: {str(e)}', 'error')
        elif action == 'login':
            c.execute('SELECT id, password FROM users WHERE username = ?', (username,))
            user = c.fetchone()
            if user and check_password_hash(user[1], password):
                if is_user_banned(user[0]):
                    print(f"Login failed: {username} is banned")
                    flash('Your account is banned.', 'error')
                else:
                    session['user'] = username
                    session['user_id'] = user[0]
                    print(f"Login successful for {username}")
                    return redirect(url_for('index'))
            else:
                print(f"Login failed: Invalid credentials for {username}")
                flash('Invalid username or password.', 'error')
        conn.close()
        return render_template('login.html', lang=session.get('lang', 'en'))
    return render_template('login.html', lang=session.get('lang', 'en'))

# Загрузка аддона
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    if is_user_banned(session['user_id']):
        flash('You are banned and cannot upload addons.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form.get('title')
        link = request.form.get('link')
        addon_type = request.form.get('type')
        tags = request.form.get('tags')
        if title and link and addon_type:
            conn = sqlite3.connect('portik.db')
            c = conn.cursor()
            c.execute('INSERT INTO addons (title, link, type, tags, user_id) VALUES (?, ?, ?, ?, ?)', 
                     (title, link, addon_type, tags, session['user_id']))
            c.execute('UPDATE profiles SET balance = balance + 10 WHERE user_id = ?', (session['user_id'],))
            conn.commit()
            conn.close()
            flash('Addon uploaded successfully! You earned 10 Portik Coins.', 'success')
            return redirect(url_for('upload'))
        else:
            flash('All fields are required.', 'error')
    return render_template('upload.html', lang=session.get('lang', 'en'))

# Форум
@app.route('/forum', methods=['GET', 'POST'])
def forum():
    if is_user_banned(session.get('user_id')) and 'user' in session:
        flash('You are banned and cannot post on the forum.', 'error')
        return redirect(url_for('index'))
    conn = sqlite3.connect('portik.db')
    c = conn.cursor()
    if request.method == 'POST' and 'content' in request.form and 'user' in session:
        content = request.form.get('content')
        if content:
            user = session['user']
            c.execute('INSERT INTO forum (user, content) VALUES (?, ?)', (user, content))
            conn.commit()
            flash('Post submitted successfully.', 'success')
            return redirect(url_for('forum'))
        else:
            flash('Content cannot be empty.', 'error')
    c.execute('''SELECT f.user, f.content, f.created_at, p.avatar, p.custom_tag, 
                        GROUP_CONCAT(b.name || ':' || b.description || ':' || b.color) as badges,
                        GROUP_CONCAT(sb.name || ':' || sb.description || ':' || sb.image) as shop_badges
                 FROM forum f 
                 JOIN profiles p ON f.user = (SELECT username FROM users WHERE id = p.user_id)
                 LEFT JOIN user_badges ub ON p.user_id = ub.user_id
                 LEFT JOIN badges b ON ub.badge_id = b.id
                 LEFT JOIN user_purchased_badges upb ON p.user_id = upb.user_id
                 LEFT JOIN shop_badges sb ON upb.badge_id = sb.id
                 GROUP BY f.id
                 ORDER BY f.created_at DESC''')
    posts = [(row[0], row[1], row[2], row[3], row[4], 
              [b.split(':') for b in row[5].split(',')] if row[5] else [],
              [b.split(':') for b in row[6].split(',')] if row[6] else []) 
             for row in c.fetchall()]
    conn.close()
    return render_template('forum.html', posts=posts, user=session.get('user'), lang=session.get('lang', 'en'))

# Страница "О нас"
@app.route('/about')
def about():
    return render_template('about.html', user=session.get('user'), lang=session.get('lang', 'en'))

# Профиль пользователя
@app.route('/profile/<username>', methods=['GET', 'POST'])
def profile(username):
    conn = sqlite3.connect('portik.db')
    c = conn.cursor()
    c.execute('''SELECT u.username, p.avatar, p.custom_tag, p.balance,
                 GROUP_CONCAT(b.name || ':' || b.description || ':' || b.color) as badges,
                 GROUP_CONCAT(sb.name || ':' || sb.description || ':' || sb.image) as shop_badges,
                 GROUP_CONCAT(w.reason || ':' || w.created_at) as warnings
                 FROM users u 
                 JOIN profiles p ON u.id = p.user_id
                 LEFT JOIN user_badges ub ON u.id = ub.user_id
                 LEFT JOIN badges b ON ub.badge_id = b.id
                 LEFT JOIN user_purchased_badges upb ON u.id = upb.user_id
                 LEFT JOIN shop_badges sb ON upb.badge_id = sb.id
                 LEFT JOIN warnings w ON u.id = w.user_id
                 WHERE u.username = ?
                 GROUP BY u.id''', (username,))
    user_data = c.fetchone()
    if not user_data:
        conn.close()
        return render_template('404.html', message='User not found', lang=session.get('lang', 'en'))
    badges = [b.split(':') for b in user_data[4].split(',')] if user_data[4] else []
    shop_badges = [b.split(':') for b in user_data[5].split(',')] if user_data[5] else []
    warnings = [b.split(':') for w in user_data[6].split(',')] if user_data[6] else []
    user_data = (user_data[0], user_data[1], user_data[2], user_data[3], badges, shop_badges, warnings)
    if request.method == 'POST' and session.get('user') == username:
        custom_tag = request.form.get('custom_tag')
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = f"{session['user_id']}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{file.filename.rsplit('.', 1)[1].lower()}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                c.execute('UPDATE profiles SET avatar = ? WHERE user_id = ?', (filename, session['user_id']))
        c.execute('UPDATE profiles SET custom_tag = ? WHERE user_id = ?', (custom_tag, session['user_id']))
        conn.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile', username=username))
    conn.close()
    return render_template('profile.html', user_data=user_data, current_user=session.get('user'), lang=session.get('lang', 'en'))

# Магазин бейджей
@app.route('/shop', methods=['GET', 'POST'])
def shop():
    if 'user' not in session:
        return redirect(url_for('login'))
    if is_user_banned(session['user_id']):
        flash('You are banned and cannot access the shop.', 'error')
        return redirect(url_for('index'))
    conn = sqlite3.connect('portik.db')
    c = conn.cursor()
    if request.method == 'POST':
        badge_id = request.form.get('badge_id')
        c.execute('SELECT price FROM shop_badges WHERE id = ?', (badge_id,))
        price = c.fetchone()[0]
        c.execute('SELECT balance FROM profiles WHERE user_id = ?', (session['user_id'],))
        balance = c.fetchone()[0]
        if balance >= price:
            try:
                c.execute('INSERT INTO user_purchased_badges (user_id, badge_id) VALUES (?, ?)', 
                         (session['user_id'], badge_id))
                c.execute('UPDATE profiles SET balance = balance - ? WHERE user_id = ?', 
                         (price, session['user_id']))
                conn.commit()
                flash('Badge purchased successfully!', 'success')
            except sqlite3.IntegrityError:
                flash('You already own this badge.', 'error')
        else:
            flash('Insufficient balance.', 'error')
    c.execute('SELECT id, name, description, price, image FROM shop_badges')
    badges = c.fetchall()
    c.execute('SELECT balance FROM profiles WHERE user_id = ?', (session['user_id'],))
    balance = c.fetchone()[0]
    conn.close()
    return render_template('shop.html', badges=badges, balance=balance, user=session.get('user'), lang=session.get('lang', 'en'))

# Личные сообщения
@app.route('/messages', methods=['GET', 'POST'])
@app.route('/messages/<receiver>', methods=['GET', 'POST'])
def messages(receiver=None):
    if 'user' not in session:
        return redirect(url_for('login'))
    if is_user_banned(session['user_id']):
        flash('You are banned and cannot send messages.', 'error')
        return redirect(url_for('index'))
    conn = sqlite3.connect('portik.db')
    c = conn.cursor()
    if request.method == 'POST' and receiver:
        content = request.form.get('content')
        if content:
            c.execute('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)', 
                     (session['user'], receiver, content))
            conn.commit()
            flash('Message sent successfully.', 'success')
            return redirect(url_for('messages', receiver=receiver))
        else:
            flash('Message cannot be empty.', 'error')
    c.execute('''SELECT DISTINCT CASE 
                    WHEN sender_id = ? THEN receiver_id 
                    ELSE sender_id 
                 END AS contact 
                 FROM messages WHERE sender_id = ? OR receiver_id = ?''', 
                 (session['user'], session['user'], session['user']))
    contacts = [row[0] for row in c.fetchall()]
    messages = []
    if receiver:
        c.execute('''SELECT m.sender_id, m.content, m.created_at, p.avatar, p.custom_tag, 
                            GROUP_CONCAT(b.name || ':' || b.description || ':' || b.color) as badges,
                            GROUP_CONCAT(sb.name || ':' || sb.description || ':' || sb.image) as shop_badges
                     FROM messages m 
                     JOIN profiles p ON (SELECT id FROM users WHERE username = m.sender_id) = p.user_id
                     LEFT JOIN user_badges ub ON p.user_id = ub.user_id
                     LEFT JOIN badges b ON ub.badge_id = b.id
                     LEFT JOIN user_purchased_badges upb ON p.user_id = upb.user_id
                     LEFT JOIN shop_badges sb ON upb.badge_id = sb.id
                     WHERE (m.sender_id = ? AND m.receiver_id = ?) OR (m.sender_id = ? AND m.receiver_id = ?) 
                     GROUP BY m.id
                     ORDER BY m.created_at''', 
                     (session['user'], receiver, receiver, session['user']))
        messages = [(row[0], row[1], row[2], row[3], row[4], 
                     [b.split(':') for b in row[5].split(',')] if row[5] else [],
                     [b.split(':') for b in row[6].split(',')] if row[6] else []) 
                    for row in c.fetchall()]
    c.execute('SELECT username FROM users WHERE username != ?', (session['user'],))
    all_users = [row[0] for row in c.fetchall()]
    conn.close()
    return render_template('messages.html', user=session.get('user'), contacts=contacts, 
                          messages=messages, receiver=receiver, all_users=all_users, lang=session.get('lang', 'en'))

# Админ-панель: Вход
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = sqlite3.connect('portik.db')
        c = conn.cursor()
        c.execute('SELECT password FROM admin_users WHERE username = ?', (username,))
        admin = c.fetchone()
        if admin and check_password_hash(admin[0], password):
            session['admin_user'] = username
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin username or password.', 'error')
        conn.close()
    return render_template('admin_login.html', lang=session.get('lang', 'en'))

# Админ-панель: Регистрация
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username != 'PTK':
            flash('Only PTK can register as an admin.', 'error')
            return render_template('admin_login.html', show_register=True, lang=session.get('lang', 'en'))
        conn = sqlite3.connect('portik.db')
        c = conn.cursor()
        try:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            c.execute('INSERT INTO admin_users (username, password) VALUES (?, ?)', (username, hashed_password))
            conn.commit()
            flash('Admin registered successfully! Please log in.', 'success')
            return redirect(url_for('admin_login'))
        except sqlite3.IntegrityError:
            flash('Admin already registered.', 'error')
        conn.close()
    return render_template('admin_login.html', show_register=True, lang=session.get('lang', 'en'))

# Админ-панель
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if session.get('admin_user') != 'PTK':
        return redirect(url_for('admin_login'))
    conn = sqlite3.connect('portik.db')
    c = conn.cursor()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create_badge':
            name = request.form.get('name')
            description = request.form.get('description')
            color = request.form.get('color')
            if name and description and color:
                try:
                    c.execute('INSERT INTO badges (name, description, color) VALUES (?, ?, ?)', 
                             (name, description, color))
                    conn.commit()
                    flash('Badge created successfully.', 'success')
                except sqlite3.IntegrityError:
                    flash('Badge with this name already exists.', 'error')
            else:
                flash('All fields are required.', 'error')
        elif action == 'create_shop_badge':
            name = request.form.get('name', '')
            description = request.form.get('description')
            price = request.form.get('price')
            image = None
            if 'image' in request.files:
                file = request.files['image']
                if file and allowed_file(file.filename):
                    image = f"badge_{uuid.uuid4().hex}.{file.filename.rsplit('.', 1)[1].lower()}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], image))
            if description and price:
                try:
                    c.execute('INSERT INTO shop_badges (name, description, price, image) VALUES (?, ?, ?, ?)', 
                             (name, description, int(price), image))
                    conn.commit()
                    flash('Shop badge created successfully.', 'success')
                except sqlite3.Error as e:
                    flash(f'Database error: {str(e)}', 'error')
            else:
                flash('Description and price are required.', 'error')
        elif action == 'delete_badge':
            badge_id = request.form.get('badge_id')
            c.execute('DELETE FROM user_badges WHERE badge_id = ?', (badge_id,))
            c.execute('DELETE FROM badges WHERE id = ?', (badge_id,))
            conn.commit()
            flash('Badge deleted.', 'success')
        elif action == 'delete_shop_badge':
            badge_id = request.form.get('badge_id')
            c.execute('SELECT image FROM shop_badges WHERE id = ?', (badge_id,))
            image = c.fetchone()
            if image and image[0]:
                try:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image[0]))
                except FileNotFoundError:
                    pass
            c.execute('DELETE FROM user_purchased_badges WHERE badge_id = ?', (badge_id,))
            c.execute('DELETE FROM shop_badges WHERE id = ?', (badge_id,))
            conn.commit()
            flash('Shop badge deleted.', 'success')
        elif action == 'assign_badge':
            user_id = request.form.get('user_id')
            badge_id = request.form.get('badge_id')
            try:
                c.execute('INSERT INTO user_badges (user_id, badge_id) VALUES (?, ?)', 
                         (user_id, badge_id))
                conn.commit()
                flash('Badge assigned.', 'success')
            except sqlite3.IntegrityError:
                flash('This badge is already assigned to the user.', 'error')
        elif action == 'remove_badge':
            user_id = request.form.get('user_id')
            badge_id = request.form.get('badge_id')
            c.execute('DELETE FROM user_badges WHERE user_id = ? AND badge_id = ?', 
                     (user_id, badge_id))
            conn.commit()
            flash('Badge removed.', 'success')
        elif action == 'issue_warning':
            user_id = request.form.get('user_id')
            reason = request.form.get('reason')
            if reason:
                c.execute('INSERT INTO warnings (user_id, reason) VALUES (?, ?)', (user_id, reason))
                conn.commit()
                flash('Warning issued.', 'success')
            else:
                flash('Reason is required.', 'error')
        elif action == 'ban_user':
            user_id = request.form.get('user_id')
            reason = request.form.get('reason')
            duration = request.form.get('duration', '')
            if reason:
                expires_at = None
                if duration:
                    expires_at = (datetime.now() + timedelta(days=int(duration))).isoformat()
                c.execute('INSERT INTO bans (user_id, reason, expires_at) VALUES (?, ?, ?)', 
                         (user_id, reason, expires_at))
                conn.commit()
                flash('User banned.', 'success')
            else:
                flash('Reason is required.', 'error')
        elif action == 'unban_user':
            user_id = request.form.get('user_id')
            c.execute('DELETE FROM bans WHERE user_id = ?', (user_id,))
            conn.commit()
            flash('User unbanned.', 'success')
    c.execute('SELECT id, name, description, color FROM badges')
    badges = c.fetchall()
    c.execute('SELECT id, name, description, price, image FROM shop_badges')
    shop_badges = c.fetchall()
    c.execute('SELECT id, username FROM users')
    users = c.fetchall()
    c.execute('''SELECT u.id, u.username, GROUP_CONCAT(b.name || ':' || b.id) as badges
                 FROM users u
                 LEFT JOIN user_badges ub ON u.id = ub.user_id
                 LEFT JOIN badges b ON ub.badge_id = b.id
                 GROUP BY u.id''')
    user_badges = [(row[0], row[1], 
                    [b.split(':') for b in row[2].split(',')] if row[2] else []) 
                   for row in c.fetchall()]
    c.execute('''SELECT u.id, u.username, GROUP_CONCAT(w.reason || ':' || w.created_at) as warnings,
                        GROUP_CONCAT(b.reason || ':' || b.created_at || ':' || b.expires_at) as bans
                 FROM users u
                 LEFT JOIN warnings w ON u.id = w.user_id
                 LEFT JOIN bans b ON u.id = b.user_id
                 GROUP BY u.id''')
    user_status = [(row[0], row[1], 
                    [w.split(':') for w in row[2].split(',')] if row[2] else [],
                    [b.split(':') for b in row[3].split(',')] if row[3] else []) 
                   for row in c.fetchall()]
    conn.close()
    return render_template('admin.html', badges=badges, shop_badges=shop_badges, 
                          users=users, user_badges=user_badges, user_status=user_status, 
                          user=session.get('user'), lang=session.get('lang', 'en'))

# API для получения аддонов
@app.route('/api/addons')
def get_addons():
    conn = sqlite3.connect('portik.db')
    c = conn.cursor()
    c.execute('SELECT title, link, type, tags FROM addons')
    addons = [{'title': row[0], 'link': row[1], 'type': row[2], 'tags': row[3]} for row in c.fetchall()]
    conn.close()
    return jsonify(addons)

# Выход
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# Админ-выход
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_user', None)
    return redirect(url_for('admin_login'))

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    init_db()
    app.run(debug=True)