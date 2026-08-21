from flask import Flask, jsonify, request
import sqlite3
import bcrypt
import logging

# Loglama ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
DB_NAME = "secure_app.db"

def init_db():
    """Veritabanını ve gerekli tabloları otomatik kurar."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Kullanıcılar Tablosu (Şifreler düz metin değil, hashlenmiş saklanır)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    
    # Görevler Tablosu
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            status TEXT DEFAULT 'Bekliyor',
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    conn.commit()
    conn.close()

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Kritik Hata: {str(e)}")
    return jsonify({"error": "Sunucu tarafında bir hata oluştu."}), 500


# --- 1. KULLANICI İŞLEMLERİ (Kayıt Ol & Giriş Yap) ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Kullanıcı adı ve şifre zorunludur."}), 400
        
    username = data['username']
    password = data['password'].encode('utf-8')
    
    # Güvenli Geliştirme: Şifreyi asla düz metin saklama, bcrypt ile hashle!
    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    
    try:
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
        conn.commit()
        conn.close()
        logging.info(f"Yeni kullanıcı kaydedildi: {username}")
        return jsonify({"message": f"Kullanıcı '{username}' başarıyla oluşturuldu."}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Bu kullanıcı adı zaten alınmış."}), 400


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Kullanıcı adı ve şifre gereklidir."}), 400
        
    username = data['username']
    password = data['password'].encode('utf-8')
    
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    if user and bcrypt.checkpw(password, user['password']):
        logging.info(f"Kullanıcı giriş yaptı: {username}")
        return jsonify({"message": "Giriş başarılı!", "user_id": user['id']}), 200
    else:
        logging.warning(f"Başarısız giriş denemesi: {username}")
        return jsonify({"error": "Geçersiz kullanıcı adı veya şifre."}), 401


# --- 2. GÖREV (TASK) YÖNETİMİ ---

@app.route('/api/tasks', methods=['POST'])
def add_task():
    data = request.get_json()
    if not data or 'user_id' not in data or 'title' not in data:
        return jsonify({"error": "user_id ve title alanları zorunludur."}), 400
        
    user_id = data['user_id']
    title = data['title']
    status = data.get('status', 'Bekliyor')
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO tasks (user_id, title, status) VALUES (?, ?, ?)", (user_id, title, status))
    conn.commit()
    task_id = cursor.lastrowid
    conn.close()
    
    logging.info(f"Yeni görev eklendi: ID {task_id}")
    return jsonify({"id": task_id, "user_id": user_id, "title": title, "status": status}), 201


@app.route('/api/tasks/<int:user_id>', methods=['GET'])
def get_tasks(user_id):
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tasks WHERE user_id = ?", (user_id,))
    rows = cursor.fetchall()
    conn.close()
    
    tasks_list = [dict(row) for row in rows]
    return jsonify(tasks_list), 200


if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)