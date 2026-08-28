from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from db import get_db_connection

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "cok-gizli-super-guvenli-anahtar-123"
jwt = JWTManager(app)

# YARDIMCI FONKSİYON: Kritik işlemleri AuditLogs tablosuna kaydetmek için
def log_action(username, action, details):
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            ip_address = request.remote_addr # İstek atan kişinin IP adresi
            cursor.execute(
                "INSERT INTO AuditLogs (username, action, ip_address, details) VALUES (?, ?, ?, ?)",
                (username, action, ip_address, details)
            )
            conn.commit()
        except Exception as e:
            print(f"Loglama hatası: {str(e)}")
        finally:
            cursor.close()
            conn.close()

# 1. Kullanici kayit endpoint'i
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Kullanici adi ve sifre zorunludur!"}), 400
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Veritabani baglanti hatasi!"}), 500

    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO Users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hashed_password, 'user')
        )
        conn.commit()
        
        # AUDIT LOG: Başarılı kayıt loglanıyor
        log_action(username, "REGISTER_SUCCESS", "Yeni kullanici basariyla kaydedildi.")
        
        return jsonify({"message": f"Kullanici '{username}' basariyla kaydedildi!"}), 201
    
    except Exception as e:
        # AUDIT LOG: Başarısız kayıt denemesi loglanıyor
        log_action(username, "REGISTER_FAIL", f"Kayit basarisiz: {str(e)}")
        return jsonify({"error": f"Kayit basarisiz (Kullanici adi kullanimda olabilir): {str(e)}"}), 400

    finally:
        cursor.close()
        conn.close()

# 2. Kullanici giris endpoint'i
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Kullanici adi ve sifre zorunludur!"}), 400
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Veritabani baglanti hatasi!"}), 500

    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, username, password_hash, role FROM Users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user:
            # AUDIT LOG: Olmayan kullanici ile giris denemesi
            log_action(username, "LOGIN_FAIL", "Geçersiz kullanici adi.")
            return jsonify({"error": "Gecersiz kullanici adi veya sifre!"}), 401

        stored_hash = user[2].encode('utf-8')
        input_password = password.encode('utf-8')

        if bcrypt.checkpw(input_password, stored_hash):
            access_token = create_access_token(identity=str(user[0]))

            # AUDIT LOG: Başarılı giriş
            log_action(username, "LOGIN_SUCCESS", "Kullanici sisteme giris yapti.")

            return jsonify({
                "message": "Giris basarili!",
                "access_token": access_token,
                "user": {
                    "id": user[0],
                    "username": user[1],
                    "role": user[3]
                }
            }), 200
        else:
            # AUDIT LOG: Yanlis sifre denemesi
            log_action(username, "LOGIN_FAIL", "Sifre hatali.")
            return jsonify({"error": "Gecersiz kullanici adi veya sifre!"}), 401

    except Exception as e:
        return jsonify({"error": f"Giris sirasinda hata olustu: {str(e)}"}), 500
    
    finally:
        cursor.close()
        conn.close()

# 3. Korumali dashboard endpoint'i
@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()

    return jsonify({
        "message": "Gizli dashboard sayfasina hosgeldiniz efendim!",
        "user_id": current_user_id
    }), 200

# 4. Adminlerin girebilecegi ozel panel
@app.route('/api/admin-panel', methods=['GET'])
@jwt_required()
def admin_panel():
    current_user_id = get_jwt_identity()

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Veritabani baglanti hatasi!"}), 500

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, role FROM Users WHERE id = ?", (current_user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Kullanici bulunamadi!"}), 404
        
        username = user[0]
        user_role = user[1]

        if user_role != 'admin':
            # AUDIT LOG: Yetkisiz admin paneli erisim denemesi
            log_action(username, "UNAUTHORIZED_ACCESS_ATTEMPT", "Normal kullanici admin paneline girmeye çalisti.")
            return jsonify({"error": "Yetkisiz islem! Bu alana sadece adminler girebilir."}), 403

        # AUDIT LOG: Basarili admin giris paneli
        log_action(username, "ADMIN_PANEL_ACCESS", "Admin paneline erisildi.")

        return jsonify({
            "message": "Admin paneline hos geldiniz efendim, her sey kontrol altinda!",
            "role": user_role
        }), 200

    except Exception as e:
        return jsonify({"error": f"Bir hata olustu: {str(e)}"}), 500

    finally:
        cursor.close()
        conn.close()

# 5. Gorev olusturma endpoint'i
@app.route('/api/tasks', methods=['POST'])
@jwt_required()
def create_task():
    current_user_id = int(get_jwt_identity())
    data = request.get_json()
    title = data.get('title')
    description = data.get('description', '')

    if not title:
        return jsonify({"error": "Gorev basligi zorunludur!"}), 400

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Veritabani baglanti hatasi!"}), 500

    cursor = conn.cursor()
    try:
        # Loglama için kullanıcı adını bulalım
        cursor.execute("SELECT username FROM Users WHERE id = ?", (current_user_id,))
        user_res = cursor.fetchone()
        username = user_res[0] if user_res else "Bilinmeyen"

        cursor.execute(
            "INSERT INTO Tasks (user_id, title, description) VALUES (?, ?, ?)",
            (current_user_id, title, description)
        )
        conn.commit()

        # AUDIT LOG: Görev oluşturuldu
        log_action(username, "TASK_CREATE", f"'{title}' baslikli gorev olusturuldu.")

        return jsonify({"message": "Gorev basariyla olusturuldu!"}), 201

    except Exception as e:
        return jsonify({"error": f"Veritabani hatasi: {str(e)}"}), 500

    finally:
        cursor.close()
        conn.close()

# 6. Gorevleri listeleme endpoint'i
@app.route('/api/tasks', methods=['GET'])
@jwt_required()
def get_tasks():
    current_user_id = int(get_jwt_identity())

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Veritabani baglanti hatasi!"}), 500

    cursor = conn.cursor()
    try:
        # Kullanicinin rolunu ve adini öğrenme
        cursor.execute("SELECT username, role FROM Users WHERE id = ?", (current_user_id,))
        user_data = cursor.fetchone()
        username = user_data[0]
        user_role = user_data[1]

        # Adminse tum gorevleri, normalse sadece kendi gorevlerini getirir
        if user_role == 'admin':
            cursor.execute("SELECT id, user_id, title, description, status, created_at FROM Tasks")
        else:
            cursor.execute("SELECT id, user_id, title, description, status, created_at FROM Tasks WHERE user_id = ?", (current_user_id,))

        columns = [column[0] for column in cursor.description]
        tasks = [dict(zip(columns, row)) for row in cursor.fetchall()]

        return jsonify({"tasks": tasks}), 200

    except Exception as e:
        return jsonify({"error": f"Gorevler getirilemedi: {str(e)}"}), 500

    finally:
        cursor.close()
        conn.close()

# 7. Gorev guncelleme endpoint'i
@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
@jwt_required()
def update_task(task_id):
    current_user_id = int(get_jwt_identity())
    data = request.get_json()
    
    title = data.get('title')
    description = data.get('description')
    status = data.get('status')

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Veritabani baglanti hatasi!"}), 500

    cursor = conn.cursor()
    try:
        # Islemi yapan kullanicinin rolunu ve adimi alma
        cursor.execute("SELECT username, role FROM Users WHERE id = ?", (current_user_id,))
        user_data = cursor.fetchone()
        username = user_data[0]
        user_role = user_data[1]

        # Görevin sahibini öğrenme
        cursor.execute("SELECT user_id FROM Tasks WHERE id = ?", (task_id,))
        task = cursor.fetchone()

        if not task:
            return jsonify({"error": "Gorev bulunamadi!"}), 404

        task_owner_id = task[0]

        # YETKİ KONTROLÜ: Görevin sahibi değilse VE admin de değilse hata döndür
        if task_owner_id != current_user_id and user_role != 'admin':
            log_action(username, "UNAUTHORIZED_TASK_UPDATE", f"{task_id} ID'li gorevi guncelleme yetkisiz deneme.")
            return jsonify({"error": "Bu gorevi guncelleme yetkiniz yok!"}), 403

        cursor.execute(
        """
            UPDATE Tasks 
            SET title = COALESCE(?, title), 
                description = COALESCE(?, description), 
                status = COALESCE(?, status)
            WHERE id = ?
        """, (title, description, status, task_id))
        
        conn.commit()

        # AUDIT LOG: Gorev guncellendi
        log_action(username, "TASK_UPDATE", f"{task_id} ID'li gorev guncellendi.")

        return jsonify({"message": f"{task_id} ID'li gorev basariyla guncellendi!"}), 200

    except Exception as e:
        return jsonify({"error": f"Guncelleme basarisiz: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()

# 8. Gorev silme endpoint'i
@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    current_user_id = int(get_jwt_identity())

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Veritabani baglanti hatasi!"}), 500

    cursor = conn.cursor()
    try:
        cursor.execute("SELECT username, role FROM Users WHERE id = ?", (current_user_id,))
        user_data = cursor.fetchone()
        username = user_data[0]
        user_role = user_data[1]

        cursor.execute("SELECT user_id FROM Tasks WHERE id = ?", (task_id,))
        task = cursor.fetchone()

        if not task:
            return jsonify({"error": "Gorev bulunamadi!"}), 404

        task_owner_id = task[0]

        # YETKİ KONTROLÜ: Sahibi değilse ve admin değilse sildirme
        if task_owner_id != current_user_id and user_role != 'admin':
            log_action(username, "UNAUTHORIZED_TASK_DELETE", f"{task_id} ID'li görevi silme yetkisiz deneme.")
            return jsonify({"error": "Bu gorevi silme yetkiniz yok!"}), 403

        cursor.execute("DELETE FROM Tasks WHERE id = ?", (task_id,))
        conn.commit()
        
        # AUDIT LOG: Görev silindi
        log_action(username, "TASK_DELETE", f"{task_id} ID'li görev silindi.")

        return jsonify({"message": f"{task_id} ID'li görev basariyla silindi!"}), 200

    except Exception as e:
        return jsonify({"error": f"Silme islemi basarisiz: {str(e)}"}), 500
    finally:
        cursor.close()
        conn.close()
        
if __name__ == '__main__':
    app.run(debug=True)