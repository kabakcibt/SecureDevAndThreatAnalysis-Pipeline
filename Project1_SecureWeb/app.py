from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from db import get_db_connection

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "cok-gizli-super-guvenli-anahtar-123"
jwt = JWTManager(app)

# 1. Kullanici kayit endpoint'i
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Kullanici adi ve sifre zorunludur!"}), 400
    
    # sifreyi guvenli bir sekilde hashleme
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
        return jsonify({"message": f"Kullanici '{username}' basariyla kaydedildi!"}), 201 # Created: Istek basarili ve sunucuda yeni kaynak olusturuldu.
    
    except Exception as e:
        return jsonify({"error": f"Kayit basarisiz (Kullanici adi kullanimda olabilir): {str(e)}"}), 400

    finally:
        cursor.close()
        conn.close()

# 2.  Kullanici giris endpoint'i
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Kullanici adi ve sifre zorunludur!"}), 400 # Bad request: hatali istek
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Veritabani baglanti hatasi!"}), 500 # Internal Server Error: Sunucu hatasi

    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id, username, password_hash, role FROM Users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Gecersiz kullanici adi ve ya sifre!"}), 401 # Unauthorized: Kimlik dogrulama hatasi.

        stored_hash = user[2].encode('utf-8')
        input_password = password.encode('utf-8')

        if  bcrypt.checkpw(input_password, stored_hash):

            access_token = create_access_token(identity=str(user[0]))

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
            return jsonify({"error": "Gecersiz kullanici adi veya sifre!"}), 401 # Unauthorized: Kimlik dogrulama hatasi.

    except Exception as e:
        return jsonify({"error": f"Giris sirasinda hata olustu: {str(e)}"}), 500 # Internal Server Error: Sunucu hatasi
    
    finally:
        cursor.close()
        conn.close()
# 3. Korumali dashboard endpoint'i (VIP bilet isteyen kapi)
@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def dashboard():
    current_user_id = get_jwt_identity()

    return jsonify({
        "message": "Gizli dashboard sayfasina hosgeldiniz efendim!",
        "user_id": current_user_id
    }), 200 # OK, Islem basarili

# 4. Adminlerin girebilecegi ozel panel (Kilitli kapi)
@app.route('/api/admin-panel', methods=['GET'])
@jwt_required()
def admin_panel():
    current_user_id = get_jwt_identity()

    conn = get_db_connection()
    if not conn:
        return jsonify({"error": "Veritabani baglanti hatasi!"}), 500 # Internal server error: Sunucu hatasi

    cursor = conn.cursor()
    try:
        # Kullanicinin rolunu veritabanindan teyit ediyoruz.
        cursor.execute("SELECT role FROM Users WHERE id = ?", (current_user_id,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Kullanici bulunamadi!"}), 404 # Not Found: Kayit bulunamadi.
        
        user_role = user[0]

        # Rol kontrolu
        if user_role != 'admin':
            return jsonify({"error": "Yetkisiz islem! Bu alana sadece adminler girebilir."}), 403 # Forbidden: Yetki hatasi.

        return jsonify({
            "message": "Admin paneline hos geldiniz efendim, her sey kontrol altinda!",
            "role": user_role
        }), 200 # OK: İslem basarisiz.

    except Exception as e:
        return jsonify({"error": f"Bir hata olustu: {str(e)}"}), 500 # Internal Server Error: Sunucu hatasi

    finally:
        cursor.close()
        conn.close()
if __name__ == '__main__':
    app.run(debug=True)