from flask import Flask, jsonify, request
import logging

# 1. Merkezi Uygulama Loglama Ayarlari
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)

# Gecici bellek ici veri yapisi
items =[
    {"id":1, "name": "Guvenlik Duvari Logu", "status": "Aktif"},
    {"id":2, "name": "Ag Trafik Analizi", "status": "Inceleniyor"}
]

# 2. Merkezi Hata Yonetimi (Tum hatalari tek elden yakalayan yapi)
@app.errorhandler(Exception)
def handle_axception(e):
    logging.error(f"Beklenmeyen bir hata olustu: {str(e)}")
    return jsonify({"error": "Sunucu tarafinda kritik bir hata olustu.", "details": str(e)}), 500

# CRUD Islemleri

# Create (Yeni Veri Ekleme)
@app.route('/api/items', methods=['POST'])
def add_item():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({"error": "Gecersiz veri! 'name' alani zorunludur."}), 400

    new_item = {
        "id": len(items) + 1 if items else 1,
        "name": data['name'],
        "status": data.get('status', 'Beklemede')
    }
    items.append(new_item)
    logging.info(f"Yeni oge eklendi: ID {new_item['id']}")
    return jsonify(new_item), 201

# Read (Tum Verileri Listeleme)
@app.route('/api/items', methods=['GET'])
def get_items():
    logging.info("Tüm veriler listelendi.")
    return jsonify(items), 200

# Update (Veri Guncelleme)
@app.route('/api/items/<int:item_id>', methods=['PUT'])
def update_item(item_id):
    data = request.get_json()
    if not data:
        return jsonify({"error": "Güncellenecek veri sağlanmadı!"}), 400
        
    target_item = None
    for item in items:
        if item['id'] == item_id:
            target_item = item
            break
            
    if not target_item:
        return jsonify({"error": "Güncellenecek kayıt bulunamadı."}), 404
        
    target_item['name'] = data.get('name', target_item['name'])
    target_item['status'] = data.get('status', target_item['status'])
    
    logging.info(f"ID {item_id} numaralı kayıt güncellendi.")
    return jsonify(target_item), 200

# Delete (Veri Silme)
@app.route('/api/items/<int:item_id>', methods=['DELETE'])
def delete_item(item_id):
    global items
    target_item = None
    for item in items:
        if item['id'] == item_id:
            target_item = item
            break
            
    if not target_item:
        return jsonify({"error": "Silinecek kayıt bulunamadı."}), 404
        
    items = [item for item in items if item['id'] != item_id]
    logging.info(f"ID {item_id} numaralı kayıt silindi.")
    return jsonify({"message": f"ID {item_id} başarıyla silindi."}), 200


if __name__ == '__main__':
    app.run(debug=True, port=5000)