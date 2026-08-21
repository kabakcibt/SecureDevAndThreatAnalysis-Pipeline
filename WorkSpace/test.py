import requests

BASE_URL = "http://127.0.0.1:5000/api"

print("1. Yeni kullanıcı kaydediliyor...")
reg_res = requests.post(f"{BASE_URL}/register", json={"username": "bilal", "password": "secure_password123"})
print("Kayıt Cevabı:", reg_res.json())

print("\n2. Giriş yapılıyor...")
login_res = requests.post(f"{BASE_URL}/login", json={"username": "bilal", "password": "secure_password123"})
print("Giriş Cevabı:", login_res.json())

# Giriş başarılı olursa dönen user_id'yi alalım
if login_res.status_code == 200:
    user_id = login_res.json().get("user_id")
    
    print(f"\n3. Kullanıcı (ID: {user_id}) için görev ekleniyor...")
    task_res = requests.post(f"{BASE_URL}/tasks", json={"user_id": user_id, "title": "Staj raporunu tamamla"})
    print("Görev Ekleme Cevabı:", task_res.json())
    
    print(f"\n4. Kullanıcının görevleri listeleniyor...")
    get_tasks_res = requests.get(f"{BASE_URL}/tasks/{user_id}")
    print("Görev Listesi:", get_tasks_res.json())