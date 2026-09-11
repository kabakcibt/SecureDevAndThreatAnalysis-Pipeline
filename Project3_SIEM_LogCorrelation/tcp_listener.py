import socket
import threading
from parsing import parse_cef, save_to_db

HOST = "0.0.0.0"
PORT = 9998

def handle_client(conn, addr):
    print(f"\n[+] Yeni TCP Baglantisi: {addr[0]}:{addr[1]}")
    try:
        conn.settimeout(60)
        while True:
            data = conn.recv(2048)
            if not data:
                break

            raw_log = data.decode('utf-8', errors='ignore').strip()
            if not raw_log:
                continue

            # Malformed Log Kontrolu
            if not raw_log.startswith("CEF"):
                print((f"[-] Uyari (Malformed TCP Log): {addr[0]} gecerli CEF formati gondermedi."))
                continue

            print(f"[+] TCP Logu ({addr[0]}): {raw_log[:50]}...")

            parsed_log = parse_cef(raw_log)
            if parsed_log:
                parsed_log.setdefault("proto", "TCP")
                parsed_log.setdefault("src", addr[0])
                parsed_log.setdefault("spt", str(addr[1]))

                save_to_db(raw_log, parsed_log)
            else:
                print("[-] TCP log parse basarisiz, akis devam ediyor.")
    except socket.timeout:
        print(f"[-] Zaman Asimi: {addr[0]} ile baglanti dustu.")
    except Exception as e:
        print(f"[-] TCP Client Hata Yalitimi ({addr[0]}): {e}")
    finally:
        conn.close()
        print(f"[-] TCP Baglantisi Kapatildi: {addr[0]}:{addr[1]}")

def start_tcp_listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"[+] TCP Listener aktif! {HOST}:{PORT} dinleniyor.")

        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.daemon = True
            client_thread.start()

    except KeyboardInterrupt:
        print("\n[!] TCP Listener durduruldu.")
    except Exception as e:
        print(f"[-] Kritik TCP Server Hatasi: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    start_tcp_listener()