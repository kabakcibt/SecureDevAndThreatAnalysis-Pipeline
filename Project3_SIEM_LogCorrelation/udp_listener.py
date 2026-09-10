import socket
from parsing import parse_cef, save_to_db

HOST = "0.0.0.0"
PORT = 514

def start_udp_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.bind((HOST, PORT))
        print(f"[+] UDP Listener aktif ve guvenli modda! {HOST}:{PORT} dinleniyor.")

        while True:
            try:
                data, addr = sock.recvfrom(2048)
                if not data:
                    continue

                # Karakter kodlama hatalarina karsi robust decode
                raw_log = data.decode('utf-8', errors='ignore').strip()
                remote_ip, remote_port = addr

                if not raw_log:
                    continue

                # Malformed (Bozuk/eksik) log kontrolu
                if not raw_log.startswith("CEF:"):
                    print(f"[-] Uyari (Malformed Log): {remote_ip} adresinden CEF formatina uymayan paket alindi.")
                    continue
                print(f"\n[+] UDP Logu Alindi ({remote_ip}:{remote_port}): {raw_log[:50]}...")

                parsed_log = parse_cef(raw_log)
                if parsed_log:
                    parsed_log.setdefault("proto", "UDP")
                    parsed_log.setdefault("src", remote_ip)
                    parsed_log.setdefault("spt", str(remote_port))

                    save_to_db(raw_log, parsed_log)
                else:
                    print("[-] Log parse edilmedi, ancak sunucu calismaya devam ediyor.")

            except UnicodeDecodeError:
                print("[-] Hata: Okunan paket UTF-8 formatina uygun degil, paket yalitildi.")
            except Exception as inner_e:
                print(f"[-] Paket isleme hatasi (Devam ediliyor): {inner_e}")

    except KeyboardInterrupt:
        print("\n[!] UDP Listener kullanici tarafindan durduruldu.")
    except Exception as e:
        print(f"[-] Kritik listener hatasi: {e}")
    finally:
        sock.close()
if __name__ == "__main__":
    start_udp_listener()
