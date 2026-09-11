import socket
import time

SERVER_IP = "127.0.0.1" 
PORT = 514

# Test edilecek CEF loglari
test_logs = [
    "CEF:0|Security|Firewall|1.0|100|Normal Login Success|3|src=192.168.1.50 spt=4433 dst=10.0.0.1 dpt=80 outcome=success",
    "CEF:0|Security|AuthService|1.0|4625|Failed login attempt|8|src=192.168.1.100 spt=50123 dst=10.0.0.1 dpt=3389 outcome=failure",
    "CEF:0|Security|Firewall|1.0|900|Critical System Failure Detected|10|src=10.0.0.1 spt=50384 dst=10.0.0.2 dpt=443 severity=9"
]

def send_udp_logs():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    print("[+] UDP Testi baslatiliyor...")

    print("[+] Brute force tetiklemek icin 12 adet ardarda hatali giris gonderiliyor (IP: 192.168.1.100)...")
    for i in range(12):
        brute_log = f"CEF:0|Security|AuthService|1.0|4625|Failed login attempt|7|src=192.168.1.100 spt=50{i}00 dst=10.0.0.1 dpt=3389 outcome=failure"
        client.sendto(brute_log.encode('utf-8'), (SERVER_IP, PORT))
        time.sleep(0.2)

    for log in test_logs:
        client.sendto(log.encode('utf-8'), (SERVER_IP, PORT))
        time.sleep(0.3)

    print("[+] UDP Test loglari basariyla gonderildi!")
    client.close()

if __name__ == "__main__":
    send_udp_logs()