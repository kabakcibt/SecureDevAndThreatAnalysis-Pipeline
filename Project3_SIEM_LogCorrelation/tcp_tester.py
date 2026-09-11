import socket

SERVER_IP = "127.0.0.1"
PORT = 9998

tcp_logs = [
    "CEF:0|Security|WebServer|1.0|200|Unauthorized Access Attempt|6|src=172.16.0.45 spt=60111 dst=10.0.0.5 dpt=443 outcome=failure",
    "CEF:0|Security|Firewall|1.0|900|Critical System Malware Alert|9|src=10.0.0.1 spt=54265 dst=10.0.0.9 dpt=22 severity=8"
]

def send_tcp_logs():
    print("[-] TCP Testi baslatiilyor...")
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((SERVER_IP, PORT))

        for log in tcp_logs:
            client.sendall((log + "\n").encode('utf-8'))

        print("[+] TCP Test loglari gonderildi ve baglanti kapatildi.")
        client.close()

    except Exception as e:
        print("[-] TCP Test Baglanti Hatasi: {e}")

if __name__ == "__main__":
    send_tcp_logs()