import time
import socket

HOST = "127.0.0.1"
PORT = 1337 

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(f"Connected by {addr}")
        key = None
        nonce = None

        with open("./solve/key_dump.bin", "rb") as f:
            key = f.read(0x20)

        with open("./solve/nonce_dump.bin", "rb") as f:
            nonce = f.read(12)

        print(f"key={key}")
        print(f"nonce={nonce}")

        input("f")

        # 32-byte key
        conn.sendall(key)
        time.sleep(0.2)
        # The nonce
        conn.sendall(nonce)
        time.sleep(0.2)
        conn.sendall(b"\x61\0\0\0")
        time.sleep(0.2)
        conn.sendall(b"solve/file_ciphertext.bin\0")
        length = conn.recv(4)
        data = conn.recv(int.from_bytes(length, byteorder="little"))
        print(f"Received length: {length}")
        print(f"Received data: {data}")

        with open("decrypted_data.bin", "wb") as f:
            f.write(data)
