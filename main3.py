import socket
import os
import subprocess
import time
from random import random

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import CertificateBuilder
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from datetime import datetime, timedelta
from cryptography import x509


def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def create_ca_cert(ca_private_key, ca_public_key):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"Certificate Authority")
    ])
    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_private_key, hashes.SHA256())
    )
    return cert


def sign_certificate_request(ca_cert, ca_private_key, csr_data):
    csr = x509.load_pem_x509_csr(csr_data)
    cert = (
        CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(ca_private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def verify_certificate(ca_cert, cert_to_verify):
    try:
        ca_cert.public_key().verify(
            cert_to_verify.signature,
            cert_to_verify.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Verification failed:", e)
        return False


def encrypt_with_public_key(public_key, data):
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            asym_padding.MGF1(algorithm=hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )


def decrypt_with_private_key(private_key, encrypted_data):
    return private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            asym_padding.MGF1(algorithm=hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )


def derive_session_key(client_random, server_random, premaster_secret):
    kdf = HKDF(
        hashes.SHA256(),
        32,
        None,
        client_random + server_random
    )
    return kdf.derive(premaster_secret)


def ca_server():
    ca_private_key, ca_public_key = generate_rsa_key_pair()
    ca_cert = create_ca_cert(ca_private_key, ca_public_key)

    server_socket = socket.socket()
    server_socket.bind(('localhost', 54321))
    server_socket.listen(5)
    print("CA Server is listening...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connection from {addr}")

        request_type = conn.recv(8).decode()
        print(request_type)
        if request_type == "SIGN_CSR":
            csr_data = conn.recv(4096)
            print("Received CSR from client.")

            signed_cert = sign_certificate_request(ca_cert, ca_private_key, csr_data)

            conn.sendall(signed_cert)
            print("Signed certificate sent to client.")

        elif request_type == "VERIFY_C":
            cert_data = conn.recv(4096)
            cert_to_verify = x509.load_pem_x509_certificate(cert_data)

            if verify_certificate(ca_cert, cert_to_verify):
                conn.sendall(b"VERIFIED")
                print("Certificate verified and result sent to client.")
            else:
                conn.sendall(b"N_VERIFY")

        conn.close()


# Нода
def server_program(node_id, peers):
    # Отримати сертифікат через центр сертифікації
    ca_socket = socket.socket()
    ca_socket.connect(('localhost', 54321))

    server_private_key, public_key = generate_rsa_key_pair()
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ]))
        .sign(server_private_key, hashes.SHA256())
    )

    ca_socket.sendall(b"SIGN_CSR")
    ca_socket.sendall(csr.public_bytes(serialization.Encoding.PEM))

    signed_cert_data = ca_socket.recv(4096)
    server_cert = x509.load_pem_x509_certificate(signed_cert_data)
    print("Received signed certificate from CA.")

    ca_socket.close()

    # Розпочати запуск підпрограми
    server_random = os.urandom(16)

    server_socket = socket.socket()
    server_socket.bind(('localhost', 12000 + node_id))
    server_socket.listen(len(peers))

    print(f"Node-{node_id}: Listening for incoming connections...")

    # Обробляти з'єднання з боку сервера
    def handle_connection(peer_id):
        conn, _ = server_socket.accept()

        # Крок 1: отримання ініціювання клієнтом рукостискання
        client_random = conn.recv(16)

        # Крок 2: відповідь сервером на рукостискання, що містить SSL-сертифікат
        conn.sendall(server_random + server_cert.public_bytes(serialization.Encoding.PEM))

        # Крок 4: отримати зашифрований секрет remaster, який розшифровується приватним ключем
        encrypted_premaster = conn.recv(256)
        premaster_secret = decrypt_with_private_key(server_private_key, encrypted_premaster)

        # Крок 5: генерування ключа сеансу за допомогою випадкових рядків сервера та клієнта і секрета premaster
        session_key = derive_session_key(client_random, server_random, premaster_secret)

        # Крок 6: отримати зашифроване сеансовим ключем повідомлення клієнта про готовність
        cipher = Cipher(algorithms.AES(session_key), modes.CFB8(b"initialiv1234567"))
        decryptor = cipher.decryptor()
        ready_message = decryptor.update(conn.recv(128))
        print(f"Node-{node_id}: Node-{peer_id} ready message: {ready_message.decode()}")

        # Крок 7: завершити рукостискання відправленням повідомлення про готовність
        encryptor = cipher.encryptor()
        conn.sendall(encryptor.update(b"Server ready"))

        # Захищене спілкування
        while True:
            encrypted_data = conn.recv(1024)
            if not encrypted_data:
                break
            decrypted_data = decryptor.update(encrypted_data)
            print(f"Node-{node_id}: Received from Node-{peer_id} (secure): {decrypted_data.decode()}")

            # message = input(f"Node-{node_id}: Enter message to send Client-{peer_id} (secure): ").encode()
            # conn.send(encryptor.update(message))

        conn.close()

    # Ініціювати з'єднання до підключених клієнтів
    def initiate_connection(peer_id):
        try:
            peer_port = 12000 + peer_id
            conn = socket.socket()
            conn.connect(("localhost", peer_port))

            # Крок 1: ініціювати рукостискання з сервером відправивши випадково згенероване значення клієнта
            conn.sendall(server_random)

            # Крок 2: отримати відповідь сервера на рукостискання з SSL-сертифікатом
            response = conn.recv(4096)
            peer_random, peer_cert_data = response[:16], response[16:]
            peer_cert = x509.load_pem_x509_certificate(peer_cert_data)

            # Крок 3: перевірити сертифікат в згенерованому центрі сертиікації
            ca_socket = socket.socket()
            ca_socket.connect(('localhost', 54321))
            ca_socket.sendall(b"VERIFY_C" + peer_cert.public_bytes(serialization.Encoding.PEM))
            ca_socket.sendall(peer_cert.public_bytes(serialization.Encoding.PEM))

            verification_result = ca_socket.recv(8).decode()
            ca_socket.close()

            if verification_result != "VERIFIED":
                print(f"Node-{node_id}: Failed to verify peer's certificate.")
                conn.close()
                return

            # Крок 4: згенерувати секрет premaster, зашифрувати публічним ключем сервера і відправити серверу
            premaster_secret = os.urandom(32)
            encrypted_premaster = encrypt_with_public_key(peer_cert.public_key(), premaster_secret)
            conn.sendall(encrypted_premaster)

            # Крок 5: згенерувати ключ сеансу
            session_key = derive_session_key(server_random, peer_random, premaster_secret)

            # Крок 6: відправити серверу зашифроване ключем сеансу повідомлення про готовність
            cipher = Cipher(algorithms.AES(session_key), modes.CFB8(b"initialiv1234567"))
            encryptor = cipher.encryptor()
            conn.sendall(encryptor.update(b"Client ready"))

            # Крок 7: завершити рукостискання отриманням повідомлення сервера про готовність
            decryptor = cipher.decryptor()
            server_ready_message = decryptor.update(conn.recv(128))
            print(f"Node-{node_id}: Server ready message from Node-{peer_id}: {server_ready_message.decode()}")

            # Захищене спілкування
            while True:
                time.sleep(0.5)
                message = (f"Node-{node_id}: Enter message to send Node-{peer_id} (secure): " + str(random())).encode()
                print(message)
                conn.sendall(encryptor.update(message))

            conn.close()
        except Exception as e:
            print(f"Node-{node_id}: Error connecting to Node-{peer_id}: {e}")

    # Почати прослуховування зв'язків
    import threading
    threads = []
    for peer_id in peers:
        if peer_id > node_id:
            thread = threading.Thread(target=handle_connection, args=(peer_id,))
            threads.append(thread)
            thread.start()

    # Під'єднатися до клієнтів
    for peer_id in peers:
        if peer_id < node_id:
            time.sleep(0.3)
            thread = threading.Thread(target=initiate_connection, args=(peer_id,))
            threads.append(thread)
            thread.start()

    for thread in threads:
        thread.join()

    server_socket.close()


# Запустити сервер та клієнт в окремих потоках
def main():
    import threading

    nodes = [1, 2, 3]  # Define three nodes
    peer_1 = [3]
    peer_2 = [3]
    ca_thread = threading.Thread(target=ca_server)
    ca_thread.start()

    node_threads = []
    for node_id in nodes:
        peers = peer_1 if node_id == 1 else peer_2 if node_id == 2 else [1, 2]
        node_thread = threading.Thread(target=server_program, args=(node_id, peers))
        node_threads.append(node_thread)
        node_thread.start()

    for node_thread in node_threads:
        node_thread.join()

    ca_thread.join()


if __name__ == "__main__":
    main()
