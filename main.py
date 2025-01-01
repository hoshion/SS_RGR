import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.x509 import CertificateBuilder
from cryptography.hazmat.primitives.hashes import SHA256
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


def create_signed_cert(ca_cert, ca_private_key, server_public_key):
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")
    ])
    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(server_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=1))
        .sign(ca_private_key, hashes.SHA256())
    )
    return cert


def encrypt_with_public_key(public_key, data):
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_with_private_key(private_key, encrypted_data):
    return private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def derive_session_key(client_random, server_random, premaster_secret):
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=client_random + server_random
    )
    return kdf.derive(premaster_secret)


# Server
def server_program():
    # Завантажити або згенерувати ключ та сертифікат центру сертифікації
    if not os.path.exists("ca_key.pem") or not os.path.exists("ca_cert.pem"):
        ca_private_key, ca_public_key = generate_rsa_key_pair()
        ca_cert = create_ca_cert(ca_private_key, ca_public_key)
        with open("ca_key.pem", "wb") as key_file:
            key_file.write(ca_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("ca_cert.pem", "wb") as cert_file:
            cert_file.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    else:
        with open("ca_key.pem", "rb") as key_file:
            ca_private_key = serialization.load_pem_private_key(
                key_file.read(), password=None
            )
        with open("ca_cert.pem", "rb") as cert_file:
            ca_cert = x509.load_pem_x509_certificate(cert_file.read())

    server_private_key, server_public_key = generate_rsa_key_pair()
    server_cert = create_signed_cert(ca_cert, ca_private_key, server_public_key)
    server_random = os.urandom(16)

    server_socket = socket.socket()
    server_socket.bind(('localhost', 12345))
    server_socket.listen(1)

    print("Server is listening...")
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

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
    cipher = Cipher(algorithms.AES(session_key), modes.CFB8(b'initialiv1234567'))
    decryptor = cipher.decryptor()
    ready_message = decryptor.update(conn.recv(128))

    print("Client ready message:", ready_message.decode())

    # Крок 7: завершити рукостискання відправленням повідомлення про готовність
    encryptor = cipher.encryptor()
    conn.sendall(encryptor.update(b"Server ready"))

    # Захищене спілкування
    while True:
        encrypted_data = conn.recv(1024)
        if not encrypted_data:
            break
        decrypted_data = decryptor.update(encrypted_data)
        print("Received (secure):", decrypted_data.decode())

        message = input("Enter message to send (secure): ").encode()
        conn.sendall(encryptor.update(message))

    conn.close()
    server_socket.close()


# Client
def client_program():
    client_socket = socket.socket()
    client_socket.connect(('localhost', 12345))

    client_random = os.urandom(16)

    # Крок 1: ініціювати рукостискання з сервером відправивши випадково згенероване значення клієнта
    client_socket.sendall(client_random)

    # Крок 2: отримати відповідь сервера на рукостискання з SSL-сертифікатом
    server_data = client_socket.recv(4096)
    server_random, server_cert_data = server_data[:16], server_data[16:]
    server_cert = x509.load_pem_x509_certificate(server_cert_data)

    # Крок 3: перевірити сертифікат в згенерованому центрі сертиікації
    with open("ca_cert.pem", "rb") as cert_file:
        ca_cert = x509.load_pem_x509_certificate(cert_file.read())
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(
            server_cert.signature,
            server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        print("Сертифікат сервера успішно перевірений!")
    except Exception as e:
        print("Перевірка сертифікату провалилась:", e)
        client_socket.close()
        return

    # Крок 4: згенерувати секрет premaster, зашифрувати публічним ключем сервера і відправити серверу
    premaster_secret = os.urandom(32)
    encrypted_premaster = encrypt_with_public_key(server_cert.public_key(), premaster_secret)
    client_socket.sendall(encrypted_premaster)

    # Крок 5: згенерувати ключ сеансу
    session_key = derive_session_key(client_random, server_random, premaster_secret)

    # Крок 6: відправити серверу зашифроване ключем сеансу повідомлення про готовність
    cipher = Cipher(algorithms.AES(session_key), modes.CFB8(b'initialiv1234567'))
    encryptor = cipher.encryptor()
    client_socket.sendall(encryptor.update(b"Client ready"))

    # Крок 7: завершити рукостискання отриманням повідомлення сервера про готовність
    decryptor = cipher.decryptor()
    server_ready_message = decryptor.update(client_socket.recv(128))
    print("Server ready message:", server_ready_message.decode())

    # Захищене спілкування
    while True:
        message = input("Enter message to send (secure): ").encode()
        client_socket.sendall(encryptor.update(message))

        encrypted_data = client_socket.recv(1024)
        if not encrypted_data:
            break
        decrypted_data = decryptor.update(encrypted_data)
        print("Received (secure):", decrypted_data.decode())

    client_socket.close()


# Запустити сервер та клієнт в окремих потоках
def main():
    import threading

    server_thread = threading.Thread(target=server_program)
    client_thread = threading.Thread(target=client_program)

    server_thread.start()
    client_thread.start()

    server_thread.join()
    client_thread.join()


if __name__ == "__main__":
    main()
