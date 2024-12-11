import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import json
import threading
import os
from base64 import b64encode, b64decode

class Agent:
    def __init__(self, name, gateway_url, port):
        self.name = name
        self.gateway_url = gateway_url
        self.port = port
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.signed_certificate = None
        self.keys = {}

    def register(self):
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        response = requests.post(
            f"{self.gateway_url}/register",
            json={'name': self.name, 'public_key': public_key_pem.decode()}
        )
        if response.status_code == 200:
            print(f"Agente {self.name} registado ")
        else:
            print("Registo falhou", response)

    def exchange_key(self, other_agent_name):
        response = requests.post(
            f"{self.gateway_url}/exchange_key",
            json={'name': self.name, 'other_agents': [other_agent_name]}
        )
        if response.status_code == 200:
            keys = response.json()['keys']
            for agent, key in keys.items():
                self.keys[agent] = serialization.load_pem_public_key(key.encode())
            print(f"Chaves trocadas com {other_agent_name} ")
        else:
            print("Falha na troca de chaves", response.json())

    def send_message(self, recipient_name, recipient_port, message):
        if recipient_name not in self.keys:
            print(f"Chave pública para {recipient_name} não encontrada.")
            return

        session_key = os.urandom(32)
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(message.encode()) + encryptor.finalize()

        encrypted_session_key = self.keys[recipient_name].encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        payload = json.dumps({
            'from': self.name,
            'encrypted_key': b64encode(encrypted_session_key).decode(),
            'iv': b64encode(iv).decode(),
            'message': b64encode(encrypted_message).decode()
        })

        recipient_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        recipient_socket.connect(("localhost", recipient_port))  
        recipient_socket.send(payload.encode())
        recipient_socket.close()

        print(f"Mensagem enviada para {recipient_name}: {message}")

    def menu(self):
        while True:
            print("Ações:")
            print("1. Registar na Gateway")
            print("2. Trocar chave com outro agente")
            print("3. Enviar mensagem para outro agente")
            print("4. Exit")
            choice = input("Selecionar ação: ")

            if choice == "1":
                self.register()
            elif choice == "2":
                other_agent = input("Insere o nome do outro agente: ")
                self.exchange_key(other_agent)
            elif choice == "3":
                recipient = input("Insere o nome do destinatário: ")
                recipient_port = int(input("Insere a port do destinatário: "))
                message = input("Insere a mensagem: ")
                self.send_message(recipient, recipient_port, message)    
            elif choice == "4":
                print("A sair...")
                break
            else:
                print("Escolha inválida")

def listen(agent):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", agent.port)) 
    server_socket.listen(5)

    while True:
        client_socket, addr = server_socket.accept()
        data = client_socket.recv(1024)
        if data:
            message = json.loads(data.decode())
            if 'message' in message:
                encrypted_key = b64decode(message['encrypted_key'])
                iv = b64decode(message['iv'])
                encrypted_message = b64decode(message['message'])

                session_key = agent.private_key.decrypt(
                    encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )

                cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
                decryptor = cipher.decryptor()
                decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()
                print("---------------------------------------------------")
                print(f"Mensagem recebida de {message['from']}: {decrypted_message.decode()}")
                print("---------------------------------------------------")
        client_socket.close()

if __name__ == "__main__":
    gateway_url = "http://localhost:5000"
    agent_name = input("Insere o nome deste agente: ")
    agent_port = int(input("Insere a port deste agente: "))
    agent = Agent(agent_name, gateway_url, agent_port)
    listener_thread = threading.Thread(target=listen, args=(agent,), daemon=True)
    listener_thread.start()
    agent.menu()