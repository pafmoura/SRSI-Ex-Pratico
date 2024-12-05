import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import socket
import json
import threading

class Agent:
    def __init__(self, name, gateway_url):
        self.name = name
        self.gateway_url = gateway_url
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.signed_certificate = None

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
            self.signed_certificate = response.json()['signed_certificate']
            print(f"Agente {self.name} registado com sucesso!")
            print(self.signed_certificate)
        else:
            print("Registration failed:", response)

    def exchange_key(self, other_agent_name):
        requests.post(
            f"{self.gateway_url}/exchange_key",
            json={'name': self.name, 'other_agents': [other_agent_name]}
        )





    def menu(self):
        while True:
            print("Ações:")
            print("1. Registar na Gateway")
            print("2. Trocar chave com outro agente")
            print("3. Exit")
            choice = input("Selecionar ação: ")

            if choice == "1":
                self.register()
            elif choice == "2":
                other_agent = input("Insere o nome do outro agente: ")
                self.exchange_key(other_agent)
            elif choice == "3":
                print("A sair...")
                break
            else:
                print("Escolha inválida, tenta outra vez.")



def listen():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 5001))  
    client_socket.send(agent_name.encode())  

    while True:
        data = client_socket.recv(1024)
        key_received = data.decode()
        print(f"Chave recebida: {key_received}")

if __name__ == "__main__":
    gateway_url = "http://localhost:5000"
    agent_name = input("Insere o nome deste agente: ")
    agent = Agent(agent_name, gateway_url)
    listener_thread = threading.Thread(target=listen, daemon=True)
    listener_thread.start()
    agent.menu()
    