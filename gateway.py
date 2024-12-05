import base64
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os 
import threading
import socket
app = Flask(__name__)

class Gateway:
    def __init__(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()
        self.certificates = {}
        self.sockets = {}


    def sign_certificate(self, agent_public_key_pem):
        agent_public_key = serialization.load_pem_public_key(agent_public_key_pem)
   
        signed_certificate = self.private_key.sign(
            agent_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signed_certificate_b64 = base64.b64encode(signed_certificate).decode('utf-8')
        
        pem_certificate = f"-----BEGIN CERTIFICATE-----\n{signed_certificate_b64}\n-----END CERTIFICATE-----"
        
        return pem_certificate

    def start_socket_server(self, host='localhost', port=5001):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(5)
        print(f"Socket server listening on {host}:{port}")
        
        def handle_client(client_socket):
            while True:
                data = client_socket.recv(1024).decode()
                if data:
                    print(f"Received from client: {data}")
                    self.sockets[data] = client_socket

        while True:
            client_socket, addr = server_socket.accept()
            print(f"New connection from {addr}")
            threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()

gateway = Gateway()
threading.Thread(target=gateway.start_socket_server, daemon=True).start()


@app.route('/register', methods=['POST'])
def register_agent():
    data = request.json
    agent_name = data.get('name')
    public_key_pem = data.get('public_key').encode()

    signed_certificate = gateway.sign_certificate(public_key_pem)
    gateway.certificates[agent_name] = public_key_pem

    



    return jsonify({
        'message': f'Agente {agent_name} registado com sucesso.',
        'signed_certificate': signed_certificate,
    })

@app.route('/exchange_key', methods=['POST'])
def exchange_key():
    data = request.json
    agent_name = data.get('name')
    other_agents = data.get('other_agents')

    if agent_name not in gateway.certificates:
        return jsonify({'error': 'Agente não registado.'}), 400
    
    key = os.urandom(32)
    iv = os.urandom(16)
    key = Cipher(algorithms.AES(key), modes.CBC(iv))


    

    for agent in other_agents:
        if agent not in gateway.certificates:
            return jsonify({'error': f'Agente {agent} não registado.'}), 400
        
        message = f"{agent_name}:{key}:{iv}"
        gateway.sockets[agent].send(message.encode())
        print(f"Chave enviada para {agent}")

    return jsonify({
        'message': 'Chave trocada com sucesso.',
        'keys': key,
        'iv': iv,
    })


    
if __name__ == '__main__':
    app.run(port=5000)
