from flask import Flask, request, jsonify
import json

app = Flask(__name__)

gateway = {
    'sockets': {},
    'keys': {}
}

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name')
    public_key = data.get('public_key')
    gateway['keys'][name] = public_key
    return jsonify({'message': 'Agente registado'})

@app.route('/exchange_key', methods=['POST'])
def exchange_key():
    data = request.json
    name = data.get('name')
    other_agents = data.get('other_agents')
    keys = {agent: gateway['keys'][agent] for agent in other_agents if agent in gateway['keys']}
    return jsonify({'keys': keys})

if __name__ == '__main__':
    app.run(port=5000)