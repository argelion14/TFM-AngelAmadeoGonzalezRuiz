from flask import Flask, request, jsonify, render_template
import sqlite3
import jwt
import base64
import json
import os

app = Flask(__name__)
SECRET_KEY = 'supersecretkey'

DB_FILE = 'permisos.db'


def get_permissions_for_subject_domain(subject_name, domain_id):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT p.permission_type
        FROM subjects s
        JOIN grants g ON s.id = g.subject_id
        JOIN rules r ON g.id = r.grant_id
        JOIN domains d ON r.id = d.rule_id
        JOIN permissions p ON r.id = p.rule_id
        WHERE s.subject_name = ? AND d.domain_id = ?
    """, (subject_name, domain_id))

    """
    Dada la combinación de usuario (por nombre) y dominio (por ID), la consulta recupera qué permisos exactos 
    tiene el usuario dentro de ese dominio, siguiendo toda la estructura relacional de 
    grants, reglas, dominios y permisos.
    """

    rows = cursor.fetchall()
    conn.close()

    return [row[0] for row in rows]


@app.route('/')
def home():
    nombre = "Bienvenido a la API de autenticación DDS Security con JWT"
    return render_template("index.html", nombre=nombre)


@app.route('/auth', methods=['POST'])
def auth():
    data = request.json
    subject_name = data['subject_name']
    domain_id = data['domain_id']

    permissions = get_permissions_for_subject_domain(subject_name, domain_id)

    if not permissions:
        return jsonify({'error': 'No permissions found'}), 403

    payload = {
        'subject': subject_name,
        'domain': domain_id,
        'permissions': permissions
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')

    # Fraccionar en 3 partes tipo JWT simulado
    header = base64.urlsafe_b64encode(json.dumps(
        {"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload_part = base64.urlsafe_b64encode(
        json.dumps(payload).encode()).decode().rstrip("=")
    signature = base64.urlsafe_b64encode(
        os.urandom(16)).decode().rstrip("=")  # Firma falsa

    fractured_token = f"{header}.{payload_part}.{signature}"

    return jsonify({'token': fractured_token})


@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    token = data['token']

    try:
        payload = decode_token_payload(token)

        subject = payload['subject']
        domain = payload['domain']
        permissions = payload['permissions']

        return jsonify({
            'valid': True,
            'subject': subject,
            'domain': domain,
            'permissions': permissions
        })
    except Exception as e:
        return jsonify({'error': 'Token inválido', 'details': str(e)}), 400


@app.route('/action', methods=['POST'])
def action():
    data = request.json
    token = data['token']
    action = data['action'].upper()  # 'PUBLISH' o 'SUBSCRIBE'

    try:
        payload = decode_token_payload(token)

        domain = payload['domain']
        permissions = payload['permissions']

        if action in permissions:
            return jsonify({
                'result': 'allowed',
                'domain': domain,
                'action': action
            })
        else:
            return jsonify({
                'result': 'denied',
                'domain': domain,
                'action': action
            }), 403

    except Exception as e:
        return jsonify({'error': 'Token inválido', 'details': str(e)}), 400


def decode_token_payload(token):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError('Token mal formado')

    payload_part = parts[1]
    padding = '=' * (-len(payload_part) % 4)
    decoded_payload = base64.urlsafe_b64decode(payload_part + padding).decode()
    return json.loads(decoded_payload)


@app.route('/token_viewer')
def token_viewer():
    return render_template("token_viewer.html")


# Página de generador de tokens
# @app.route('/generator')
# def generator():
#     conn = sqlite3.connect(DB_FILE)
#     cursor = conn.cursor()
#     cursor.execute("SELECT id, subject_name FROM subjects")
#     users = cursor.fetchall()

#     cursor.execute("SELECT id, subject_name FROM domains")
#     domains = cursor.fetchall()

#     conn.close()
#     return render_template("generator.html", users=users, domains=domains)

# # Endpoint que genera el token
# @app.route('/generate_token', methods=['POST'])
# def generate_token():
#     data = request.json
#     user_id = data.get('user_id')
#     domain_id = data.get('domain_id')

#     if not user_id or not domain_id:
#         return jsonify({'error': 'user_id y domain_id requeridos'}), 400

#     conn = sqlite3.connect(DB_FILE)
#     cursor = conn.cursor()

#     cursor.execute("""
#     SELECT permissions.action, domains.name FROM permissions
#     JOIN domains ON permissions.domain_id = domains.id
#     WHERE permissions.subject_id = ? AND permissions.domain_id = ?
#     """, (user_id, domain_id))

#     permissions = cursor.fetchall()
#     conn.close()

#     if not permissions:
#         return jsonify({'error': 'No tiene permisos asignados'}), 403

#     domain_name = permissions[0][1]
#     actions = [perm[0] for perm in permissions]

#     token_data = {
#         'user_id': user_id,
#         'domain': domain_name,
#         'actions': actions
#     }

#     token = jwt.encode(token_data, SECRET_KEY, algorithm='HS256')
#     return jsonify({'token': token})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
