import datetime
import jwt
from flask import Flask, request, jsonify

app = Flask(__name__)

# Clave secreta para firmar los JWT
SECRET_KEY = "mi_secreto_super_seguro"

# Ruta de inicio (por ejemplo, para simular un login)


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Simulación de validación de usuario
    if username == "usuario" and password == "password":
        # Crear un token JWT
        token = jwt.encode(
            {
                "username": username,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expira en 1 hora
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"token": token})
    else:
        return jsonify({"message": "Credenciales inválidas"}), 401

# Ruta protegida


@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"message": "Token no proporcionado"}), 403

    try:
        # Decodificar el token
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return jsonify({"message": f"Bienvenido, {decoded['username']}!"})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "El token ha expirado"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"message": "Token inválido"}), 403


# Ejecutar la aplicación
if __name__ == '__main__':
    app.run(debug=True)
