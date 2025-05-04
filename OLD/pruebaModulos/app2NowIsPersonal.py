from flask import Flask, request, jsonify, abort, render_template
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Configuración básica
app = Flask(__name__)
SECRET_KEY = "mi_secreto_supersecreto"

# Base de datos simulada para usuarios (para pruebas)
USERS_DB = {
    "alice": {
        "password": generate_password_hash("alice_password"),
        "role": "admin",
        "permissions": ["read", "write"]
    },
    "bob": {
        "password": generate_password_hash("bob_password"),
        "role": "user",
        "permissions": ["read"]
    }
}

# Función para autenticar y generar el token JWT
def generate_jwt(user):
    payload = {
        "sub": user,  # Sujeto: usuario
        "role": USERS_DB[user]["role"],
        "permissions": USERS_DB[user]["permissions"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Expira en 1 hora
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Verificar el token JWT
def verify_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        abort(401, description="Token expirado")
    except jwt.InvalidTokenError:
        abort(401, description="Token inválido")

# Ruta para la página de inicio
@app.route("/")
def home():
    return render_template("home.html")

# Ruta para autenticar usuarios y generar JWT
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    
    # Verificación de usuario y contraseña
    if username not in USERS_DB or not check_password_hash(USERS_DB[username]["password"], password):
        abort(401, description="Credenciales incorrectas")
    
    # Generar token JWT
    token = generate_jwt(username)
    return jsonify({"token": token})

# Ruta protegida que requiere token y verifica permisos
@app.route("/resource", methods=["GET"])
def resource():
    # Obtener el token de la cabecera Authorization
    token = request.headers.get("Authorization")
    
    if not token:
        abort(401, description="Token requerido")
    
    # Verificar el token JWT
    payload = verify_jwt(token)
    
    # Comprobación de permisos
    if "read" not in payload["permissions"]:
        abort(403, description="Acceso denegado")
    
    return jsonify({"message": "Acceso a recurso permitido", "user": payload["sub"]})

# Ruta protegida con escritura (requiere permisos de escritura)
@app.route("/resource/write", methods=["POST"])
def write_resource():
    # Obtener el token de la cabecera Authorization
    token = request.headers.get("Authorization")
    
    if not token:
        abort(401, description="Token requerido")
    
    # Verificar el token JWT
    payload = verify_jwt(token)
    
    # Comprobación de permisos
    if "write" not in payload["permissions"]:
        abort(403, description="Acceso denegado")
    
    return jsonify({"message": "Acceso a escritura permitido", "user": payload["sub"]})

if __name__ == "__main__":
    app.run(debug=True)
