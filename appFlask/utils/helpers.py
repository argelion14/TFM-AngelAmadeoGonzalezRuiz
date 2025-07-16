# utils/helpers.py

from datetime import datetime, timedelta
import os
import sqlite3

from flask import request
import jwt
from cryptography.x509 import load_pem_x509_certificate
from dotenv import load_dotenv

load_dotenv()

JWT_EXPIRATION_MINUTES = 60

CA_CERT_PATH = os.getenv("CA_CERT_PATH")
CA_KEY_PATH = os.getenv("CA_KEY_PATH")

with open(CA_CERT_PATH, "rb") as f:
    cert_bytes = f.read()
CA_CERT = load_pem_x509_certificate(cert_bytes)
CA_PUBLIC_KEY = CA_CERT.public_key()


with open(CA_KEY_PATH, "rb") as f:
    CA_KEY = f.read()


def get_db_connection():
    # Carpeta raíz del proyecto (donde está TFM.db)
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    db_path = os.path.join(BASE_DIR, "TFM.db")

    conn = sqlite3.connect(db_path)
    conn.execute('PRAGMA foreign_keys = ON')
    conn.row_factory = sqlite3.Row  # Para acceder por nombre de columna
    return conn


def verificar_jwt_api():
    """
    Verifies the JWT sent in the Authorization header of an API request.

    Returns:
        dict | None: The token data if valid, or None if invalid or missing.
    """
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    return decodificar_jwt(token)


def decodificar_jwt(token):
    """
    Intenta decodificar un token JWT.

    Args:
        token (str): El token JWT a decodificar.

    Returns:
        dict | None: Datos decodificados o None si el token es inválido o expirado.
    """
    if not token:
        return None
    try:
        return jwt.decode(token, CA_PUBLIC_KEY, algorithms=["ES256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

def generar_jwt(user):
    payload = {
        'username': user[0],
        'cert': user[2],
        'is_superuser': user[3] == 1,
        'exp': datetime.now() + timedelta(minutes=JWT_EXPIRATION_MINUTES)
    }
    token = jwt.encode(payload, CA_KEY, algorithm="ES256")
    return token


def verificar_jwt():
    """
    Verifica el JWT almacenado en la cookie 'token' de una solicitud HTML.

    Returns:
        dict | None: Los datos del token si es válido, o None si es inválido o no existe.
    """
    token = request.cookies.get("token")
    return decodificar_jwt(token)

# swagger_template = {
#     "swagger": "2.0",
#     "info": {
#         "description": "This is a sample server Petstore server.  You can find out more about Swagger at [http://swagger.io](http://swagger.io) or on [irc.freenode.net, #swagger](http://swagger.io/irc/).  For this sample, you can use the api key `special-key` to test the authorization filters.",
#         "version": "1.0.0",
#         "title": "Swagger API ROLES CONNECT",
#         "termsOfService": "http://swagger.io/terms/",
#         "contact": {
#             "email": "apiteam@swagger.io"
#         },
#         "license": {
#             "name": "Apache 2.0",
#             "url": "http://www.apache.org/licenses/LICENSE-2.0.html"
#         }
#     },
#     "securityDefinitions": {
#         "BearerAuth": {
#             "type": "apiKey",
#             "name": "Authorization",
#             "in": "header",
#             "description": "Token JWT en formato: **Bearer &lt;token&gt;**"
#         }
#     },
#     "definitions": {
#         "Role": {
#             "type": "object",
#             "required": ["name", "exp_time"],
#             "properties": {
#                 "id": {
#                     "type": "integer",
#                     "format": "int64",
#                     "readOnly": True
#                 },
#                 "name": {
#                     "type": "string",
#                     "example": "admin",
#                     "description": "Nombre único del rol"
#                 },
#                 "description": {
#                     "type": "string",
#                     "example": "Rol de administrador con todos los permisos"
#                 },
#                 "exp_time": {
#                     "type": "integer",
#                     "format": "int32",
#                     "example": 60,
#                     "description": "Tiempo de expiración del token en minutos"
#                 }
#             }
#         }
#     },
#     "externalDocs": {
#         "description": "Find out more about Swagger",
#         "url": "http://swagger.io"
#     }
# }

# swagger = Swagger(app, config=swagger_config, template=swagger_template)