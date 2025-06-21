import os
import sqlite3
import datetime
import tempfile
import xml.etree.ElementTree as ET

import bcrypt
import jwt
import xmlschema
import functools

from flask import (
    Flask, abort, render_template, request, redirect, url_for,
    flash, make_response, g, jsonify
)

from flasgger import Swagger, swag_from

app = Flask(__name__)

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "api-docs",            # 👉 Nombre del endpoint JSON
            "route": "/api-docs.json",         # 👉 Ruta visible
            "rule_filter": lambda rule: True,  # Todas las rutas
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/swagger_static",
    "swagger_ui": True,
    "specs_route": "/docs/"                  # 👉 Ruta del Swagger UI
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Mi API segura",
        "version": "1.0"
    },
    "securityDefinitions": {
        "BearerAuth": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Token JWT en formato: **Bearer &lt;token&gt;**"
        }
    }
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)

app.secret_key = 'tu_clave_secreta'
app.config['UPLOAD_FOLDER'] = 'uploads'
JWT_SECRET = 'clave_jwt_segura'
JWT_EXPIRATION_MINUTES = 60


def get_db_connection():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row  # Para acceder a columnas por nombre
    return conn


@app.route('/listGrantTemplates', methods=['GET'])
def listar_grant_templates():
    """
    Lista todos los grantTemplates (requiere autenticación JWT)
    ---
    security:
      - BearerAuth: []
    responses:
      200:
        description: Lista de plantillas
        schema:
          type: array
          items:
            type: object
            properties:
              id:
                type: integer
              name:
                type: string
              default_action:
                type: string
              role_id:
                type: integer
      401:
        description: No autorizado
    """
    user = verificar_jwt()
    if not user:
        return jsonify({'error': 'No autorizado'}), 401

    conn = get_db_connection()
    cursor = conn.execute('SELECT * FROM grantTemplate')
    filas = cursor.fetchall()
    conn.close()

    resultado = [dict(fila) for fila in filas]
    return jsonify(resultado)


@app.route('/api/login', methods=['POST'])
def login_api():
    """
    Autenticación de usuario y obtención de JWT
    ---
    consumes:
      - application/json
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Autenticación exitosa
        schema:
          type: object
          properties:
            token:
              type: string
      401:
        description: Credenciales inválidas
    """
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Faltan datos'}), 400

    username = data['username']
    password = data['password']

    user = get_user(username)

    if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
        token = generar_jwt(user)
        # Aquí devuelves el token usable en Swagger
        return jsonify({'token': token})
    else:
        return jsonify({'error': 'Usuario o contraseña incorrectos'}), 401


def verificar_jwt_api():
    """
    Verifica el JWT enviado en el encabezado Authorization de una solicitud API.

    Returns:
        dict | None: Los datos del token si es válido, o None si es inválido o no existe.
    """
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    return decodificar_jwt(token)

def superadmin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = verificar_jwt_api()
        if not user or not user.get("is_superuser", False):
            abort(403, "Solo superadmin puede realizar esta acción")
        return f(*args, **kwargs)
    return wrapper


#########################
# SECCIÓN DE ROLES
# Funciones auxiliares para gestión de roles
#########################


@app.route('/api/roles', methods=['GET'])
@swag_from({
    'tags': ['Roles'],
    'summary': 'Obtiene todos los roles',
    'description': 'Devuelve los detalles de todos los roles que existen',
    'responses': {
        200: {
            'description': 'Lista de roles',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'id': {'type': 'integer'},
                        'name': {'type': 'string'},
                        'description': {'type': 'string'}
                    }
                }
            }
        }
    }
})
def get_roles():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles")
    rows = cursor.fetchall()
    conn.close()
    roles = [dict(row) for row in rows]
    return jsonify(roles)


@app.route('/api/roles/<int:role_id>', methods=['GET'])
@swag_from({
    'tags': ['Roles'],
    'summary': 'Obtiene un rol por ID',
    'description': 'Devuelve los detalles del rol si existe, en caso contrario devuelve un error 404.',
    'parameters': [
        {
            'name': 'role_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID del rol a obtener'
        }
    ],
    'responses': {
        200: {
            'description': 'Detalles del rol',
            'schema': {
                'type': 'object',
                'properties': {
                    'id': {'type': 'integer'},
                    'name': {'type': 'string'},
                    'description': {'type': 'string'}
                }
            }
        },
        404: {
            'description': 'Rol no encontrado'
        }
    }
})
def get_role(role_id):
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles WHERE id=?", (role_id,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "Rol no encontrado"}), 404
    return jsonify(dict(row))


@app.route('/api/roles', methods=['POST'])
@superadmin_required
@swag_from({
    'tags': ['Roles'],
    'summary': 'Añade un nuevo rol (solo superadmin)',
    'description': 'Permite a un superadmin crear un nuevo rol proporcionando nombre y descripción.',
    'parameters': [
        {
            'in': 'body',
            'name': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'required': ['name'],
                'properties': {
                    'name': {
                        'type': 'string',
                        'description': 'Nombre único del rol'
                    },
                    'description': {
                        'type': 'string',
                        'description': 'Descripción del rol'
                    }
                }
            }
        }
    ],
    'responses': {
        201: {
            'description': 'Rol creado correctamente'
        },
        400: {
            'description': 'Datos inválidos o rol duplicado'
        },
        403: {
            'description': 'Acceso denegado'
        }
    },
    'security': [
        {'BearerAuth': []}
    ]
})
def add_role():
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({"error": "El campo 'name' es obligatorio"}), 400

    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO roles (name, description) VALUES (?, ?)",
                       (data['name'], data.get('description')))
        conn.commit()
        new_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Rol con ese nombre ya existe"}), 400
    conn.close()
    return jsonify({"message": "Rol creado", "id": new_id}), 201


@app.route('/api/roles/<int:role_id>', methods=['DELETE'])
@superadmin_required
@swag_from({
    'tags': ['Roles'],
    'summary': 'Eliminar un rol por ID (solo superadmin)',
    'description': 'Permite a un superadmin eliminar un rol existente utilizando su ID.',
    'parameters': [
        {
            'name': 'role_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID del rol a eliminar'
        }
    ],
    'responses': {
        200: {
            'description': 'Rol eliminado correctamente'
        },
        404: {
            'description': 'Rol no encontrado'
        },
        403: {
            'description': 'Acceso denegado'
        }
    },
    'security': [
        {'BearerAuth': []}
    ]
})
def delete_role(role_id):
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM roles WHERE id=?", (role_id,))
    if cursor.fetchone() is None:
        conn.close()
        return jsonify({"error": "Rol no encontrado"}), 404
    cursor.execute("DELETE FROM roles WHERE id=?", (role_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": "Rol eliminado correctamente"})


@app.route('/api/roles/<int:role_id>', methods=['PUT'])
@superadmin_required
@swag_from({
    'tags': ['Roles'],
    'summary': 'Actualizar un rol por ID (solo superadmin)',
    'description': 'Permite actualizar el nombre o la descripción de un rol existente mediante su ID.',
    'parameters': [
        {
            'name': 'role_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID del rol a actualizar'
        },
        {
            'in': 'body',
            'name': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'name': {
                        'type': 'string',
                        'description': 'Nuevo nombre del rol'
                    },
                    'description': {
                        'type': 'string',
                        'description': 'Nueva descripción del rol'
                    }
                }
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Rol actualizado correctamente'
        },
        400: {
            'description': 'Datos inválidos o nombre duplicado'
        },
        404: {
            'description': 'Rol no encontrado'
        },
        403: {
            'description': 'Acceso denegado'
        }
    },
    'security': [
        {'BearerAuth': []}
    ]
})
def update_role(role_id):
    data = request.get_json()
    if not data:
        return jsonify({"error": "Se requiere un cuerpo JSON"}), 400

    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()

    # Verificar si el rol existe
    cursor.execute("SELECT id FROM roles WHERE id=?", (role_id,))
    if cursor.fetchone() is None:
        conn.close()
        return jsonify({"error": "Rol no encontrado"}), 404

    # Construir actualización dinámica
    campos = []
    valores = []
    if 'name' in data:
        campos.append("name = ?")
        valores.append(data['name'])
    if 'description' in data:
        campos.append("description = ?")
        valores.append(data['description'])

    if not campos:
        conn.close()
        return jsonify({"error": "No se especificó ningún campo a actualizar"}), 400

    valores.append(role_id)

    try:
        cursor.execute(
            f"UPDATE roles SET {', '.join(campos)} WHERE id = ?", valores)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Ya existe un rol con ese nombre"}), 400

    conn.close()
    return jsonify({"message": "Rol actualizado correctamente"})


#########################
# SECCIÓN DE USERS
# Funciones auxiliares para gestión de usuarios
#########################


@app.route('/api/users', methods=['GET'])
@swag_from({
    'tags': ['Usuarios'],
    'responses': {
        200: {
            'description': 'Lista de usuarios',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'id': {'type': 'integer'},
                        'username': {'type': 'string'},
                        'cert': {'type': 'string'},
                        'is_superuser': {'type': 'boolean'}
                    }
                }
            }
        }
    }
})
def listar_usuarios():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT id, username, cert, is_superuser FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)


@app.route('/api/users/<int:user_id>', methods=['GET'])
@swag_from({
    'tags': ['Usuarios'],
    'parameters': [
        {'name': 'user_id', 'in': 'path', 'type': 'integer', 'required': True}
    ],
    'responses': {
        200: {'description': 'Usuario encontrado'},
        404: {'description': 'Usuario no encontrado'}
    }
})
def obtener_usuario(user_id):
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.execute(
        "SELECT id, username, cert, is_superuser FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return jsonify(dict(row))
    return jsonify({'error': 'Usuario no encontrado'}), 404


@app.route('/api/users', methods=['POST'])
@superadmin_required
@swag_from({
    'tags': ['Usuarios'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'},
                    'cert': {'type': 'string'},
                    'is_superuser': {'type': 'boolean'}
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        201: {'description': 'Usuario creado'},
        400: {'description': 'Error al crear usuario'}
    }
})
def crear_usuario():
    datos = request.json
    username = datos.get('username')
    password = datos.get('password')
    cert = datos.get('cert', '')
    is_superuser = 1 if datos.get('is_superuser', False) else 0

    if not username or not password:
        return jsonify({'error': 'Faltan campos requeridos'}), 400

    hashed_pw = bcrypt.hashpw(password.encode(
        'utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = sqlite3.connect('roles.db')
    try:
        conn.execute(
            "INSERT INTO users (username, password, cert, is_superuser) VALUES (?, ?, ?, ?)",
            (username, hashed_pw, cert, is_superuser)
        )
        conn.commit()
        return jsonify({'message': 'Usuario creado'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Nombre de usuario ya existe'}), 400
    finally:
        conn.close()


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@superadmin_required
@swag_from({
    'tags': ['Usuarios'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {'name': 'user_id', 'in': 'path', 'type': 'integer', 'required': True}
    ],
    'responses': {
        200: {'description': 'Usuario eliminado'},
        404: {'description': 'Usuario no encontrado'}
    }
})
def eliminar_usuario(user_id):
    conn = sqlite3.connect('roles.db')
    cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    if cursor.rowcount:
        return jsonify({'message': 'Usuario eliminado'})
    return jsonify({'error': 'Usuario no encontrado'}), 404


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@superadmin_required
@swag_from({
    'tags': ['Usuarios'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {'name': 'user_id', 'in': 'path', 'type': 'integer', 'required': True},
        {
            'name': 'body',
            'in': 'body',
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string'},
                    'password': {'type': 'string'},
                    'cert': {'type': 'string'},
                    'is_superuser': {'type': 'boolean'}
                }
            }
        }
    ],
    'responses': {
        200: {'description': 'Usuario actualizado'},
        404: {'description': 'Usuario no encontrado'}
    }
})
def actualizar_usuario(user_id):
    datos = request.json
    campos = []
    valores = []

    if 'username' in datos:
        campos.append("username = ?")
        valores.append(datos['username'])
    if 'password' in datos:
        hashed_pw = bcrypt.hashpw(datos['password'].encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')
        campos.append("password = ?")
        valores.append(hashed_pw)
    if 'cert' in datos:
        campos.append("cert = ?")
        valores.append(datos['cert'])
    if 'is_superuser' in datos:
        campos.append("is_superuser = ?")
        valores.append(1 if datos['is_superuser'] else 0)

    if not campos:
        return jsonify({'error': 'No se proporcionaron campos para actualizar'}), 400

    valores.append(user_id)

    conn = sqlite3.connect('roles.db')
    cursor = conn.execute(
        f"UPDATE users SET {', '.join(campos)} WHERE id = ?", valores)
    conn.commit()
    conn.close()

    if cursor.rowcount:
        return jsonify({'message': 'Usuario actualizado'})
    return jsonify({'error': 'Usuario no encontrado'}), 404

#########################
# SECCIÓN DE XML
# Funciones auxiliares para gestión de XML
#########################

@app.route('/api/validar-xml', methods=['POST'])
@swag_from({
    'tags': ['XML'],
    'summary': 'Valida un archivo XML según el esquema DDS Permissions 7.5.0',
    'consumes': ['multipart/form-data'],
    'parameters': [
        {
            'name': 'xml_file',
            'in': 'formData',
            'type': 'file',
            'required': True,
            'description': 'Archivo XML a validar'
        }
    ],
    'responses': {
        200: {
            'description': 'Resultado de la validación del XML',
            'schema': {
                'type': 'object',
                'properties': {
                    'valid': {'type': 'boolean'},
                    'message': {'type': 'string'},
                    'errors': {
                        'type': 'array',
                        'items': {'type': 'string'}
                    }
                }
            }
        },
        400: {
            'description': 'Archivo no proporcionado o error de validación'
        }
    }
})
def validar_xml_api():
    xml_file = request.files.get('xml_file')
    if not xml_file:
        return jsonify({"error": "No se ha proporcionado un archivo XML"}), 400

    schema_url = "https://community.rti.com/schema/7.5.0/dds_security_permissions.xsd"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
        xml_path = tmp.name
        xml_file.save(xml_path)

    try:
        schema = xmlschema.XMLSchema(schema_url)
        if schema.is_valid(xml_path):
            resultado = {
                "valid": True,
                "message": "✅ El archivo XML es válido según el esquema DDS Permissions 7.5.0.",
                "errors": []
            }
        else:
            errores = [str(e) for e in schema.iter_errors(xml_path)]
            resultado = {
                "valid": False,
                "message": "❌ El archivo XML no es válido.",
                "errors": errores
            }
        return jsonify(resultado)
    except Exception as e:
        return jsonify({"error": f"❌ Error al validar: {str(e)}"}), 400
    finally:
        os.remove(xml_path)



#########################
# SECCIÓN DE HTML
#########################

#########################
# SECCIÓN DE HTML ROLES
#########################

def get_roles():
    """
    Recupera todos los roles almacenados en la base de datos.

    Conecta con la base de datos SQLite 'roles.db', realiza una consulta
    para obtener todos los registros de la tabla 'roles' y devuelve los resultados
    como una lista de objetos `sqlite3.Row`.

    Returns:
        list[sqlite3.Row]: Lista de filas que representan los roles existentes en la base de datos.
    """
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_roles_by_username(username):
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT r.name, r.description
        FROM users u
        JOIN user_roles ur ON u.id = ur.user_id
        JOIN roles r ON ur.role_id = r.id
        WHERE u.username = ?
    ''', (username,))
    roles = cursor.fetchall()
    conn.close()
    return roles


def get_all_users_and_roles():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users")
    users = cursor.fetchall()

    cursor.execute("SELECT id, name FROM roles")
    roles = cursor.fetchall()

    conn.close()
    return users, roles


def assign_role_to_user(user_id, role_id):
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    # Comprobamos si ya está asignado
    cursor.execute(
        "SELECT * FROM user_roles WHERE user_id = ? AND role_id = ?", (user_id, role_id))
    if not cursor.fetchone():
        cursor.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))
        conn.commit()
    conn.close()








#########################
# SECCIÓN DE HTML AUTENTICACIÓN JWT
#########################

def generar_jwt(user):
    payload = {
        'username': user[0],
        'cert': user[2],
        'is_superuser': user[3] == 1,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token


def verificar_jwt():
    """
    Verifica el JWT almacenado en la cookie 'token' de una solicitud HTML.

    Returns:
        dict | None: Los datos del token si es válido, o None si es inválido o no existe.
    """
    token = request.cookies.get("token")
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
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None


#########################
# SECCIÓN DE HTML OTROS
#########################


def get_users():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, cert FROM users")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_user(username):
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, password, cert, is_superuser FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user  # Será una tupla (username, password, cert, is_superuser)

def get_users2():
    conn = sqlite3.connect('roles.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Recuperamos todos los usuarios
    cursor.execute("""
        SELECT u.id, u.username, u.cert,
               GROUP_CONCAT(r.name) AS roles
        FROM users u
        LEFT JOIN user_roles ur ON u.id = ur.user_id
        LEFT JOIN roles r ON ur.role_id = r.id
        GROUP BY u.id
    """)
    rows = cursor.fetchall()
    conn.close()

    # Transformamos roles en lista
    usuarios = []
    for row in rows:
        usuarios.append({
            'id': row['id'],
            'username': row['username'],
            'cert': row['cert'],
            'roles': row['roles'].split(',') if row['roles'] else []
        })

    return usuarios



def insert_grant_from_xml(xml_path, role_id, db_path='roles.db'):
    if not os.path.exists(xml_path):
        raise FileNotFoundError(f"El fichero {xml_path} no existe")

    role_id = int(role_id)
    tree = ET.parse(xml_path)
    root = tree.getroot()

    default_elem = root.find('.//default')
    if default_elem is None or default_elem.text is None:
        raise ValueError("No se encontró elemento <default> en el XML")

    default_action = default_elem.text.strip().upper()
    if default_action not in ('ALLOW', 'DENY'):
        raise ValueError(f"Valor de default inválido: {default_action}")

    grant_elem = root.find('.//grant')
    name = grant_elem.attrib.get('name', 'unnamed_grant')

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    try:
        # 1. Insertar grantTemplate
        cursor.execute('''
            INSERT INTO grantTemplate (name, default_action, role_id)
            VALUES (?, ?, ?)
        ''', (name, default_action, role_id))
        grant_id = cursor.lastrowid

        # 2. Procesar reglas
        for rule_type in ['allow_rule', 'deny_rule']:
            for rule in root.findall(f'.//grant/{rule_type}'):
                permiso = rule_type

                cursor.execute(
                    'INSERT INTO rules (permiso, description) VALUES (?, ?)', (permiso, '')
                )
                rule_id = cursor.lastrowid

                # Dominios
                for domain in rule.findall('./domains/id'):
                    if domain.text:
                        domain_name = domain.text.strip()
                        cursor.execute(
                            'INSERT OR IGNORE INTO domains (name) VALUES (?)', (domain_name,))
                        cursor.execute(
                            'SELECT id FROM domains WHERE name = ?', (domain_name,))
                        domain_id = cursor.fetchone()[0]

                        cursor.execute('''
                            INSERT INTO rule_domains (rule_id, domain_id)
                            VALUES (?, ?)
                        ''', (rule_id, domain_id))

                # Topics - Publish
                for topic in rule.findall('./publish/topics/topic'):
                    if topic.text:
                        topic_name = topic.text.strip()
                        cursor.execute(
                            'INSERT OR IGNORE INTO topics (name) VALUES (?)', (topic_name,))
                        cursor.execute(
                            'SELECT id FROM topics WHERE name = ?', (topic_name,))
                        topic_id = cursor.fetchone()[0]

                        # Insertar en rule_topics como publish
                        cursor.execute('''
                            INSERT INTO rule_topics (rule_id, topic_id, action)
                            VALUES (?, ?, 'publish')
                        ''', (rule_id, topic_id))

                # Topics - Subscribe
                for topic in rule.findall('./subscribe/topics/topic'):
                    if topic.text:
                        topic_name = topic.text.strip()
                        cursor.execute(
                            'INSERT OR IGNORE INTO topics (name) VALUES (?)', (topic_name,))
                        cursor.execute(
                            'SELECT id FROM topics WHERE name = ?', (topic_name,))
                        topic_id = cursor.fetchone()[0]

                        # Insertar en rule_topics como subscribe
                        cursor.execute('''
                            INSERT INTO rule_topics (rule_id, topic_id, action)
                            VALUES (?, ?, 'subscribe')
                        ''', (rule_id, topic_id))

                # Asociar regla con el grant
                cursor.execute('''
                    INSERT INTO grant_rules (grant_id, rule_id)
                    VALUES (?, ?)
                ''', (grant_id, rule_id))

        conn.commit()
        return grant_id, name, default_action

    except (sqlite3.IntegrityError, sqlite3.OperationalError) as e:
        conn.rollback()
        raise ValueError(f"Error al insertar en la base de datos: {e}")
    finally:
        conn.close()


#########################
# SECCIÓN DE RUTAS
#########################

@app.route('/swagger-json')
def redirigir_a_swagger_json():
    return redirect('/api-docs.json')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = get_user(username)  # Recupera el usuario de la base de datos

        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            token = generar_jwt(user)
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('token', token, httponly=True, samesite='Lax')
            return resp
        else:
            flash('Usuario o contraseña incorrectos', 'danger')

    return render_template('login.html')


@app.route('/logout')
def logout():
    resp = make_response(redirect(url_for('index')))
    resp.set_cookie('token', '', expires=0)
    return resp


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/decode')
def decode():
    return render_template('decode.html')


@app.route('/informacion')
def informacion():
    return render_template('informacion.html')


@app.route("/roles")
def roles():
    roles = get_roles()
    return render_template("roles.html", roles=roles)


@app.route('/usuarios')
def usuarios():
    user = verificar_jwt()
    if user:
        users = get_users()
        return render_template('usuarios.html', usuarios=users)
    return redirect(url_for('login'))


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.route('/mis_roles')
def mis_roles():
    user = verificar_jwt()
    if user:
        username = user.get('username')
        roles = get_roles_by_username(username)
        return render_template('mis_roles.html', username=username, roles=roles)
    return redirect(url_for('login'))


@app.route("/usuarios2")
def usuarios2():
    user = verificar_jwt()

    match user:
        case None:
            # No se encontró usuario, redirige al login
            return redirect(url_for('login'))
        case {"is_superuser": 1}:
            # Usuario válido y es superusuario
            users = get_users2()
            return render_template("usuarios_roles.html", usuarios=users)
        case _:
            # Usuario válido pero no es superusuario
            return render_template("acceso_denegado.html"), 403


@app.route("/asignar_rol", methods=["GET", "POST"])
def asignar_rol():

    user = verificar_jwt()

    match user:
        case None:
            return redirect(url_for('login'))
        case {"is_superuser": 1}:
            if request.method == "POST":
                user_id = request.form.get("user_id")
                role_id = request.form.get("role_id")
                if user_id and role_id:
                    conn = sqlite3.connect('roles.db')
                    cursor = conn.cursor()

                    # Validar que el user_id existe
                    cursor.execute(
                        "SELECT username FROM users WHERE id = ?", (user_id,))
                    user_row = cursor.fetchone()

                    # Validar que el role_id existe
                    cursor.execute(
                        "SELECT name FROM roles WHERE id = ?", (role_id,))
                    role_row = cursor.fetchone()

                    if not user_row or not role_row:
                        flash("❌ Usuario o rol no encontrado.", "danger")
                        conn.close()
                        return redirect(url_for("asignar_rol"))

                    # Asignar rol
                    assign_role_to_user(user_id, role_id)
                    conn.close()

                    username = user_row[0]
                    role_name = role_row[0]
                    flash(
                        f"✅ Rol '{role_name}' asignado a '{username}' correctamente.", "success")
                    return redirect(url_for("asignar_rol"))

            users, roles = get_all_users_and_roles()
            return render_template("asignar_rol.html", users=users, roles=roles)
        case _:
            return render_template("acceso_denegado.html"), 403


@app.route('/dashboard')
def dashboard():
    user = verificar_jwt()
    if user:
        return render_template('dashboard.html', username=user['username'], cert=user['cert'])
    return redirect(url_for('login'))


@app.route('/new_grant', methods=['GET', 'POST'])
def new_grant():
    import os
    from flask import request, flash, redirect, url_for, render_template
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    cursor.execute("SELECT id, name FROM roles")
    roles = [dict(id=row[0], name=row[1]) for row in cursor.fetchall()]
    conn.close()

    if request.method == 'POST':
        f = request.files.get('xml_file')
        role_id = request.form.get('role_id')

        if not f or not role_id:
            flash('Falta fichero o rol', 'danger')
            return redirect(request.url)

        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
            f.save(path)

            grant_id, name, default_action = insert_grant_from_xml(
                path, role_id)
            flash(
                f'Grant "{name}" creado con default="{default_action}" y rol asignado.', 'success')
            return redirect(url_for('new_grant'))
        except Exception as e:
            flash(f'Error: {e}', 'danger')

    return render_template('new_grant.html', roles=roles)


# TODO: Añadir que solo los superuser puedan listar los grants
@app.route('/list_grant_templates')
def list_grant_templates():
    conn = sqlite3.connect('roles.db')
    cursor = conn.cursor()
    query = '''
        SELECT gt.id, gt.name, gt.default_action, r.name as role_name
        FROM grantTemplate gt
        JOIN roles r ON gt.role_id = r.id
    '''
    cursor.execute(query)
    grant_templates = cursor.fetchall()  # Devuelve lista de tuplas

    # Opcional: transformar a lista de dicts
    grants = [
        {
            'id': row[0],
            'name': row[1],
            'default_action': row[2],
            'role_name': row[3]
        } for row in grant_templates
    ]

    return render_template('grant_templates.html', grants=grants)


@app.route('/delete_grant/<int:grant_id>', methods=['POST'])
def delete_grant_template(grant_id):
    conn = sqlite3.connect('roles.db')
    conn.execute('PRAGMA foreign_keys = ON')
    cursor = conn.cursor()
    try:
        # 1. Obtener todas las rule_ids asociadas al grant
        cursor.execute(
            'SELECT rule_id FROM grant_rules WHERE grant_id = ?', (grant_id,))
        rule_ids = [row[0] for row in cursor.fetchall()]

        # 2. Eliminar relaciones en grant_rules (esto puede ser opcional si ON DELETE CASCADE ya se encarga)
        cursor.execute(
            'DELETE FROM grant_rules WHERE grant_id = ?', (grant_id,))

        # 3. Eliminar reglas (esto borrará también rule_domains y rule_topics por cascada)
        for rule_id in rule_ids:
            cursor.execute('DELETE FROM rules WHERE id = ?', (rule_id,))

        # 4. Eliminar el grantTemplate
        cursor.execute('DELETE FROM grantTemplate WHERE id = ?', (grant_id,))

        # 5. Limpieza opcional: eliminar domains sin uso
        cursor.execute('''
            DELETE FROM domains
            WHERE id NOT IN (SELECT domain_id FROM rule_domains)
        ''')

        # 6. Limpieza opcional: eliminar topics sin uso
        cursor.execute('''
            DELETE FROM topics
            WHERE id NOT IN (SELECT topic_id FROM rule_topics)
        ''')

        conn.commit()
        flash(
            f"Grant template con ID {grant_id} y sus datos asociados fueron eliminados correctamente.", 'success')
    except Exception as e:
        conn.rollback()
        flash(f"Error al eliminar: {e}", 'danger')
    finally:
        conn.close()
    return redirect(url_for('list_grant_templates'))


@app.route('/validar-xml', methods=['GET', 'POST'])
def validar_xml():
    if request.method == 'POST':
        xml_file = request.files.get('xml_file')
        if not xml_file:
            flash("❌ No se ha proporcionado un archivo XML.", "error")
            return redirect(request.url)

        # Guardar el archivo XML en un archivo temporal
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
            xml_path = tmp.name
            xml_file.save(xml_path)

        schema_url = "https://community.rti.com/schema/7.5.0/dds_security_permissions.xsd"

        try:
            schema = xmlschema.XMLSchema(schema_url)
            if schema.is_valid(xml_path):
                flash(
                    "✅ El archivo XML es válido según el esquema DDS Permissions 7.5.0.", "success")
            else:
                errores = [f"- {e}" for e in schema.iter_errors(xml_path)]
                for e in errores:
                    flash(f"❌ Error: {e}", "error")
        except Exception as e:
            flash(f"❌ Error al validar: {e}", "error")
        finally:
            os.remove(xml_path)

        return redirect(url_for('validar_xml'))

    # Si es GET, simplemente muestra el formulario
    return render_template('validar_xml.html')


@app.context_processor
def inyectar_datos_token():
    token = request.cookies.get('token')
    datos_token = {}
    if token:
        datos = decodificar_jwt(token)
        if datos:
            datos_token = datos  # Contiene username, cert, is_superuser, etc.
    return {'token_data': datos_token}


@app.before_request
def cargar_usuario_desde_token():
    token = request.cookies.get('token')
    g.user = None
    if token:
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            g.user = data
        except jwt.ExpiredSignatureError:
            g.user = None
        except jwt.InvalidTokenError:
            g.user = None


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
