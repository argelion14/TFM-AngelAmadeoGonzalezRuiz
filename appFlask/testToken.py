import base64
import os
import io
import sqlite3
import subprocess
import tempfile
import platform
import functools
import yaml
import bcrypt
import jwt
import xmlschema
import xml.etree.ElementTree as ET
from functools import wraps
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from xml.dom import minidom
from cryptography.x509 import load_pem_x509_certificate

from flask import (
    Flask, abort, json, render_template, request, redirect, url_for,
    flash, make_response, g, jsonify, send_file, Response
)
from werkzeug.utils import secure_filename
from flasgger import Swagger, swag_from
from dotenv import load_dotenv

from utils.helpers import (
    get_db_connection, verificar_jwt_api, decodificar_jwt, generar_jwt, verificar_jwt
)

load_dotenv()

CA_CERT_PATH = os.getenv("CA_CERT_PATH")
CA_KEY_PATH = os.getenv("CA_KEY_PATH")

with open(CA_CERT_PATH, "rb") as f:
    cert_bytes = f.read()
CA_CERT = load_pem_x509_certificate(cert_bytes)
CA_PUBLIC_KEY = CA_CERT.public_key()

with open(CA_KEY_PATH, "rb") as f:
    CA_KEY = f.read()

app = Flask(__name__)

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "api-docs",
            "route": "/api-docs.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/swagger_static",
    "swagger_ui": True,
    "specs_route": "/docs/"
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
swagger_file = os.path.join(BASE_DIR, "swagger_template.yml")

with open(swagger_file, "r") as f:
    swagger_template = yaml.safe_load(f)

swagger = Swagger(app, config=swagger_config, template=swagger_template)

app.secret_key = 'super secret key'


# TODO: Verificar todos los métodos de la API que funcionan correctamente

#########################
# SECCIÓN DE AUTENTICACION JWT PARA LA API
# Funciones auxiliares para gestión de seguridad
#########################


@app.route('/api/login', methods=['POST'])
@swag_from({
    'tags': ['Authentication'],
    'summary': 'User Login',
    'description': 'Authenticates a user with username and password. Returns a JWT token if successful.',
    'consumes': ['application/json'],
    'parameters': [{
        'name': 'body',
        'in': 'body',
        'required': True,
        'schema': {
            'type': 'object',
            'required': ['username', 'password'],
            'properties': {
                'username': {'type': 'string', 'example': 'admin'},
                'password': {'type': 'string', 'example': 'yourpassword123'}
            }
        },
        'description': 'User credentials'
    }],
    'responses': {
        200: {
            'description': 'Successful authentication. Returns a JWT token.',
            'schema': {
                'type': 'object',
                'properties': {
                    'token': {'type': 'string', 'example': 'eyJ0eXAiOiJKV1QiLCJhbGci...'}
                }
            }
        },
        400: {'description': 'Missing username or password.'},
        401: {'description': 'Invalid credentials.'}
    }
})
def login_api():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Faltan datos'}), 400

    username = data['username']
    password = data['password']

    user = get_user(username)

    if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
        token = generar_jwt(user)
        return jsonify({'token': token})
    else:
        return jsonify({'error': 'Usuario o contraseña incorrectos'}), 401


def superadmin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = verificar_jwt_api()
        if not user or not user.get("is_superuser", False):
            abort(403, "Only superadmin can perform this action")
        return f(*args, **kwargs)
    return wrapper


def user_required_api(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = verificar_jwt_api()
        if not user or not user.get("username"):
            abort(403, "Invalid token or unauthorized user")
        return f(*args, **kwargs)
    return wrapper


#########################
# SECCIÓN DE GrantTemplate
# Funciones auxiliares para gestión de GrantTemplate
#########################


@app.route('/api/grant-templates', methods=['GET'])
@user_required_api
@swag_from({
    'tags': ['Grant Templates'],
    'summary': 'Lists all grant templates',
    'description': 'Retrieves a list of grant templates with their default action. Requires JWT authentication.',
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'List of grant templates',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'id': {'type': 'integer'},
                        'name': {'type': 'string'},
                        'default_action': {'type': 'string'}
                    }
                }
            }
        },
        403: {'description': 'Invalid or unauthorized token'}
    }
})
def list_grant_templates_api():
    conn = get_db_connection()
    cursor = conn.cursor()
    query = '''
        SELECT id, name, default_action
        FROM grantTemplate
    '''
    cursor.execute(query)
    grant_templates = cursor.fetchall()
    conn.close()

    grants = [
        {
            'id': row[0],
            'name': row[1],
            'default_action': row[2]
        } for row in grant_templates
    ]
    return jsonify(grants)


@app.route('/api/grants', methods=['POST'])
@superadmin_required
@swag_from({
    'tags': ['Grant Templates'],
    'summary': 'Create a new grant from an XML DDS Permissions file',
    'description': 'Allows uploading an XML file to create a grant template and its associated rules.',
    'security': [{'BearerAuth': []}],
    'consumes': ['multipart/form-data'],
    'parameters': [
        {
            'name': 'xml_file',
            'in': 'formData',
            'type': 'file',
            'required': True,
            'description': 'XML DDS Permissions file'
        },
        {
            'name': 'name_override',
            'in': 'formData',
            'type': 'string',
            'required': False,
            'description': 'Optional name for the grant template'
        }
    ],
    'responses': {
        200: {
            'description': 'Grant successfully created',
            'schema': {
                'type': 'object',
                'properties': {
                    'grant_id': {'type': 'integer'},
                    'name': {'type': 'string'},
                    'default_action': {'type': 'string'}
                }
            }
        },
        400: {
            'description': 'Error while creating the grant',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def create_grant_api():
    xml_file = request.files.get('xml_file')
    name_override = request.form.get('name_override', '').strip()

    if not xml_file:
        return jsonify({'error': 'Missing XML file'}), 400

    try:
        grant_id, name, default_action = insert_grant_from_xml_file(
            xml_file.stream, name_override or None
        )
        return jsonify({
            'grant_id': grant_id,
            'name': name,
            'default_action': default_action
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/api/grants/<int:grant_id>', methods=['DELETE'])
@superadmin_required
@swag_from({
    'tags': ['Grant Templates'],
    'summary': 'Delete a grant template by its ID',
    'description': 'Deletes a grant template and all its associated data, including rules, unused domains, and topics.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'grant_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the grant template to delete'
        }
    ],
    'responses': {
        200: {
            'description': 'Grant template successfully deleted',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'}
                }
            }
        },
        404: {
            'description': 'Grant template not found',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        },
        500: {
            'description': 'Internal server error',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def delete_grant_api(grant_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        delete_grant_template_by_id(grant_id, conn)
        conn.commit()
        return jsonify({"message": f"Grant template {grant_id} eliminado correctamente"}), 200
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

#########################
# SECCIÓN DE Auth Role
# Funciones auxiliares para gestión token de roles
#########################


@app.route('/api/auth-role', methods=['POST'])
@user_required_api
@swag_from({
    'tags': ['Auth_role_JWT'],
    'summary': 'Authenticate a specific role for an already authenticated user',
    'description': 'Returns a JWT if the authenticated user has the requested role and it is assigned to a grantTemplate.',
    'security': [{'BearerAuth': []}],
    'consumes': ['application/x-www-form-urlencoded'],
    'parameters': [
        {
            'name': 'role_id',
            'in': 'formData',
            'type': 'integer',
            'required': True,
            'description': 'ID of the role to authenticate'
        },
        {
            'name': 'exp_minutes',
            'in': 'formData',
            'type': 'integer',
            'required': True,
            'description': 'Requested expiration time in minutes (must not exceed the role limit)'
        }
    ],
    'responses': {
        200: {
            'description': 'JWT successfully issued',
            'schema': {
                'type': 'object',
                'properties': {
                    'token': {'type': 'string'}
                }
            }
        },
        401: {
            'description': 'Unauthorized',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def auth_role():
    role_id = request.form.get('role_id', type=int)
    requested_minutes = request.form.get('exp_minutes', type=int)

    if not role_id or not requested_minutes:
        return jsonify({'error': 'Missing required fields'}), 400

    user_data = verificar_jwt_api()
    username = user_data.get('username')
    if not username:
        return jsonify({'error': 'Invalid token'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Get user_id from username
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 401

    user_id = user[0]

    # 2. Verify that the user has the role
    cursor.execute(
        'SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ?', (user_id, role_id))
    if cursor.fetchone() is None:
        conn.close()
        return jsonify({'error': 'User does not have the specified role'}), 401

    # 3. Verify that the role is linked to a grantTemplate and get max exp time
    cursor.execute(
        'SELECT grant_id, exp_time FROM roles WHERE id = ?', (role_id,))
    result = cursor.fetchone()
    if not result or result[0] is None:
        conn.close()
        return jsonify({'error': 'Role is not linked to a grantTemplate'}), 401

    max_minutes = result[1]
    final_minutes = min(requested_minutes, max_minutes)

    # 4. Issue new JWT for this role
    payload = {
        'user_id': user_id,
        'role_id': role_id,
        'exp': datetime.now(timezone.utc) + timedelta(minutes=final_minutes)
    }
    token = jwt.encode(payload, CA_KEY, algorithm="ES256")

    conn.close()
    return jsonify({'token': token})


@app.route('/api/verify-role-token', methods=['POST'])
@swag_from({
    'tags': ['Auth_role_JWT'],
    'summary': 'Verify a role JWT token',
    'description': 'Checks whether the provided JWT token is valid and whether the user has the role specified in the token.',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'token': {
                        'type': 'string',
                        'description': 'JWT containing user_id and role_id',
                        'example': 'eyJhbGciOiJIUzI1NiIsInR5cCI6...'
                    }
                },
                'required': ['token']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Valid token',
            'schema': {
                'type': 'object',
                'properties': {
                    'valid': {'type': 'boolean'},
                    'user_id': {'type': 'integer'},
                    'role_id': {'type': 'integer'}
                }
            }
        },
        400: {
            'description': 'Missing token or invalid format',
            'schema': {
                'type': 'object',
                'properties': {
                    'valid': {'type': 'boolean'},
                    'error': {'type': 'string'}
                }
            }
        },
        401: {
            'description': 'Invalid token or mismatched user/role',
            'schema': {
                'type': 'object',
                'properties': {
                    'valid': {'type': 'boolean'},
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def verify_role_token():
    data = request.get_json()
    token = data.get('token')

    if not token:
        return jsonify({'valid': False, 'error': 'Token not provided'}), 400

    try:
        payload = jwt.decode(token, CA_PUBLIC_KEY, algorithms=["ES256"])
    except jwt.ExpiredSignatureError:
        return jsonify({'valid': False, 'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valid': False, 'error': 'Invalid token'}), 401

    user_id = payload.get('user_id')
    role_id = payload.get('role_id')

    if not user_id or not role_id:
        return jsonify({'valid': False, 'error': 'Incomplete token'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT 1 FROM users WHERE id = ?', (user_id,))
    if cursor.fetchone() is None:
        conn.close()
        return jsonify({'valid': False, 'error': 'User does not exist'}), 401

    cursor.execute('SELECT 1 FROM roles WHERE id = ?', (role_id,))
    if cursor.fetchone() is None:
        conn.close()
        return jsonify({'valid': False, 'error': 'Role does not exist'}), 401

    cursor.execute(
        'SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ?', (user_id, role_id))
    if cursor.fetchone() is None:
        conn.close()
        return jsonify({'valid': False, 'error': 'User does not have this role'}), 401

    conn.close()
    return jsonify({'valid': True, 'user_id': user_id, 'role_id': role_id})


#########################
# SECCIÓN DE ROLES
# Funciones auxiliares para gestión de roles
#########################

@app.route('/api/roles', methods=['GET'])
@user_required_api
@swag_from({
    'tags': ['Roles'],
    'summary': 'Get all roles',
    'description': 'Returns the details of all existing roles',
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'List of roles',
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
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles")
    rows = cursor.fetchall()
    conn.close()
    roles = [dict(row) for row in rows]
    return jsonify(roles)


@app.route('/api/roles/<int:role_id>', methods=['GET'])
@user_required_api
@swag_from({
    'tags': ['Roles'],
    'summary': 'Get role by ID',
    'description': 'Returns role details if it exists, otherwise returns a 404 error.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'role_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the role to retrieve'
        }
    ],
    'responses': {
        200: {
            'description': 'Role details',
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
            'description': 'Role not found'
        }
    }
})
def get_role(role_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles WHERE id=?", (role_id,))
    row = cursor.fetchone()
    conn.close()
    if row is None:
        return jsonify({"error": "Role not found"}), 404
    return jsonify(dict(row))


@app.route('/api/roles', methods=['POST'])
@superadmin_required
@swag_from({
    'tags': ['Roles'],
    'summary': 'Add a new role (superadmin only)',
    'description': 'Allows a superadmin to create a new role by providing a name, optional description, and a required grant_id.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'in': 'body',
            'name': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'required': ['name', 'grant_id'],
                'properties': {
                    'name': {
                        'type': 'string',
                        'description': 'Unique name of the role'
                    },
                    'description': {
                        'type': 'string',
                        'description': 'Description of the role'
                    },
                    'grant_id': {
                        'type': 'integer',
                        'description': 'ID of the grantTemplate this role belongs to'
                    }
                }
            }
        }
    ],
    'responses': {
        201: {
            'description': 'Role successfully created'
        },
        400: {
            'description': 'Invalid data, nonexistent grant_id or duplicate role'
        },
        403: {
            'description': 'Access denied'
        }
    }
})
def add_role():
    data = request.get_json()
    name = data.get('name')
    grant_id = data.get('grant_id')
    description = data.get('description')

    if not name or grant_id is None:
        return jsonify({"error": "Fields 'name' and 'grant_id' are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Verificar que el grant_id existe
    cursor.execute("SELECT id FROM grantTemplate WHERE id = ?", (grant_id,))
    if cursor.fetchone() is None:
        conn.close()
        return jsonify({"error": f"grant_id {grant_id} does not exist"}), 400

    try:
        cursor.execute(
            "INSERT INTO roles (name, description, grant_id) VALUES (?, ?, ?)",
            (name, description, grant_id)
        )
        conn.commit()
        new_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Role with that name already exists"}), 400

    conn.close()
    return jsonify({"message": "Role created", "id": new_id}), 201


@app.route('/api/roles/<int:role_id>', methods=['DELETE'])
@superadmin_required
@swag_from({
    'tags': ['Roles'],
    'summary': 'Delete a role by ID (superadmin only)',
    'description': 'Allows a superadmin to delete an existing role by its ID. The grantTemplate associated to the role, if any, will NOT be deleted.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'role_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the role to delete'
        }
    ],
    'responses': {
        200: {
            'description': 'Role deleted successfully'
        },
        404: {
            'description': 'Role not found'
        },
        403: {
            'description': 'Access denied'
        }
    }
})
def delete_role(role_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('PRAGMA foreign_keys = ON')

    try:
        # Verificar que el rol existe
        cursor.execute("SELECT id FROM roles WHERE id=?", (role_id,))
        if cursor.fetchone() is None:
            return jsonify({"error": "Role not found"}), 404

        # Eliminar el rol (esto también elimina user_roles por ON DELETE CASCADE)
        cursor.execute("DELETE FROM roles WHERE id=?", (role_id,))
        conn.commit()

        return jsonify({"message": "Role deleted successfully"}), 200

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        conn.close()


@app.route('/api/roles/<int:role_id>', methods=['PUT'])
@superadmin_required
@swag_from({
    'tags': ['Roles'],
    'summary': 'Update a role by ID (superadmin only)',
    'description': 'Allows a superadmin to update the name, description or associated grantTemplate of an existing role by its ID.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'role_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the role to update'
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
                        'description': 'New name for the role'
                    },
                    'description': {
                        'type': 'string',
                        'description': 'New description for the role'
                    },
                    'grant_id': {
                        'type': 'integer',
                        'description': 'ID of the associated grantTemplate'
                    }
                }
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Role successfully updated'
        },
        400: {
            'description': 'Invalid data, grantTemplate not found or duplicate role name'
        },
        404: {
            'description': 'Role not found'
        },
        403: {
            'description': 'Access denied'
        }
    }
})
def update_role(role_id):
    data = request.get_json()
    if not data:
        return jsonify({"error": "A JSON body is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if role exists
    cursor.execute("SELECT id FROM roles WHERE id=?", (role_id,))
    if cursor.fetchone() is None:
        conn.close()
        return jsonify({"error": "Role not found"}), 404

    if 'grant_id' in data and data['grant_id'] is not None:
        cursor.execute(
            "SELECT id FROM grantTemplate WHERE id = ?", (data['grant_id'],))
        if cursor.fetchone() is None:
            conn.close()
            return jsonify({"error": "grantTemplate not found"}), 400

    fields = []
    values = []
    if 'name' in data:
        fields.append("name = ?")
        values.append(data['name'])
    if 'description' in data:
        fields.append("description = ?")
        values.append(data['description'])
    if 'grant_id' in data:
        fields.append("grant_id = ?")
        values.append(data['grant_id'])

    if not fields:
        conn.close()
        return jsonify({"error": "No fields specified to update"}), 400

    values.append(role_id)

    try:
        cursor.execute(
            f"UPDATE roles SET {', '.join(fields)} WHERE id = ?", values)
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "A role with that name already exists"}), 400

    conn.close()
    return jsonify({"message": "Role successfully updated"})


#########################
# SECCIÓN DE USERS
# Funciones auxiliares para gestión de usuarios
#########################

@app.route('/api/users', methods=['GET'])
@user_required_api
@swag_from({
    'tags': ['Users'],
    'summary': 'Retrieve all users',
    'description': 'Returns a list of all users with their ID, username, certificate, superuser status, and public certificate.',
    'security': [{'BearerAuth': []}],
    'responses': {
        200: {
            'description': 'List of users',
            'schema': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'id': {'type': 'integer'},
                        'username': {'type': 'string'},
                        'cert': {'type': 'string'},
                        'is_superuser': {'type': 'boolean'},
                        'public_cert': {'type': 'string'}
                    }
                }
            }
        }
    }
})
def list_users():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.execute('''
        SELECT
            u.id,
            u.username,
            u.cert,
            u.is_superuser,
            uk.public_cert
        FROM users u
        LEFT JOIN user_keys uk ON u.id = uk.user_id AND uk.is_active = 1
    ''')
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)


@app.route('/api/users/<int:user_id>', methods=['GET'])
@swag_from({
    'tags': ['Users'],
    'summary': 'Get user by ID',
    'description': 'Retrieves detailed information about a specific user, including key data if available.',
    'parameters': [
        {'name': 'user_id', 'in': 'path', 'type': 'integer',
         'required': True, 'description': 'ID of the user to retrieve'}
    ],
    'responses': {
        200: {'description': 'User found'},
        404: {'description': 'User not found'}
    }
})
def get_user(user_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Obtener datos del usuario
    cursor.execute(
        "SELECT id, username, cert, is_superuser FROM users WHERE id = ?", (user_id,))
    user_row = cursor.fetchone()

    if not user_row:
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    user_data = dict(user_row)

    cursor.execute(
        "SELECT public_cert FROM user_keys WHERE user_id = ?", (user_id,))
    key_row = cursor.fetchone()

    if key_row and 'public_cert' in key_row.keys():
        user_data['public_cert'] = key_row['public_cert']
    else:
        user_data['public_cert'] = None

    conn.close()
    return jsonify(user_data)


@app.route('/api/users', methods=['POST'])
@superadmin_required
@swag_from({
    'tags': ['Users'],
    'summary': 'Create a new user',
    'description': 'Creates a new user with certificate and key generation. Requires superadmin privileges.',
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
                    'is_superuser': {'type': 'boolean'}
                },
                'required': ['username', 'password']
            }
        }
    ],
    'responses': {
        201: {'description': 'User created successfully'},
        400: {'description': 'Error creating user, e.g., username already exists or missing required fields'},
        500: {'description': 'Internal server error'}
    }
})
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    is_superuser = 1 if data.get('is_superuser', False) else 0

    if not username or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    hashed_pw = bcrypt.hashpw(password.encode(
        'utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (username, password, is_superuser)
            VALUES (?, ?, ?)
        ''', (username, hashed_pw, is_superuser))
        user_id = cursor.lastrowid
        conn.commit()

        # ==== GENERACIÓN DE CLAVES Y CERTIFICADO ====
        ca_cert = os.getenv("CA_CERT_PATH")
        ca_key = os.getenv("CA_KEY_PATH")
        base_dir = os.path.join("appFlask", "certs", username)
        os.makedirs(base_dir, exist_ok=True)

        key_path = os.path.join(base_dir, "private.key")
        csr_path = os.path.join(base_dir, "request.csr")
        cert_path = os.path.join(base_dir, "certificate.pem")

        # Detectar entorno
        if platform.system() == "Windows":
            OPENSSL_PATH = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
        else:
            # Se espera que esté en el PATH (como en Docker)
            OPENSSL_PATH = "/usr/bin/openssl"

        # 1. Clave privada
        subprocess.run([
            OPENSSL_PATH, "genpkey", "-algorithm", "EC",
            "-pkeyopt", "ec_paramgen_curve:P-256",
            "-out", key_path
        ], check=True)

        # 2. CSR
        subj = f"/C=US/ST=CA/O=RTI Demo/CN={username}"
        subprocess.run([
            OPENSSL_PATH, "req", "-new", "-key", key_path,
            "-out", csr_path, "-subj", subj
        ], check=True)

        # 3. Certificado firmado
        subprocess.run([
            OPENSSL_PATH, "x509", "-req", "-in", csr_path,
            "-CA", ca_cert, "-CAkey", ca_key,
            "-CAcreateserial", "-out", cert_path,
            "-days", "365"
        ], check=True)

        # 4. Leer contenido del certificado
        with open(cert_path, 'r') as f:
            cert_pem = f.read()

        # 4.1 Extraer subject real
        result = subprocess.run([
            OPENSSL_PATH, "x509", "-in", cert_path, "-noout", "-subject"
        ], capture_output=True, text=True, check=True)

        subject_line = result.stdout.strip()
        subject_clean = subject_line.replace("subject=", "").strip()

        # 4.2 Actualizar campo cert en la tabla users
        cursor.execute('''
            UPDATE users SET cert = ? WHERE id = ?
        ''', (subject_clean, user_id))

        # 5. Insertar en tabla user_keys
        cursor.execute('''
            INSERT INTO user_keys (user_id, public_cert, private_key_path)
            VALUES (?, ?, ?)
        ''', (user_id, cert_pem, key_path))

        conn.commit()
        return jsonify({'message': 'User and certificate created successfully'}), 201

    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    except subprocess.CalledProcessError as e:
        return jsonify({'error': f'Certificate generation failed: {e}'}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# TODO: Que borre el usuario y sus certificados


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@superadmin_required
@swag_from({
    'tags': ['Users'],
    'summary': 'Delete a user',
    'description': 'Deletes the user and their associated keys from the database. Requires superadmin privileges.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {'name': 'user_id', 'in': 'path', 'type': 'integer',
            'required': True, 'description': 'ID of the user to delete'}
    ],
    'responses': {
        200: {'description': 'User and keys deleted successfully'},
        404: {'description': 'User not found'}
    }
})
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Verificar si el usuario existe
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    # Eliminar claves asociadas al usuario (si existen)
    cursor.execute('DELETE FROM user_keys WHERE user_id = ?', (user_id,))

    # Eliminar el usuario
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))

    conn.commit()
    conn.close()

    return jsonify({'message': 'User and associated keys deleted successfully'}), 200


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@superadmin_required
@swag_from({
    'tags': ['Users'],
    'summary': 'Update a user',
    'description': 'Updates username and superuser status. Requires superadmin privileges.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to update'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'username': {'type': 'string', 'description': 'New username'},
                    'is_superuser': {'type': 'boolean', 'description': 'Superuser status'}
                },
                'required': ['username']  # username es obligatorio
            }
        }
    ],
    'responses': {
        200: {'description': 'User updated successfully'},
        400: {'description': 'Invalid input or user not found'},
        404: {'description': 'User not found'}
    }
})
def update_user(user_id):
    data = request.get_json()

    if not data or 'username' not in data:
        return jsonify({'error': 'Username is required'}), 400

    username = data['username']
    is_superuser = 1 if data.get('is_superuser', False) else 0

    conn = get_db_connection()
    cursor = conn.cursor()

    # Verificar si el usuario existe
    cursor.execute("SELECT id FROM users WHERE id = ?", (user_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    # Realizar la actualización
    cursor.execute("""
        UPDATE users
        SET username = ?, is_superuser = ?
        WHERE id = ?
    """, (username, is_superuser, user_id))

    conn.commit()
    conn.close()

    return jsonify({'message': 'User updated successfully'}), 200


@app.route('/api/users/<int:user_id>/roles', methods=['POST'])
@swag_from({
    'tags': ['TEST'],
    'summary': 'Associate roles to a user',
    'description': 'Adds one or more roles to the specified user. Skips any roles already associated.',
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user to update'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'role_ids': {
                        'type': 'array',
                        'items': {'type': 'integer'},
                        'description': 'List of role IDs to associate with the user'
                    }
                },
                'required': ['role_ids']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Roles associated successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'user_id': {'type': 'integer'},
                    'roles_added': {
                        'type': 'array',
                        'items': {'type': 'integer'}
                    }
                }
            }
        },
        400: {
            'description': 'Invalid user_id or role_ids'
        },
        404: {
            'description': 'User not found'
        }
    }
})
def assign_roles_to_user(user_id):
    data = request.get_json()
    role_ids = data.get('role_ids')

    if not role_ids or not isinstance(role_ids, list):
        return jsonify({'error': 'role_ids must be a non-empty list'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Verificar existencia del usuario
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    roles_added = []
    for role_id in role_ids:
        # Verificar si el rol existe
        cursor.execute("SELECT id FROM roles WHERE id=?", (role_id,))
        if not cursor.fetchone():
            continue  # Ignora roles inexistentes

        # Verificar si ya está asociado
        cursor.execute(
            "SELECT 1 FROM user_roles WHERE user_id=? AND role_id=?", (user_id, role_id))
        if not cursor.fetchone():
            cursor.execute(
                "INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)", (user_id, role_id))
            roles_added.append(role_id)

    conn.commit()
    conn.close()

    return jsonify({
        'message': 'Roles associated successfully',
        'user_id': user_id,
        'roles_added': roles_added
    }), 200


@app.route('/api/users/<int:user_id>/roles', methods=['GET'])
@swag_from({
    'tags': ['Users'],
    'summary': 'Get roles assigned to a user',
    'description': 'Returns a list of role IDs assigned to the given user.',
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user'
        }
    ],
    'responses': {
        200: {
            'description': 'List of assigned role IDs',
            'schema': {
                'type': 'object',
                'properties': {
                    'assigned_role_ids': {
                        'type': 'array',
                        'items': {'type': 'integer'}
                    }
                }
            }
        },
        404: {
            'description': 'User not found'
        }
    }
})
def get_user_roles(user_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    # Comprueba si el usuario existe
    user_check = conn.execute(
        "SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user_check:
        conn.close()
        return jsonify({"error": "User not found"}), 404

    # Extrae los roles del usuario
    cursor = conn.execute(
        "SELECT role_id FROM user_roles WHERE user_id = ?", (user_id,))
    roles = [row['role_id'] for row in cursor.fetchall()]
    conn.close()
    return jsonify({'assigned_role_ids': roles})

#########################
# SECCIÓN DE XML
# Funciones auxiliares para gestión de XML
#########################


@app.route('/api/validate-xml', methods=['POST'])
@swag_from({
    'tags': ['XML'],
    'summary': 'Validate an XML file against the DDS Permissions 7.5.0 schema',
    'description': 'Uploads and validates an XML file using the DDS Permissions 7.5.0 XSD schema, returning validation results.',
    'consumes': ['multipart/form-data'],
    'parameters': [
        {
            'name': 'xml_file',
            'in': 'formData',
            'type': 'file',
            'required': True,
            'description': 'XML file to be validated'
        }
    ],
    'responses': {
        200: {
            'description': 'Result of the XML validation',
            'schema': {
                'type': 'object',
                'properties': {
                    'valid': {'type': 'boolean', 'description': 'Whether the XML is valid'},
                    'message': {'type': 'string', 'description': 'Validation message'},
                    'errors': {
                        'type': 'array',
                        'items': {'type': 'string'},
                        'description': 'List of validation errors if any'
                    }
                }
            }
        },
        400: {
            'description': 'No file provided or validation error'
        }
    }
})
def validate_xml_api():
    xml_file = request.files.get('xml_file')
    if not xml_file:
        return jsonify({"error": "No XML file provided"}), 400

    schema_url = "https://community.rti.com/schema/7.5.0/dds_security_permissions.xsd"
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as tmp:
        xml_path = tmp.name
        xml_file.save(xml_path)

    try:
        schema = xmlschema.XMLSchema(schema_url)
        if schema.is_valid(xml_path):
            result = {
                "valid": True,
                "message": "✅ The XML file is valid according to the DDS Permissions 7.5.0 schema.",
                "errors": []
            }
        else:
            errors = [str(e) for e in schema.iter_errors(xml_path)]
            result = {
                "valid": False,
                "message": "❌ The XML file is not valid.",
                "errors": errors
            }
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": f"❌ Validation error: {str(e)}"}), 400
    finally:
        os.remove(xml_path)


def generar_xml_grant_by_role(role_id, user_data, conn):
    cursor = conn.cursor()

    # Obtener el grant_id y datos del grant
    cursor.execute('''
        SELECT g.id, g.name, g.default_action
        FROM roles r
        JOIN grantTemplate g ON r.grant_id = g.id
        WHERE r.id = ?
    ''', (role_id,))
    row = cursor.fetchone()
    if not row:
        return None, None, 'No grant associated with this role'

    grant_id, grant_name, default_action = row

    # Construcción del XML
    dds = ET.Element('dds', {
        'xmlns:xsi': "http://www.w3.org/2001/XMLSchema-instance",
        'xsi:noNamespaceSchemaLocation': "http://community.rti.com/schema/7.3.0/dds_security_permissions.xsd"
    })
    permissions = ET.SubElement(dds, 'permissions')
    grant_elem = ET.SubElement(permissions, 'grant', {'name': grant_name})

    subject = ET.SubElement(grant_elem, 'subject_name')
    subject.text = user_data.get('cert', 'CN=Unknown')

    cursor.execute('SELECT exp_time FROM roles WHERE id = ?', (role_id,))
    exp_minutes = cursor.fetchone()
    exp_minutes = exp_minutes[0] if exp_minutes else 60

    now = datetime.now()
    not_before_str = now.strftime('%Y-%m-%dT%H:%M:%S')
    not_after_str = (now + timedelta(minutes=exp_minutes)
                     ).strftime('%Y-%m-%dT%H:%M:%S')

    validity = ET.SubElement(grant_elem, 'validity')
    ET.SubElement(validity, 'not_before').text = not_before_str
    ET.SubElement(validity, 'not_after').text = not_after_str

    cursor.execute('''
        SELECT rules.id, rules.permiso
        FROM rules
        JOIN grant_rules ON rules.id = grant_rules.rule_id
        WHERE grant_rules.grant_id = ?
    ''', (grant_id,))
    rules = cursor.fetchall()

    for rule_id, permiso in rules:
        rule_tag = ET.SubElement(grant_elem, permiso)

        cursor.execute('''
            SELECT domains.name FROM rule_domains
            JOIN domains ON rule_domains.domain_id = domains.id
            WHERE rule_domains.rule_id = ?
        ''', (rule_id,))
        domain_rows = cursor.fetchall()
        if domain_rows:
            domains_elem = ET.SubElement(rule_tag, 'domains')
            for (domain,) in domain_rows:
                ET.SubElement(domains_elem, 'id').text = domain

        cursor.execute('''
            SELECT topics.name FROM rule_topics
            JOIN topics ON rule_topics.topic_id = topics.id
            WHERE rule_topics.rule_id = ? AND rule_topics.action = 'publish'
        ''', (rule_id,))
        publish_rows = cursor.fetchall()
        if publish_rows:
            pub_elem = ET.SubElement(rule_tag, 'publish')
            topics_elem = ET.SubElement(pub_elem, 'topics')
            for (topic,) in publish_rows:
                ET.SubElement(topics_elem, 'topic').text = topic

        cursor.execute('''
            SELECT topics.name FROM rule_topics
            JOIN topics ON rule_topics.topic_id = topics.id
            WHERE rule_topics.rule_id = ? AND rule_topics.action = 'subscribe'
        ''', (rule_id,))
        subscribe_rows = cursor.fetchall()
        if subscribe_rows:
            sub_elem = ET.SubElement(rule_tag, 'subscribe')
            topics_elem = ET.SubElement(sub_elem, 'topics')
            for (topic,) in subscribe_rows:
                ET.SubElement(topics_elem, 'topic').text = topic

    ET.SubElement(grant_elem, 'default').text = default_action

    xml_str = ET.tostring(dds, encoding='utf-8')
    pretty_xml = minidom.parseString(xml_str).toprettyxml(
        indent="  ", encoding='utf-8')

    return pretty_xml, grant_name, None


@app.route('/api/export-grantbyrole', methods=['POST'])
@swag_from({
    'tags': ['XML'],
    'summary': 'Export a grantTemplate in XML format using JWT token, optionally signed',
    'description': 'Authenticated users submit a signed JWT token that includes the role_id and exp timestamp. If authorized, the XML is returned. Use the "sign" parameter to get it signed.',
    'security': [{'BearerAuth': []}],
    'consumes': ['application/x-www-form-urlencoded'],
    'parameters': [
        {
            'name': 'token',
            'in': 'formData',
            'type': 'string',
            'required': True,
            'description': 'Signed JWT token with role_id and exp'
        },
        {
            'name': 'sign',
            'in': 'formData',
            'type': 'string',
            'required': False,
            'description': 'Set to "on" or "true" to return signed XML (.p7s)'
        }
    ],
    'responses': {
        200: {'description': 'XML or signed file returned successfully'},
        400: {'description': 'Missing or invalid input'},
        401: {'description': 'Unauthorized user'},
        403: {'description': 'User does not have access to this role'},
        404: {'description': 'Role or grant not found'}
    }
})
@user_required_api
def export_grant_by_role_token():
    token = request.form.get("token")
    sign = request.form.get("sign", "").lower() in ["on", "true", "1"]

    if not token:
        return jsonify({'error': 'Token is required'}), 400

    try:
        payload = jwt.decode(token, CA_KEY, algorithms=["ES256"])
        role_id = payload.get("role_id")
        exp = payload.get("exp")

        if not role_id or not exp:
            return jsonify({'error': 'Invalid token: missing role_id or exp'}), 400

        not_before = datetime.now()
        not_after = datetime.fromtimestamp(exp)
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 400

    user_data = verificar_jwt_api()
    username = user_data.get('username')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()

    if not user:
        return jsonify({'error': 'User not found'}), 401

    user_id = user[0]
    cursor.execute(
        'SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ?', (user_id, role_id))
    if cursor.fetchone() is None:
        return jsonify({'error': 'Role does not belong to user'}), 403

    xml_data, grant_name, error = generar_xml_grant(
        role_id, user_data, conn,
        not_before=not_before,
        not_after=not_after
    )
    conn.close()

    if error:
        return jsonify({'error': error}), 404

    if sign:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as xml_file:
            xml_file.write(xml_data)
            xml_path = xml_file.name

        signed_output_path = os.path.join(
            tempfile.gettempdir(), f"{grant_name}.p7s"
        )

        OPENSSL_PATH = (
            r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
            if platform.system() == "Windows"
            else "/usr/bin/openssl"
        )

        result = subprocess.run([
            OPENSSL_PATH, "smime", "-sign",
            "-in", xml_path,
            "-out", signed_output_path,
            "-signer", CA_CERT_PATH,
            "-inkey", CA_KEY_PATH,
            "-outform", "DER",
            "-nodetach"
        ], capture_output=True)

        os.remove(xml_path)

        if result.returncode != 0:
            return jsonify({'error': 'Signing failed: ' + result.stderr.decode()}), 400

        return send_file(signed_output_path,
                         as_attachment=True,
                         download_name=f"{grant_name}.p7s",
                         mimetype='application/pkcs7-signature')

    else:
        return Response(xml_data,
                        mimetype='application/xml',
                        headers={
                            'Content-Disposition': f'attachment; filename={grant_name}.xml'
                        })


#########################
# SECCIÓN DE TEST
# Funciones auxiliares para gestión de TEST
#########################


@app.route('/api/verify-signed-file', methods=['POST'])
@swag_from({
    'tags': ['TEST'],
    'summary': 'Verifica un archivo .p7s firmado (PKCS#7)',
    'description': 'Verifica la firma digital de un archivo .p7s usando el certificado del firmante',
    'consumes': ['multipart/form-data'],
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'file',
            'in': 'formData',
            'type': 'file',
            'required': True,
            'description': 'Archivo firmado (.p7s)'
        }
    ],
    'responses': {
        200: {'description': 'Firma verificada correctamente'},
        400: {'description': 'Faltan parámetros o archivo inválido'},
        500: {'description': 'Error al verificar la firma'}
    }
})
def verify_signed_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No se envió ningún archivo'}), 400

    file = request.files['file']

    with tempfile.NamedTemporaryFile(delete=False, suffix=".p7s") as temp_signed:
        file.save(temp_signed.name)
        signed_path = temp_signed.name

    # Temporal para la salida verificada
    verified_path = signed_path + ".verified"

    # Detectar entorno
    if platform.system() == "Windows":
        OPENSSL_PATH = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    else:
        # Se espera que esté en el PATH (como en Docker)
        OPENSSL_PATH = "/usr/bin/openssl"

    try:
        result = subprocess.run([
            OPENSSL_PATH, "smime", "-verify",
            "-in", signed_path,
            "-inform", "DER",
            "-CAfile", CA_CERT_PATH,
            "-out", verified_path
        ], capture_output=True)

        if result.returncode != 0:
            return jsonify({
                'error': 'La verificación falló',
                'details': result.stderr.decode()
            }), 400

        with open(verified_path, 'rb') as f:
            content = f.read()

        return {
            'message': 'Firma verificada correctamente',
            'original_data': content.decode('utf-8', errors='replace')
        }, 200

    finally:
        os.remove(signed_path)
        if os.path.exists(verified_path):
            os.remove(verified_path)


#########################
# SECCIÓN DE grantTemplate - rols
# Funciones auxiliares para interacción entre roles y grantTemplate
#########################

@app.route('/api/roles/<int:role_id>/grant', methods=['PATCH'])
@swag_from({
    'tags': ['TEST'],
    'summary': 'Associate or update a grantTemplate to a role',
    'description': 'Updates the grantTemplate (grant_id) associated with a given role.',
    'parameters': [
        {
            'name': 'role_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the role to update'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'grant_id': {
                        'type': 'integer',
                        'description': 'ID of an existing grantTemplate'
                    }
                },
                'required': ['grant_id']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'GrantTemplate updated',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'role_id': {'type': 'integer'},
                    'grant_id': {'type': 'integer'}
                }
            }
        },
        400: {
            'description': 'Invalid grant_id or role_id'
        },
        404: {
            'description': 'Role not found'
        }
    }
})
def update_role_grant(role_id):
    data = request.get_json()
    grant_id = data.get('grant_id')

    if grant_id is None:
        return jsonify({'error': 'grant_id is required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM roles WHERE id=?", (role_id,))
    role = cursor.fetchone()
    if not role:
        conn.close()
        return jsonify({'error': 'Role not found'}), 404

    cursor.execute("SELECT id FROM grantTemplate WHERE id=?", (grant_id,))
    grant = cursor.fetchone()
    if not grant:
        conn.close()
        return jsonify({'error': 'Invalid grant_id'}), 400

    cursor.execute("UPDATE roles SET grant_id=? WHERE id=?",
                   (grant_id, role_id))
    conn.commit()
    conn.close()

    return jsonify({
        'message': 'GrantTemplate updated',
        'role_id': role_id,
        'grant_id': grant_id
    }), 200

#########################
# SECCIÓN DE usuarios - roles
# Funciones auxiliares para interacción entre usuarios y roles
#########################


@app.route('/api/users/<int:user_id>/roles', methods=['DELETE'])
@swag_from({
    'tags': ['TEST'],
    'summary': 'Remove roles from a user',
    'description': 'Removes one or more roles associated with a user. Ignores roles that are not currently associated.',
    'parameters': [
        {
            'name': 'user_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the user'
        },
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'role_ids': {
                        'type': 'array',
                        'items': {'type': 'integer'},
                        'description': 'List of role IDs to remove from the user'
                    }
                },
                'required': ['role_ids']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Roles removed successfully',
            'schema': {
                'type': 'object',
                'properties': {
                    'message': {'type': 'string'},
                    'user_id': {'type': 'integer'},
                    'roles_removed': {
                        'type': 'array',
                        'items': {'type': 'integer'}
                    }
                }
            }
        },
        400: {
            'description': 'Invalid input'
        },
        404: {
            'description': 'User not found'
        }
    }
})
def remove_roles_from_user(user_id):
    data = request.get_json()
    role_ids = data.get('role_ids')

    if not role_ids or not isinstance(role_ids, list):
        return jsonify({'error': 'role_ids must be a non-empty list'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE id=?", (user_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'User not found'}), 404

    roles_removed = []
    for role_id in role_ids:
        cursor.execute(
            "DELETE FROM user_roles WHERE user_id=? AND role_id=?", (user_id, role_id))
        if cursor.rowcount > 0:
            roles_removed.append(role_id)

    conn.commit()
    conn.close()

    return jsonify({
        'message': 'Roles removed successfully',
        'user_id': user_id,
        'roles_removed': roles_removed
    }), 200


#########################
########## Decode API #########
#########################

@app.route('/api/decode', methods=['POST'])
@swag_from({
    'tags': ['JWT Utilities'],
    'summary': 'Decode JWT payload',
    'description': 'Decodes the payload of a JWT token and shows UNIX timestamp fields in UTC and Madrid time (UTC+2 fixed offset).',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'token': {
                        'type': 'string',
                        'description': 'JWT token to decode',
                        'example': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJleHAiOjE3MDEwMjAwMDB9.abc123'
                    }
                },
                'required': ['token']
            }
        }
    ],
    'responses': {
        200: {
            'description': 'Decoded token payload with formatted timestamps',
            'schema': {
                'type': 'object',
                'properties': {
                    'payload': {'type': 'object'}
                }
            }
        },
        400: {
            'description': 'Invalid or malformed token',
            'schema': {
                'type': 'object',
                'properties': {
                    'error': {'type': 'string'}
                }
            }
        }
    }
})
def api_decode():
    data = request.get_json()
    token = data.get('token', '').strip()
    parts = token.split('.')

    if len(parts) != 3:
        return jsonify({'error': '❌ Invalid token: it must have 3 parts (header.payload.signature).'}), 400

    try:
        padded_payload = parts[1] + '=' * (-len(parts[1]) % 4)
        decoded_bytes = base64.urlsafe_b64decode(padded_payload)
        payload_data = json.loads(decoded_bytes)

        # Simula horario de verano manualmente
        madrid_offset = timedelta(hours=2)
        madrid_tz = timezone(madrid_offset)

        for key in ['exp', 'iat', 'nbf']:
            if key in payload_data:
                try:
                    timestamp = int(payload_data[key])
                    utc_dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                    madrid_dt = utc_dt.astimezone(madrid_tz)

                    payload_data[key] = {
                        'utc': utc_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'madrid': madrid_dt.strftime('%Y-%m-%d %H:%M:%S +02:00 Europe/Madrid (fixed offset)')
                    }
                except Exception:
                    pass

        return jsonify({'payload': payload_data})

    except Exception as e:
        return jsonify({'error': f'❌ Failed to decode token payload: {str(e)}'}), 400


#########################
########## HTML #########
#########################


def superuser_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = verificar_jwt()
        if not user:
            return redirect(url_for('login'))
        if not user.get('is_superuser', False):
            return render_template("access_denied.html"), 403
        return f(*args, **kwargs)
    return decorated_function


def user_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = verificar_jwt()
        if not user:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

#########################
# SECCIÓN DE HTML ROLES
#########################


def get_roles_html():
    """
    Recupera todos los roles junto con el nombre del grantTemplate asociado.

    Returns:
        list[sqlite3.Row]: Lista de filas con información de roles y sus grant templates.
    """
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT
            roles.id,
            roles.name,
            roles.description,
            roles.exp_time,
            grantTemplate.name AS grant_name
        FROM roles
        LEFT JOIN grantTemplate ON roles.grant_id = grantTemplate.id
    ''')
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_roles_by_username(username):
    conn = get_db_connection()
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


@app.route('/role_list', methods=['GET'])
@superuser_required
def role_list():
    roles = get_roles_html()
    return render_template("role_list.html", roles=roles)


@app.route('/create_role', methods=['GET', 'POST'])
@superuser_required
def create_role():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        exp_time = request.form.get('exp_time')
        grant_id = request.form.get('grant_id')

        # Validación básica
        if not name or not exp_time:
            flash("❌ Nombre y tiempo de expiración son obligatorios.", "danger")
        else:
            try:
                cursor.execute(
                    "INSERT INTO roles (name, description, exp_time, grant_id) VALUES (?, ?, ?, ?)",
                    (name, description, exp_time, grant_id if grant_id else None)
                )
                conn.commit()
                flash(f"✅ Rol '{name}' creado correctamente.", "success")
                return redirect(url_for('role_list'))
            except Exception as e:
                flash(f"❌ Error al crear el rol: {str(e)}", "danger")

    # Obtener los templates para la lista desplegable
    cursor.execute("SELECT id, name FROM grantTemplate")
    templates = cursor.fetchall()

    conn.close()
    return render_template("role_create.html", templates=templates)


@app.route('/delete_role/<int:role_id>', methods=['POST'])
@superuser_required
def delete_role_html(role_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # 👈 Esto permite acceder con ['name']
    cursor = conn.cursor()

    # Verificamos si el rol existe
    cursor.execute("SELECT name FROM roles WHERE id = ?", (role_id,))
    role = cursor.fetchone()

    if not role:
        conn.close()
        flash("❌ Rol no encontrado.", "danger")
        return redirect(url_for('role_list'))

    # Eliminamos el rol
    cursor.execute("DELETE FROM roles WHERE id = ?", (role_id,))
    conn.commit()
    conn.close()

    flash(f"✅ Rol '{role['name']}' eliminado correctamente.", "success")
    return redirect(url_for('role_list'))


@app.route('/edit_role/<int:role_id>', methods=['GET', 'POST'])
@superuser_required
def edit_role(role_id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        exp_time = request.form['exp_time']
        grant_id = request.form.get('grant_id') or None

        cursor.execute('''
            UPDATE roles SET name=?, description=?, exp_time=?, grant_id=?
            WHERE id=?
        ''', (name, description, exp_time, grant_id, role_id))
        conn.commit()
        conn.close()
        return redirect(url_for('role_list'))

    cursor.execute("SELECT * FROM roles WHERE id=?", (role_id,))
    role = cursor.fetchone()

    if not role:
        abort(404)

    cursor.execute("SELECT * FROM grantTemplate")
    grant_templates = cursor.fetchall()
    conn.close()

    return render_template("role_edit.html", role=role, grant_templates=grant_templates)


@app.route('/role_assign', methods=['GET', 'POST'])
@superuser_required
def role_assign():
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == 'POST':
        try:
            user_id = int(request.form.get('user_id'))
            selected_roles = set(map(int, request.form.getlist('role_ids')))
        except (ValueError, TypeError):
            flash('Invalid data. Please select a user and roles.', 'danger')
            return redirect(url_for('role_assign'))

        cursor.execute(
            'SELECT role_id FROM user_roles WHERE user_id = ?', (user_id,))
        current_roles = set(row['role_id'] for row in cursor.fetchall())

        to_add = selected_roles - current_roles
        to_remove = current_roles - selected_roles

        for role_id in to_add:
            cursor.execute(
                'INSERT INTO user_roles (user_id, role_id) VALUES (?, ?)', (user_id, role_id))

        for role_id in to_remove:
            cursor.execute(
                'DELETE FROM user_roles WHERE user_id = ? AND role_id = ?', (user_id, role_id))

        conn.commit()

        if to_add or to_remove:
            messages = []
            if to_add:
                messages.append(f'added: {sorted(to_add)}')
            if to_remove:
                messages.append(f'removed: {sorted(to_remove)}')
            flash(
                f'Roles updated ({", ".join(messages)}) for user ID {user_id}.', 'success')
        else:
            flash('No changes were made to the user roles.', 'info')

    cursor.execute("SELECT id, username FROM users ORDER BY username")
    users = cursor.fetchall()

    cursor.execute("SELECT id, name FROM roles ORDER BY name")
    roles = cursor.fetchall()

    user_roles_map = {}
    for user in users:
        cursor.execute(
            "SELECT role_id FROM user_roles WHERE user_id = ?", (user['id'],))
        user_roles_map[user['id']] = [row['role_id']
                                      for row in cursor.fetchall()]

    conn.close()

    return render_template('role_assign.html', users=users, roles=roles, user_roles_map=user_roles_map)


#########################
# SECCIÓN DE USER HTML
#########################


def get_user(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, password, cert, is_superuser FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_users():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, cert FROM users")
    rows = cursor.fetchall()
    conn.close()
    return rows


@app.route('/user_list')
def user_list():
    user = verificar_jwt()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()

    # Obtener los roles asociados a cada usuario
    users_with_roles = []
    for u in users:
        cursor.execute('''
            SELECT r.name
            FROM roles r
            INNER JOIN user_roles ur ON ur.role_id = r.id
            WHERE ur.user_id = ?
        ''', (u['id'],))
        roles = [row['name'] for row in cursor.fetchall()]
        users_with_roles.append({
            'id': u['id'],
            'username': u['username'],
            'cert': u['cert'],
            'roles': roles
        })

    conn.close()
    return render_template('user_list.html', usuarios=users_with_roles)


@app.route('/user/<int:id>')
@superuser_required
def user_detail(id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        'SELECT username, is_superuser, cert FROM users WHERE id = ?', (id,))
    user = cursor.fetchone()

    cursor.execute(
        'SELECT user_id, public_cert FROM user_keys WHERE user_id = ?', (id,))
    keys = cursor.fetchone()

    cursor.execute(
        '''SELECT r.name FROM roles r
           INNER JOIN user_roles ur ON ur.role_id = r.id
           WHERE ur.user_id = ?''', (id,))
    roles = [row['name'] for row in cursor.fetchall()]

    conn.close()

    if not user:
        flash("User not found", "danger")
        return redirect(url_for('user_list'))

    return render_template('user_detail.html', user=user, keys=keys, roles=roles)


@app.route('/user_create', methods=['GET', 'POST'])
@superuser_required
def user_create():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_superuser = 1 if request.form.get('is_superuser') == 'on' else 0

        if not username or not password:
            flash("Usuario y contraseña son obligatorios", "danger")
            return redirect(url_for('user_create'))

        hashed_pw = bcrypt.hashpw(password.encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            # ====== INSERCIÓN PREVIA EN TABLA users ======
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, password, is_superuser)
                VALUES (?, ?, ?)
            ''', (username, hashed_pw, is_superuser))
            user_id = cursor.lastrowid
            conn.commit()

            # ====== GENERACIÓN DE CLAVES Y CERTIFICADO ======
            ca_cert = os.getenv("CA_CERT_PATH")
            ca_key = os.getenv("CA_KEY_PATH")
            base_dir = f"certs/{username}"
            os.makedirs(base_dir, exist_ok=True)

            key_path = os.path.join(base_dir, "private.key")
            csr_path = os.path.join(base_dir, "request.csr")
            cert_path = os.path.join(base_dir, "certificate.pem")

            # Detectar entorno
            if platform.system() == "Windows":
                OPENSSL_PATH = r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
            else:
                # Se espera que esté en el PATH (como en Docker)
                OPENSSL_PATH = "/usr/bin/openssl"

            # 1. Clave privada
            subprocess.run([
                OPENSSL_PATH, "genpkey", "-algorithm", "EC",
                "-pkeyopt", "ec_paramgen_curve:P-256",
                "-out", key_path
            ], check=True)

            # 2. CSR
            subj = f"/C=US/ST=CA/O=RTI Demo/CN={username}"
            subprocess.run([
                OPENSSL_PATH, "req", "-new", "-key", key_path,
                "-out", csr_path, "-subj", subj
            ], check=True)

            # 3. Firmar con la CA
            subprocess.run([
                OPENSSL_PATH, "x509", "-req", "-in", csr_path,
                "-CA", ca_cert, "-CAkey", ca_key,
                "-CAcreateserial", "-out", cert_path,
                "-days", "365"
            ], check=True)

            # 4. Leer contenido del certificado
            with open(cert_path, 'r') as f:
                cert_pem = f.read()

            # 4.1 Obtener el subject real del certificado firmado
            result = subprocess.run([
                OPENSSL_PATH, "x509", "-in", cert_path, "-noout", "-subject"
            ], capture_output=True, text=True, check=True)

            # ejemplo: "subject= C=US, ST=CA, O=RTI Demo, CN=bobby"
            subject_line = result.stdout.strip()
            subject_clean = subject_line.replace("subject=", "").strip()

            # 4.2 Actualizar el campo cert en la tabla users
            cursor.execute('''
                UPDATE users SET cert = ? WHERE id = ?
            ''', (subject_clean, user_id))

            # 5. Guardar en tabla user_keys
            cursor.execute('''
                INSERT INTO user_keys (user_id, public_cert, private_key_path)
                VALUES (?, ?, ?)
            ''', (user_id, cert_pem, key_path))

            conn.commit()
            conn.close()

            flash('Usuario y claves creadas correctamente', 'success')
            return redirect(url_for('user_list'))

        except sqlite3.IntegrityError:
            flash('El nombre de usuario ya existe', 'danger')
            return redirect(url_for('user_create'))
        except subprocess.CalledProcessError as e:
            flash(f'Error generando claves: {e}', 'danger')
            return redirect(url_for('user_create'))

    return render_template('user_create.html')

# TODO He de borrar también los certificados


@app.route('/usuarios/<int:id>/eliminar', methods=['POST'])
@superuser_required
def eliminar_usuario(id):
    # Evitar eliminarse a sí mismo (opcional: descomenta si se quiere proteger)
    # current_user = verificar_jwt()
    # if current_user['id'] == id:
    #     flash('No puedes eliminar tu propio usuario.', 'warning')
    #     return redirect(url_for('user_list'))

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Eliminar claves asociadas al usuario (si existen)
    cursor.execute('DELETE FROM user_keys WHERE user_id = ?', (id,))

    # Eliminar el usuario
    cursor.execute('DELETE FROM users WHERE id = ?', (id,))

    conn.commit()
    conn.close()

    flash('Usuario y claves asociadas eliminados correctamente', 'success')
    return redirect(url_for('user_list'))

# TODO Hacer que si se edita el name se ha de generar un nuevo certificado


@app.route('/usuarios/<int:id>/editar', methods=['GET', 'POST'])
@superuser_required
def editar_usuario(id):
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row  # <- Esta línea permite usar ['columna']
    cursor = conn.cursor()

    if request.method == 'POST':
        username = request.form['username']
        is_superuser = 1 if request.form.get('is_superuser') == 'on' else 0

        cursor.execute('''
            UPDATE users
            SET username = ?, is_superuser = ?
            WHERE id = ?
        ''', (username, is_superuser, id))
        conn.commit()
        conn.close()
        flash('Usuario actualizado correctamente', 'success')
        return redirect(url_for('user_list'))

    # GET: cargar datos del usuario
    cursor.execute('SELECT * FROM users WHERE id = ?', (id,))
    usuario = cursor.fetchone()

    # Obtener el certificado público (sin la clave privada)
    cursor.execute(
        'SELECT public_cert FROM user_keys WHERE user_id = ?', (id,))
    key_data = cursor.fetchone()

    conn.close()

    if usuario is None:
        abort(404)

    return render_template('user_update.html', usuario=usuario, cert=key_data['public_cert'] if key_data else None)


#########################
# SECCIÓN DE GrantTemplate HTML
#########################

def get_grant_templates():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            gt.id,
            gt.name,
            gt.default_action,
            GROUP_CONCAT(r.name, ', ') AS roles
        FROM grantTemplate gt
        LEFT JOIN roles r ON r.grant_id = gt.id
        GROUP BY gt.id
    ''')

    rows = cursor.fetchall()
    conn.close()
    return rows


def insert_grant_from_xml_file(xml_file_obj, override_name=None):
    try:
        tree = ET.parse(xml_file_obj)
    except ET.ParseError:
        raise ValueError("Invalid XML structure.")

    root = tree.getroot()

    default_elem = root.find('.//default')
    if default_elem is None or default_elem.text is None:
        raise ValueError("Element <default> not found in the XML")

    default_action = default_elem.text.strip().upper()
    if default_action not in ('ALLOW', 'DENY'):
        raise ValueError(f"Invalid default value: {default_action}")

    grant_elem = root.find('.//grant')
    name = override_name.strip() if override_name else grant_elem.attrib.get(
        'name', 'unnamed_grant')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute('''
            INSERT INTO grantTemplate (name, default_action)
            VALUES (?, ?)
        ''', (name, default_action))
        grant_id = cursor.lastrowid

        for rule_type in ['allow_rule', 'deny_rule']:
            for rule in root.findall(f'.//grant/{rule_type}'):
                permiso = rule_type
                cursor.execute(
                    'INSERT INTO rules (permiso) VALUES (?)', (permiso,))
                rule_id = cursor.lastrowid

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

                for topic in rule.findall('./publish/topics/topic'):
                    if topic.text:
                        topic_name = topic.text.strip()
                        cursor.execute(
                            'INSERT OR IGNORE INTO topics (name) VALUES (?)', (topic_name,))
                        cursor.execute(
                            'SELECT id FROM topics WHERE name = ?', (topic_name,))
                        topic_id = cursor.fetchone()[0]

                        cursor.execute('''
                            INSERT INTO rule_topics (rule_id, topic_id, action)
                            VALUES (?, ?, 'publish')
                        ''', (rule_id, topic_id))

                for topic in rule.findall('./subscribe/topics/topic'):
                    if topic.text:
                        topic_name = topic.text.strip()
                        cursor.execute(
                            'INSERT OR IGNORE INTO topics (name) VALUES (?)', (topic_name,))
                        cursor.execute(
                            'SELECT id FROM topics WHERE name = ?', (topic_name,))
                        topic_id = cursor.fetchone()[0]

                        cursor.execute('''
                            INSERT INTO rule_topics (rule_id, topic_id, action)
                            VALUES (?, ?, 'subscribe')
                        ''', (rule_id, topic_id))

                cursor.execute('''
                    INSERT INTO grant_rules (grant_id, rule_id)
                    VALUES (?, ?)
                ''', (grant_id, rule_id))

        conn.commit()
        return grant_id, name, default_action

    except (sqlite3.IntegrityError, sqlite3.OperationalError) as e:
        conn.rollback()
        raise ValueError(f"Database error: {e}")
    finally:
        conn.close()


def delete_grant_template_by_id(grant_id, conn):
    cursor = conn.cursor()

    cursor.execute('PRAGMA foreign_keys = ON')

    cursor.execute(
        'SELECT rule_id FROM grant_rules WHERE grant_id = ?', (grant_id,))
    rule_ids = [row[0] for row in cursor.fetchall()]

    cursor.execute('DELETE FROM grant_rules WHERE grant_id = ?', (grant_id,))

    for rule_id in rule_ids:
        cursor.execute('DELETE FROM rules WHERE id = ?', (rule_id,))

    cursor.execute('DELETE FROM grantTemplate WHERE id = ?', (grant_id,))

    cursor.execute('''
        DELETE FROM domains
        WHERE id NOT IN (SELECT domain_id FROM rule_domains)
    ''')

    cursor.execute('''
        DELETE FROM topics
        WHERE id NOT IN (SELECT topic_id FROM rule_topics)
    ''')


@app.route('/grant_templates')
@superuser_required
def grant_template_list():
    user = verificar_jwt()
    if not user:
        return redirect(url_for('login'))

    templates = get_grant_templates()
    return render_template('grant_template_list.html', templates=templates)


@app.route('/grant_templates/<int:grant_id>')
@superuser_required
def grant_template_detail(grant_id):
    user = verificar_jwt()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Obtener el grantTemplate
    cursor.execute('''
        SELECT id, name, default_action
        FROM grantTemplate
        WHERE id = ?
    ''', (grant_id,))
    grant = cursor.fetchone()
    if not grant:
        conn.close()
        return render_template('404.html'), 404

    # Obtener roles asociados
    cursor.execute('''
        SELECT name, description, exp_time
        FROM roles
        WHERE grant_id = ?
    ''', (grant_id,))
    roles = cursor.fetchall()

    # Obtener reglas asociadas al grant
    cursor.execute('''
        SELECT r.id, r.permiso
        FROM rules r
        JOIN grant_rules gr ON gr.rule_id = r.id
        WHERE gr.grant_id = ?
    ''', (grant_id,))
    rules = cursor.fetchall()

    # Para cada regla, obtener dominios y tópicos
    detailed_rules = []
    for rule in rules:
        rule_id = rule['id']

        # Dominios
        cursor.execute('''
            SELECT d.name
            FROM domains d
            JOIN rule_domains rd ON rd.domain_id = d.id
            WHERE rd.rule_id = ?
        ''', (rule_id,))
        domains = [row['name'] for row in cursor.fetchall()]

        # Tópicos y acciones
        cursor.execute('''
            SELECT t.name, rt.action
            FROM topics t
            JOIN rule_topics rt ON rt.topic_id = t.id
            WHERE rt.rule_id = ?
        ''', (rule_id,))
        topics = [{'name': row['name'], 'action': row['action']}
                  for row in cursor.fetchall()]

        detailed_rules.append({
            'id': rule_id,
            'permiso': rule['permiso'],
            'domains': domains,
            'topics': topics
        })

    conn.close()
    return render_template('grant_template_detail.html', grant=grant, roles=roles, rules=detailed_rules)


@app.route('/grants/new', methods=['GET', 'POST'])
@superuser_required
def new_grant_template():
    if request.method == 'POST':
        xml_file = request.files.get('xml_file')
        name_override = request.form.get('name_override', '').strip()

        if not xml_file:
            flash('You must upload an XML file.', 'danger')
            return redirect(request.url)

        try:
            grant_id, name, default_action = insert_grant_from_xml_file(
                xml_file.stream, name_override or None)
            flash(
                f'Permission template "{name}" successfully created with default action "{default_action}".', 'success')
            return redirect(url_for('grant_template_detail', grant_id=grant_id))
        except Exception as e:
            print("❌ Error al procesar el XML:", str(e))
            flash(f'Error creating the template: {str(e)}', 'danger')
            return redirect(request.url)

    return render_template('grant_template_create.html')


@app.route('/grant_templates/delete/<int:grant_id>', methods=['POST'])
@superuser_required
def delete_grant_template(grant_id):
    user = verificar_jwt()
    if not user:
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        delete_grant_template_by_id(grant_id, conn)
        conn.commit()
        flash(f'Grant template {grant_id} eliminado correctamente.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error al eliminar el grant template: {e}', 'danger')
    finally:
        conn.close()

    return redirect(url_for('grant_template_list'))

#########################
# SECCIÓN DE XML HTML
#########################


@app.route('/xml_vality', methods=['GET', 'POST'])
@user_required
def xml_vality():
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

        return redirect(url_for('xml_vality'))

    # Si es GET, simplemente muestra el formulario
    return render_template('xml_vality.html')

#########################
# SECCIÓN DE AuthRole HTML
#########################


@app.route('/auth-role', methods=['GET', 'POST'])
@user_required
def auth_role_html():
    user_data = verificar_jwt()
    if not user_data:
        flash("You are not authorized to access this page", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Obtener user_id
    cursor.execute("SELECT id FROM users WHERE username = ?",
                   (user_data["username"],))
    user_row = cursor.fetchone()
    if not user_row:
        conn.close()
        flash("User not found in database", "danger")
        return redirect(url_for("login"))
    user_id = user_row[0]

    # Obtener roles y exp_time
    if user_data["is_superuser"]:
        cursor.execute("""
            SELECT r.id, r.name, r.description, r.grant_id, r.exp_time
            FROM roles r
            WHERE r.grant_id IS NOT NULL
        """)
    else:
        cursor.execute("""
            SELECT r.id, r.name, r.description, r.grant_id, r.exp_time
            FROM roles r
            JOIN user_roles ur ON ur.role_id = r.id
            JOIN users u ON u.id = ur.user_id
            WHERE r.grant_id IS NOT NULL
              AND u.username = ?
        """, (user_data["username"],))

    roles = [dict(r) for r in cursor.fetchall()]
    error = None
    token = None
    warning = None

    if request.method == 'POST':
        role_id = request.form.get('role_id', type=int)
        requested_minutes = request.form.get('exp_minutes', type=int)

        selected = next((r for r in roles if r['id'] == role_id), None)

        if not selected:
            error = 'Invalid or unauthorized role.'
        elif not requested_minutes:
            error = 'You must specify an expiration time.'
        else:
            max_minutes = selected['exp_time']
            final_minutes = min(requested_minutes, max_minutes)

            if requested_minutes > max_minutes:
                warning = (f"Requested expiration time ({requested_minutes} min) "
                           f"exceeds the role's limit ({max_minutes} min). "
                           f"Token created with maximum allowed time.")

            payload = {
                'user_id': user_id,
                'role_id': role_id,
                'exp': datetime.now(timezone.utc) + timedelta(minutes=final_minutes)
            }
            token = jwt.encode(payload, CA_KEY, algorithm="ES256")

    conn.close()
    return render_template('authrole_create.html', roles=roles, error=error, warning=warning, token=token)


@app.route('/authrole_vality', methods=['GET', 'POST'])
def authrole_vality():
    result = None

    if request.method == 'POST':
        token = request.form.get('token')

        if not token:
            result = {'valid': False, 'error': 'Token not provided'}
        else:
            try:
                payload = jwt.decode(token, CA_PUBLIC_KEY,
                                     algorithms=["ES256"])
            except jwt.ExpiredSignatureError:
                result = {'valid': False, 'error': 'Token expired'}
            except jwt.InvalidTokenError:
                result = {'valid': False, 'error': 'Invalid token'}
            else:
                user_id = payload.get('user_id')
                role_id = payload.get('role_id')

                if not user_id or not role_id:
                    result = {'valid': False, 'error': 'Incomplete token'}
                else:
                    conn = get_db_connection()
                    cursor = conn.cursor()

                    cursor.execute(
                        'SELECT 1 FROM users WHERE id = ?', (user_id,))
                    if cursor.fetchone() is None:
                        result = {'valid': False,
                                  'error': 'User does not exist'}
                    else:
                        cursor.execute(
                            'SELECT 1 FROM roles WHERE id = ?', (role_id,))
                        if cursor.fetchone() is None:
                            result = {'valid': False,
                                      'error': 'Role does not exist'}
                        else:
                            cursor.execute(
                                'SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ?', (user_id, role_id))
                            if cursor.fetchone() is None:
                                result = {
                                    'valid': False, 'error': 'User does not have this role'}
                            else:
                                result = {'valid': True,
                                          'user_id': user_id, 'role_id': role_id}

                    conn.close()

    return render_template('authrole_vality.html', result=result)


#########################
# SECCIÓN DE ADDITIONAL HTML
#########################


@app.route('/swagger-json')
def redirigir_a_swagger_json():
    return redirect('/api-docs.json')


@app.route('/swagger-json-api')
def redirigir_a_swagger_json_api():
    return redirect('/docs')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = get_user(username)  # Recupera el usuario de la base de datos

        if user and bcrypt.checkpw(password.encode('utf-8'), user[1].encode('utf-8')):
            token = generar_jwt(user)
            resp = make_response(redirect(url_for('index')))
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


# @app.route('/')
# def home():
#     return render_template('home.html')

@app.route('/')
def home():
    return redirect(url_for('index'))


@app.route('/index')
def index():
    return render_template('index.html')


@app.route('/decode', methods=['GET', 'POST'])
def decode():
    payload_data = None
    error = None

    if request.method == 'POST':
        token = request.form.get('jwt_token', '').strip()
        parts = token.split('.')
        if len(parts) != 3:
            error = "❌ Invalid token: it must have 3 parts (header.payload.signature)."
        else:
            try:
                padded_payload = parts[1] + '=' * (-len(parts[1]) % 4)
                decoded_bytes = base64.urlsafe_b64decode(padded_payload)
                payload_data = json.loads(decoded_bytes)

                # Formatear los campos que son timestamps UNIX
                madrid_tz = ZoneInfo('Europe/Madrid')
                for key in ['exp', 'iat', 'nbf']:
                    if key in payload_data:
                        try:
                            timestamp = int(payload_data[key])
                            utc_dt = datetime.fromtimestamp(
                                timestamp, tz=timezone.utc)
                            madrid_dt = utc_dt.astimezone(madrid_tz)
                            payload_data[key] = {
                                'utc': utc_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                'madrid': madrid_dt.strftime('%Y-%m-%d %H:%M:%S Europe/Madrid')
                            }
                        except Exception:
                            pass

            except Exception as e:
                error = f"❌ Failed to decode token payload: {str(e)}"

    return render_template('decode.html', payload=payload_data, error=error)


@app.route('/information')
def information():
    return render_template('information.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.route('/dashboard')
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    stats = {
        "total_users": cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "total_superusers": cursor.execute("SELECT COUNT(*) FROM users WHERE is_superuser = 1").fetchone()[0],
        "users_with_keys": cursor.execute("SELECT COUNT(*) FROM user_keys WHERE is_active = 1").fetchone()[0],
        "total_roles": cursor.execute("SELECT COUNT(*) FROM roles").fetchone()[0],
        "roles_with_grants": cursor.execute("SELECT COUNT(*) FROM roles WHERE grant_id IS NOT NULL").fetchone()[0],
        "total_grants": cursor.execute("SELECT COUNT(*) FROM grantTemplate").fetchone()[0],
        "total_domains": cursor.execute("SELECT COUNT(*) FROM domains").fetchone()[0],
        "total_topics": cursor.execute("SELECT COUNT(*) FROM topics").fetchone()[0],
        "total_rules": cursor.execute("SELECT COUNT(*) FROM rules").fetchone()[0],
        "rules_with_domains": cursor.execute("SELECT COUNT(DISTINCT rule_id) FROM rule_domains").fetchone()[0],
        "rules_with_topics": cursor.execute("SELECT COUNT(DISTINCT rule_id) FROM rule_topics").fetchone()[0],
        "grant_rules_count": cursor.execute("SELECT COUNT(*) FROM grant_rules").fetchone()[0],
        "active_key_ratio": None
    }

    # Ratio de claves activas respecto a usuarios totales
    if stats["total_users"] > 0:
        stats["active_key_ratio"] = round(
            (stats["users_with_keys"] / stats["total_users"]) * 100, 2)
    else:
        stats["active_key_ratio"] = 0

    conn.close()
    return render_template('dashboard.html', stats=stats)


@app.context_processor
def inyectar_datos_token():
    token = request.cookies.get('token')
    datos_token = {}
    if token:
        datos = decodificar_jwt(token)
        if datos:
            datos_token = datos  # Contiene username, cert, is_superuser, etc.
    return {'token_data': datos_token}


@app.route('/download-signed-grant/<path:filename>')
@user_required
def download_signed_grant(filename):
    path = os.path.join(tempfile.gettempdir(), filename)
    if not os.path.exists(path):
        flash('File not found', 'danger')
        return redirect(url_for('role_list'))
    return send_file(path, as_attachment=True, mimetype='application/pkcs7-signature')


@app.route('/download_unsigned_grant/<filename>')
@user_required
def download_unsigned_grant(filename):
    file_path = os.path.join(tempfile.gettempdir(), filename)
    if not os.path.exists(file_path):
        flash("The requested XML file does not exist.", "danger")
        return redirect(url_for('xml_sign_grant_by_role_html'))

    return send_file(file_path, as_attachment=True)


def generar_xml_grant(role_id, user_data, conn, not_before, not_after):
    cursor = conn.cursor()

    # Obtener el grant_id y datos del grant
    cursor.execute('''
        SELECT g.id, g.name, g.default_action
        FROM roles r
        JOIN grantTemplate g ON r.grant_id = g.id
        WHERE r.id = ?
    ''', (role_id,))
    row = cursor.fetchone()
    if not row:
        return None, None, 'No grant associated with this role'

    grant_id, grant_name, default_action = row

    # Construcción del XML
    dds = ET.Element('dds', {
        'xmlns:xsi': "http://www.w3.org/2001/XMLSchema-instance",
        'xsi:noNamespaceSchemaLocation': "http://community.rti.com/schema/7.3.0/dds_security_permissions.xsd"
    })
    permissions = ET.SubElement(dds, 'permissions')
    grant_elem = ET.SubElement(permissions, 'grant', {'name': grant_name})

    subject = ET.SubElement(grant_elem, 'subject_name')
    subject.text = user_data.get('cert', 'CN=Unknown')

    # Insertar fechas de validez desde parámetros
    validity = ET.SubElement(grant_elem, 'validity')
    ET.SubElement(validity, 'not_before').text = not_before.strftime(
        '%Y-%m-%dT%H:%M:%S')
    ET.SubElement(validity, 'not_after').text = not_after.strftime(
        '%Y-%m-%dT%H:%M:%S')

    # Reglas del grant
    cursor.execute('''
        SELECT rules.id, rules.permiso
        FROM rules
        JOIN grant_rules ON rules.id = grant_rules.rule_id
        WHERE grant_rules.grant_id = ?
    ''', (grant_id,))
    rules = cursor.fetchall()

    for rule_id, permiso in rules:
        rule_tag = ET.SubElement(grant_elem, permiso)

        cursor.execute('''
            SELECT domains.name FROM rule_domains
            JOIN domains ON rule_domains.domain_id = domains.id
            WHERE rule_domains.rule_id = ?
        ''', (rule_id,))
        domain_rows = cursor.fetchall()
        if domain_rows:
            domains_elem = ET.SubElement(rule_tag, 'domains')
            for (domain,) in domain_rows:
                ET.SubElement(domains_elem, 'id').text = domain

        cursor.execute('''
            SELECT topics.name FROM rule_topics
            JOIN topics ON rule_topics.topic_id = topics.id
            WHERE rule_topics.rule_id = ? AND rule_topics.action = 'publish'
        ''', (rule_id,))
        publish_rows = cursor.fetchall()
        if publish_rows:
            pub_elem = ET.SubElement(rule_tag, 'publish')
            topics_elem = ET.SubElement(pub_elem, 'topics')
            for (topic,) in publish_rows:
                ET.SubElement(topics_elem, 'topic').text = topic

        cursor.execute('''
            SELECT topics.name FROM rule_topics
            JOIN topics ON rule_topics.topic_id = topics.id
            WHERE rule_topics.rule_id = ? AND rule_topics.action = 'subscribe'
        ''', (rule_id,))
        subscribe_rows = cursor.fetchall()
        if subscribe_rows:
            sub_elem = ET.SubElement(rule_tag, 'subscribe')
            topics_elem = ET.SubElement(sub_elem, 'topics')
            for (topic,) in subscribe_rows:
                ET.SubElement(topics_elem, 'topic').text = topic

    ET.SubElement(grant_elem, 'default').text = default_action

    xml_str = ET.tostring(dds, encoding='utf-8')
    pretty_xml = minidom.parseString(xml_str).toprettyxml(
        indent="  ", encoding='utf-8')

    return pretty_xml, grant_name, None


@app.route('/xml_sign_grant_by_role_html', methods=['GET', 'POST'])
@user_required
def xml_sign_grant_by_role_html():
    xml_output = None
    grant_name = None
    token = None
    role_id = None

    if request.method == 'POST':
        token = request.form.get("token")
        sign = request.form.get("sign")  # "on" si está marcado

        if not token:
            flash("Token is required", "danger")
            return redirect(request.url)

        try:
            payload = jwt.decode(token, CA_KEY, algorithms=["ES256"])
            role_id = payload.get("role_id")
            exp = payload.get("exp")
            if not role_id or not exp:
                flash("Invalid token: missing role_id or expiration", "danger")
                return redirect(request.url)

            not_before = datetime.now()
            not_after = datetime.fromtimestamp(exp)

        except jwt.ExpiredSignatureError:
            flash("Token has expired", "danger")
            return redirect(request.url)
        except jwt.InvalidTokenError:
            flash("Invalid token", "danger")
            return redirect(request.url)

        user_data = verificar_jwt()
        if not user_data:
            flash("You are not authorized", "danger")
            return redirect(url_for("login"))

        conn = get_db_connection()
        xml_data, grant_name, error = generar_xml_grant(
            role_id, user_data, conn,
            not_before=not_before,
            not_after=not_after
        )

        if error:
            flash(f'Error generating XML: {error}', 'danger')
        else:
            if sign == "on":
                # Firmar el XML como .p7s
                with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as xml_file:
                    xml_file.write(xml_data)
                    xml_path = xml_file.name

                signed_output_path = os.path.join(
                    tempfile.gettempdir(), f"{grant_name}.p7s"
                )

                OPENSSL_PATH = (
                    r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"
                    if platform.system() == "Windows"
                    else "/usr/bin/openssl"
                )

                result = subprocess.run([
                    OPENSSL_PATH, "smime", "-sign",
                    "-in", xml_path,
                    "-out", signed_output_path,
                    "-signer", CA_CERT_PATH,
                    "-inkey", CA_KEY_PATH,
                    "-outform", "DER",
                    "-nodetach"
                ], capture_output=True)

                os.remove(xml_path)

                if result.returncode != 0:
                    flash("Signing failed: " + result.stderr.decode(), "danger")
                else:
                    flash("Grant signed successfully!", "success")
            else:
                xml_output = xml_data.decode("utf-8")

                # Guardamos el XML temporal para descarga
                unsigned_xml_path = os.path.join(
                    tempfile.gettempdir(), f"{grant_name}.xml")
                with open(unsigned_xml_path, "wb") as f:
                    f.write(xml_data)

                flash("Grant generated without signature.", "info")

        conn.close()

    return render_template('xml_sign_grant_by_role.html', grant_name=grant_name, xml_output=xml_output)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
