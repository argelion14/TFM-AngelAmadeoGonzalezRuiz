import io
import os
import sqlite3
import datetime
import tempfile
import xml.etree.ElementTree as ET
import yaml
import bcrypt
import jwt
import xmlschema
import functools

from flask import (
    Flask, abort, render_template, request, redirect, url_for,
    flash, make_response, g, jsonify
)

from werkzeug.utils import secure_filename
from flasgger import Swagger, swag_from


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

with open("swagger_template.yml", "r") as f:
    swagger_template = yaml.safe_load(f)

swagger = Swagger(app, config=swagger_config, template=swagger_template)


app.secret_key = 'tu_clave_secreta'
app.config['UPLOAD_FOLDER'] = 'uploads'
JWT_SECRET = 'clave_jwt_segura'
JWT_EXPIRATION_MINUTES = 60

# TODO Mejorar la estructura de la base.html
# TODO Hacer que todos los endpoint que necesiten de esto, lo usan en el swag_from de la misma manera, le tengo que añadir el bearer en el security

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


def verificar_jwt_api():
    """
    Verifies the JWT sent in the Authorization header of an API request.

    Returns:
        dict | None: The token data if valid, or None if invalid or missing.
    """
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    return decodificar_jwt(token)


def superadmin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = verificar_jwt_api()
        if not user or not user.get("is_superuser", False):
            abort(403, "Only superadmin can perform this action")
        return f(*args, **kwargs)
    return wrapper


def user_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user = verificar_jwt_api()
        if not user or not user.get("username"):
            abort(403, "Invalid token or unauthorized user")
        return f(*args, **kwargs)
    return wrapper


def get_db_connection():
    conn = sqlite3.connect('TFM.db')
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

#########################
# SECCIÓN DE GrantTemplate
# Funciones auxiliares para gestión de GrantTemplate
#########################

# TODO Pensar si tiene que ser algo protegido


@app.route('/api/grant-templates', methods=['GET'])
@user_required
@swag_from({
    'tags': ['Grant Templates'],
    'summary': 'Lists all grant templates',
    'description': 'Retrieves a list of grant templates along with their default action and associated role name. Requires JWT authentication.',
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
                        'default_action': {'type': 'string'},
                        'role_name': {'type': 'string'}
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
        SELECT gt.id, gt.name, gt.default_action, r.name as role_name
        FROM grantTemplate gt
        JOIN roles r ON gt.role_id = r.id
    '''
    cursor.execute(query)
    grant_templates = cursor.fetchall()
    conn.close()

    grants = [
        {
            'id': row[0],
            'name': row[1],
            'default_action': row[2],
            'role_name': row[3]
        } for row in grant_templates
    ]
    return jsonify(grants)


@app.route('/api/grants', methods=['POST'])
@superadmin_required
@swag_from({
    'tags': ['Grant Templates'],
    'summary': 'Create a new grant from an XML DDS Permissions file',
    'security': [{'BearerAuth': []}],
    'description': 'Allows uploading an XML file and a role_id to create a grant and its associated rules.',
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
            'name': 'role_id',
            'in': 'formData',
            'type': 'integer',
            'required': True,
            'description': 'ID of the role to which the grant will be assigned'
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
    f = request.files.get('xml_file')
    role_id = request.form.get('role_id')

    if not f or not role_id:
        return jsonify({'error': 'Missing file or role_id'}), 400

    try:
        filename = secure_filename(f.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(path)

        grant_id, name, default_action = insert_grant_from_xml(path, role_id)
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
    'security': [{'BearerAuth': []}],
    'summary': 'Delete a grant template by its ID',
    'description': 'Deletes a grant template and all its associated data, including rules, unused domains, and topics.',
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


@app.route('/api/auth-role', methods=['POST'])
@user_required
@swag_from({
    'tags': ['Auth_role_JWT'],
    'summary': 'Authenticate a specific role for an already authenticated user',
    'description': 'Returns a JWT if the authenticated user has the requested role and it is assigned to a single grantTemplate.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'role_id': {'type': 'integer'}
                },
                'required': ['role_id']
            }
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
    data = request.get_json()
    role_id = data.get('role_id')

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

    # 3. Verify that the role is linked to a single grantTemplate
    cursor.execute(
        'SELECT id FROM grantTemplate WHERE role_id = ?', (role_id,))
    templates = cursor.fetchall()
    if len(templates) != 1:
        conn.close()
        return jsonify({'error': 'Role is not linked to a single grantTemplate'}), 401

    # 4. Issue new JWT for this role
    payload = {
        'user_id': user_id,
        'role_id': role_id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')

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
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
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
@swag_from({
    'tags': ['Roles'],
    'summary': 'Get all roles',
    'description': 'Returns the details of all existing roles',
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
@swag_from({
    'tags': ['Roles'],
    'summary': 'Get role by ID',
    'description': 'Returns role details if it exists, otherwise returns a 404 error.',
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
    'description': 'Allows a superadmin to create a new role by providing a name and optional description.',
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
                        'description': 'Unique name of the role'
                    },
                    'description': {
                        'type': 'string',
                        'description': 'Description of the role'
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
            'description': 'Invalid data or duplicate role'
        },
        403: {
            'description': 'Access denied'
        }
    },
    'security': [
        {'BearerAuth': []}
    ]
})
def add_role():
    data = request.get_json()
    if not data or not data.get('name'):
        return jsonify({"error": "The 'name' field is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO roles (name, description) VALUES (?, ?)",
                       (data['name'], data.get('description')))
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
    'description': 'Allows a superadmin to delete an existing role by its ID.',
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
    },
    'security': [
        {'BearerAuth': []}
    ]
})
def delete_role(role_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('PRAGMA foreign_keys = ON')

    try:
        # Verificar que el rol existe
        cursor.execute("SELECT id FROM roles WHERE id=?", (role_id,))
        if cursor.fetchone() is None:
            conn.close()
            return jsonify({"error": "Role not found"}), 404

        # Buscar si hay un grantTemplate asociado a este rol
        cursor.execute(
            "SELECT id FROM grantTemplate WHERE role_id = ?", (role_id,))
        grant_row = cursor.fetchone()

        if grant_row:
            grant_id = grant_row[0]
            delete_grant_template_by_id(grant_id, conn)

        # Eliminar el rol (esto también elimina user_roles por ON DELETE CASCADE)
        cursor.execute("DELETE FROM roles WHERE id=?", (role_id,))

        conn.commit()
        return jsonify({"message": "Role and associated grantTemplate (if any) deleted successfully"}), 200

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
    'description': 'Allows a superadmin to update the name or description of an existing role by its ID.',
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
            'description': 'Invalid data or duplicate role name'
        },
        404: {
            'description': 'Role not found'
        },
        403: {
            'description': 'Access denied'
        }
    },
    'security': [
        {'BearerAuth': []}
    ]
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

    # Build dynamic update
    fields = []
    values = []
    if 'name' in data:
        fields.append("name = ?")
        values.append(data['name'])
    if 'description' in data:
        fields.append("description = ?")
        values.append(data['description'])

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
@swag_from({
    'tags': ['Users'],
    'summary': 'Retrieve all users',
    'description': 'Returns a list of all users with their ID, username, certificate, and superuser status.',
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
                        'is_superuser': {'type': 'boolean'}
                    }
                }
            }
        }
    }
})
def list_users():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.execute("SELECT id, username, cert, is_superuser FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(users)


@app.route('/api/users/<int:user_id>', methods=['GET'])
@swag_from({
    'tags': ['Users'],
    'summary': 'Get user by ID',
    'description': 'Retrieves the details of a specific user identified by their user ID.',
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
    cursor = conn.execute(
        "SELECT id, username, cert, is_superuser FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return jsonify(dict(row))
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/users', methods=['POST'])
@superadmin_required
@swag_from({
    'tags': ['Users'],
    'summary': 'Create a new user',
    'description': 'Creates a new user with the provided username, password, certificate, and superuser status. Requires superadmin privileges.',
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
        201: {'description': 'User created successfully'},
        400: {'description': 'Error creating user, e.g., username already exists or missing required fields'}
    }
})
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    cert = data.get('cert', '')
    is_superuser = 1 if data.get('is_superuser', False) else 0

    if not username or not password:
        return jsonify({'error': 'Missing required fields'}), 400

    hashed_pw = bcrypt.hashpw(password.encode(
        'utf-8'), bcrypt.gensalt()).decode('utf-8')

    conn = get_db_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password, cert, is_superuser) VALUES (?, ?, ?, ?)",
            (username, hashed_pw, cert, is_superuser)
        )
        conn.commit()
        return jsonify({'message': 'User created successfully'}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@superadmin_required
@swag_from({
    'tags': ['Users'],
    'summary': 'Delete a user',
    'description': 'Deletes the user identified by the provided user ID. Requires superadmin privileges.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {'name': 'user_id', 'in': 'path', 'type': 'integer',
            'required': True, 'description': 'ID of the user to delete'}
    ],
    'responses': {
        200: {'description': 'User deleted successfully'},
        404: {'description': 'User not found'}
    }
})
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    if cursor.rowcount:
        return jsonify({'message': 'User deleted successfully'})
    return jsonify({'error': 'User not found'}), 404


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@superadmin_required
@swag_from({
    'tags': ['Users'],
    'summary': 'Update a user',
    'description': 'Updates the details of the user identified by the given user ID. Requires superadmin privileges.',
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
                    'password': {'type': 'string', 'description': 'New password'},
                    'cert': {'type': 'string', 'description': 'Certificate info'},
                    'is_superuser': {'type': 'boolean', 'description': 'Superuser status'}
                }
            }
        }
    ],
    'responses': {
        200: {'description': 'User updated successfully'},
        400: {'description': 'No fields provided for update'},
        404: {'description': 'User not found'}
    }
})
def update_user(user_id):
    data = request.json
    fields = []
    values = []

    if 'username' in data:
        fields.append("username = ?")
        values.append(data['username'])
    if 'password' in data:
        hashed_pw = bcrypt.hashpw(data['password'].encode(
            'utf-8'), bcrypt.gensalt()).decode('utf-8')
        fields.append("password = ?")
        values.append(hashed_pw)
    if 'cert' in data:
        fields.append("cert = ?")
        values.append(data['cert'])
    if 'is_superuser' in data:
        fields.append("is_superuser = ?")
        values.append(1 if data['is_superuser'] else 0)

    if not fields:
        return jsonify({'error': 'No fields provided for update'}), 400

    values.append(user_id)

    conn = get_db_connection()
    cursor = conn.execute(
        f"UPDATE users SET {', '.join(fields)} WHERE id = ?", values)
    conn.commit()
    conn.close()

    if cursor.rowcount:
        return jsonify({'message': 'User updated successfully'})
    return jsonify({'error': 'User not found'}), 404

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


@app.route('/api/export_grant/<int:grant_id>', methods=['GET'])
@swag_from({
    'tags': ['XML'],
    'summary': 'Export a grant as an XML file',
    'description': 'Generates and exports an XML file for a specific grant ID, including associated domains and topic rules, following the DDS Permissions 7.3.0 schema.',
    'parameters': [
        {
            'name': 'grant_id',
            'in': 'path',
            'type': 'integer',
            'required': True,
            'description': 'ID of the grant to export'
        }
    ],
    'responses': {
        200: {
            'description': 'XML file generated successfully',
            'content': {
                'application/xml': {
                    'schema': {
                        'type': 'string'
                    }
                }
            }
        },
        404: {
            'description': 'Grant not found'
        }
    },
    'deprecated': True
})
def export_grant(grant_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Retrieve grant data
    cursor.execute(
        'SELECT name, default_action FROM grantTemplate WHERE id = ?', (grant_id,))
    row = cursor.fetchone()
    if not row:
        return {"error": "Grant not found"}, 404

    grant_name, default_action = row

    # Build XML structure
    dds = ET.Element('dds', {
        'xmlns:xsi': "http://www.w3.org/2001/XMLSchema-instance",
        'xsi:noNamespaceSchemaLocation': "http://community.rti.com/schema/7.3.0/dds_security_permissions.xsd"
    })
    permissions = ET.SubElement(dds, 'permissions')
    grant_elem = ET.SubElement(permissions, 'grant', {'name': grant_name})

    # Sample subject_name and validity (hardcoded for now)
    subject = ET.SubElement(grant_elem, 'subject_name')
    subject.text = "C=ES, ST=CLM, O=JCCM, emailAddress=argel@arge.site, CN=FlaskExported"

    validity = ET.SubElement(grant_elem, 'validity')
    not_before = ET.SubElement(validity, 'not_before')
    not_before.text = '2019-10-31T13:00:00'
    not_after = ET.SubElement(validity, 'not_after')
    not_after.text = '2029-10-31T13:00:00'

    # Retrieve associated rules
    cursor.execute('''
        SELECT rules.id, rules.permiso
        FROM rules
        JOIN grant_rules ON rules.id = grant_rules.rule_id
        WHERE grant_rules.grant_id = ?
    ''', (grant_id,))
    rules = cursor.fetchall()

    for rule_id, permiso in rules:
        rule_tag = ET.SubElement(grant_elem, permiso)

        # Domains
        cursor.execute('''
            SELECT domains.name
            FROM rule_domains
            JOIN domains ON rule_domains.domain_id = domains.id
            WHERE rule_domains.rule_id = ?
        ''', (rule_id,))
        domain_rows = cursor.fetchall()
        if domain_rows:
            domains_elem = ET.SubElement(rule_tag, 'domains')
            for (domain,) in domain_rows:
                ET.SubElement(domains_elem, 'id').text = domain

        # Topics - publish
        cursor.execute('''
            SELECT topics.name
            FROM rule_topics
            JOIN topics ON rule_topics.topic_id = topics.id
            WHERE rule_topics.rule_id = ? AND rule_topics.action = 'publish'
        ''', (rule_id,))
        publish_rows = cursor.fetchall()
        if publish_rows:
            publish_elem = ET.SubElement(rule_tag, 'publish')
            topics_elem = ET.SubElement(publish_elem, 'topics')
            for (topic,) in publish_rows:
                ET.SubElement(topics_elem, 'topic').text = topic

        # Topics - subscribe
        cursor.execute('''
            SELECT topics.name
            FROM rule_topics
            JOIN topics ON rule_topics.topic_id = topics.id
            WHERE rule_topics.rule_id = ? AND rule_topics.action = 'subscribe'
        ''', (rule_id,))
        subscribe_rows = cursor.fetchall()
        if subscribe_rows:
            subscribe_elem = ET.SubElement(rule_tag, 'subscribe')
            topics_elem = ET.SubElement(subscribe_elem, 'topics')
            for (topic,) in subscribe_rows:
                ET.SubElement(topics_elem, 'topic').text = topic

    # Default action
    default_elem = ET.SubElement(grant_elem, 'default')
    default_elem.text = default_action

    # Generate XML in memory
    xml_io = io.BytesIO()
    tree = ET.ElementTree(dds)
    tree.write(xml_io, encoding='utf-8', xml_declaration=True)
    xml_io.seek(0)

    response = make_response(xml_io.read())
    response.headers['Content-Type'] = 'application/xml'
    response.headers['Content-Disposition'] = f'attachment; filename=grant_{grant_id}.xml'
    return response


@app.route('/api/export-grantbyrole/<int:role_id>', methods=['GET'])
@user_required
@swag_from({
    'tags': ['XML'],
    'summary': 'Export a grantTemplate in XML format associated with a role',
    'description': 'Authenticated users who have access to the requested role can export the corresponding XML grant definition. The XML contains permission rules, domains, topics (publish/subscribe), and default actions.',
    'security': [{'BearerAuth': []}],
    'parameters': [
        {
            'name': 'role_id',
            'in': 'path',
            'required': True,
            'type': 'integer',
            'description': 'ID of the role for which the grant should be exported'
        }
    ],
    'responses': {
        200: {'description': 'XML file generated successfully'},
        401: {'description': 'Invalid token or unauthorized user'},
        403: {'description': 'User does not have access to this role'},
        404: {'description': 'Role or grant not found'}
    }
})
def export_grant_by_role(role_id):
    user_data = verificar_jwt_api()
    username = user_data.get('username')

    if not username:
        return jsonify({'error': 'Invalid token'}), 401

    conn = get_db_connection()
    cursor = conn.cursor()

    # Obtener user_id desde el username
    cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 401

    user_id = user[0]

    # Comprobar si el rol pertenece al usuario
    cursor.execute(
        'SELECT 1 FROM user_roles WHERE user_id = ? AND role_id = ?', (user_id, role_id))
    if cursor.fetchone() is None:
        conn.close()
        return jsonify({'error': 'Role does not belong to user'}), 403

    # Comprobar que el rol existe
    cursor.execute('SELECT id FROM roles WHERE id = ?', (role_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Role not found'}), 404

    # Obtener el grant asociado al role_id
    cursor.execute(
        'SELECT id, name, default_action FROM grantTemplate WHERE role_id = ?', (role_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'No grant associated with this role'}), 404

    grant_id, grant_name, default_action = row

    # Construir el XML
    dds = ET.Element('dds', {
        'xmlns:xsi': "http://www.w3.org/2001/XMLSchema-instance",
        'xsi:noNamespaceSchemaLocation': "http://community.rti.com/schema/7.3.0/dds_security_permissions.xsd"
    })
    permissions = ET.SubElement(dds, 'permissions')
    grant_elem = ET.SubElement(permissions, 'grant', {'name': grant_name})

    subject = ET.SubElement(grant_elem, 'subject_name')
    subject.text = "C=ES, ST=CLM, O=JCCM, emailAddress=argel@arge.site, CN=FlaskExported"

    validity = ET.SubElement(grant_elem, 'validity')
    not_before = ET.SubElement(validity, 'not_before')
    not_before.text = '2019-10-31T13:00:00'
    not_after = ET.SubElement(validity, 'not_after')
    not_after.text = '2029-10-31T13:00:00'

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

        # Dominios
        cursor.execute('''
            SELECT domains.name
            FROM rule_domains
            JOIN domains ON rule_domains.domain_id = domains.id
            WHERE rule_domains.rule_id = ?
        ''', (rule_id,))
        domain_rows = cursor.fetchall()
        if domain_rows:
            domains_elem = ET.SubElement(rule_tag, 'domains')
            for (domain,) in domain_rows:
                ET.SubElement(domains_elem, 'id').text = domain

        # Topics - publish
        cursor.execute('''
            SELECT topics.name
            FROM rule_topics
            JOIN topics ON rule_topics.topic_id = topics.id
            WHERE rule_topics.rule_id = ? AND rule_topics.action = 'publish'
        ''', (rule_id,))
        publish_rows = cursor.fetchall()
        if publish_rows:
            publish_elem = ET.SubElement(rule_tag, 'publish')
            topics_elem = ET.SubElement(publish_elem, 'topics')
            for (topic,) in publish_rows:
                ET.SubElement(topics_elem, 'topic').text = topic

        # Topics - subscribe
        cursor.execute('''
            SELECT topics.name
            FROM rule_topics
            JOIN topics ON rule_topics.topic_id = topics.id
            WHERE rule_topics.rule_id = ? AND rule_topics.action = 'subscribe'
        ''', (rule_id,))
        subscribe_rows = cursor.fetchall()
        if subscribe_rows:
            subscribe_elem = ET.SubElement(rule_tag, 'subscribe')
            topics_elem = ET.SubElement(subscribe_elem, 'topics')
            for (topic,) in subscribe_rows:
                ET.SubElement(topics_elem, 'topic').text = topic

    # Acción por defecto
    default_elem = ET.SubElement(grant_elem, 'default')
    default_elem.text = default_action

    # Generar XML
    xml_io = io.BytesIO()
    tree = ET.ElementTree(dds)
    tree.write(xml_io, encoding='utf-8', xml_declaration=True)
    xml_io.seek(0)

    conn.close()
    response = make_response(xml_io.read())
    response.headers['Content-Type'] = 'application/xml'
    response.headers[
        'Content-Disposition'] = f'attachment; filename=grant_role_{role_id}.xml'
    return response


#########################
########## HTML #########
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
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM roles")
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


def get_all_users_and_roles():
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username FROM users")
    users = cursor.fetchall()

    cursor.execute("SELECT id, name FROM roles")
    roles = cursor.fetchall()

    conn.close()
    return users, roles


def assign_role_to_user(user_id, role_id):
    conn = get_db_connection()
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
    conn = get_db_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, cert FROM users")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_user(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, password, cert, is_superuser FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user  # Será una tupla (username, password, cert, is_superuser)


def get_users2():
    conn = get_db_connection()
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


def insert_grant_from_xml(xml_path, role_id):
    if not os.path.exists(xml_path):
        raise FileNotFoundError(f"The file {xml_path} does not exist")

    role_id = int(role_id)
    tree = ET.parse(xml_path)
    root = tree.getroot()

    default_elem = root.find('.//default')
    if default_elem is None or default_elem.text is None:
        raise ValueError("Element <default> not found in the XML")

    default_action = default_elem.text.strip().upper()
    if default_action not in ('ALLOW', 'DENY'):
        raise ValueError(f"Invalid default value: {default_action}")

    grant_elem = root.find('.//grant')
    name = grant_elem.attrib.get('name', 'unnamed_grant')

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if the role exists
        cursor.execute("SELECT id FROM roles WHERE id = ?", (role_id,))
        if cursor.fetchone() is None:
            raise ValueError(f"Role with ID {role_id} does not exist")

        # 1. Insert into grantTemplate
        cursor.execute('''
            INSERT INTO grantTemplate (name, default_action, role_id)
            VALUES (?, ?, ?)
        ''', (name, default_action, role_id))
        grant_id = cursor.lastrowid

        # 2. Process rules
        for rule_type in ['allow_rule', 'deny_rule']:
            for rule in root.findall(f'.//grant/{rule_type}'):
                permiso = rule_type  # Either 'allow_rule' or 'deny_rule'

                # Insert into rules table (permiso is required)
                cursor.execute(
                    'INSERT INTO rules (permiso) VALUES (?)', (permiso,)
                )
                rule_id = cursor.lastrowid

                # Domains
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

                        cursor.execute('''
                            INSERT INTO rule_topics (rule_id, topic_id, action)
                            VALUES (?, ?, 'subscribe')
                        ''', (rule_id, topic_id))

                # Link rule with grant
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

@app.route('/contact')
def contact():
    return render_template('contact.html')

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
            return render_template("access_denied.html"), 403


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
                    conn = get_db_connection()
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
            return render_template("access_denied.html"), 403


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
    conn = get_db_connection()
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
                f'Grant "{name}", con id {grant_id}, creado con default="{default_action}" y rol asignado.', 'success')
            return redirect(url_for('new_grant'))
        except Exception as e:
            flash(f'Error: {e}', 'danger')

    return render_template('new_grant.html', roles=roles)


# TODO: Añadir que solo los superuser puedan listar los grants
@app.route('/list_grant_templates')
def list_grant_templates():
    conn = get_db_connection()
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


def delete_grant_template_by_id(grant_id, conn):
    cursor = conn.cursor()

    # Activar claves foráneas
    cursor.execute('PRAGMA foreign_keys = ON')

    # 1. Obtener todas las rule_ids asociadas al grant
    cursor.execute(
        'SELECT rule_id FROM grant_rules WHERE grant_id = ?', (grant_id,))
    rule_ids = [row[0] for row in cursor.fetchall()]

    # 2. Eliminar relaciones en grant_rules (por si no hay ON DELETE CASCADE)
    cursor.execute('DELETE FROM grant_rules WHERE grant_id = ?', (grant_id,))

    # 3. Eliminar reglas (esto borrará también rule_domains y rule_topics por cascada)
    for rule_id in rule_ids:
        cursor.execute('DELETE FROM rules WHERE id = ?', (rule_id,))

    # 4. Eliminar el grantTemplate
    cursor.execute('DELETE FROM grantTemplate WHERE id = ?', (grant_id,))

    # 5. Limpieza opcional de domains sin uso
    cursor.execute('''
        DELETE FROM domains
        WHERE id NOT IN (SELECT domain_id FROM rule_domains)
    ''')

    # 6. Limpieza opcional de topics sin uso
    cursor.execute('''
        DELETE FROM topics
        WHERE id NOT IN (SELECT topic_id FROM rule_topics)
    ''')


@app.route('/delete_grant/<int:grant_id>', methods=['POST'])
def delete_grant_template(grant_id):
    conn = get_db_connection()
    try:
        delete_grant_template_by_id(grant_id, conn)
        conn.commit()
        flash(
            f"Grant template con ID {grant_id} y sus datos asociados fueron eliminados correctamente.", 'success')
    except Exception as e:
        conn.rollback()
        flash(f"Error al eliminar: {e}", 'danger')
    finally:
        conn.close()
    return redirect(url_for('list_grant_templates'))


@app.route('/xml_vality', methods=['GET', 'POST'])
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
