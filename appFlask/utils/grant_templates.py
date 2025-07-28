
# from flask import abort, jsonify
# from utils.helpers import *



# import functools

# def user_required(f):
#     @functools.wraps(f)
#     def wrapper(*args, **kwargs):
#         user = verificar_jwt_api()
#         if not user or not user.get("username"):
#             abort(403, "Invalid token or unauthorized user")
#         return f(*args, **kwargs)
#     return wrapper

# @app.route('/api/grant-templates', methods=['GET'])
# @user_required
# @swag_from({
#     'tags': ['Grant Templates'],
#     'summary': 'Lists all grant templates',
#     'description': 'Retrieves a list of grant templates with their default action. Requires JWT authentication.',
#     'security': [{'BearerAuth': []}],
#     'responses': {
#         200: {
#             'description': 'List of grant templates',
#             'schema': {
#                 'type': 'array',
#                 'items': {
#                     'type': 'object',
#                     'properties': {
#                         'id': {'type': 'integer'},
#                         'name': {'type': 'string'},
#                         'default_action': {'type': 'string'}
#                     }
#                 }
#             }
#         },
#         403: {'description': 'Invalid or unauthorized token'}
#     }
# })
# def list_grant_templates_api():
#     conn = get_db_connection()
#     cursor = conn.cursor()
#     query = '''
#         SELECT id, name, default_action
#         FROM grantTemplate
#     '''
#     cursor.execute(query)
#     grant_templates = cursor.fetchall()
#     conn.close()

#     grants = [
#         {
#             'id': row[0],
#             'name': row[1],
#             'default_action': row[2]
#         } for row in grant_templates
#     ]
#     return jsonify(grants)

