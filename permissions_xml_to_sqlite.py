import sqlite3
import xml.etree.ElementTree as ET

# Archivo XML de entrada
XML_FILE = 'permissions.xml'

# Crear base de datos SQLite
conn = sqlite3.connect('permisos_importados.db')
cursor = conn.cursor()

# Crear las tablas (idénticas al modelo anterior)
cursor.executescript('''
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS topics;
DROP TABLE IF EXISTS domains;
DROP TABLE IF EXISTS rules;
DROP TABLE IF EXISTS grants;
DROP TABLE IF EXISTS subjects;

CREATE TABLE subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_name TEXT UNIQUE NOT NULL
);

CREATE TABLE grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id INTEGER NOT NULL,
    grant_name TEXT NOT NULL,
    validity_start TEXT,
    validity_end TEXT,
    default_action TEXT NOT NULL,
    FOREIGN KEY (subject_id) REFERENCES subjects(id)
);

CREATE TABLE rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id INTEGER NOT NULL,
    rule_type TEXT NOT NULL,
    FOREIGN KEY (grant_id) REFERENCES grants(id)
);

CREATE TABLE domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    domain_id INTEGER,
    FOREIGN KEY (rule_id) REFERENCES rules(id)
);

CREATE TABLE topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    topic_name TEXT,
    FOREIGN KEY (rule_id) REFERENCES rules(id)
);

CREATE TABLE permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id INTEGER NOT NULL,
    permission_type TEXT NOT NULL,
    FOREIGN KEY (rule_id) REFERENCES rules(id)
);
''')

# Parsear el XML
tree = ET.parse(XML_FILE)
root = tree.getroot()

for grant in root.findall('.//grant'):
    subject_name = grant.find('subject_name').text
    grant_name = grant.attrib.get('name')
    validity = grant.find('validity')
    default_action = grant.find('default').text

    validity_start = validity.find('not_before').text.split('T')[0] if validity is not None and validity.find('not_before') is not None else None
    validity_end = validity.find('not_after').text.split('T')[0] if validity is not None and validity.find('not_after') is not None else None

    # Insertar subject (o ignorar si ya existe)
    cursor.execute('INSERT OR IGNORE INTO subjects (subject_name) VALUES (?)', (subject_name,))
    cursor.execute('SELECT id FROM subjects WHERE subject_name = ?', (subject_name,))
    subject_id = cursor.fetchone()[0]

    # Insertar grant
    cursor.execute('''
    INSERT INTO grants (subject_id, grant_name, validity_start, validity_end, default_action)
    VALUES (?, ?, ?, ?, ?)
    ''', (subject_id, grant_name, validity_start, validity_end, default_action))
    grant_id = cursor.lastrowid

    # Procesar reglas (allow_rule, deny_rule)
    for rule_tag in ['allow_rule', 'deny_rule']:
        for rule in grant.findall(rule_tag):
            cursor.execute('INSERT INTO rules (grant_id, rule_type) VALUES (?, ?)', (grant_id, rule_tag.split('_')[0].upper()))
            rule_id = cursor.lastrowid

            # Domains
            for domain_id in rule.findall('.//domains/id'):
                cursor.execute('INSERT INTO domains (rule_id, domain_id) VALUES (?, ?)', (rule_id, int(domain_id.text)))

            # Permisos (publish, subscribe, relay, etc.)
            for permission_type in ['publish', 'subscribe', 'relay']:
                for perm in rule.findall(permission_type):
                    cursor.execute('INSERT INTO permissions (rule_id, permission_type) VALUES (?, ?)', (rule_id, permission_type))

                    # Topics (si existen)
                    for topic in perm.findall('.//topics/topic'):
                        cursor.execute('INSERT INTO topics (rule_id, topic_name) VALUES (?, ?)', (rule_id, topic.text))

conn.commit()
conn.close()

print("✅ Archivo 'permissions.xml' importado a 'permisos_importados.db'.")
