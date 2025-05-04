import sqlite3
import xml.etree.ElementTree as ET
import argparse
import os

# Argumentos
parser = argparse.ArgumentParser(description='Importa permisos DDS desde archivos XML a una base de datos SQLite.')
parser.add_argument('xml_files', nargs='+', help='Lista de archivos XML a importar')
parser.add_argument('--db', default='permissions.db', help='Nombre de la base de datos (por defecto: permissions.db)')
args = parser.parse_args()

# Crear base de datos
conn = sqlite3.connect(args.db)
cursor = conn.cursor()

# Crear tablas si no existen
cursor.executescript("""
CREATE TABLE IF NOT EXISTS grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    subject_name TEXT,
    not_before TEXT,
    not_after TEXT,
    default_permission TEXT
);

CREATE TABLE IF NOT EXISTS allow_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    grant_id INTEGER,
    domain_id INTEGER,
    FOREIGN KEY(grant_id) REFERENCES grants(id)
);

CREATE TABLE IF NOT EXISTS topics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    allow_rule_id INTEGER,
    topic TEXT,
    action TEXT,
    FOREIGN KEY(allow_rule_id) REFERENCES allow_rules(id)
);
""")

# Procesar cada archivo XML
for xml_file in args.xml_files:
    if not os.path.exists(xml_file):
        print(f"❌ Archivo no encontrado: {xml_file}")
        continue

    print(f"📂 Procesando {xml_file}")
    tree = ET.parse(xml_file)
    root = tree.getroot()

    for grant in root.findall('.//grant'):
        name = grant.get('name')
        subject = grant.findtext('subject_name')
        not_before = grant.find('validity/not_before').text
        not_after = grant.find('validity/not_after').text
        default_permission = grant.findtext('default')

        # Verifica si el grant ya existe
        cursor.execute("SELECT id FROM grants WHERE name = ?", (name,))
        result = cursor.fetchone()
        if result:
            print(f"⚠️  Grant '{name}' ya existe. Saltando...")
            grant_id = result[0]
        else:
            cursor.execute("""
                INSERT INTO grants (name, subject_name, not_before, not_after, default_permission)
                VALUES (?, ?, ?, ?, ?)
            """, (name, subject, not_before, not_after, default_permission))
            grant_id = cursor.lastrowid

        for rule in grant.findall('allow_rule'):
            for domain in rule.findall('domains/id'):
                domain_id = int(domain.text)
                cursor.execute("""
                    INSERT INTO allow_rules (grant_id, domain_id) VALUES (?, ?)
                """, (grant_id, domain_id))
                allow_rule_id = cursor.lastrowid

                # Buscar acciones permitidas (publish, subscribe, relay, etc.)
                for action in ['publish', 'subscribe', 'relay']:
                    for topic in rule.findall(f'{action}/topics/topic'):
                        cursor.execute("""
                            INSERT INTO topics (allow_rule_id, topic, action)
                            VALUES (?, ?, ?)
                        """, (allow_rule_id, topic.text, action))

conn.commit()
conn.close()

print(f"\n✅ Base de datos actualizada: {args.db}")
