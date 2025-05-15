import sqlite3
import xml.etree.ElementTree as ET

# Conexión a la base de datos
conn = sqlite3.connect('permisos.db')
cursor = conn.cursor()

# Crear raíz del XML
root = ET.Element('dds', {
    'xmlns:xsi': 'http://www.w3.org/2001/XMLSchema-instance',
    'xsi:noNamespaceSchemaLocation': 'http://www.omg.org/spec/DDS-SECURITY/20170901/omg_shared_ca_permissions.xsd'
})
permissions = ET.SubElement(root, 'permissions')

# Obtener grants
cursor.execute('''
SELECT g.id, s.subject_name, g.grant_name, g.validity_start, g.validity_end, g.default_action
FROM grants g
JOIN subjects s ON g.subject_id = s.id
''')

grants = cursor.fetchall()

for grant_id, subject_name, grant_name, start, end, default_action in grants:
    grant_el = ET.SubElement(permissions, 'grant', {'name': grant_name})
    ET.SubElement(grant_el, 'subject_name').text = subject_name
    if start and end:
        validity_el = ET.SubElement(grant_el, 'validity')
        ET.SubElement(validity_el, 'not_before').text = f"{start}T00:00:00Z"
        ET.SubElement(validity_el, 'not_after').text = f"{end}T00:00:00Z"
    ET.SubElement(grant_el, 'default').text = default_action

    # Obtener rules asociadas al grant
    cursor.execute('SELECT id, rule_type FROM rules WHERE grant_id = ?', (grant_id,))
    rules = cursor.fetchall()

    for rule_id, rule_type in rules:
        rule_el = ET.SubElement(grant_el, f'{rule_type.lower()}_rule')

        # Domains
        cursor.execute('SELECT domain_id FROM domains WHERE rule_id = ?', (rule_id,))
        domains = cursor.fetchall()
        if domains:
            domains_el = ET.SubElement(rule_el, 'domains')
            for (domain_id,) in domains:
                if domain_id is not None:
                    ET.SubElement(domains_el, 'id').text = str(domain_id)

        # Topics y Permissions
        cursor.execute('SELECT DISTINCT permission_type FROM permissions WHERE rule_id = ?', (rule_id,))
        permission_types = cursor.fetchall()

        for (permission_type,) in permission_types:
            perm_el = ET.SubElement(rule_el, permission_type)
            cursor.execute('SELECT topic_name FROM topics WHERE rule_id = ?', (rule_id,))
            topics = cursor.fetchall()
            if topics:
                topics_el = ET.SubElement(perm_el, 'topics')
                for (topic_name,) in topics:
                    if topic_name:
                        ET.SubElement(topics_el, 'topic').text = topic_name
            else:
                # Si no hay topics, poner '*'
                topics_el = ET.SubElement(perm_el, 'topics')
                ET.SubElement(topics_el, 'topic').text = '*'

# Generar archivo XML
tree = ET.ElementTree(root)
tree.write('permissions.xml', encoding='utf-8', xml_declaration=True)

conn.close()

print("✅ Archivo 'permissions.xml' generado desde 'permisos.db'.")
