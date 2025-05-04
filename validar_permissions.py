import xmlschema
import sys

# Verificamos que se haya pasado el archivo XML como argumento
if len(sys.argv) != 2:
    print("Uso: python validar_permissions.py <archivo_permissions.xml>")
    sys.exit(1)

# Archivo XML a validar (pasado como argumento)
xml_file = sys.argv[1]

# URL del esquema oficial de RTI Connext DDS 7.5.0
schema_url = "https://community.rti.com/schema/7.5.0/dds_security_permissions.xsd"

try:
    # Cargar el esquema
    schema = xmlschema.XMLSchema(schema_url)

    # Validar el archivo
    if schema.is_valid(xml_file):
        print("✅ El archivo XML es válido según el esquema DDS Permissions 7.5.0.")
    else:
        print("❌ El archivo XML NO es válido. Errores encontrados:")
        for error in schema.iter_errors(xml_file):
            print(f"- {error}")
except Exception as e:
    print(f"❌ Error al validar: {e}")
