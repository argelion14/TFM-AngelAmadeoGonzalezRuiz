#!/bin/bash

# Archivos de entrada/salida
XML_FILE="./permissions.xml"

# Archivos CA
CA_KEY="ecdsa01RootCaKey.pem"
CA_CERT="ecdsa01RootCaCert.pem"

# Archivos identidad de Alice
ALICE_KEY="ecdsa01Peer01Key.pem"
ALICE_CSR="ecdsa01Peer01.csr"
ALICE_CERT="ecdsa01Peer01Cert.pem"

SIGNED_PERMISSIONS="permissions.p7s"

### 1. Crear clave privada de la CA
echo "🔑 Generando clave privada de la CA..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$CA_KEY"

### 2. Crear certificado autofirmado de la CA
echo "📜 Generando certificado autofirmado de la CA..."
openssl req -new -x509 -key "$CA_KEY" -out "$CA_CERT" -days 3650 -subj "/C=US/ST=CA/O=RTI Demo/CN=ecdsa01 Root CA"

### 3. Crear identidad de Alice
echo "👤 Generando clave privada para Alice..."
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$ALICE_KEY"
echo "📝 Generando CSR de Alice..."
openssl req -new -key "$ALICE_KEY" -out "$ALICE_CSR" -subj "/C=US/ST=CA/O=RTI Demo/CN=Alice"
echo "🔏 Firmando certificado de Alice con la CA..."
openssl x509 -req -in "$ALICE_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$ALICE_CERT" -days 365

### 4. Verifica el archivo de permisos
if [ ! -f "$XML_FILE" ]; then
    echo "❌ Error: No se encontró el archivo $XML_FILE"
fi
### 5. Firmar el archivo XML
echo "✍️  Firmando $XML_FILE..."
openssl smime -sign -in "$XML_FILE" -out "$SIGNED_PERMISSIONS" -signer "$CA_CERT" -inkey "$CA_KEY" -outform DER -nodetach

### 6. Verificar la firma

echo "😄 Verificando $XML_FILE..."
openssl smime -verify \
  -inform DER \
  -in "$SIGNED_PERMISSIONS" \
  -CAfile "$CA_CERT" \
  -out /dev/null

openssl x509 -in "$ALICE_CERT" -text -noout