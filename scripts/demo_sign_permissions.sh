#!/bin/bash

# Archivos de entrada/salida
PERMISSIONS_XML="permissions.xml"
CA_KEY="demo_ca.key"
CA_CERT="demo_ca.crt"
SIGNING_KEY="alice.key"
SIGNING_CSR="alice.csr"
SIGNING_CERT="alice.crt"
SIGNED_PERMISSIONS="permissions.p7s"
SIGNED_PERMISSIONS_PEM="permissions.p7s.pem"

# 1. Crear CA autofirmada si no existe
if [ ! -f "$CA_CERT" ]; then
  echo "🔧 Generando CA autofirmada..."
  openssl req -x509 -newkey rsa:2048 -keyout "$CA_KEY" -out "$CA_CERT" -days 365 -nodes -subj "/C=US/ST=CA/L=Demo/O=DemoCA/CN=DemoRoot"
fi

# 2. Crear clave y CSR del firmante
echo "🔐 Generando clave y CSR de Alice..."
openssl req -newkey rsa:2048 -nodes -keyout "$SIGNING_KEY" -out "$SIGNING_CSR" -subj "/C=US/ST=CA/L=Demo/O=DemoSigner/CN=Alice"

# 3. Firmar el certificado con la CA
echo "✍️ Firmando certificado de Alice con la CA..."
openssl x509 -req -in "$SIGNING_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial -out "$SIGNING_CERT" -days 365

# 4. Firmar el archivo XML
echo "📄 Firmando $PERMISSIONS_XML..."
openssl smime -sign -binary \
  -in "$PERMISSIONS_XML" \
  -signer "$SIGNING_CERT" \
  -inkey "$SIGNING_KEY" \
  -outform DER \
  -nodetach \
  -out "$SIGNED_PERMISSIONS"

openssl smime -sign -in "$PERMISSIONS_XML" -text -out "$SIGNED_PERMISSIONS" -signer cert\ecdsa01\ca\ecdsa01RootCaCert.pem -inkey cert\ecdsa01\ca\private\ecdsa01RootCaKey.pem

# # 5. Verificar la firma
# echo "🔍 Verificando firma..."
# openssl pkcs7 -inform DER -in "$SIGNED_PERMISSIONS" -out "$SIGNED_PERMISSIONS_PEM" -print_certs

# openssl smime -verify \
#   -in "$SIGNED_PERMISSIONS_PEM" \
#   -inform PEM \
#   -content "$PERMISSIONS_XML" \
#   -CAfile "$CA_CERT" \
#   -purpose any \
#   -out /dev/null

# if [ $? -eq 0 ]; then
#   echo "✅ Firma verificada correctamente con la CA demo"
# else
#   echo "❌ Verificación fallida"
# fi
