#!/bin/bash

# Uso: ./sign_and_verify_permissions.sh permissions.xml signing_cert.pem signing_key.pem ca_cert.pem

if [ "$#" -ne 4 ]; then
  echo "Uso: $0 <permissions.xml> <cert.pem> <key.pem> <ca_cert.pem>"
  echo "Ejemplo: $0 permissions.xml signing_cert.pem signing_key.pem ca_cert.pem"
  exit 1
fi

PERMISSIONS_XML="$1"
CERT="$2"
KEY="$3"
CA_CERT="$4"
SIG_OUT="permissions.p7s"

# Paso 1: Firmar el archivo
echo "📄 Firmando $PERMISSIONS_XML..."
openssl smime -sign -binary \
  -in "$PERMISSIONS_XML" \
  -signer "$CERT" \
  -inkey "$KEY" \
  -outform DER \
  -nodetach \
  -out "$SIG_OUT"

if [ $? -ne 0 ]; then
  echo "❌ Error al firmar el archivo"
  exit 2
fi
echo "✅ Firma generada: $SIG_OUT"

# Paso 2: Verificar la firma
echo "🔍 Verificando la firma con la CA..."

# Convertir a formato PEM para la verificación
SIG_PEM="permissions.p7s.pem"
openssl pkcs7 -inform DER -in "$SIG_OUT" -out "$SIG_PEM" -print_certs

# Usar smime para verificar
openssl smime -verify \
  -in "$SIG_PEM" \
  -inform PEM \
  -content "$PERMISSIONS_XML" \
  -CAfile "$CA_CERT" \
  -purpose any \
  -out /dev/null

if [ $? -eq 0 ]; then
  echo "✅ Firma VERIFICADA correctamente con CA: $CA_CERT"
else
  echo "❌ La verificación de la firma FALLÓ"
  exit 3
fi
