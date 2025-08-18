import os
import requests
import time

# 🔧 CONFIGURACIÓN desde variables de entorno
API_BASE = os.getenv("API_BASE", "http://host.docker.internal:5000")
AUTH_HEADER = os.getenv("AUTH_HEADER", "")
ROLE_ID = int(os.getenv("ROLE_ID", 1))
EXP_MINUTES = int(os.getenv("EXP_MINUTES", 1))

OUTPUT_PATH = "/output/rol_firmado.p7s"

# Calculamos el tiempo a esperar en segundos,
# restando 10 segundos para renovar el token antes de que expire.
WAIT_SECONDS = max(EXP_MINUTES * 60 - 10, 1)  # mínimo 1 seg para evitar negativo

# 🚀 INICIO DEL BUCLE
while True:
    print("🔐 Solicitando nuevo token JWT...")

    try:
        # Paso 1: Obtener token JWT corto
        auth_response = requests.post(
            f"{API_BASE}/api/auth-role",
            headers={
                "Authorization": AUTH_HEADER,
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data={
                "role_id": str(ROLE_ID),
                "exp_minutes": str(EXP_MINUTES)
            }
        )

        if auth_response.status_code != 200:
            print(
                f"❌ Error al obtener token: {auth_response.status_code} - {auth_response.text}")
            time.sleep(5)
            continue

        jwt_token = auth_response.json().get("token")
        if not jwt_token:
            print("❌ No se recibió token en la respuesta.")
            time.sleep(5)
            continue

        print("✅ Token obtenido correctamente.")

        # Paso 2: Usar token para exportar y firmar
        print("📥 Solicitando fichero firmado...")

        export_response = requests.post(
            f"{API_BASE}/api/export-grantbyrole",
            headers={
                "Authorization": AUTH_HEADER,
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data={
                "token": jwt_token,
                "sign": "on"
            }
        )

        if export_response.status_code == 200:
            with open(OUTPUT_PATH, "wb") as f:
                f.write(export_response.content)

            print(f"✅ Fichero sobrescrito en: {OUTPUT_PATH}")
        else:
            print(
                f"❌ Error al exportar: {export_response.status_code} - {export_response.text}")

    except Exception as e:
        print(f"💥 Excepción: {str(e)}")

    # ⏳ Esperar el tiempo calculado antes de repetir para renovar el token anticipadamente
    print(f"⏳ Esperando {WAIT_SECONDS} segundos antes de pedir un nuevo token...")
    time.sleep(WAIT_SECONDS)