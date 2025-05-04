import requests

# URL del endpoint de login
url = "http://127.0.0.1:5000/login"

# Datos a enviar en el cuerpo de la solicitud POST
payload = {
    "username": "alice",
    "password": "alice_password"
}

try:
    # Realizar la solicitud POST con un timeout de 10 segundos
    response = requests.post(url, json=payload, timeout=10)

    # Verificar el estado de la respuesta
    if response.status_code == 200:
        # Si la respuesta es exitosa, obtener el token de la respuesta JSON
        data = response.json()
        token = data.get("token")  # Ajusta esto según cómo sea el campo del token en la respuesta
        print(f"Token obtenido: {token}")
        
        # Usar el token para acceder a los recursos protegidos
        
        # 1. Acceder al recurso protegido (GET /resource)
        resource_url = "http://127.0.0.1:5000/resource"
        headers = {"Authorization": f"Bearer {token}"}
        resource_response = requests.get(resource_url, headers=headers)
        
        if resource_response.status_code == 200:
            print(f"Acceso al recurso permitido: {resource_response.json()}")
        else:
            print(f"Error al acceder al recurso: {resource_response.status_code} - {resource_response.text}")
        
        # 2. Acceder al recurso protegido con permisos de escritura (POST /resource/write)
        write_url = "http://127.0.0.1:5000/resource/write"
        write_response = requests.post(write_url, headers=headers)
        
        if write_response.status_code == 200:
            print(f"Acceso a escritura permitido: {write_response.json()}")
        else:
            print(f"Error al acceder a escritura: {write_response.status_code} - {write_response.text}")
    
    else:
        print(f"Error en el login: {response.status_code} - {response.text}")
except requests.exceptions.RequestException as e:
    print(f"Se produjo un error al intentar hacer la solicitud: {e}")
