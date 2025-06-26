from datetime import datetime, timedelta

# Fecha actual
ahora = datetime.now()

# Fecha actual + 60 minutos
mas_60_min = ahora + timedelta(minutes=60)

# Formato deseado: 2019-10-31T13:00:00
formato = "%Y-%m-%dT%H:%M:%S"

# Imprimir resultados
print("Fecha actual:         ", ahora.strftime(formato))
print("Fecha actual + 60 min:", mas_60_min.strftime(formato))
