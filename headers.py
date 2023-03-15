import argparse
import requests
from tabulate import tabulate

# Definimos el parser de argumentos para recibir la URL como parámetro
parser = argparse.ArgumentParser(description='Extraer headers de seguridad de una URL.')
parser.add_argument('-u', '--url', type=str, required=True, help='URL a analizar')
parser.add_argument('-v', '--verbose', action='store_true', help='Muestra el valor obtenido de cada header')
parser.add_argument('-r', '--redirects', choices=['full', 'none'], default='none', help='Seguir redirecciones')
parser.add_argument('-i', '--info', action='store_true', help='Imprime información de cada header')

# Parseamos los argumentos
args = parser.parse_args()

# Imprimimos información sobre cada header
if args.info:
    print('\nInformación sobre los headers de seguridad:')
    print('----------------------------------------')
    print('X-Content-Type-Options: Prohibe que el navegador interprete el contenido con un tipo MIME diferente al declarado.')
    print('X-Frame-Options: Permite configurar qué sitios pueden incluir esta página en un marco o iframe.')
    print('X-XSS-Protection: Ayuda a evitar ataques de cross-site scripting (XSS).')
    print('Content-Security-Policy: Ayuda a reducir el riesgo de ataques de inyección de código.')
    print('Strict-Transport-Security: Obliga al navegador a utilizar HTTPS para todas las peticiones durante un tiempo determinado.')
    print('Referrer-Policy: Controla qué información se envía al sitio al que se hace referencia cuando se hace clic en un enlace.')
    print('Feature-Policy: Permite controlar qué características pueden ser usadas por los iframes.')

# Creamos la sesión HTTP y configuramos si se siguen o no redirecciones
session = requests.Session()
if args.redirects == 'none':
    session.max_redirects = 0

# Realizamos la petición HTTP a la URL especificada
response = session.get(args.url)

# Obtenemos los headers de seguridad
headers_seguridad = [
    'X-Content-Type-Options',
    'X-Frame-Options',
    'X-XSS-Protection',
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'Referrer-Policy',
    'Feature-Policy'
]

headers_presentes = []
headers_no_presentes = []

for header in headers_seguridad:
    valor_obtenido = response.headers.get(header)
    if valor_obtenido is not None:
        headers_presentes.append([header, '✔', valor_obtenido if args.verbose else ''])
    else:
        headers_no_presentes.append([header, '✘', ''])

# Imprimimos los resultados en dos tablas separadas
print('\n')
print('Headers de seguridad presentes en la URL', args.url, ':')
print(tabulate(headers_presentes, headers=['Header', 'Presente', 'Valor obtenido']))
print()
print('Headers de seguridad no presentes en la URL', args.url, ':')
print(tabulate(headers_no_presentes, headers=['Header', 'Presente', 'Valor obtenido']))
