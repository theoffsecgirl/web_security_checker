#!/usr/bin/env python

import requests
from lxml import html
from urllib.parse import urlparse
from tqdm import tqdm
from requests.packages.urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from colorama import Fore, Style

# Definición de colores
class Colores:
    VERDE = Fore.GREEN
    ROJO = Fore.RED
    AMARILLO = Fore.YELLOW
    RESET = Style.RESET_ALL

def imprimir_banner():
    """Imprime un banner de bienvenida."""
    banner = r"""
    ▄ ▄   ▄███▄   ███       ▄     ▄   █        ▄    ▄  █   ▄      ▄     ▄▄▄▄▀ ▄███▄   █▄▄▄▄ 
    █   █  █▀   ▀  █  █       █     █  █         █  █   █    █      █ ▀▀▀ █    █▀   ▀  █  ▄▀ 
    █ ▄   █ ██▄▄    █ ▀ ▄ █     █ █   █ █     ██   █ ██▀▀█ █   █ ██   █    █    ██▄▄    █▀▀▌  
    █  █  █ █▄   ▄▀ █  ▄▀  █    █ █   █ ███▄  █ █  █ █   █ █   █ █ █  █   █     █▄   ▄▀ █  █  
    █▐    ▀███▀   ███     █  █  █▄ ▄█     ▀ █  █ █    █  █▄ ▄█ █  █ █  ▀      ▀███▀     █   
     ▐                                                                                    
                                     by TheOffSecGirl
    """
    print(Colores.VERDE + banner + Colores.RESET)

def validar_url(url):
    """Valida que la URL sea correcta."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) or (result.netloc and not result.scheme)
    except ValueError:
        return False

def verificar_csrf(formulario):
    """Verifica si hay un token CSRF en el formulario."""
    csrf_token = formulario.xpath('//input[@name="csrf_token"]')
    if not csrf_token:
        print(Colores.AMARILLO + "⚠️ Posible vulnerabilidad CSRF en el formulario." + Colores.RESET)
    else:
        print(Colores.VERDE + "✅ Token CSRF encontrado." + Colores.RESET)

def verificar_inyeccion_sql_avanzado(url):
    """Verifica inyección SQL enviando payloads comunes."""
    payloads = ["' OR 1=1--", "' OR 'a'='a", "' OR 1=1#", "' AND 1=1--"]
    vulnerable = False
    for payload in tqdm(payloads, desc="Verificando SQL Injection"):
        try:
            response = requests.get(f"{url}{payload}", timeout=10)
            if "SQL" in response.text or "syntax" in response.text:
                print(Colores.AMARILLO + f"⚠️ Posible vulnerabilidad de inyección SQL con el payload: {payload}" + Colores.RESET)
                vulnerable = True
        except requests.RequestException as e:
            print(Colores.ROJO + f"❌ Error al verificar inyección SQL avanzada: {e}" + Colores.RESET)
    if not vulnerable:
        print(Colores.VERDE + "✅ No se detectaron inyecciones SQL." + Colores.RESET)

def verificar_xss_avanzado(url):
    """Verifica vulnerabilidades XSS enviando payloads comunes."""
    payload = "<script>alert('XSS')</script>"
    try:
        response = requests.get(url, params={"q": payload}, timeout=10)
        if payload in response.text:
            print(Colores.AMARILLO + "⚠️ Posible vulnerabilidad de Cross-Site Scripting (XSS) reflejado." + Colores.RESET)
        else:
            print(Colores.VERDE + "✅ No se detectaron vulnerabilidades XSS reflejado." + Colores.RESET)
    except requests.RequestException as e:
        print(Colores.ROJO + f"❌ Error al verificar XSS avanzado: {e}" + Colores.RESET)

def escanear_vulnerabilidades(url, opciones, modo):
    """Escanea la URL en busca de las vulnerabilidades seleccionadas."""
    if not validar_url(url):
        print(Colores.ROJO + "❌ URL inválida. Por favor, ingrese una URL válida." + Colores.RESET)
        return

    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[ 500, 502, 503, 504 ])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'})

    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()  # Lanza un error si la solicitud no fue exitosa
        root = html.fromstring(response.content)

        # Verificar vulnerabilidades según las opciones seleccionadas
        formularios = root.xpath('//form')
        for formulario in formularios:
            if 'csrf' in opciones:
                verificar_csrf(formulario)
        if 'sql' in opciones:
            verificar_inyeccion_sql_avanzado(url)
        if 'xss' in opciones:
            verificar_xss_avanzado(url)

    except requests.RequestException as e:
        print(Colores.ROJO + f"❌ Error al escanear la URL: {e}" + Colores.RESET)

if __name__ == "__main__":
    imprimir_banner()  # Imprime el banner al inicio
    url_a_escanear = input("Ingrese la URL a escanear: ")

    print("Seleccione las vulnerabilidades a comprobar:")
    print("1. CSRF")
    print("2. Inyección SQL")
    print("3. XSS")
    print("4. Todas")

    seleccion = input("Ingrese el número de la opción: ")

    opciones_seleccionadas = []
    if seleccion == '1':
        opciones_seleccionadas.append('csrf')
    elif seleccion == '2':
        opciones_seleccionadas.append('sql')
    elif seleccion == '3':
        opciones_seleccionadas.append('xss')
    elif seleccion == '4':
        opciones_seleccionadas = ['csrf', 'sql', 'xss']
    else:
        print(Colores.ROJO + "❌ Opción no válida. Saliendo." + Colores.RESET)
        exit()

    print("Seleccione el modo de escaneo:")
    print("1. Activo")
    print("2. Pasivo")
    modo = input("Ingrese el número de la opción: ")

    if modo == '1':
        modo = 'activo'
    elif modo == '2':
        modo = 'pasivo'
    else:
        print(Colores.ROJO + "❌ Opción no válida. Saliendo." + Colores.RESET)
        exit()

    escanear_vulnerabilidades(url_a_escanear, opciones_seleccionadas, modo)
