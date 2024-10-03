#!/usr/bin/env python

import requests
from lxml import html

# Definición de colores
class Colores:
    VERDE = "\033[92m"
    ROJO = "\033[91m"
    AMARILLO = "\033[93m"
    RESET = "\033[0m"

def imprimir_banner():
    """Imprime un banner de bienvenida."""
    banner = r"""
     _____   _             ___     __    __   ___               ___   _         _ 
    |_   _| | |_    ___   / _ \   / _|  / _| / __|  ___   __   / __| (_)  _ _  | |
      | |   | ' \  / -_) | (_) | |  _| |  _| \__ \ / -_) / _| | (_ | | | | '_| | |
      |_|   |_||_| \___|  \___/  |_|   |_|   |___/ \___| \__|  \___| |_| |_|   |_|
    """
    print(Colores.VERDE + banner + Colores.RESET)

def verificar_csrf(formulario):
    """Verifica si hay un token CSRF en el formulario."""
    csrf_token = formulario.xpath('//input[@name="csrf_token"]')
    if not csrf_token:
        print(Colores.AMARILLO + "⚠️ Posible vulnerabilidad CSRF en el formulario." + Colores.RESET)

def verificar_inyeccion_sql(url):
    """Verifica posibles vulnerabilidades de inyección SQL en la URL."""
    palabras_clave_sql = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION']
    try:
        response = requests.get(url)
        response.raise_for_status()  # Lanza un error si la solicitud no fue exitosa
        for palabra_clave in palabras_clave_sql:
            if palabra_clave in response.text:
                print(Colores.AMARILLO + f"⚠️ Posible vulnerabilidad de inyección SQL detectada: {palabra_clave}" + Colores.RESET)
    except requests.RequestException as e:
        print(Colores.ROJO + f"❌ Error al verificar inyección SQL: {e}" + Colores.RESET)

def verificar_xss(url):
    """Verifica posibles vulnerabilidades de XSS en la URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Lanza un error si la solicitud no fue exitosa
        root = html.fromstring(response.content)
        scripts = root.xpath('//script')
        if scripts:
            print(Colores.AMARILLO + "⚠️ Posible vulnerabilidad de Cross-Site Scripting (XSS) detectada." + Colores.RESET)
    except requests.RequestException as e:
        print(Colores.ROJO + f"❌ Error al verificar XSS: {e}" + Colores.RESET)

def escanear_vulnerabilidades(url, opciones):
    """Escanea la URL en busca de las vulnerabilidades seleccionadas."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Lanza un error si la solicitud no fue exitosa
        root = html.fromstring(response.content)

        # Verificar vulnerabilidades según las opciones seleccionadas
        formularios = root.xpath('//form')
        for formulario in formularios:
            if 'csrf' in opciones:
                verificar_csrf(formulario)
        if 'sql' in opciones:
            verificar_inyeccion_sql(url)
        if 'xss' in opciones:
            verificar_xss(url)

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

    escanear_vulnerabilidades(url_a_escanear, opciones_seleccionadas)
