#!/usr/bin/env python

import requests
from lxml import html

def verificar_csrf(formulario):
    csrf_token = formulario.xpath('//input[@name="csrf_token"]')
    if not csrf_token:
        print("Posible vulnerabilidad CSRF en el formulario.")

def verificar_inyeccion_sql(url):
    palabras_clave_sql = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'UNION']
    response = requests.get(url)
    for palabra_clave in palabras_clave_sql:
        if palabra_clave in response.text:
            print(f"Posible vulnerabilidad de inyección SQL detectada: {palabra_clave}")

def verificar_xss(url):
    response = requests.get(url)
    root = html.fromstring(response.content)
    scripts = root.xpath('//script')
    if scripts:
        print("Posible vulnerabilidad de Cross-Site Scripting (XSS) detectada.")

def escanear_vulnerabilidades(url, opciones):
    try:
        # Obtener el contenido HTML de la página
        response = requests.get(url)
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
        print(f"Error al realizar la solicitud: {e}")

if __name__ == "__main__":
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
        print("Opción no válida. Saliendo.")
        exit()

    escanear_vulnerabilidades(url_a_escanear, opciones_seleccionadas)
