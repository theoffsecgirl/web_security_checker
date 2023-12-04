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

def escanear_vulnerabilidades(url):
    try:
        # Obtener el contenido HTML de la página
        response = requests.get(url)
        root = html.fromstring(response.content)

        # Verificar vulnerabilidades comunes
        formularios = root.xpath('//form')
        for formulario in formularios:
            verificar_csrf(formulario)

        # Agregar más verificaciones según sea necesario
        verificar_inyeccion_sql(url)
        verificar_xss(url)

    except requests.RequestException as e:
        print(f"Error al realizar la solicitud: {e}")

if __name__ == "__main__":
    url_a_escanear = "https://www.ejemplo.com"
    escanear_vulnerabilidades(url_a_escanear)
