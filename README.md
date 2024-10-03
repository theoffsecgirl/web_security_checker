# Web Security Checker - theoffsecgirl

Este script automatiza el escaneo de vulnerabilidades en aplicaciones web, verificando específicamente las siguientes vulnerabilidades:

- **CSRF (Cross-Site Request Forgery)**
- **Inyección SQL**
- **XSS (Cross-Site Scripting)**

## Descripción

El script utiliza la biblioteca `requests` para realizar solicitudes HTTP y `lxml` para analizar el contenido HTML de las páginas. Dependiendo de las opciones seleccionadas, verifica si hay tokens CSRF en los formularios, posibles inyecciones SQL y vulnerabilidades de XSS.

## Requisitos

- Python 3.x
- Bibliotecas necesarias:
  - `requests`
  - `lxml`

Puedes instalar las bibliotecas necesarias usando `pip`:

```bash
pip install requests lxml
```
# Uso
1.	Clona el repositorio o descarga el script:

```
git clone https://github.com/theoffsecgirl/web_security_checker
cd web_security_checker
python3 python3 web_security_checker.py
````



# Ejemplo de SALIDA
     _____   _             ___     __    __   ___               ___   _         _ 
    |_   _| | |_    ___   / _ \   / _|  / _| / __|  ___   __   / __| (_)  _ _  | |
      | |   | ' \  / -_) | (_) | |  _| |  _| \__ \ / -_) / _| | (_ | | | | '_| | |
      |_|   |_||_| \___|  \___/  |_|   |_|   |___/ \___| \__|  \___| |_| |_|   |_| 

Ingrese la URL a escanear: http://ejemplo.com
Seleccione las vulnerabilidades a comprobar:
1. CSRF
2. Inyección SQL
3. XSS
4. Todas
Ingrese el número de la opción: 1
⚠️ Posible vulnerabilidad CSRF en el formulario.
 
