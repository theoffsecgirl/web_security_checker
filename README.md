# WebFlow: Escanador de Vulnerabilidades Web 🕵️‍♀️

Este es un script Python para escanear vulnerabilidades web que permite descubrir URLs en un sitio web, escanear para vulnerabilidades como inyección SQL e XSS, y proporcionar instrucciones sobre cómo explotar manualmente las vulnerabilidades.

## Características principales 🔍

- Descubrimiento de URLs en un sitio web y numeración de éstas 📊
- Escaneo de URLs descubiertas para vulnerabilidades como SQL injection e XSS ⚠️
- Instrucciones detalladas sobre el ataque de vulnerabilidades 💡
- Apertura automática del navegador para fácil explotación 🌐

## Requisitos 💻

- Python 3.x
- Biblioteca requests
- lxml
- urllib
- tqdm
- string
- time
- subprocess

## Instalación 🔧

1. Clona el repositorio:
```bash
git clone https://github.com/tu_usuario/web-vulnerability.git
```

2. Cambia al directorio del proyecto:

```bash
cd webflow
```

3. Instala las dependencias requeridas:

```bash
pip install -r requirements.txt
```

## Uso 🖥️
https://www.example.com/
Ejecuta el script con el siguiente comando:

```bash
pyhton3 webflow.py https://www.example.com
```

Sustituye `https://www.example.com` con la URL del sitio web objetivo que deseas escanear para vulnerabilidades.

## Funcionalidades 🛠️

- Análisis de vulnerabilidades en URL 🔍
- Reconocimiento de subdominios 👀
- Escaneo de puertos ⚡
- Ataques de inyección SQL condicional y basados en tiempo 💻
- Verificación de encabezados HTTP 🌐
- Bypass de WAF 🕷️

## Limitaciones ⚠️

Este script es solo una herramienta básica y puede requerir ajustes adicionales para adaptarse a tu caso de uso específico. El testing de seguridad web es una tarea compleja, por lo que este script debe ser solo una parte de una estrategia de testing de seguridad integral.

## Aviso Legal 🚫

Por favor, asegúrate de tener autorización adecuada antes de realizar cualquier prueba de vulnerabilidad. Usa esta herramienta responsablemente y solo para fines educativos. No somos responsables de ningún uso indebido o actividades ilegales.

## Contribuciones 🤝

Las contribuciones son bienvenidas! Si tienes sugerencias, mejoras o nuevas características para agregar, por favor abre una solicitud de incorporación de cambios o envía una solicitud de extracción.
