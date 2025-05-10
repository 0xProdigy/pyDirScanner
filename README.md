# pyDirScanner

## Descripción

**pyDirScanner** es una herramienta en Python diseñada para auditorías de seguridad en sitios web. Se encarga de rastrear y descubrir directorios dentro de un sitio web, verificando cuáles de ellos están activos y cuáles no. La herramienta explora recursivamente la estructura del sitio web, proporcionando retroalimentación detallada sobre enlaces activos e inactivos, y filtrando recursos estáticos como imágenes, archivos CSS y JavaScript.

## Características

- **Rastreo recursivo**: Descubre directorios y subdirectorios dentro de un sitio web de manera recursiva.
- **Reporte de códigos de estado**: Informa sobre los códigos de estado HTTP como 200 OK, 404 Not Found, 403 Forbidden, entre otros.
- **Filtrado dinámico**: Excluye directorios relacionados con recursos estáticos como `/images/`, `/css/`, etc.
- **Detección de dominios externos**: Detecta y reporta automáticamente dominios externos vinculados dentro del sitio.
- **Personalizable**: Admite la opción `--no-color` para usuarios que prefieren la salida en texto plano.

## Instalación

Para usar la herramienta **pyDirScanner**, necesitas tener Python 3 instalado. Puedes clonar el repositorio e instalar las dependencias necesarias siguiendo estos pasos:

1. Clona el repositorio:

   ```bash
   git clone https://github.com/0xProdigy/pyDirScanner.git
   cd pyDirScanner
   pip install -r requirements.txt

## uso 
- **Para comenzar a rastrear un sitio web, utiliza el siguiente comando**: python pyDirScanner.py <URL>
- **Por ejemplo**: python pyDirScanner.py http://testphp.vulnweb.com

## Opciones adicionales:
--no-color: Desactiva la salida con colores en la terminal.
- **Por ejemplo**: python pyDirScanner.py http://testphp.vulnweb.com --no-color
