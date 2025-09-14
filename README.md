# 🕵️‍♂️ pyDirScanner

## 📖 Descripción

**pyDirScanner** es una herramienta en Python diseñada para auditorías de seguridad en sitios web. 🔍  
Se encarga de rastrear y descubrir directorios y archivos dentro de un sitio web, verificando cuáles de ellos están activos y cuáles no.  
La herramienta explora recursivamente la estructura del sitio web, proporcionando retroalimentación detallada sobre enlaces activos e inactivos, filtrando recursos estáticos como imágenes, CSS, JavaScript, fuentes, etc., y detectando posibles referencias sospechosas ⚠️ que deben revisarse manualmente.

## ✨ Características

- 🔄 **Rastreo recursivo**: Descubre directorios, subdirectorios y archivos dentro de un sitio web.
- 📡 **Reporte de códigos de estado**: Informa sobre los códigos de estado HTTP como `200 OK`, `404 Not Found`, `403 Forbidden`, entre otros.
- 🧹 **Filtrado dinámico**: Excluye directorios y archivos relacionados con recursos estáticos como `/images/`, `.css`, `.js`, `.jpg`, `.png`, `.pdf`, `.woff2`, `.ttf`, etc.
- 🌍 **Detección de dominios externos**: Detecta y reporta automáticamente dominios externos vinculados dentro del sitio.
- 🚨 **Detección de entradas sospechosas**: Identifica y lista enlaces o atributos no estándar (`mailto:`, `javascript:`, emails ocultos, valores malformados, etc.), sin seguirlos automáticamente.
- 📑 **Exportación a CSV**: Permite exportar las entradas sospechosas con la opción `--export-suspicious`.
- 📏 **Control de profundidad**: Posibilidad de limitar el nivel de rastreo con `--max-depth=N`.
- 🎨 **Personalizable**: Opción `--no-color` para usuarios que prefieren la salida en texto plano.

## ⚙️ Instalación

Para usar la herramienta **pyDirScanner**, necesitas tener Python 3 instalado. Puedes clonar el repositorio e instalar las dependencias necesarias siguiendo estos pasos:

```bash
git clone https://github.com/0xProdigy/pyDirScanner.git
cd pyDirScanner
pip install -r requirements.txt
```

## 🚀 Uso básico

Para comenzar a rastrear un sitio web:

```bash
python pyDirScanner.py <URL>
```

Ejemplo:

```bash
python pyDirScanner.py http://testphp.vulnweb.com
```

## 🔧 Opciones adicionales

- 🎨 `--no-color` → Desactiva la salida con colores en la terminal.  
  Ejemplo:  
  ```bash
  python pyDirScanner.py http://testphp.vulnweb.com --no-color
  ```

- 📏 `--max-depth=N` → Limita la profundidad de rastreo.  
  Ejemplo:  
  ```bash
  python pyDirScanner.py http://testphp.vulnweb.com --max-depth=2
  ```

- 📑 `--export-suspicious=archivo.csv` → Exporta las entradas sospechosas detectadas a un archivo CSV.  
  Ejemplo:  
  ```bash
  python pyDirScanner.py http://testphp.vulnweb.com --export-suspicious=sospechosos.csv
  ```
