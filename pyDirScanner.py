#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys
import re

visited = set()
external_domains = set()
use_colors = True

# Filtrar directorios estáticos comunes
STATIC_EXTENSIONS = re.compile(r"\.(css|jpg|jpeg|png|gif|svg|ico|js|mp4|pdf)$", re.IGNORECASE)
STATIC_DIRS = ["images", "css", "js", "assets", "media"]

def is_internal(url, base_domain):
    parsed = urlparse(url)
    return parsed.netloc == "" or parsed.netloc == base_domain

def get_html(url):
    try:
        response = requests.get(url, timeout=10)
        return response.status_code, response.text
    except requests.RequestException:
        return None, None

def extract_internal_paths(html, base_url, base_domain):
    soup = BeautifulSoup(html, "html.parser")
    paths = set()

    tags = soup.find_all(['a', 'link', 'script', 'img'])

    for tag in tags:
        attr = tag.get("href") or tag.get("src")
        if attr:
            full_url = urljoin(base_url, attr)
            parsed = urlparse(full_url)

            # Filtrar dominios externos
            if parsed.netloc and parsed.netloc != base_domain:
                external_domains.add(parsed.netloc)
                continue

            # Filtrar directorios estáticos (imágenes, css, js, etc.)
            path_parts = parsed.path.strip('/').split('/')
            if len(path_parts) > 0 and path_parts[0].lower() in STATIC_DIRS:
                continue

            # Filtrar extensiones estáticas
            if STATIC_EXTENSIONS.search(parsed.path):
                continue

            # Tomar solo el path limpio y relativo
            clean_path = parsed.path.rstrip("/")
            if clean_path and clean_path not in visited:
                paths.add(clean_path)

    return paths

def print_status(path, status):
    if use_colors:
        if status == 200:
            print(f"\033[92m[+] {path}/   --> 200 OK\033[0m")
        elif status == 403:
            print(f"\033[93m[?] {path}/   --> 403 Forbidden\033[0m")
        elif status == 404:
            print(f"\033[91m[!] {path}/   --> 404 Not Found\033[0m")
        else:
            print(f"\033[93m[-] {path}/   --> {status}\033[0m")
    else:
        if status == 200:
            print(f"[+] {path}/   --> 200 OK")
        elif status == 403:
            print(f"[?] {path}/   --> 403 Forbidden")
        elif status == 404:
            print(f"[!] {path}/   --> 404 Not Found")
        else:
            print(f"[-] {path}/   --> {status}")

def crawl(base_url):
    base_domain = urlparse(base_url).netloc
    queue = ["/"]

    print(f"[i] Iniciando rastreo desde: {base_url}")

    while queue:
        current_path = queue.pop(0)
        full_url = urljoin(base_url, current_path + "/")

        if current_path in visited:
            continue

        visited.add(current_path)

        status, html = get_html(full_url)
        if status is None:
            print(f"[!] Error accediendo a {full_url}")
            continue

        print_status(current_path, status)

        if html and status == 200:
            new_paths = extract_internal_paths(html, full_url, base_domain)
            for p in new_paths:
                if p not in visited:
                    queue.append(p)

    if external_domains:
        print("\n[⚠] Se encontraron referencias a dominios externos:")
        for ext in sorted(external_domains):
            print(f"    - {ext}")
        print("[i] Puedes analizarlos manualmente si deseas continuar más allá del dominio original.")

def main():
    global use_colors

    if len(sys.argv) < 2:
        print("Uso: python3 pyDirScanner.py <URL> [--no-color]")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    if not base_url.startswith("http"):
        base_url = "http://" + base_url

    if "--no-color" in sys.argv:
        use_colors = False

    crawl(base_url)

if __name__ == "__main__":
    main()
