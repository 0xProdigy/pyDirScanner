#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import sys
import re
import csv

visited = set()
external_domains = set()
suspicious_entries = []  # [(origin_path, raw_attr, reason)]
use_colors = True

# Filtrar directorios estáticos comunes
STATIC_EXTENSIONS = re.compile(r"\.(css|jpg|jpeg|png|gif|svg|ico|js|mp4|pdf|woff2?|ttf)$", re.IGNORECASE)
STATIC_DIRS = ["images", "css", "js", "assets", "media"]

# Extensiones que consideramos "archivos" (no agregar slash al pedirlos)
FILE_EXTENSIONS = re.compile(r"\.(php|html|htm|asp|aspx|jsp|cgi|pl)$", re.IGNORECASE)

# Esquemas no-http que consideramos sospechosos (pero no seguimos)
NON_HTTP_SCHEMES = ("mailto:", "javascript:", "tel:", "data:", "vbscript:")

def get_html(url):
    try:
        response = requests.get(url, timeout=10)
        return response.status_code, response.text
    except requests.RequestException:
        return None, None

def normalize_path(path: str) -> str:
    """Normaliza un path para evitar duplicados (/ vs /index vs /index/)."""
    if not path:
        return "/"
    parsed = urlparse(path)
    p = parsed.path or "/"
    if not p.startswith("/"):
        p = "/" + p
    if p != "/" and p.endswith("/"):
        p = p.rstrip("/")
    return p

def is_file_path(path: str) -> bool:
    """True si path parece apuntar a un archivo por extensión."""
    return bool(FILE_EXTENSIONS.search(path))

def dirname_path(path: str) -> str:
    """Devuelve el directorio padre normalizado; dirname('/a/b/c.php') -> '/a/b'"""
    if not path or path == "/":
        return "/"
    p = normalize_path(path)
    parts = p.strip("/").split("/")
    if len(parts) <= 1:
        return "/"
    parent = "/" + "/".join(parts[:-1])
    return parent

def mark_suspicious(origin, raw, reason):
    suspicious_entries.append((origin, raw, reason))

def looks_malformed(s: str) -> bool:
    # heurística: espacios en uri, paréntesis no balanceados, comillas sobrantes
    if " " in s:
        return True
    if s.count("(") != s.count(")"):
        return True
    if s.count("'") % 2 != 0 or s.count('"') % 2 != 0:
        return True
    return False

def extract_internal_paths(html, current_path, base_root, base_domain):
    """
    current_path: path normalizado de la página actual (ej. '/Mod_Rewrite_Shop' o '/index.php')
    base_root: 'http://host:port/' (la raíz que usamos para urljoin)
    Esta versión:
      - guarda en suspicious_entries los hrefs/attrs raros (no los sigue)
      - sigue/extracta URLs limpias como antes (pero más estricta)
    """
    soup = BeautifulSoup(html, "html.parser")
    paths = set()

    tags = soup.find_all(['a', 'link', 'script', 'img', 'iframe', 'source', 'form', 'button'])

    # calcular base para relativos (híbrido)
    if is_file_path(current_path):
        page_base = urljoin(base_root, dirname_path(current_path).lstrip("/") + "/")
    else:
        page_base = urljoin(base_root, current_path.lstrip("/") + "/")
    root_base = base_root

    # helper: decidir si una cadena parece una URL/path legítimo
    def is_likely_url_candidate(s: str) -> bool:
        s = s.strip()
        if not s:
            return False
        low = s.lower()
        if low.startswith("http://") or low.startswith("https://"):
            return True
        if low.startswith("/") or low.startswith("./") or low.startswith("../"):
            return True
        # si contiene una extensión de archivo esperada (con posible querystring)
        if re.search(r"\.(php|html|htm|js|css|png|jpg|jpeg|gif)(?:[\?#].*)?$", low):
            return True
        return False

    for tag in tags:
        candidates = []

        # atributos comunes
        for a in ("href", "src", "action", "data-src", "data-href"):
            v = tag.get(a)
            if v:
                candidates.append(v)

        # atributos on* (onclick, onload...)
        for k, v in tag.attrs.items():
            if k.startswith("on") and isinstance(v, str):
                candidates.append(v)

        # script inline: buscar patrones JS simples (pero con cuidado)
        if tag.name == "script":
            js = ""
            if tag.string:
                js = tag.string
            else:
                js = tag.get_text("")

            if js:
                # llamadas ajax/fetch con string directo
                js_urls = re.findall(r"(?:fetch|axios|ajax)\(\s*['\"]([^'\"]+)['\"]", js, flags=re.I)
                candidates.extend(js_urls)
                # open/fetch/etc: buscamos también 'open' pero lo extraemos sólo si el argumento es una URL clara
                other_calls = re.findall(r"[a-zA-Z_]\w*\(\s*['\"]([^'\"]+)['\"]\s*\)", js)
                candidates.extend(other_calls)
                # strings que terminan en extensión típica entre comillas
                string_urls = re.findall(r"['\"](\/?\.{0,2}[\w\-/\.]+\.(?:php|html|htm|js|css|png|jpg|jpeg|gif)(?:\?[^'\"\)]*)?)['\"]", js)
                candidates.extend(string_urls)

        for attr in candidates:
            if not attr or not isinstance(attr, str):
                continue
            raw = attr.strip()

            # descartar anchors
            if raw.startswith("#"):
                continue

            low = raw.lower()

            # detectamos esquemas no-http
            if any(low.startswith(s) for s in NON_HTTP_SCHEMES):
                mark_suspicious(current_path, raw, "non-http-scheme")
                continue

            # Si parece un correo electrónico dentro de un href (sin mailto), marcar como sospechoso
            if "@" in raw and not raw.startswith("http"):
                mark_suspicious(current_path, raw, "contains-@-maybe-email")
                continue

            # Intentar extraer una cadena entre comillas con extensión esperada (primer intento)
            m = re.search(r"""['"](?P<u>/?\.{0,2}[\w\-/\.]+\.(?:php|html|htm|js|css|png|jpg|jpeg|gif)(?:\?[^'"]*)?)['"]""", raw)
            if m:
                candidate = m.group("u")
            else:
                # si raw ya es una cadena simple (sin paréntesis envolventes) y parece URL, la usamos
                if is_likely_url_candidate(raw):
                    # limpiar terminadores comunes
                    candidate = re.sub(r"^[\s\(\)]+|[\s\(\);]+$", "", raw)
                else:
                    # cadena no parece una URL válida - marcar como suspicious y continuar
                    mark_suspicious(current_path, raw, "not-url-like")
                    continue

            # resolver a full_url
            if candidate.startswith("http://") or candidate.startswith("https://"):
                full_url = candidate
            elif candidate.startswith("/"):
                full_url = urljoin(root_base, candidate)
            else:
                full_url = urljoin(page_base, candidate)

            parsed = urlparse(full_url)

            # dominios externos
            if parsed.netloc and parsed.netloc != base_domain:
                external_domains.add(parsed.netloc)
                continue

            # excluir directorios/extensiones estáticas
            path_parts = parsed.path.strip('/').split('/') if parsed.path else []
            if len(path_parts) > 0 and path_parts[0].lower() in STATIC_DIRS:
                continue
            if STATIC_EXTENSIONS.search(parsed.path or ""):
                continue

            clean_path = normalize_path(parsed.path)
            if clean_path and clean_path not in visited:
                paths.add(clean_path)

    return paths

def print_status(path, status):
    if use_colors:
        if status == 200:
            print(f"\033[92m[+] {path}   --> 200 OK\033[0m")
        elif status == 403:
            print(f"\033[93m[?] {path}   --> 403 Forbidden\033[0m")
        elif status == 404:
            print(f"\033[91m[!] {path}   --> 404 Not Found\033[0m")
        else:
            print(f"\033[93m[-] {path}   --> {status}\033[0m")
    else:
        if status == 200:
            print(f"[+] {path}   --> 200 OK")
        elif status == 403:
            print(f"[?] {path}   --> 403 Forbidden")
        elif status == 404:
            print(f"[!] {path}   --> 404 Not Found")
        else:
            print(f"[-] {path}   --> {status}")

def crawl(base_url, max_depth=None):
    # asegurar la raíz con slash final
    if not base_url.endswith("/"):
        base_root = base_url + "/"
    else:
        base_root = base_url

    base_domain = urlparse(base_root).netloc
    queue = ["/"]
    depth_map = {"/": 0}

    print(f"[i] Iniciando rastreo desde: {base_root}")

    while queue:
        current_path = normalize_path(queue.pop(0))
        current_depth = depth_map.get(current_path, 0)

        if max_depth is not None and current_depth > max_depth:
            continue

        if current_path in visited:
            continue

        visited.add(current_path)

        # construir full_url: si es archivo, NO agregar slash final; si es dir, agregar slash
        if is_file_path(current_path):
            full_url = urljoin(base_root, current_path.lstrip("/"))
        else:
            full_url = urljoin(base_root, current_path.lstrip("/") + "/")

        status, html = get_html(full_url)
        if status is None:
            print(f"[!] Error accediendo a {full_url}")
            continue

        print_status(current_path, status)

        if html and status == 200:
            new_paths = extract_internal_paths(html, current_path, base_root, base_domain)
            for p in new_paths:
                if p not in visited and p not in queue:
                    queue.append(p)
                    depth_map[p] = current_depth + 1

    # resultados finales
    if external_domains:
        print("\n[⚠] Se encontraron referencias a dominios externos:")
        for ext in sorted(external_domains):
            print(f"    - {ext}")

    if suspicious_entries:
        print("\n[!] Entradas sospechosas / no seguidas (revisar manualmente):")
        for origin, raw, reason in suspicious_entries:
            print(f"    - Origen: {origin}  |  Valor: {raw}  |  Motivo: {reason}")
        print("[i] Estas entradas no se siguieron automáticamente; revisalas manualmente para análisis profundo.")

def export_suspicious_csv(path):
    try:
        with open(path, "w", newline='', encoding="utf-8") as csvfile:
            w = csv.writer(csvfile)
            w.writerow(["origin_path", "raw_value", "reason"])
            for origin, raw, reason in suspicious_entries:
                w.writerow([origin, raw, reason])
        print(f"[i] Exportadas {len(suspicious_entries)} entradas sospechosas a {path}")
    except Exception as e:
        print("[!] Error exportando CSV:", e)

def main():
    global use_colors

    if len(sys.argv) < 2:
        print("Uso: python3 pyDirScanner.py <URL> [--no-color] [--max-depth=N] [--export-suspicious=file.csv]")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    if not base_url.startswith("http"):
        base_url = "http://" + base_url

    max_depth = None
    export_file = None
    for arg in sys.argv[2:]:
        if arg.startswith("--max-depth="):
            try:
                max_depth = int(arg.split("=", 1)[1])
            except:
                pass
        if arg == "--no-color":
            use_colors = False
        if arg.startswith("--export-suspicious="):
            export_file = arg.split("=", 1)[1]

    crawl(base_url, max_depth=max_depth)
    if export_file:
        export_suspicious_csv(export_file)

if __name__ == "__main__":
    main()
