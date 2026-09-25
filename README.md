# Escáner de puertos con Nmap

`escaneo_nmap.py` ejecuta Nmap y convierte su resultado en un reporte fácil de leer en español (`txt`, `json` o `csv`).

## Requisitos

- Python 3.10 o posterior
- Nmap instalado y disponible en el `PATH`

## Uso

```bash
python3 escaneo_nmap.py 127.0.0.1
python3 escaneo_nmap.py 127.0.0.1 -p 22,80,443 -o reporte_local.txt
python3 escaneo_nmap.py 127.0.0.1 -p 1-1024 -sV
python3 escaneo_nmap.py 192.168.1.0/24 --top-ports 100 --formato json -o reporte.json
python3 escaneo_nmap.py 127.0.0.1 --top-ports 50 --rapido --timeout 120 -v
python3 escaneo_nmap.py ejemplo.com -p T:22,U:53 --no-ping --formato csv
```

Opciones principales:

- `-p/--puertos`: `22,80,443`, `1-1024`, `T:22,U:53`, `p-` (todos). Excluyente con `--top-ports`.
- `--top-ports N`: los N puertos más comunes.
- `--formato txt|json|csv`: por defecto `txt` (se infiere de `-o` si termina en `.json`/`.csv`).
- `-sV`, `-O/--detectar-so`, `--tipo connect|syn|udp`, `--no-ping` (`-Pn`).
- `--rapido` (`-T4`), `--min-rate`, `--max-retries`, `--timeout` (segundos, `0` = sin límite), `-v/--verbose`.
- `-o/--salida`: por defecto `reporte_nmap_<objetivo>.<ext>`.

Por defecto se escanean los puertos `1-1024`. Usa el programa únicamente sobre sistemas propios
o con autorización.

## Desarrollo

```bash
python3 -m pytest
```
