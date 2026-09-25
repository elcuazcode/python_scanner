# Escáner de puertos con Nmap

`escaneo_nmap.py` ejecuta Nmap y convierte su resultado en un reporte `.txt` fácil de leer en español.

## Requisitos

- Python 3.10 o posterior
- Nmap instalado y disponible en el `PATH`

## Uso

```bash
python3 escaneo_nmap.py 127.0.0.1
python3 escaneo_nmap.py 127.0.0.1 -p 22,80,443 -o reporte_local.txt
python3 escaneo_nmap.py 127.0.0.1 -p 1-1024 -sV
```

Por defecto se escanean los puertos `1-1024` y se crea un archivo con el nombre
`reporte_nmap_<objetivo>.txt`. Usa el programa únicamente sobre sistemas propios
o con autorización.
