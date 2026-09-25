#!/usr/bin/env python3
"""Escáner de puertos con Nmap y reporte en español (txt/json/csv)."""

from __future__ import annotations

import argparse
import csv
import io
import json
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET


FORMATOS_VALIDOS = ("txt", "json", "csv")
TIPOS_ESCANEO = ("default", "connect", "syn", "udp")
EXTENSION_POR_FORMATO = {"txt": ".txt", "json": ".json", "csv": ".csv"}

# Caracteres permitidos en un objetivo (IP, CIDR, rango, hostname, IPv6).
CARACTERES_OBJETIVO = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "._-/:,[] "
)


def crear_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ejecuta un escaneo de puertos con Nmap y genera un reporte en español."
    )
    parser.add_argument(
        "objetivo",
        help="Dirección IP, nombre DNS o rango autorizado que se desea escanear.",
    )
    grupo_puertos = parser.add_mutually_exclusive_group()
    grupo_puertos.add_argument(
        "-p",
        "--puertos",
        default=None,
        help="Puertos o rango para escanear (por defecto: 1-1024). "
        "Ejemplos: 22,80,443 · 1-1024 · T:22,U:53 · p- (todos).",
    )
    grupo_puertos.add_argument(
        "--top-ports",
        type=int,
        default=None,
        metavar="N",
        help="Escanea los N puertos más comunes (ej.: --top-ports 100).",
    )
    parser.add_argument(
        "-o",
        "--salida",
        type=Path,
        default=None,
        help="Ruta del reporte (por defecto: reporte_nmap_<objetivo>.<ext>).",
    )
    parser.add_argument(
        "--formato",
        choices=FORMATOS_VALIDOS,
        default=None,
        help="Formato del reporte (por defecto: txt; se infiere de -o si termina en .json/.csv).",
    )
    parser.add_argument(
        "-sV",
        "--detectar-versiones",
        action="store_true",
        help="Solicita a Nmap la detección de servicios y versiones.",
    )
    parser.add_argument(
        "--rapido",
        action="store_true",
        help="Usa una temporización más rápida (-T4). Puede generar más tráfico.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=300.0,
        help="Tiempo máximo en segundos para Nmap (por defecto: 300; 0 = sin límite).",
    )
    parser.add_argument(
        "--min-rate",
        type=int,
        default=None,
        metavar="N",
        help="Tasa mínima de paquetes por segundo (--min-rate N).",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        default=None,
        metavar="N",
        help="Número máximo de reintentos (--max-retries N).",
    )
    parser.add_argument(
        "--no-ping",
        action="store_true",
        help="Omite el descubrimiento de hosts (-Pn). Útil si el host bloquea ping.",
    )
    parser.add_argument(
        "--tipo",
        choices=TIPOS_ESCANEO,
        default="default",
        help="Tipo de escaneo: connect (-sT), syn (-sS, requiere privilegios) o udp (-sU).",
    )
    parser.add_argument(
        "-O",
        "--detectar-so",
        action="store_true",
        help="Activa la detección de sistema operativo (-O, requiere privilegios).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Muestra el comando Nmap y pasa -v a Nmap.",
    )
    return parser


def nombre_reporte(objetivo: str, formato: str = "txt") -> Path:
    nombre = "".join(
        caracter if caracter.isalnum() or caracter in "._-" else "_"
        for caracter in objetivo
    )
    extension = EXTENSION_POR_FORMATO.get(formato, ".txt")
    return Path(f"reporte_nmap_{nombre or 'objetivo'}{extension}")


def validar_puertos(puertos: str) -> bool:
    """Valida el subconjunto de sintaxis -p de Nmap que aceptamos.

    Acepta: ``22``, ``22,80,443``, ``1-1024``, ``p-``/``-`` (todos),
    y prefijos de protocolo ``T:``/``U:`` (ej.: ``T:22,U:53``).
    """
    if puertos is None:
        return False
    texto = puertos.strip()
    if not texto:
        return False
    if texto in ("-", "p-", "P-"):
        return True
    for elemento in texto.split(","):
        parte = elemento.strip()
        if not parte:
            return False
        # Prefijo opcional de protocolo: T: / U:
        if len(parte) > 2 and parte[1] == ":" and parte[0] in "TUtu":
            parte = parte[2:].strip()
            if not parte:
                return False
        extremos = parte.split("-")
        if len(extremos) > 2:
            return False
        if any(
            not extremo.isdigit() or not 1 <= int(extremo) <= 65535
            for extremo in extremos
        ):
            return False
        if len(extremos) == 2 and int(extremos[0]) > int(extremos[1]):
            return False
    return True


def validar_objetivo(objetivo: str) -> bool:
    """Chequeo mínimo: no vacío y sin metacaracteres de shell."""
    if objetivo is None:
        return False
    texto = objetivo.strip()
    if not texto or len(texto) > 1024:
        return False
    peligrosos = set(";|&$`'\"()!\\")
    if any(c in peligrosos for c in texto):
        return False
    if any(c not in CARACTERES_OBJETIVO for c in texto):
        return False
    return True


def verificar_dependencias() -> str | None:
    """Devuelve la ruta de nmap o None si no está disponible."""
    return shutil.which("nmap")


def obtener_atributo(elemento: ET.Element | None, clave: str, predeterminado: str = "") -> str:
    return elemento.get(clave, predeterminado) if elemento is not None else predeterminado


def ejecutar_nmap(
    objetivo: str,
    puertos: str | None = "1-1024",
    top_ports: int | None = None,
    detectar_versiones: bool = False,
    rapido: bool = False,
    timeout: float | None = 300.0,
    min_rate: int | None = None,
    max_retries: int | None = None,
    no_ping: bool = False,
    tipo_escaneo: str = "default",
    detectar_so: bool = False,
    verbose: bool = False,
) -> tuple[ET.Element, list[str], str]:
    """Ejecuta Nmap y devuelve (xml_root, comando, advertencia).

    Si Nmap sale con código != 0 pero dejó XML parseable (p. ej. host
    inalcanzable), se devuelven los resultados parciales y el detalle
    de stderr como advertencia en lugar de fallar en seco.
    """
    comando = ["nmap", "-oX", "-", "--reason"]
    if top_ports is not None:
        comando += ["--top-ports", str(top_ports)]
    else:
        comando += ["-p", puertos or "1-1024"]
    if detectar_versiones:
        comando.append("-sV")
    if rapido:
        comando.append("-T4")
    if no_ping:
        comando.append("-Pn")
    if tipo_escaneo == "connect":
        comando.append("-sT")
    elif tipo_escaneo == "syn":
        comando.append("-sS")
    elif tipo_escaneo == "udp":
        comando.append("-sU")
    if detectar_so:
        comando.append("-O")
    if min_rate is not None:
        comando += ["--min-rate", str(min_rate)]
    if max_retries is not None:
        comando += ["--max-retries", str(max_retries)]
    if verbose:
        comando.append("-v")
    comando.append(objetivo)

    tiempo_limite = None if timeout is None or timeout <= 0 else timeout
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=tiempo_limite,
        )
    except FileNotFoundError as error:
        raise RuntimeError(
            "Nmap no está instalado o no se encuentra en PATH."
        ) from error
    except OSError as error:
        raise RuntimeError(f"No se pudo ejecutar Nmap: {error}") from error
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"Nmap excedió el tiempo límite de {tiempo_limite} s. "
            "Reintenta con --timeout mayor, --top-ports o --rapido."
        ) from error

    salida_xml = (resultado.stdout or "").strip()
    error_txt = (resultado.stderr or "").strip()

    if not salida_xml or "<nmaprun" not in salida_xml:
        detalle = error_txt or (
            f"Nmap terminó con código {resultado.returncode} sin salida XML."
        )
        raise RuntimeError(detalle)

    try:
        raiz = ET.fromstring(resultado.stdout)
    except ET.ParseError as error:
        raise RuntimeError("Nmap no devolvió un resultado XML válido.") from error

    advertencia = ""
    if resultado.returncode != 0:
        advertencia = error_txt or (
            f"Nmap terminó con código {resultado.returncode}; "
            "los resultados pueden estar parciales."
        )
    return raiz, comando, advertencia


def parsear_resultado(xml: ET.Element) -> dict:
    """Convierte el XML de Nmap en un dict serializable compartido por txt/json/csv."""
    version_nmap = xml.get("version", "")
    linea_args = obtener_atributo(xml.find("scaninfo"), "type", "")
    nodo_fin = xml.find("runstats/finished")
    segundos = obtener_atributo(nodo_fin, "elapsed", "")
    resumen = obtener_atributo(nodo_fin, "summary", "")

    hosts: list[dict] = []
    for host in xml.findall("host"):
        estado_nodo = host.find("status")
        direccion = obtener_atributo(host.find("address"), "addr", "")
        nombre = obtener_atributo(host.find("./hostnames/hostname"), "name")
        estado = obtener_atributo(estado_nodo, "state", "desconocido")
        motivo_host = obtener_atributo(estado_nodo, "reason", "")
        sistema = obtener_atributo(host.find("./os/osmatch"), "name", "")

        puertos: list[dict] = []
        conteo: dict[str, int] = {}
        for puerto in host.findall("./ports/port"):
            estado_puerto = obtener_atributo(puerto.find("state"), "state", "desconocido")
            conteo[estado_puerto] = conteo.get(estado_puerto, 0) + 1
            servicio = puerto.find("service")
            puertos.append(
                {
                    "puerto": obtener_atributo(puerto, "portid"),
                    "protocolo": obtener_atributo(puerto, "protocol"),
                    "estado": estado_puerto,
                    "motivo": obtener_atributo(puerto.find("state"), "reason"),
                    "servicio": obtener_atributo(servicio, "name", "desconocido"),
                    "producto": obtener_atributo(servicio, "product"),
                    "version": obtener_atributo(servicio, "version"),
                }
            )
        hosts.append(
            {
                "direccion": direccion,
                "estado": estado,
                "motivo_host": motivo_host,
                "nombre": nombre,
                "sistema": sistema,
                "puertos": puertos,
                "conteo_estados": conteo,
            }
        )

    return {
        "version_nmap": version_nmap,
        "tipo_escaneo_xml": linea_args,
        "segundos": segundos,
        "resumen": resumen,
        "hosts": hosts,
    }


def construir_reporte(
    xml: ET.Element,
    comando: list[str],
    objetivo: str,
    fecha: datetime | None = None,
    advertencia: str = "",
) -> str:
    datos = parsear_resultado(xml)
    hosts = datos["hosts"]
    hosts_activos = [h for h in hosts if h["estado"] == "up"]
    momento = fecha or datetime.now().astimezone()
    lineas = [
        "=" * 72,
        "REPORTE DE ESCANEO DE PUERTOS",
        "=" * 72,
        f"Fecha y hora: {momento.strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"Objetivo: {objetivo}",
        f"Comando: {' '.join(comando)}",
        f"Versión de Nmap: {datos['version_nmap'] or 'desconocida'}",
        f"Duración del escaneo: {datos['segundos'] or '?'} s",
        f"Equipos detectados: {len(hosts)}",
        f"Equipos activos: {len(hosts_activos)}",
        "",
        "NOTA: Ejecuta escaneos únicamente sobre sistemas propios o con autorización.",
        "",
    ]
    if advertencia:
        lineas.append(f"ADVERTENCIA: {advertencia}")
        lineas.append("")

    if not hosts:
        lineas.append("No se encontraron equipos en la respuesta de Nmap.")

    for indice, host in enumerate(hosts, start=1):
        abiertos = [p for p in host["puertos"] if p["estado"] == "open"]
        otros = {k: v for k, v in host["conteo_estados"].items() if k != "open"}
        lineas.extend(
            [
                "-" * 72,
                f"EQUIPO {indice}: {host['direccion'] or objetivo}",
                f"Estado: {host['estado']}"
                + (f" (motivo: {host['motivo_host']})" if host["motivo_host"] else ""),
                f"Nombre: {host['nombre'] or 'no identificado'}",
            ]
        )
        if host["sistema"]:
            lineas.append(f"Sistema estimado: {host['sistema']}")
        lineas.append(f"Puertos abiertos: {len(abiertos)}")
        if otros:
            detalle_otros = ", ".join(f"{estado}: {n}" for estado, n in sorted(otros.items()))
            lineas.append(f"Otros estados: {detalle_otros}")

        if abiertos:
            lineas.append("")
            lineas.append("Puerto   Protocolo   Servicio              Producto/versión          Motivo")
            lineas.append("-" * 72)
            for abierto in abiertos:
                detalle = " ".join(
                    parte
                    for parte in (abierto["producto"], abierto["version"])
                    if parte
                )
                lineas.append(
                    f"{abierto['puerto']:<8} {abierto['protocolo']:<11} "
                    f"{abierto['servicio']:<21} {detalle or '-':<25} "
                    f"{abierto['motivo'] or '-'}"
                )
        else:
            lineas.append("No se encontraron puertos abiertos en el rango indicado.")

    lineas.extend(["", "=" * 72, "Fin del reporte", "=" * 72, ""])
    return "\n".join(lineas)


def construir_json(
    xml: ET.Element,
    comando: list[str],
    objetivo: str,
    fecha: datetime | None = None,
    advertencia: str = "",
) -> str:
    datos = parsear_resultado(xml)
    momento = fecha or datetime.now().astimezone()
    documento = {
        "fecha": momento.isoformat(),
        "objetivo": objetivo,
        "comando": comando,
        "version_nmap": datos["version_nmap"],
        "duracion_s": datos["segundos"],
        "advertencia": advertencia,
        "equipos_detectados": len(datos["hosts"]),
        "hosts": datos["hosts"],
    }
    return json.dumps(documento, indent=2, ensure_ascii=False) + "\n"


def construir_csv(xml: ET.Element) -> str:
    datos = parsear_resultado(xml)
    buffer = io.StringIO()
    escritor = csv.writer(buffer)
    escritor.writerow(
        [
            "host",
            "hostname",
            "host_estado",
            "puerto",
            "protocolo",
            "estado_puerto",
            "motivo",
            "servicio",
            "producto",
            "version",
        ]
    )
    for host in datos["hosts"]:
        if not host["puertos"]:
            escritor.writerow([host["direccion"], host["nombre"], host["estado"], "", "", "", "", "", "", ""])
        for puerto in host["puertos"]:
            escritor.writerow(
                [
                    host["direccion"],
                    host["nombre"],
                    host["estado"],
                    puerto["puerto"],
                    puerto["protocolo"],
                    puerto["estado"],
                    puerto["motivo"],
                    puerto["servicio"],
                    puerto["producto"],
                    puerto["version"],
                ]
            )
    return buffer.getvalue()


def guardar_reporte(salida: Path, contenido: str) -> None:
    try:
        salida.parent.mkdir(parents=True, exist_ok=True)
        salida.write_text(contenido, encoding="utf-8")
    except OSError as error:
        raise OSError(f"No se pudo escribir el reporte en '{salida}': {error}") from error


def resolver_formato(formato: str | None, salida: Path) -> str:
    if formato is not None:
        return formato
    sufijo = salida.suffix.lower()
    if sufijo == ".json":
        return "json"
    if sufijo == ".csv":
        return "csv"
    return "txt"


def main() -> int:
    parser = crear_parser()
    argumentos = parser.parse_args()

    if verificar_dependencias() is None:
        parser.error(
            "Nmap no está instalado o no se encuentra en PATH. "
            "Instálalo con el gestor de paquetes de tu sistema."
        )
    if not validar_objetivo(argumentos.objetivo):
        parser.error("Objetivo inválido: usa una IP, CIDR, rango o nombre DNS.")
    if argumentos.top_ports is not None and not 1 <= argumentos.top_ports <= 65535:
        parser.error("--top-ports debe estar entre 1 y 65535.")
    puertos = argumentos.puertos
    if argumentos.top_ports is None:
        puertos = puertos or "1-1024"
        if not validar_puertos(puertos):
            parser.error(
                "Formato de puertos inválido. Usa valores como 22,80,443, 1-1024, "
                "T:22,U:53 o p-."
            )
    if argumentos.timeout is not None and argumentos.timeout < 0:
        parser.error("--timeout debe ser >= 0 (0 = sin límite).")
    if argumentos.min_rate is not None and argumentos.min_rate <= 0:
        parser.error("--min-rate debe ser > 0.")
    if argumentos.max_retries is not None and argumentos.max_retries < 0:
        parser.error("--max-retries debe ser >= 0.")

    formato = resolver_formato(
        argumentos.formato, argumentos.salida or Path("reporte.txt")
    )
    salida = argumentos.salida or nombre_reporte(argumentos.objetivo, formato)

    if argumentos.verbose:
        print(f"Objetivo: {argumentos.objetivo} | formato: {formato} | salida: {salida}")

    try:
        xml, comando, advertencia = ejecutar_nmap(
            argumentos.objetivo,
            puertos,
            argumentos.top_ports,
            argumentos.detectar_versiones,
            argumentos.rapido,
            None if argumentos.timeout == 0 else argumentos.timeout,
            argumentos.min_rate,
            argumentos.max_retries,
            argumentos.no_ping,
            argumentos.tipo,
            argumentos.detectar_so,
            argumentos.verbose,
        )
        if argumentos.verbose:
            print(f"Ejecutando: {' '.join(comando)}")
        if formato == "json":
            contenido = construir_json(xml, comando, argumentos.objetivo, advertencia=advertencia)
        elif formato == "csv":
            contenido = construir_csv(xml)
            if advertencia:
                print(f"Advertencia: {advertencia}", file=sys.stderr)
        else:
            contenido = construir_reporte(xml, comando, argumentos.objetivo, advertencia=advertencia)
        guardar_reporte(salida, contenido)
    except KeyboardInterrupt:
        print("\nEscaneo cancelado por el usuario.", file=sys.stderr)
        return 130
    except (OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"Escaneo terminado. Reporte guardado en: {salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
