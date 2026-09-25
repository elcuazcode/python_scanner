#!/usr/bin/env python3
"""Escáner de puertos con Nmap y reporte de texto en español."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path
import xml.etree.ElementTree as ET


def crear_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Ejecuta un escaneo de puertos con Nmap y genera un reporte en español."
    )
    parser.add_argument(
        "objetivo",
        help="Dirección IP, nombre DNS o rango autorizado que se desea escanear.",
    )
    parser.add_argument(
        "-p",
        "--puertos",
        default="1-1024",
        help="Puertos o rango para escanear (por defecto: 1-1024). Ejemplo: 22,80,443",
    )
    parser.add_argument(
        "-o",
        "--salida",
        type=Path,
        default=None,
        help="Ruta del reporte .txt (por defecto: reporte_nmap_<objetivo>.txt).",
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
    return parser


def nombre_reporte(objetivo: str) -> Path:
    nombre = "".join(
        caracter if caracter.isalnum() or caracter in "._-" else "_"
        for caracter in objetivo
    )
    return Path(f"reporte_nmap_{nombre or 'objetivo'}.txt")


def validar_puertos(puertos: str) -> bool:
    """Valida la sintaxis básica de puertos aceptada por Nmap."""
    if not puertos.strip():
        return False
    for elemento in puertos.split(","):
        parte = elemento.strip()
        extremos = parte.split("-")
        if len(extremos) > 2 or any(
            not extremo.isdigit() or not 1 <= int(extremo) <= 65535
            for extremo in extremos
        ):
            return False
        if len(extremos) == 2 and int(extremos[0]) > int(extremos[1]):
            return False
    return True


def ejecutar_nmap(
    objetivo: str, puertos: str, detectar_versiones: bool, rapido: bool
) -> tuple[ET.Element, list[str]]:
    comando = ["nmap", "-oX", "-", "-p", puertos]
    if detectar_versiones:
        comando.append("-sV")
    if rapido:
        comando.append("-T4")
    comando.append(objetivo)

    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"No se pudo ejecutar Nmap: {error}") from error

    if resultado.returncode != 0:
        detalle = resultado.stderr.strip() or "Nmap terminó con un error desconocido."
        raise RuntimeError(detalle)

    try:
        return ET.fromstring(resultado.stdout), comando
    except ET.ParseError as error:
        raise RuntimeError("Nmap no devolvió un resultado XML válido.") from error


def obtener_atributo(elemento: ET.Element | None, clave: str, predeterminado: str = "") -> str:
    return elemento.get(clave, predeterminado) if elemento is not None else predeterminado


def construir_reporte(
    xml: ET.Element, comando: list[str], objetivo: str
) -> str:
    hosts = xml.findall("host")
    hosts_activos = [
        host for host in hosts if obtener_atributo(host.find("status"), "state") == "up"
    ]
    lineas = [
        "=" * 72,
        "REPORTE DE ESCANEO DE PUERTOS",
        "=" * 72,
        f"Fecha y hora: {datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"Objetivo: {objetivo}",
        f"Comando: {' '.join(comando)}",
        f"Equipos detectados: {len(hosts)}",
        f"Equipos activos: {len(hosts_activos)}",
        "",
        "NOTA: Ejecuta escaneos únicamente sobre sistemas propios o con autorización.",
        "",
    ]

    if not hosts:
        lineas.append("No se encontraron equipos en la respuesta de Nmap.")

    for indice, host in enumerate(hosts, start=1):
        direccion = obtener_atributo(host.find("address"), "addr", objetivo)
        estado = obtener_atributo(host.find("status"), "state", "desconocido")
        nombre = obtener_atributo(host.find("./hostnames/hostname"), "name")
        puertos_abiertos: list[dict[str, str]] = []

        for puerto in host.findall("./ports/port"):
            estado_puerto = obtener_atributo(puerto.find("state"), "state")
            if estado_puerto != "open":
                continue
            servicio = puerto.find("service")
            puertos_abiertos.append(
                {
                    "puerto": obtener_atributo(puerto, "portid"),
                    "protocolo": obtener_atributo(puerto, "protocol"),
                    "servicio": obtener_atributo(servicio, "name", "desconocido"),
                    "producto": obtener_atributo(servicio, "product"),
                    "version": obtener_atributo(servicio, "version"),
                }
            )

        lineas.extend(
            [
                "-" * 72,
                f"EQUIPO {indice}: {direccion}",
                f"Estado: {estado}",
                f"Nombre: {nombre or 'no identificado'}",
                f"Puertos abiertos: {len(puertos_abiertos)}",
            ]
        )
        if puertos_abiertos:
            lineas.append("")
            lineas.append("Puerto   Protocolo   Servicio              Producto/versión")
            lineas.append("-" * 72)
            for abierto in puertos_abiertos:
                detalle = " ".join(
                    parte
                    for parte in (abierto["producto"], abierto["version"])
                    if parte
                )
                lineas.append(
                    f"{abierto['puerto']:<8} {abierto['protocolo']:<11} "
                    f"{abierto['servicio']:<21} {detalle or '-'}"
                )
        else:
            lineas.append("No se encontraron puertos abiertos en el rango indicado.")

    lineas.extend(["", "=" * 72, "Fin del reporte", "=" * 72, ""])
    return "\n".join(lineas)


def main() -> int:
    parser = crear_parser()
    argumentos = parser.parse_args()

    if shutil.which("nmap") is None:
        parser.error(
            "Nmap no está instalado o no se encuentra en PATH. "
            "Instálalo con el gestor de paquetes de tu sistema."
        )
    if not validar_puertos(argumentos.puertos):
        parser.error(
            "Formato de puertos inválido. Usa valores como 22,80,443 o 1-1024."
        )

    salida = argumentos.salida or nombre_reporte(argumentos.objetivo)
    try:
        xml, comando = ejecutar_nmap(
            argumentos.objetivo,
            argumentos.puertos,
            argumentos.detectar_versiones,
            argumentos.rapido,
        )
        reporte = construir_reporte(xml, comando, argumentos.objetivo)
        salida.parent.mkdir(parents=True, exist_ok=True)
        salida.write_text(reporte, encoding="utf-8")
    except (OSError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1

    print(f"Escaneo terminado. Reporte guardado en: {salida}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
