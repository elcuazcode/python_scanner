"""Tests de parsear_resultado y de los constructores de reporte."""

import csv
import io
import json
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

import pytest

from escaneo_nmap import (
    construir_csv,
    construir_json,
    construir_reporte,
    obtener_atributo,
    parsear_resultado,
)

XML_MULTIHOST = """<?xml version="1.0"?>
<nmaprun version="7.95">
  <scaninfo type="connect"/>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="router" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="filtered" reason="no-response"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open|filtered" reason="no-response"/>
        <service name="domain"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
  </host>
  <runstats><finished elapsed="4.56" summary="2 IP addresses (1 host up)"/></runstats>
</nmaprun>
"""

XML_VACIO = '<?xml version="1.0"?><nmaprun version="7.95"></nmaprun>'

FECHA = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def xml_multihost():
    return ET.fromstring(XML_MULTIHOST)


@pytest.fixture
def xml_vacio():
    return ET.fromstring(XML_VACIO)


# --- obtener_atributo ---------------------------------------------------------


def test_obtener_atributo_con_elemento_y_sin_elemento():
    elemento = ET.fromstring('<a x="1"/>')
    assert obtener_atributo(elemento, "x") == "1"
    assert obtener_atributo(elemento, "y", "def") == "def"
    assert obtener_atributo(None, "x", "def") == "def"
    assert obtener_atributo(None, "x") == ""


# --- parsear_resultado --------------------------------------------------------


def test_parsear_metadatos(xml_multihost):
    datos = parsear_resultado(xml_multihost)
    assert datos["version_nmap"] == "7.95"
    assert datos["tipo_escaneo_xml"] == "connect"
    assert datos["segundos"] == "4.56"
    assert datos["resumen"] == "2 IP addresses (1 host up)"
    assert len(datos["hosts"]) == 2


def test_parsear_host_activo(xml_multihost):
    host = parsear_resultado(xml_multihost)["hosts"][0]
    assert host["direccion"] == "10.0.0.1"
    assert host["nombre"] == "router"
    assert host["estado"] == "up"
    assert host["motivo_host"] == "syn-ack"
    assert host["sistema"] == ""
    assert host["conteo_estados"] == {"open": 2, "filtered": 1, "open|filtered": 1}
    ssh = host["puertos"][0]
    assert ssh == {
        "puerto": "22",
        "protocolo": "tcp",
        "estado": "open",
        "motivo": "syn-ack",
        "servicio": "ssh",
        "producto": "OpenSSH",
        "version": "9.6",
    }


def test_parsear_puerto_sin_servicio_usa_desconocido(xml_multihost):
    puertos = parsear_resultado(xml_multihost)["hosts"][0]["puertos"]
    telnet = next(p for p in puertos if p["puerto"] == "23")
    assert telnet["servicio"] == "desconocido"
    assert telnet["producto"] == ""
    assert telnet["version"] == ""


def test_parsear_host_caido_sin_puertos(xml_multihost):
    host = parsear_resultado(xml_multihost)["hosts"][1]
    assert host["estado"] == "down"
    assert host["nombre"] == ""
    assert host["puertos"] == []
    assert host["conteo_estados"] == {}


def test_parsear_xml_vacio(xml_vacio):
    datos = parsear_resultado(xml_vacio)
    assert datos["hosts"] == []
    assert datos["segundos"] == ""
    assert datos["tipo_escaneo_xml"] == ""


def test_parsear_host_sin_status():
    xml = ET.fromstring('<nmaprun><host><address addr="1.2.3.4"/></host></nmaprun>')
    host = parsear_resultado(xml)["hosts"][0]
    assert host["estado"] == "desconocido"
    assert host["direccion"] == "1.2.3.4"


# --- construir_reporte (txt) --------------------------------------------------


def test_reporte_txt_multihost(xml_multihost):
    reporte = construir_reporte(
        xml_multihost, ["nmap", "-p", "1-100", "10.0.0.0/30"], "10.0.0.0/30", fecha=FECHA
    )
    assert "Fecha y hora: 2026-09-25 12:00:00 UTC" in reporte
    assert "Objetivo: 10.0.0.0/30" in reporte
    assert "Comando: nmap -p 1-100 10.0.0.0/30" in reporte
    assert "Equipos detectados: 2" in reporte
    assert "Equipos activos: 1" in reporte
    assert "EQUIPO 1: 10.0.0.1" in reporte
    assert "EQUIPO 2: 10.0.0.2" in reporte
    assert "Nombre: router" in reporte
    assert "Puertos abiertos: 2" in reporte
    assert "Otros estados: filtered: 1, open|filtered: 1" in reporte
    assert "OpenSSH 9.6" in reporte
    assert "Estado: down (motivo: no-response)" in reporte
    assert "Nombre: no identificado" in reporte
    assert "No se encontraron puertos abiertos en el rango indicado." in reporte
    assert reporte.rstrip().endswith("=" * 72)
    assert "ADVERTENCIA" not in reporte


def test_reporte_txt_con_advertencia(xml_multihost):
    reporte = construir_reporte(
        xml_multihost, ["nmap"], "x", fecha=FECHA, advertencia="host inalcanzable"
    )
    assert "ADVERTENCIA: host inalcanzable" in reporte


def test_reporte_txt_sin_hosts(xml_vacio):
    reporte = construir_reporte(xml_vacio, ["nmap"], "10.9.9.9", fecha=FECHA)
    assert "No se encontraron equipos en la respuesta de Nmap." in reporte
    assert "Equipos detectados: 0" in reporte
    assert "Duración del escaneo: ? s" in reporte


def test_reporte_txt_incluye_sistema_operativo():
    xml = ET.fromstring(
        '<nmaprun><host><status state="up"/><address addr="1.1.1.1"/>'
        '<os><osmatch name="Linux 6.x"/></os></host></nmaprun>'
    )
    reporte = construir_reporte(xml, ["nmap"], "1.1.1.1", fecha=FECHA)
    assert "Sistema estimado: Linux 6.x" in reporte


def test_reporte_txt_usa_objetivo_si_no_hay_direccion():
    xml = ET.fromstring('<nmaprun><host><status state="up"/></host></nmaprun>')
    reporte = construir_reporte(xml, ["nmap"], "mi-host", fecha=FECHA)
    assert "EQUIPO 1: mi-host" in reporte


# --- construir_json -----------------------------------------------------------


def test_json_completo(xml_multihost):
    texto = construir_json(
        xml_multihost, ["nmap", "10.0.0.0/30"], "10.0.0.0/30", fecha=FECHA, advertencia="ojo"
    )
    assert texto.endswith("\n")
    datos = json.loads(texto)
    assert datos["fecha"] == "2026-09-25T12:00:00+00:00"
    assert datos["comando"] == ["nmap", "10.0.0.0/30"]
    assert datos["version_nmap"] == "7.95"
    assert datos["duracion_s"] == "4.56"
    assert datos["advertencia"] == "ojo"
    assert datos["equipos_detectados"] == 2
    assert [h["direccion"] for h in datos["hosts"]] == ["10.0.0.1", "10.0.0.2"]


def test_json_conserva_caracteres_no_ascii(xml_vacio):
    texto = construir_json(xml_vacio, ["nmap"], "host", fecha=FECHA, advertencia="conexión")
    assert "conexión" in texto


# --- construir_csv ------------------------------------------------------------


def test_csv_filas_y_columnas(xml_multihost):
    filas = list(csv.reader(io.StringIO(construir_csv(xml_multihost))))
    cabecera, *datos = filas
    assert cabecera == [
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
    # 4 puertos del primer host + 1 fila vacía del host caído
    assert len(datos) == 5
    assert datos[0] == ["10.0.0.1", "router", "up", "22", "tcp", "open", "syn-ack", "ssh", "OpenSSH", "9.6"]
    assert datos[-1] == ["10.0.0.2", "", "down", "", "", "", "", "", "", ""]
    assert all(len(fila) == len(cabecera) for fila in datos)


def test_csv_sin_hosts_solo_cabecera(xml_vacio):
    filas = list(csv.reader(io.StringIO(construir_csv(xml_vacio))))
    assert len(filas) == 1
