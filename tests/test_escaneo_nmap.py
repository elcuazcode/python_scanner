"""Tests para escaneo_nmap (sin ejecutar Nmap real)."""

from datetime import datetime, timezone
import xml.etree.ElementTree as ET

from escaneo_nmap import (
    construir_csv,
    construir_json,
    construir_reporte,
    nombre_reporte,
    resolver_formato,
    validar_objetivo,
    validar_puertos,
)

XML_EJEMPLO = """<?xml version="1.0"?>
<nmaprun version="7.94">
  <scaninfo type="syn"/>
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="localhost" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
        <service name="http"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.x"/></os>
  </host>
  <runstats><finished elapsed="1.23" summary="done"/></runstats>
</nmaprun>
"""


def _xml():
    return ET.fromstring(XML_EJEMPLO)


def test_validar_puertos_basicos():
    assert validar_puertos("22")
    assert validar_puertos("22,80,443")
    assert validar_puertos("1-1024")
    assert validar_puertos("p-")
    assert validar_puertos("T:22,U:53")
    assert not validar_puertos("")
    assert not validar_puertos("0")
    assert not validar_puertos("99999")
    assert not validar_puertos("100-10")
    assert not validar_puertos("22,,80")


def test_validar_objetivo():
    assert validar_objetivo("127.0.0.1")
    assert validar_objetivo("192.168.1.0/24")
    assert validar_objetivo("example.com")
    assert not validar_objetivo("")
    assert not validar_objetivo("  ")
    assert not validar_objetivo("a; rm -rf /")
    assert not validar_objetivo("host$(whoami)")


def test_nombre_reporte_y_formato():
    assert nombre_reporte("127.0.0.1").name == "reporte_nmap_127.0.0.1.txt"
    assert nombre_reporte("192.168.1.0/24", "json").suffix == ".json"
    assert nombre_reporte("a/b", "csv").name.startswith("reporte_nmap_a_b")
    from pathlib import Path

    assert resolver_formato(None, Path("x.json")) == "json"
    assert resolver_formato(None, Path("x.csv")) == "csv"
    assert resolver_formato(None, Path("x.txt")) == "txt"
    assert resolver_formato("csv", Path("x.txt")) == "csv"


def test_reporte_txt_incluye_estados_y_stats():
    fecha = datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc)
    reporte = construir_reporte(_xml(), ["nmap", "127.0.0.1"], "127.0.0.1", fecha=fecha)
    assert "Puertos abiertos: 1" in reporte
    assert "Otros estados: closed: 1" in reporte
    assert "Versión de Nmap: 7.94" in reporte
    assert "Duración del escaneo: 1.23 s" in reporte
    assert "22" in reporte and "ssh" in reporte


def test_json_y_csv():
    import json

    texto = construir_json(_xml(), ["nmap"], "127.0.0.1")
    datos = json.loads(texto)
    assert datos["objetivo"] == "127.0.0.1"
    assert datos["hosts"][0]["direccion"] == "127.0.0.1"

    csv_texto = construir_csv(_xml())
    assert "estado_puerto" in csv_texto.splitlines()[0]
    assert "22" in csv_texto and "open" in csv_texto
