"""Tests de ejecutar_nmap, guardar_reporte, validaciones extra y main (Nmap simulado)."""

import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

import escaneo_nmap
from escaneo_nmap import (
    crear_parser,
    ejecutar_nmap,
    guardar_reporte,
    nombre_reporte,
    validar_objetivo,
    validar_puertos,
)

XML_OK = """<?xml version="1.0"?>
<nmaprun version="7.94">
  <host>
    <status state="up" reason="localhost-response"/>
    <address addr="127.0.0.1"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <runstats><finished elapsed="0.10"/></runstats>
</nmaprun>
"""


class FakeRun:
    """Sustituto de subprocess.run que registra el comando recibido."""

    def __init__(self, stdout=XML_OK, stderr="", returncode=0, excepcion=None):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.excepcion = excepcion
        self.comando = None
        self.kwargs = None

    def __call__(self, comando, **kwargs):
        self.comando = comando
        self.kwargs = kwargs
        if self.excepcion is not None:
            raise self.excepcion
        return SimpleNamespace(
            stdout=self.stdout, stderr=self.stderr, returncode=self.returncode
        )


@pytest.fixture
def fake_run(monkeypatch):
    falso = FakeRun()
    monkeypatch.setattr(escaneo_nmap.subprocess, "run", falso)
    return falso


# --- validaciones extra -------------------------------------------------------


@pytest.mark.parametrize(
    "puertos",
    ["-", "P-", "t:22", "u:53", " 22 , 80 ", "1-65535", "65535", "T:1-100,U:53"],
)
def test_validar_puertos_validos(puertos):
    assert validar_puertos(puertos)


@pytest.mark.parametrize(
    "puertos",
    [None, "   ", "abc", "1-2-3", "-5", "22,", "T:", "X:22", "22;ls", "65536", "0-10", "80-"],
)
def test_validar_puertos_invalidos(puertos):
    assert not validar_puertos(puertos)


@pytest.mark.parametrize(
    "objetivo",
    ["::1", "[fe80::1]", "10.0.0.1-50", "host1,host2", "sub.dominio-ejemplo.com"],
)
def test_validar_objetivo_validos(objetivo):
    assert validar_objetivo(objetivo)


@pytest.mark.parametrize(
    "objetivo",
    [None, "a" * 1025, "host|cat", "host&", "`id`", "a'b", 'a"b', "a\\b", "ñandú", "a\nb", "a*"],
)
def test_validar_objetivo_invalidos(objetivo):
    assert not validar_objetivo(objetivo)


def test_nombre_reporte_objetivo_vacio_y_formato_desconocido():
    assert nombre_reporte("").name == "reporte_nmap_objetivo.txt"
    assert nombre_reporte("x", "xml").suffix == ".txt"


# --- ejecutar_nmap: construcción del comando ----------------------------------


def test_ejecutar_nmap_comando_por_defecto(fake_run):
    raiz, comando, advertencia = ejecutar_nmap("127.0.0.1")
    assert comando == ["nmap", "-oX", "-", "--reason", "-p", "1-1024", "127.0.0.1"]
    assert fake_run.comando == comando
    assert fake_run.kwargs["timeout"] == 300.0
    assert fake_run.kwargs["check"] is False
    assert raiz.tag == "nmaprun"
    assert advertencia == ""


def test_ejecutar_nmap_puertos_none_usa_rango_por_defecto(fake_run):
    _, comando, _ = ejecutar_nmap("h", puertos=None)
    assert comando[comando.index("-p") + 1] == "1-1024"


def test_ejecutar_nmap_todas_las_opciones(fake_run):
    _, comando, _ = ejecutar_nmap(
        "10.0.0.1",
        puertos="22",
        top_ports=50,
        detectar_versiones=True,
        rapido=True,
        min_rate=500,
        max_retries=2,
        no_ping=True,
        tipo_escaneo="syn",
        detectar_so=True,
        verbose=True,
    )
    assert comando == [
        "nmap", "-oX", "-", "--reason",
        "--top-ports", "50",
        "-sV", "-T4", "-Pn", "-sS", "-O",
        "--min-rate", "500",
        "--max-retries", "2",
        "-v",
        "10.0.0.1",
    ]
    assert "-p" not in comando  # --top-ports tiene prioridad


@pytest.mark.parametrize(
    "tipo, bandera",
    [("connect", "-sT"), ("syn", "-sS"), ("udp", "-sU")],
)
def test_ejecutar_nmap_tipos_de_escaneo(fake_run, tipo, bandera):
    _, comando, _ = ejecutar_nmap("h", tipo_escaneo=tipo)
    assert bandera in comando


def test_ejecutar_nmap_tipo_default_sin_bandera(fake_run):
    _, comando, _ = ejecutar_nmap("h", tipo_escaneo="default")
    assert not {"-sT", "-sS", "-sU"} & set(comando)


@pytest.mark.parametrize("timeout", [None, 0, -1])
def test_ejecutar_nmap_sin_limite_de_tiempo(fake_run, timeout):
    ejecutar_nmap("h", timeout=timeout)
    assert fake_run.kwargs["timeout"] is None


# --- ejecutar_nmap: errores y advertencias ------------------------------------


def test_ejecutar_nmap_codigo_no_cero_con_xml_devuelve_advertencia(fake_run):
    fake_run.returncode = 1
    fake_run.stderr = "Failed to resolve"
    raiz, _, advertencia = ejecutar_nmap("h")
    assert raiz is not None
    assert advertencia == "Failed to resolve"


def test_ejecutar_nmap_codigo_no_cero_sin_stderr(fake_run):
    fake_run.returncode = 2
    _, _, advertencia = ejecutar_nmap("h")
    assert "código 2" in advertencia


def test_ejecutar_nmap_sin_xml_usa_stderr(fake_run):
    fake_run.stdout = ""
    fake_run.stderr = "You requested a scan type which requires root privileges."
    fake_run.returncode = 1
    with pytest.raises(RuntimeError, match="root privileges"):
        ejecutar_nmap("h")


def test_ejecutar_nmap_sin_xml_ni_stderr(fake_run):
    fake_run.stdout = "texto cualquiera"
    fake_run.returncode = 255
    with pytest.raises(RuntimeError, match="código 255 sin salida XML"):
        ejecutar_nmap("h")


def test_ejecutar_nmap_xml_invalido(fake_run):
    fake_run.stdout = "<nmaprun><host>"
    with pytest.raises(RuntimeError, match="XML válido"):
        ejecutar_nmap("h")


@pytest.mark.parametrize(
    "excepcion, mensaje",
    [
        (FileNotFoundError("nmap"), "no está instalado"),
        (PermissionError("denegado"), "No se pudo ejecutar Nmap"),
        (subprocess.TimeoutExpired("nmap", 5), "tiempo límite de 5 s"),
    ],
)
def test_ejecutar_nmap_excepciones(monkeypatch, excepcion, mensaje):
    monkeypatch.setattr(escaneo_nmap.subprocess, "run", FakeRun(excepcion=excepcion))
    with pytest.raises(RuntimeError, match=mensaje):
        ejecutar_nmap("h", timeout=5)


# --- guardar_reporte ----------------------------------------------------------


def test_guardar_reporte_crea_directorios(tmp_path):
    destino = tmp_path / "a" / "b" / "reporte.txt"
    guardar_reporte(destino, "contenido ñ")
    assert destino.read_text(encoding="utf-8") == "contenido ñ"


def test_guardar_reporte_error_de_escritura(tmp_path):
    destino = tmp_path / "carpeta"
    destino.mkdir()
    with pytest.raises(OSError, match="No se pudo escribir el reporte"):
        guardar_reporte(destino, "x")


# --- crear_parser -------------------------------------------------------------


def test_parser_valores_por_defecto():
    args = crear_parser().parse_args(["127.0.0.1"])
    assert args.objetivo == "127.0.0.1"
    assert args.puertos is None
    assert args.top_ports is None
    assert args.formato is None
    assert args.timeout == 300.0
    assert args.tipo == "default"
    assert not args.detectar_versiones
    assert not args.verbose


def test_parser_puertos_y_top_ports_son_excluyentes():
    with pytest.raises(SystemExit):
        crear_parser().parse_args(["h", "-p", "22", "--top-ports", "10"])


def test_parser_formato_invalido():
    with pytest.raises(SystemExit):
        crear_parser().parse_args(["h", "--formato", "xml"])


# --- main ---------------------------------------------------------------------


@pytest.fixture
def entorno_main(monkeypatch, tmp_path):
    """Simula nmap instalado y ejecuta main dentro de un directorio temporal."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(escaneo_nmap, "verificar_dependencias", lambda: "/usr/bin/nmap")
    falso = FakeRun()
    monkeypatch.setattr(escaneo_nmap.subprocess, "run", falso)

    def ejecutar(*argumentos):
        monkeypatch.setattr(sys, "argv", ["escaneo_nmap.py", *argumentos])
        return escaneo_nmap.main()

    ejecutar.run = falso
    ejecutar.dir = tmp_path
    return ejecutar


def test_main_txt_por_defecto(entorno_main, capsys):
    assert entorno_main("127.0.0.1") == 0
    reporte = entorno_main.dir / "reporte_nmap_127.0.0.1.txt"
    assert "REPORTE DE ESCANEO DE PUERTOS" in reporte.read_text(encoding="utf-8")
    assert "Reporte guardado en" in capsys.readouterr().out


def test_main_formato_inferido_json(entorno_main):
    assert entorno_main("127.0.0.1", "-o", "salida/r.json") == 0
    datos = json.loads((entorno_main.dir / "salida" / "r.json").read_text(encoding="utf-8"))
    assert datos["hosts"][0]["puertos"][0]["puerto"] == "22"


def test_main_formato_csv_explicito(entorno_main):
    assert entorno_main("127.0.0.1", "--formato", "csv") == 0
    contenido = (entorno_main.dir / "reporte_nmap_127.0.0.1.csv").read_text(encoding="utf-8")
    assert contenido.startswith("host,hostname")


def test_main_csv_muestra_advertencia_en_stderr(entorno_main, capsys):
    entorno_main.run.returncode = 1
    entorno_main.run.stderr = "aviso parcial"
    assert entorno_main("127.0.0.1", "--formato", "csv") == 0
    assert "Advertencia: aviso parcial" in capsys.readouterr().err


def test_main_pasa_opciones_a_nmap(entorno_main, capsys):
    codigo = entorno_main(
        "127.0.0.1", "--top-ports", "10", "-sV", "--rapido", "--no-ping",
        "--tipo", "connect", "--min-rate", "100", "--max-retries", "1", "--timeout", "0", "-v",
    )
    assert codigo == 0
    comando = entorno_main.run.comando
    assert comando[comando.index("--top-ports") + 1] == "10"
    for bandera in ("-sV", "-T4", "-Pn", "-sT", "-v"):
        assert bandera in comando
    assert entorno_main.run.kwargs["timeout"] is None
    salida = capsys.readouterr().out
    assert "Ejecutando: nmap" in salida
    assert "formato: txt" in salida


def test_main_error_de_nmap_devuelve_1(entorno_main, capsys):
    entorno_main.run.stdout = ""
    entorno_main.run.stderr = "fallo grave"
    entorno_main.run.returncode = 1
    assert entorno_main("127.0.0.1") == 1
    assert "Error: fallo grave" in capsys.readouterr().err


def test_main_cancelado_por_usuario(entorno_main, capsys):
    entorno_main.run.excepcion = KeyboardInterrupt()
    assert entorno_main("127.0.0.1") == 130
    assert "cancelado" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argumentos, mensaje",
    [
        (["host;ls"], "Objetivo inválido"),
        (["h", "-p", "99999"], "Formato de puertos inválido"),
        (["h", "--top-ports", "0"], "--top-ports debe estar entre"),
        (["h", "--timeout", "-1"], "--timeout debe ser >= 0"),
        (["h", "--min-rate", "0"], "--min-rate debe ser > 0"),
        (["h", "--max-retries", "-1"], "--max-retries debe ser >= 0"),
    ],
)
def test_main_validaciones(entorno_main, capsys, argumentos, mensaje):
    with pytest.raises(SystemExit) as salida:
        entorno_main(*argumentos)
    assert salida.value.code == 2
    assert mensaje in capsys.readouterr().err
    assert entorno_main.run.comando is None  # nunca se llegó a ejecutar Nmap


def test_main_sin_nmap_instalado(entorno_main, monkeypatch, capsys):
    monkeypatch.setattr(escaneo_nmap, "verificar_dependencias", lambda: None)
    with pytest.raises(SystemExit):
        entorno_main("127.0.0.1")
    assert "Nmap no está instalado" in capsys.readouterr().err


def test_verificar_dependencias_usa_which(monkeypatch):
    monkeypatch.setattr(escaneo_nmap.shutil, "which", lambda nombre: f"/opt/{nombre}")
    assert escaneo_nmap.verificar_dependencias() == "/opt/nmap"
