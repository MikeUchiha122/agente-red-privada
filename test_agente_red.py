#!/usr/bin/env python3
"""
Tests para Agente de Seguridad de Red v3.0 (NMAP) - Cobertura mejorada
"""

import unittest
import sys
import os
import sqlite3
import tempfile
import shutil
import unittest.mock as _mock
from unittest.mock import patch, MagicMock, call

import logging as _logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ── Importar detector_deauth manejando el PermissionError de /var/log ──
# Usamos NullHandler (handler real) para evitar que el MagicMock envenene
# el atributo `level` del logger raíz y rompa imports posteriores.
_DETECTOR_DISPONIBLE = False
with _mock.patch('logging.FileHandler',
                 side_effect=lambda *a, **kw: _logging.NullHandler()):
    try:
        import detector_deauth
        _DETECTOR_DISPONIBLE = True
    except Exception:
        pass


# ════════════════════════════════════════════════════════════════
# GRUPO 1 — Tests de validación e identificación
# ════════════════════════════════════════════════════════════════

class TestNMAPImport(unittest.TestCase):
    """Verifica que NMAP esté disponible"""

    def test_importar_nmap(self):
        try:
            import nmap
        except ImportError:
            self.skipTest("NMAP no instalado")


class TestValidadores(unittest.TestCase):
    """Tests para _validar_ip"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    def test_validar_ip_valida(self):
        self.assertTrue(self.agente._validar_ip("192.168.1.1"))
        self.assertTrue(self.agente._validar_ip("10.0.0.1"))
        self.assertTrue(self.agente._validar_ip("8.8.8.8"))

    def test_validar_ip_invalida(self):
        self.assertFalse(self.agente._validar_ip("256.1.1.1"))
        self.assertFalse(self.agente._validar_ip("abc"))
        self.assertFalse(self.agente._validar_ip("192.168.1"))

    def test_validar_ip_casos_borde(self):
        """IPs límite y formatos atípicos"""
        self.assertTrue(self.agente._validar_ip("0.0.0.0"))
        self.assertTrue(self.agente._validar_ip("255.255.255.255"))
        self.assertFalse(self.agente._validar_ip(""))
        self.assertFalse(self.agente._validar_ip("192.168.1.1.1"))


class TestIdentificacion(unittest.TestCase):
    """Tests para identificar_dispositivo"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    def test_identificar_apple(self):
        resultado = self.agente.identificar_dispositivo("68:A4:0E:AA:BB:CC")
        self.assertIn("Apple", resultado["marca"])

    def test_identificar_router(self):
        resultado = self.agente.identificar_dispositivo("00:1A:8A:AA:BB:CC")
        self.assertEqual(resultado["categoria"], "router")

    def test_identificar_vacio(self):
        resultado = self.agente.identificar_dispositivo("")
        self.assertEqual(resultado["tipo"], "Desconocido")


class TestDeteccionAmenazas(unittest.TestCase):
    """Tests para detectar_amenazas"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    def test_detectar_telnet(self):
        resultado = self.agente.detectar_amenazas([23])
        self.assertTrue(len(resultado["encontradas"]) > 0)

    def test_detectar_rdp(self):
        resultado = self.agente.detectar_amenazas([3389])
        self.assertTrue(len(resultado["encontradas"]) > 0)

    def test_nivel_alto(self):
        resultado = self.agente.detectar_amenazas([23, 3389, 445])
        self.assertEqual(resultado["nivel"], "alto")

    def test_puertos_seguros(self):
        resultado = self.agente.detectar_amenazas([8000, 9000])
        self.assertEqual(resultado["nivel"], "bajo")


class TestCalculoRed(unittest.TestCase):
    """Tests para calcular_red, incluyendo casos borde"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    def test_calcular_red_24(self):
        ips = self.agente.calcular_red("192.168.1.1", 24)
        self.assertEqual(len(ips), 254)

    def test_calcular_red_32(self):
        """Una /32 solo tiene 1 host (la propia dirección)"""
        ips = self.agente.calcular_red("192.168.1.1", 32)
        self.assertEqual(len(ips), 1)

    def test_calcular_red_16(self):
        ips = self.agente.calcular_red("10.0.0.1", 16)
        self.assertEqual(len(ips), 65534)

    def test_calcular_red_ip_invalida(self):
        ips = self.agente.calcular_red("not.an.ip", 24)
        self.assertEqual(ips, [])


class TestInforme(unittest.TestCase):
    """Tests para generar_informe"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()
        self.disp_base = {
            "ip": "192.168.1.1",
            "mac": "",
            "estado": "up",
            "sistema": "Linux",
            "puertos": [],
            "servicios": {},
            "dispositivo": {"tipo": "PC", "marca": "Test", "categoria": "computadora"},
            "amenazas": {"encontradas": [], "nivel": "bajo", "emoji": "OK"},
            "fecha": "2024-01-01",
        }

    def test_generar_informe_contiene_ip(self):
        informe = self.agente.generar_informe(self.disp_base)
        self.assertIn("192.168.1.1", informe)

    def test_informe_nivel_alto(self):
        disp = dict(self.disp_base)
        disp["amenazas"] = {
            "encontradas": [{"tipo": "Telnet", "descripcion": "Inseguro", "nivel": "alto",
                             "simbolo": "[TELNET]", "puertos": [23]}],
            "nivel": "alto", "emoji": "[PELIGRO]",
        }
        informe = self.agente.generar_informe(disp)
        self.assertIn("PELIGRO", informe)

    def test_informe_marca_gateway(self):
        disp = dict(self.disp_base)
        disp["es_gateway"] = True
        informe = self.agente.generar_informe(disp)
        self.assertIn("PUERTA DE ENLACE", informe)


class TestAnalisisInformes(unittest.TestCase):
    """Tests para _analizar_mac, _analizar_puertos, _analizar_amenazas, _dar_recomendaciones"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    def test_analizar_mac_vacia(self):
        resultado = self.agente._analizar_mac("", "Unknown")
        self.assertIn("Sin MAC visible", resultado)

    def test_analizar_mac_unknown(self):
        resultado = self.agente._analizar_mac("AA:BB:CC:DD:EE:FF", "Unknown")
        self.assertIn("FABRICANTE NO IDENTIFICADO", resultado)
        self.assertIn("AA:BB:CC", resultado)

    def test_analizar_mac_detectado(self):
        resultado = self.agente._analizar_mac("68:A4:0E:AA:BB:CC", "Apple")
        self.assertIn("Apple", resultado)

    def test_analizar_puertos_vacio(self):
        resultado = self.agente._analizar_puertos([], {})
        self.assertIn("Sin puertos abiertos", resultado)

    def test_analizar_puertos_telnet(self):
        resultado = self.agente._analizar_puertos([23], {23: {"name": "telnet"}})
        self.assertIn("23", resultado)
        self.assertIn("Telnet", resultado)

    def test_analizar_puertos_ssh(self):
        resultado = self.agente._analizar_puertos([22], {})
        self.assertIn("22", resultado)
        self.assertIn("SSH", resultado)

    def test_analizar_amenazas_vacio(self):
        resultado = self.agente._analizar_amenazas({"encontradas": [], "nivel": "bajo"})
        self.assertIn("Sin amenazas", resultado)

    def test_analizar_amenazas_telnet(self):
        resultado = self.agente._analizar_amenazas({
            "encontradas": [{"tipo": "Telnet", "descripcion": "Inseguro",
                             "nivel": "alto", "simbolo": "[TELNET]", "puertos": [23]}],
            "nivel": "alto",
        })
        self.assertIn("Telnet", resultado)
        self.assertIn("ALTO", resultado)

    def test_dar_recomendaciones_vacio(self):
        disp = {
            "ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF", "puertos": [],
            "dispositivo": {"marca": "Test", "categoria": "computadora"},
            "amenazas": {"encontradas": []},
        }
        resultado = self.agente._dar_recomendaciones(disp)
        self.assertIsInstance(resultado, str)

    def test_dar_recomendaciones_router(self):
        disp = {
            "ip": "192.168.1.1", "mac": "AA:BB:CC:DD:EE:FF", "puertos": [],
            "dispositivo": {"marca": "TP-Link", "categoria": "router"},
            "amenazas": {"encontradas": []},
        }
        resultado = self.agente._dar_recomendaciones(disp)
        self.assertIn("ROUTER", resultado)

    def test_dar_recomendaciones_telnet(self):
        disp = {
            "ip": "192.168.1.100", "mac": "AA:BB:CC:DD:EE:FF", "puertos": [23],
            "dispositivo": {"marca": "Test", "categoria": "computadora"},
            "amenazas": {"encontradas": []},
        }
        resultado = self.agente._dar_recomendaciones(disp)
        self.assertIn("Telnet", resultado)

    def test_dar_recomendaciones_minero(self):
        disp = {
            "ip": "192.168.1.100", "mac": "AA:BB:CC:DD:EE:FF", "puertos": [8888],
            "dispositivo": {"marca": "Test", "categoria": "computadora"},
            "amenazas": {"encontradas": []},
        }
        resultado = self.agente._dar_recomendaciones(disp)
        self.assertIn("mineria", resultado.lower())


# ════════════════════════════════════════════════════════════════
# GRUPO 2 — Alertas: canal no configurado
# ════════════════════════════════════════════════════════════════

class TestAlertasNoConfiguradas(unittest.TestCase):
    """Las alertas devuelven False cuando las variables de entorno no están seteadas"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()
        # Asegurar que las variables NO estén presentes
        self._env_backup = {}
        for var in ('TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID',
                    'DISCORD_WEBHOOK_URL',
                    'SMTP_SERVER', 'SMTP_USER', 'SMTP_PASSWORD', 'FROM_EMAIL', 'TO_EMAIL'):
            self._env_backup[var] = os.environ.pop(var, None)

    def tearDown(self):
        for var, val in self._env_backup.items():
            if val is not None:
                os.environ[var] = val

    def test_telegram_no_configurado(self):
        self.assertFalse(self.agente.enviar_alerta_telegram("Test"))

    def test_discord_no_configurado(self):
        self.assertFalse(self.agente.enviar_alerta_discord("Test"))

    def test_email_no_configurado(self):
        self.assertFalse(self.agente.enviar_alerta_email("Asunto", "Cuerpo"))

    def test_alerta_multiple_no_lanza_excepcion(self):
        """enviar_alerta_multiple no debe propagar excepciones"""
        try:
            self.agente.enviar_alerta_multiple("Test mensaje")
        except Exception as exc:
            self.fail(f"enviar_alerta_multiple lanzó excepción: {exc}")


# ════════════════════════════════════════════════════════════════
# GRUPO 3 — Alertas: happy path con HTTP mockeado
# ════════════════════════════════════════════════════════════════

class TestAlertasHappyPath(unittest.TestCase):
    """Alertas con respuestas HTTP simuladas"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    @patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN': 'token123', 'TELEGRAM_CHAT_ID': 'chat456'})
    @patch('agente_red.requests.post')
    def test_telegram_exito(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)

        resultado = self.agente.enviar_alerta_telegram("Alerta de prueba")

        self.assertTrue(resultado)
        mock_post.assert_called_once()
        _, kwargs = mock_post.call_args
        self.assertIn("token123", mock_post.call_args[0][0])
        self.assertEqual(kwargs['json']['chat_id'], 'chat456')
        self.assertEqual(kwargs['json']['text'], 'Alerta de prueba')

    @patch.dict(os.environ, {'TELEGRAM_BOT_TOKEN': 'token123', 'TELEGRAM_CHAT_ID': 'chat456'})
    @patch('agente_red.requests.post')
    def test_telegram_error_401(self, mock_post):
        mock_post.return_value = MagicMock(status_code=401)
        self.assertFalse(self.agente.enviar_alerta_telegram("Test"))

    @patch.dict(os.environ, {'DISCORD_WEBHOOK_URL': 'https://discord.com/api/webhooks/test'})
    @patch('agente_red.requests.post')
    def test_discord_exito_200(self, mock_post):
        mock_post.return_value = MagicMock(status_code=200)

        resultado = self.agente.enviar_alerta_discord("Alerta Discord")

        self.assertTrue(resultado)
        _, kwargs = mock_post.call_args
        self.assertEqual(kwargs['json']['content'], 'Alerta Discord')

    @patch.dict(os.environ, {'DISCORD_WEBHOOK_URL': 'https://discord.com/api/webhooks/test'})
    @patch('agente_red.requests.post')
    def test_discord_exito_204(self, mock_post):
        """Discord puede devolver 204 No Content en éxito"""
        mock_post.return_value = MagicMock(status_code=204)
        self.assertTrue(self.agente.enviar_alerta_discord("Test 204"))

    @patch.dict(os.environ, {
        'SMTP_SERVER': 'smtp.test.com', 'SMTP_PORT': '587',
        'SMTP_USER': 'user@test.com', 'SMTP_PASSWORD': 'pass123',
        'FROM_EMAIL': 'from@test.com', 'TO_EMAIL': 'to@test.com',
    })
    @patch('smtplib.SMTP')
    def test_email_exito(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value = mock_server

        resultado = self.agente.enviar_alerta_email("Asunto Test", "Cuerpo del email")

        self.assertTrue(resultado)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with('user@test.com', 'pass123')
        mock_server.sendmail.assert_called_once()
        mock_server.quit.assert_called_once()

    @patch.dict(os.environ, {
        'TELEGRAM_BOT_TOKEN': 'tok', 'TELEGRAM_CHAT_ID': 'cid',
        'DISCORD_WEBHOOK_URL': 'https://discord.test',
    })
    @patch('agente_red.requests.post')
    def test_alerta_multiple_llama_todos_canales(self, mock_post):
        """enviar_alerta_multiple debe invocar Telegram y Discord"""
        mock_post.return_value = MagicMock(status_code=200)

        self.agente.enviar_alerta_multiple("Test múltiple")

        self.assertGreaterEqual(mock_post.call_count, 2)


# ════════════════════════════════════════════════════════════════
# GRUPO 4 — Funciones de escaneo con mocks de subprocess / socket
# ════════════════════════════════════════════════════════════════

class TestEscanearPingRapido(unittest.TestCase):
    """escanear_ping_rapido con subprocess mockeado"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    @patch('agente_red.subprocess.run')
    def test_ping_responde(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        self.assertTrue(self.agente.escanear_ping_rapido("192.168.1.1"))

    @patch('agente_red.subprocess.run')
    def test_ping_no_responde(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        self.assertFalse(self.agente.escanear_ping_rapido("192.168.1.200"))

    @patch('agente_red.subprocess.run', side_effect=OSError("timeout"))
    def test_ping_error_os(self, _mock_run):
        self.assertFalse(self.agente.escanear_ping_rapido("192.168.1.1"))

    @patch('agente_red.subprocess.run', side_effect=Exception("fallo"))
    def test_ping_excepcion_generica_se_propaga(self, _mock_run):
        """Exception genérica (fuera del catch) se propaga al llamador"""
        with self.assertRaises(Exception):
            self.agente.escanear_ping_rapido("192.168.1.1")


class TestEscanearPuertoRapido(unittest.TestCase):
    """escanear_puerto_rapido con socket mockeado"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    @patch('agente_red.socket.socket')
    def test_puerto_abierto(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value = mock_sock

        self.assertTrue(self.agente.escanear_puerto_rapido("192.168.1.1", 22))

    @patch('agente_red.socket.socket')
    def test_puerto_cerrado(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.connect_ex.return_value = 111  # ECONNREFUSED
        mock_socket_class.return_value = mock_sock

        self.assertFalse(self.agente.escanear_puerto_rapido("192.168.1.1", 9999))

    @patch('agente_red.socket.socket', side_effect=OSError("socket error"))
    def test_puerto_error_socket(self, _mock):
        self.assertFalse(self.agente.escanear_puerto_rapido("192.168.1.1", 22))


# ════════════════════════════════════════════════════════════════
# GRUPO 5 — Detección de red: obtener_ip_local y obtener_gateway
# ════════════════════════════════════════════════════════════════

class TestObtenerIPLocal(unittest.TestCase):
    """obtener_ip_local con socket mockeado"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    @patch('agente_red.socket.socket')
    def test_ip_local_normal(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)
        mock_sock.getsockname.return_value = ("192.168.1.50", 0)
        mock_socket_class.return_value = mock_sock

        ip = self.agente.obtener_ip_local()
        self.assertEqual(ip, "192.168.1.50")

    @patch('agente_red.socket.socket', side_effect=OSError("sin red"))
    def test_ip_local_sin_red_devuelve_loopback(self, _mock):
        """Sin conexión de red, devuelve 127.0.0.1"""
        ip = self.agente.obtener_ip_local()
        self.assertEqual(ip, "127.0.0.1")


class TestObtenerGateway(unittest.TestCase):
    """obtener_gateway con subprocess mockeado (Linux y Windows)"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()

    @patch('agente_red.subprocess.run')
    def test_gateway_linux(self, mock_run):
        self.agente.sistema = "Linux"
        mock_run.return_value = MagicMock(
            stdout="default via 192.168.1.1 dev wlan0 proto dhcp\n"
        )
        self.assertEqual(self.agente.obtener_gateway(), "192.168.1.1")

    @patch('agente_red.subprocess.run')
    def test_gateway_windows(self, mock_run):
        self.agente.sistema = "Windows"
        mock_run.return_value = MagicMock(
            stdout="     0.0.0.0    0.0.0.0  192.168.1.1  192.168.1.100     25\n"
        )
        self.assertEqual(self.agente.obtener_gateway(), "192.168.1.1")

    @patch('agente_red.subprocess.run', side_effect=OSError("comando no encontrado"))
    def test_gateway_error_devuelve_vacio(self, _mock):
        self.agente.sistema = "Linux"
        self.assertEqual(self.agente.obtener_gateway(), "")

    @patch('agente_red.subprocess.run')
    def test_gateway_linux_sin_ruta_por_defecto(self, mock_run):
        """Sin ruta por defecto, devuelve cadena vacía"""
        self.agente.sistema = "Linux"
        mock_run.return_value = MagicMock(stdout="")
        self.assertEqual(self.agente.obtener_gateway(), "")


# ════════════════════════════════════════════════════════════════
# GRUPO 6 — Base de datos con assertions sobre datos reales
# ════════════════════════════════════════════════════════════════

class TestBaseDeDatos(unittest.TestCase):
    """Operaciones de BD verificando que los datos se persistan correctamente"""

    def setUp(self):
        from agente_red import AgenteSeguridadRed
        self.agente = AgenteSeguridadRed()
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmpdir, "test_agente.db")

        # Redirigir sqlite3.connect al archivo temporal
        _orig = sqlite3.connect
        def _connect_to_temp(path, **kwargs):
            return _orig(self.db_path, **kwargs)

        self.patcher = patch('sqlite3.connect', side_effect=_connect_to_temp)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_inicializar_crea_tablas(self):
        resultado = self.agente.inicializar_base_datos()

        self.assertTrue(resultado)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tablas = {row[0] for row in cursor.fetchall()}
        conn.close()

        self.assertIn("escaneos", tablas)
        self.assertIn("alertas", tablas)
        self.assertIn("dispositivos", tablas)

    def test_guardar_escaneo_inserta_fila(self):
        self.agente.inicializar_base_datos()
        self.agente.guardar_escaneo_db("red_local", 5, 2, "Detalles de prueba")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT tipo, dispositivos, amenazas, detalles FROM escaneos")
        filas = cursor.fetchall()
        conn.close()

        self.assertEqual(len(filas), 1)
        tipo, dispositivos, amenazas, detalles = filas[0]
        self.assertEqual(tipo, "red_local")
        self.assertEqual(dispositivos, 5)
        self.assertEqual(amenazas, 2)
        self.assertEqual(detalles, "Detalles de prueba")

    def test_guardar_alerta_inserta_fila(self):
        self.agente.inicializar_base_datos()
        self.agente.guardar_alerta_db("DEAUTH", "Ataque detectado", "whatsapp")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT tipo, mensaje, canal FROM alertas")
        filas = cursor.fetchall()
        conn.close()

        self.assertEqual(len(filas), 1)
        tipo, mensaje, canal = filas[0]
        self.assertEqual(tipo, "DEAUTH")
        self.assertEqual(mensaje, "Ataque detectado")
        self.assertEqual(canal, "whatsapp")

    def test_guardar_multiples_escaneos(self):
        self.agente.inicializar_base_datos()
        self.agente.guardar_escaneo_db("red_local", 3, 0, "Primero")
        self.agente.guardar_escaneo_db("ip_especifica", 1, 1, "Segundo")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM escaneos")
        count = cursor.fetchone()[0]
        conn.close()

        self.assertEqual(count, 2)

    def test_guardar_escaneo_fallo_bd_no_propaga_excepcion(self):
        """Si la BD falla, guardar_escaneo_db no debe propagar la excepción"""
        self.patcher.stop()
        with patch('sqlite3.connect', side_effect=sqlite3.OperationalError("sin permisos")):
            try:
                self.agente.guardar_escaneo_db("test", 1, 0, "")
            except Exception as exc:
                self.fail(f"guardar_escaneo_db propagó excepción: {exc}")
        self.patcher.start()


# ════════════════════════════════════════════════════════════════
# GRUPO 7 — consultar_mac_vendor (HTTP mockeado)
# ════════════════════════════════════════════════════════════════

class TestConsultarMacVendor(unittest.TestCase):
    """Tests para la función módulo-nivel consultar_mac_vendor"""

    def setUp(self):
        import agente_red
        agente_red._MAC_CACHE.clear()

    @patch('agente_red.requests.get')
    def test_vendor_encontrado(self, mock_get):
        from agente_red import consultar_mac_vendor
        mock_get.return_value = MagicMock(status_code=200, text="Apple, Inc.")

        self.assertEqual(consultar_mac_vendor("68:A4:0E:AA:BB:CC"), "Apple, Inc.")

    @patch('agente_red.requests.get')
    def test_vendor_404(self, mock_get):
        from agente_red import consultar_mac_vendor
        mock_get.return_value = MagicMock(status_code=404)

        self.assertEqual(consultar_mac_vendor("AA:BB:CC:DD:EE:FF"), "Unknown")

    @patch('agente_red.requests.get', side_effect=Exception("timeout"))
    def test_vendor_timeout(self, _mock):
        from agente_red import consultar_mac_vendor
        self.assertEqual(consultar_mac_vendor("AA:BB:CC:DD:EE:FF"), "Unknown")

    def test_vendor_mac_vacia(self):
        from agente_red import consultar_mac_vendor
        self.assertEqual(consultar_mac_vendor(""), "Unknown")

    @patch('agente_red.requests.get')
    def test_vendor_usa_cache(self, mock_get):
        """Dos llamadas con el mismo OUI deben hacer solo una petición HTTP"""
        from agente_red import consultar_mac_vendor
        mock_get.return_value = MagicMock(status_code=200, text="TestVendor")

        consultar_mac_vendor("FF:EE:DD:11:22:33")
        consultar_mac_vendor("FF:EE:DD:44:55:66")  # Mismo OUI

        mock_get.assert_called_once()


# ════════════════════════════════════════════════════════════════
# GRUPO 8 — detector_deauth.py (lógica pura y mocks)
# ════════════════════════════════════════════════════════════════

@unittest.skipUnless(_DETECTOR_DISPONIBLE, "detector_deauth no disponible en este entorno")
class TestValidarTelefono(unittest.TestCase):
    """Tests para _validar_telefono (función pura)"""

    def setUp(self):
        from detector_deauth import _validar_telefono
        self._validar = _validar_telefono

    def test_telefono_valido_mexico(self):
        self.assertTrue(self._validar("+521234567890"))

    def test_telefono_valido_espana(self):
        self.assertTrue(self._validar("+34612345678"))

    def test_telefono_valido_usa(self):
        self.assertTrue(self._validar("+12025551234"))

    def test_telefono_sin_plus(self):
        self.assertFalse(self._validar("521234567890"))

    def test_telefono_vacio(self):
        self.assertFalse(self._validar(""))

    def test_telefono_none(self):
        self.assertFalse(self._validar(None))

    def test_telefono_muy_corto(self):
        """Menos de 10 caracteres incluido el '+'"""
        self.assertFalse(self._validar("+12345"))

    def test_telefono_exactamente_10_chars(self):
        self.assertTrue(self._validar("+123456789"))


@unittest.skipUnless(_DETECTOR_DISPONIBLE, "detector_deauth no disponible en este entorno")
class TestDetectorDeauthLogica(unittest.TestCase):
    """Tests de lógica pura en DetectorDeauth"""

    def setUp(self):
        from detector_deauth import DetectorDeauth
        self.detector = DetectorDeauth()

    def test_analizar_patron_ataque_devuelve_lista(self):
        resultado = self.detector.analizar_patron_ataque({"AA:BB:CC:DD:EE:FF"}, 10)
        self.assertIsInstance(resultado, list)

    def test_analizar_patron_ataque_intensivo(self):
        """Más de 50 paquetes → 'ataque intensivo'"""
        resultado = self.detector.analizar_patron_ataque({"AA:BB:CC:DD:EE:FF"}, 60)
        self.assertTrue(any("intensivo" in r.lower() for r in resultado))

    def test_analizar_patron_ataque_ddos(self):
        """Más de 100 paquetes → DDoS"""
        resultado = self.detector.analizar_patron_ataque({"AA:BB:CC:DD:EE:FF"}, 150)
        self.assertTrue(any("DDoS" in r for r in resultado))

    def test_analizar_patron_ataque_dirigido(self):
        """Una sola MAC no-broadcast → ataque dirigido"""
        resultado = self.detector.analizar_patron_ataque({"AA:BB:CC:DD:EE:FF"}, 10)
        self.assertTrue(any("solo dispositivo" in r.lower() for r in resultado))

    def test_analizar_patron_ataque_masivo(self):
        """Más de 5 MACs → desautenticación masiva"""
        macs = {f"AA:BB:CC:DD:EE:{i:02X}" for i in range(6)}
        resultado = self.detector.analizar_patron_ataque(macs, 10)
        self.assertTrue(any("masiva" in r.lower() for r in resultado))

    def test_analizar_patron_excluye_broadcast(self):
        """La MAC broadcast no cuenta como dispositivo víctima"""
        macs = {"FF:FF:FF:FF:FF:FF"}
        resultado = self.detector.analizar_patron_ataque(macs, 10)
        self.assertFalse(any("solo dispositivo" in r.lower() for r in resultado))

    def test_analizar_patron_conjunto_vacio(self):
        resultado = self.detector.analizar_patron_ataque(set(), 0)
        self.assertIsInstance(resultado, list)

    def test_stop_cambia_flag_running(self):
        self.assertTrue(self.detector.running)
        self.detector.stop()
        self.assertFalse(self.detector.running)


@unittest.skipUnless(_DETECTOR_DISPONIBLE, "detector_deauth no disponible en este entorno")
class TestDetectorDeauthFabricante(unittest.TestCase):
    """Tests para obtener_fabricante"""

    def setUp(self):
        from detector_deauth import DetectorDeauth
        self.detector = DetectorDeauth()

    def test_fabricante_apple(self):
        self.assertEqual(self.detector.obtener_fabricante("68:A4:00:11:22:33"), "Apple")

    def test_fabricante_raspberry_pi(self):
        self.assertEqual(self.detector.obtener_fabricante("B8:27:EB:11:22:33"), "Raspberry Pi")

    def test_fabricante_tp_link(self):
        self.assertEqual(self.detector.obtener_fabricante("14:CC:20:11:22:33"), "TP-Link")

    def test_fabricante_mac_vacia(self):
        self.assertEqual(self.detector.obtener_fabricante(""), "Unknown")

    @patch('detector_deauth._consultar_mac_vendor', return_value="Unknown")
    def test_fabricante_desconocido(self, _mock):
        # Una MAC que no está en FABRICANTES_OUI ni en la API
        resultado = self.detector.obtener_fabricante("02:00:00:11:22:33")
        self.assertEqual(resultado, "Unknown")


@unittest.skipUnless(_DETECTOR_DISPONIBLE, "detector_deauth no disponible en este entorno")
class TestDetectorDeauthInicializar(unittest.TestCase):
    """Tests para inicializar_scapy"""

    def setUp(self):
        from detector_deauth import DetectorDeauth
        self.detector = DetectorDeauth()

    def test_inicializar_scapy_con_mock_devuelve_true(self):
        """Con Scapy mockeado, debe devolver True y rellenar self.scanner"""
        mock_scapy = MagicMock()
        with patch.dict('sys.modules', {'scapy': mock_scapy, 'scapy.all': mock_scapy}):
            resultado = self.detector.inicializar_scapy()

        self.assertTrue(resultado)
        self.assertIsNotNone(self.detector.scanner)

    def test_inicializar_scapy_devuelve_bool(self):
        """inicializar_scapy siempre devuelve bool (True si instalado, False si no)"""
        resultado = self.detector.inicializar_scapy()
        self.assertIsInstance(resultado, bool)


@unittest.skipUnless(_DETECTOR_DISPONIBLE, "detector_deauth no disponible en este entorno")
class TestDetectorDeauthWhatsApp(unittest.TestCase):
    """Tests para enviar_alerta_whatsapp"""

    def setUp(self):
        from detector_deauth import DetectorDeauth
        self.detector = DetectorDeauth()

    @patch.dict(os.environ, {'WHATSAPP_API_KEY': 'test_api_key'})
    @patch('detector_deauth.requests.get')
    def test_callmebot_exito(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)

        resultado = self.detector.enviar_alerta_whatsapp("Test alerta")

        self.assertTrue(resultado)
        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        self.assertIn('phone', kwargs['params'])
        self.assertIn('text', kwargs['params'])
        self.assertIn('apikey', kwargs['params'])

    def test_sin_api_key_ni_twilio_devuelve_false(self):
        """Sin credenciales configuradas, cae al fallback y devuelve False"""
        env_limpio = {k: v for k, v in os.environ.items()
                      if k not in ('WHATSAPP_API_KEY', 'TWILIO_ACCOUNT_SID',
                                   'TWILIO_AUTH_TOKEN', 'TWILIO_WHATSAPP_FROM')}
        with patch.dict(os.environ, env_limpio, clear=True):
            with patch('detector_deauth.requests.get') as mock_get:
                resultado = self.detector.enviar_alerta_whatsapp("Test")
                mock_get.assert_not_called()

        self.assertFalse(resultado)


# ════════════════════════════════════════════════════════════════
# Runner
# ════════════════════════════════════════════════════════════════

def ejecutar_tests():
    """Ejecuta todos los tests"""
    print("""
============================================================
      AGENTE DE SEGURIDAD RED v3.0 (NMAP) - TESTS
============================================================
    """)

    clases = [
        TestNMAPImport,
        TestValidadores,
        TestIdentificacion,
        TestDeteccionAmenazas,
        TestCalculoRed,
        TestInforme,
        TestAnalisisInformes,
        TestAlertasNoConfiguradas,
        TestAlertasHappyPath,
        TestEscanearPingRapido,
        TestEscanearPuertoRapido,
        TestObtenerIPLocal,
        TestObtenerGateway,
        TestBaseDeDatos,
        TestConsultarMacVendor,
        TestValidarTelefono,
        TestDetectorDeauthLogica,
        TestDetectorDeauthFabricante,
        TestDetectorDeauthInicializar,
        TestDetectorDeauthWhatsApp,
    ]

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for clase in clases:
        suite.addTests(loader.loadTestsFromTestCase(clase))

    runner = unittest.TextTestRunner(verbosity=2)
    resultado = runner.run(suite)

    print(f"""
============================================================
Tests ejecutados : {resultado.testsRun}
Fallos           : {len(resultado.failures)}
Errores          : {len(resultado.errors)}
Omitidos         : {len(resultado.skipped)}
============================================================""")

    if resultado.wasSuccessful():
        print(">>> TODOS LOS TESTS PASARON <<<")
    else:
        print(">>> ALGUNOS TESTS FALLARON <<<")

    return resultado.wasSuccessful()


if __name__ == "__main__":
    success = ejecutar_tests()
    sys.exit(0 if success else 1)
