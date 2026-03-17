#!/usr/bin/env python3
"""
Agente de Monitoreo de Seguridad WiFi
Detecta ataques Deauth (Flipper Zero) y envía alertas por WhatsApp
Designed for Raspberry Pi with Kali Linux

Autor: MikeUchiha122
"""

import os
import sys
import time
import json
import signal
import logging
import requests
from datetime import datetime
from typing import Set, Dict, List

_MAC_VENDOR_CACHE = {}

# Configuracion
TELEFONO_ALERTA = "+521234567890"  # Tu numero
INTERFAZ = "wlan0"  # Interfaz WiFi en modo monitor
UMBRAL_DEAUTH = 5  # Paquetes Deauth para considerar ataque
TIEMPO_ENTRE_ALERTAS = 300  # 5 minutos entre alertas
LOG_FILE = "/var/log/deteccion_deauth.log"

# Base de datos de OUI (fabricantes conocidos)
FABRICANTES_OUI = {
    "00:C0": "Apple",
    "00:1A": "Apple",
    "00:25": "Apple",
    "00:26": "Apple",
    "A4:83": "Apple",
    "F0:18": "Apple",
    "3C:06": "Apple",
    "68:A4": "Apple",
    "DC:A6": "Raspberry Pi",
    "B8:27": "Raspberry Pi",
    "E4:5F": "Raspberry Pi",
    "00:50": "VMware",
    "00:0C": "VMware",
    "08:00": "VirtualBox",
    "00:15": "Hyper-V",
    "00:1A": "Cisco",
    "00:21": "Cisco",
    "00:17": "Cisco/Linksys",
    "00:40": "D-Link",
    "00:1B": "Intel",
    "00:1F": "Intel/Dell",
    "00:1C": "HP",
    "00:25": "HP",
    "00:26": "Tenda",
    "00:1A": "Netgear",
    "00:22": "Netgear",
    "28:10": "Xiaomi",
    "34:80": "Xiaomi",
    "64:09": "Xiaomi",
    "00:1D": "TP-Link",
    "14:CC": "TP-Link",
    "50:C7": "TP-Link",
    "EC:17": "TP-Link",
    "C0:25": "ASUS",
    "30:5A": "ASUS",
    "2C:4D": "ASUS",
    "C8:3A": "Mercusys",
    "30:B5": "Mercusys",
    "AC:DE": "Google",
    "F4:F5": "Google/Chromecast",
    "64:16": "Amazon",
    "68:54": "Amazon/Fire TV",
    "00:FC": "Amazon/Kindle",
    "00:17": "Philips Hue",
    "00:1A": "AXIS Cameras",
    "00:40": "D-Link",
    "F0:EF": "Samsung",
    "9C:02": "Samsung",
    "00:1E": "Samsung",
    "00:24": "Nintendo",
    "28:76": "Nintendo Switch",
    "00:27": "Nintendo",
    "08:6D": "Samsung Galaxy",
    "00:02": "Lafon",
    "00:12": "Linksys",
    "00:14": "Linksys",
    "00:0E": "Linksys/Cisco",
    "00:23": "Netgear",
    "00:26": "Netgear",
    "20:EE": "Netgear",
    "C0:FF": "D-Link",
    "1C:7E": "D-Link",
    "5C:D9": "D-Link",
    "00:18": "D-Link",
    "00:50": "D-Link",
    "9C:D6": "Xiaomi",
    "74:23": "Xiaomi",
    "78:02": "Xiaomi",
    "34:80": "Xiaomi",
    "00:9E": "Xiaomi",
}

# Tipos de ataques conocidos
TIPOS_ATAQUE = [
    "Flipper Zero",
    "ESP32/ESP8266 Deauther",
    "WiFi Deauther (Python)",
    "Aircrack-ng",
    "Wifite",
    "MDK3",
    "Reaver",
    "Fern WiFi Cracker",
    "Pixie Dust",
    "Hashcat",
    "Cowpatty",
    "Hostapd-wpe",
    "Mana Toolkit",
    "Bettercap",
    "WiFi Pumpkin",
    "Evil Twin AP",
    "Router attack",
    "Unknown attacker"
]

def _consultar_mac_vendor(mac: str) -> str:
    """Consulta macvendors.com para obtener el fabricante de una MAC"""
    if not mac:
        logger.debug("MAC vacía, retornando Unknown")
        return "Unknown"
    
    mac_limpia = mac.upper().replace(':', '').replace('-', '')
    if len(mac_limpia) < 6:
        logger.debug(f"MAC inválida (muy corta): {mac}")
        return "Unknown"
    
    oui = mac_limpia[:6]
    
    if oui in _MAC_VENDOR_CACHE:
        logger.debug(f"Cache hit para OUI: {oui}")
        return _MAC_VENDOR_CACHE[oui]
    
    try:
        url = f"https://api.macvendors.com/{oui}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            vendor = response.text.strip()
            _MAC_VENDOR_CACHE[oui] = vendor
            logger.info(f"Vendor encontrado para {oui}: {vendor}")
            return vendor
        elif response.status_code == 404:
            _MAC_VENDOR_CACHE[oui] = "Unknown"
            logger.debug(f"Vendor no encontrado para OUI: {oui}")
            return "Unknown"
    except requests.RequestException as e:
        logger.warning(f"Error al consultar macvendors.com: {e}")
    except Exception as e:
        logger.error(f"Error inesperado en consulta MAC: {e}")
    
    return "Unknown"

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Validar numero de telefono
def _validar_telefono(telefono: str) -> bool:
    """Valida que el numero de telefono tenga formato válido"""
    return bool(telefono and telefono.startswith('+') and len(telefono) >= 10)

class DetectorDeauth:
    def __init__(self):
        self.scanner = None
        self.deauth_detectados: Set[str] = set()
        self.ultima_alerta = 0
        self.contador_paquetes = 0
        self.running = True
        
    def inicializar_scapy(self) -> bool:
        """Inicializa scapy para capturar paquetes"""
        try:
            from scapy.all import Dot11Deauth, Dot11, sniff, RadioTap
            self.scanner = {
                'Dot11Deauth': Dot11Deauth,
                'Dot11': Dot11,
                'RadioTap': RadioTap,
                'sniff': sniff
            }
            logger.info("Scapy inicializado correctamente")
            return True
        except ImportError:
            logger.error("Scapy no esta instalado. Ejecuta: pip install scapy")
            return False
        except Exception as e:
            logger.error(f"Error al inicializar scapy: {e}")
            return False
    
    def enviar_alerta_whatsapp(self, mensaje: str) -> bool:
        """Envía alerta por WhatsApp"""
        import requests
        
        # Metodo 1: CallMeBot (gratis con limitaciones)
        try:
            # Obtener API key de variable de entorno o usar por defecto
            api_key = os.getenv('WHATSAPP_API_KEY', '')
            if api_key:
                url = f"https://api.callmebot.com/whatsapp.php"
                params = {
                    'phone': TELEFONO_ALERTA.replace('+', ''),
                    'text': mensaje.replace('\n', ' '),
                    'apikey': api_key
                }
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    logger.info("Alerta enviada por WhatsApp (CallMeBot)")
                    return True
        except Exception as e:
            logger.warning(f"CallMeBot error: {e}")
        
        # Metodo 2: Twilio (requiere configuracion)
        try:
            from twilio.rest import Client
            account_sid = os.getenv('TWILIO_ACCOUNT_SID')
            auth_token = os.getenv('TWILIO_AUTH_TOKEN')
            from_number = os.getenv('TWILIO_WHATSAPP_FROM')
            
            if account_sid and auth_token and from_number:
                client = Client(account_sid, auth_token)
                message = client.messages.create(
                    from_=from_number,
                    body=mensaje,
                    to=TELEFONO_ALERTA
                )
                logger.info(f"Alerta enviada por Twilio: {message.sid}")
                return True
        except Exception as e:
            logger.warning(f"Twilio error: {e}")
        
        # Metodo 3: Imprimir alerta (fallback)
        logger.critical(f"ALERTA DEAUTH - NO SE PUDO ENVIAR POR WHATSAPP:\n{mensaje}")
        return False
    
    def obtener_fabricante(self, mac: str) -> str:
        """Obtiene el fabricante de una MAC"""
        if not mac:
            return "Unknown"
        
        oui = mac.replace(':', '').upper()[:6]
        
        for prefijo, fabricante in FABRICANTES_OUI.items():
            prefijo_limpio = prefijo.replace(':', '').upper()
            if oui.startswith(prefijo_limpio):
                return fabricante
        
        vendor = _consultar_mac_vendor(mac)
        if vendor != "Unknown":
            return vendor
        
        return "Unknown"
    
    def analizar_patron_ataque(self, macs: Set[str], cantidad: int) -> List[str]:
        """Analiza el patron del ataque para determinar el tipo"""
        ataques_detectados = []
        
        # Analizar por cantidad de paquetes
        if cantidad > 50:
            ataques_detectados.append("Ataque intensivo (posible herramienta automatica)")
        
        if cantidad > 100:
            ataques_detectados.append("DDoS WiFi detectado")
        
        # Analizar MACs únicas
        macs_sin_broadcast = [m for m in macs if m and m != "FF:FF:FF:FF:FF:FF"]
        
        if len(macs_sin_broadcast) == 1:
            ataques_detectados.append("Ataque dirigido a un solo dispositivo")
        elif len(macs_sin_broadcast) > 5:
            ataques_detectados.append("Ataque de desautenticacion masiva")
        
        # Verificar si hay MACs conocidas de dispositivos comunes
        fabricantes_encontrados = set()
        for mac in macs_sin_broadcast:
            fab = self.obtener_fabricante(mac)
            if fab != "Unknown":
                fabricantes_encontrados.add(fab)
        
        if fabricantes_encontrados:
            ataques_detectados.append(f"Dispositivos afectados: {', '.join(fabricantes_encontrados)}")
        
        return ataques_detectados
    
    def procesar_paquete(self, pkt):
        """Procesa cada paquete capturado"""
        try:
            if not self.scanner:
                return
            
            Dot11Deauth = self.scanner['Dot11Deauth']
            Dot11 = self.scanner['Dot11']
            
            if pkt.haslayer(Dot11Deauth):
                self.contador_paquetes += 1
                
                # Obtener MAC del dispositivo que envia el Deauth
                mac_origen = "Unknown"
                mac_destino = "Unknown"
                
                try:
                    mac_origen = pkt[Dot11].addr2  # Quien envia
                    mac_destino = pkt[Dot11].addr1  # A quien va dirigido
                except:
                    pass
                
                self.deauth_detectados.add(mac_origen)
                
                # Obtener fabricante
                fabricante = self.obtener_fabricante(mac_origen)
                
                logger.warning(f"Paquete Deauth! De: {mac_origen} ({fabricante}) -> Para: {mac_destino}")
                
                # Verificar si debemos enviar alerta
                tiempo_actual = time.time()
                if (len(self.deauth_detectados) >= UMBRAL_DEAUTH and 
                    tiempo_actual - self.ultima_alerta > TIEMPO_ENTRE_ALERTAS):
                    
                    self.enviar_alerta(mac_origen)
                    self.ultima_alerta = tiempo_actual
                    
        except Exception as e:
            logger.error(f"Error procesando paquete: {e}")
    
    def enviar_alerta(self, mac_sospechoso: str = None):
        """Envía alerta de ataque"""
        # Analizar patron del ataque
        ataques = self.analizar_patron_ataque(self.deauth_detectados, self.contador_paquetes)
        
        fabricante = self.obtener_fabricante(mac_sospechoso) if mac_sospechoso else "Unknown"
        
        mensaje = f"⚠️ ALERTA DE SEGURIDAD WiFi ⚠️\n\n"
        mensaje += f"*** ATAQUE DEAUTH DETECTADO ***\n\n"
        mensaje += f"Red: {self.obtener_ip_local()}\n"
        mensaje += f"Interfaz: {INTERFAZ}\n"
        mensaje += f"Paquetes Deauth: {self.contador_paquetes}\n\n"
        
        mensaje += f"*** DISPOSITIVOS SOSPECHOSOS ***\n"
        mensaje += f"Total MACs detectadas: {len(self.deauth_detectados)}\n"
        
        if mac_sospechoso:
            mensaje += f"Atacante: {mac_sospechoso}\n"
            mensaje += f"Fabricante: {fabricante}\n"
        
        mensaje += f"\n*** ANALISIS ***\n"
        for ataque in ataques:
            mensaje += f"- {ataque}\n"
        
        mensaje += f"\n*** POSIBLES HERRAMIENTAS ***\n"
        mensaje += "- Flipper Zero\n"
        mensaje += "- ESP32/8266 Deauther\n"
        mensaje += "- Aircrack-ng/MDK3\n"
        mensaje += "- WiFi Deauther (Python)\n"
        mensaje += "- Cualquier dispositivo con capacidad de injection\n\n"
        
        mensaje += f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        mensaje += f"\n*** ACCION RECOMENDADA ***\n"
        mensaje += "1. Desconectar dispositivos importantes\n"
        mensaje += "2. Cambiar contrasena WiFi\n"
        mensaje += "3. Habilitar filtrado MAC en router\n"
        mensaje += "4. Contactar proveedor de internet"
        
        self.enviar_alerta_whatsapp(mensaje)
        
        # Guardar en log
        with open('/tmp/alertas_deauth.json', 'a') as f:
            json.dump({
                'fecha': datetime.now().isoformat(),
                'macs': list(self.deauth_detectados),
                'total_paquetes': self.contador_paquetes,
                'analisis': ataques
            }, f)
            f.write('\n')
    
    def obtener_ip_local(self) -> str:
        """Obtiene la IP local"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "Unknown"
    
    def verificar_modo_monitor(self) -> bool:
        """Verifica si la interfaz esta en modo monitor"""
        try:
            with open(f'/sys/class/net/{INTERFAZ}/type', 'r') as f:
                tipo = f.read().strip()
                # 803 = monitor mode, 1 = managed
                if tipo == '803':
                    logger.info(f"Interfaz {INTERFAZ} esta en modo MONITOR")
                    return True
                else:
                    logger.warning(f"Interfaz {INTERFAZ} NO esta en modo monitor")
                    logger.warning("Ejecuta: airmon-ng start wlan0")
                    return False
        except FileNotFoundError:
            logger.error(f"Interfaz {INTERFAZ} no encontrada")
            return False
    
    def iniciar_monitoreo(self):
        """Inicia el monitoreo continuo"""
        logger.info("=" * 60)
        logger.info("INICIANDO DETECTOR DEAUTH")
        logger.info(f"Interfaz: {INTERFAZ}")
        logger.info(f"Telefono: {TELEFONO_ALERTA}")
        logger.info(f"Umbral: {UMBRAL_DEAUTH} paquetes")
        logger.info("=" * 60)
        
        # Verificar modo monitor
        if not self.verificar_modo_monitor():
            logger.error("La interfaz debe estar en modo monitor!")
            logger.info("Para activar modo monitor:")
            logger.info("  1. airmon-ng start wlan0")
            logger.info("  2. Cambia INTERFAZ a 'wlan0mon'")
            return
        
        # Inicializar scapy
        if not self.inicializar_scapy():
            logger.error("No se pudo inicializar scapy")
            return
        
        # Enviar mensaje de inicio
        self.enviar_alerta_whatsapp(
            f"🔒 MONITOREO INICIADO\n"
            f"Red: {self.obtener_ip_local()}\n"
            f"Interfaz: {INTERFAZ}\n"
            f"Detecto ataques Deauth automaticamente"
        )
        
        logger.info("Monitoreando red... Presiona Ctrl+C para detener")
        
        try:
            # Capturar paquetes
            self.scanner['sniff'](
                iface=INTERFAZ,
                prn=self.procesar_paquete,
                store=0,
                stop_filter=lambda x: not self.running
            )
        except KeyboardInterrupt:
            logger.info("Monitoreo detenido por el usuario")
        except Exception as e:
            logger.error(f"Error durante el monitoreo: {e}")
        
        # Cleanup
        logger.info("Guardando datos...")
        self.running = False
        
        # Resumen final
        logger.info("=" * 60)
        logger.info("RESUMEN FINAL")
        logger.info(f"Paquetes Deauth: {self.contador_paquetes}")
        logger.info(f"MACs detectados: {len(self.deauth_detectados)}")
        logger.info("=" * 60)
    
    def stop(self):
        """Detiene el monitoreo"""
        self.running = False
        logger.info("Deteniendo monitoreo...")


def mostrar_ayuda():
    """Muestra la ayuda"""
    print("""
╔════════════════════════════════════════════════════════════╗
║   DETECTOR DEAUTH - MONITOREO CONTINUO WiFi             ║
║   Para Raspberry Pi con Kali Linux                      ║
╚════════════════════════════════════════════════════════════╝

INSTALACION:
  1. Instalar dependencias:
     sudo apt update
     sudo apt install python3-pip aircrack-ng
     pip3 install scapy requests twilio

  2. Activar modo monitor:
     sudo airmon-ng start wlan0
     (la interfaz cambiara a wlan0mon)

  3. Ejecutar el script:
     sudo python3 detector_deauth.py

CONFIGURAR ALERTAS:
  - Variable de entorno para WhatsApp:
    export WHATSAPP_API_KEY=tu_api_key
    
  - O configurar Twilio en variables de entorno:
    export TWILIO_ACCOUNT_SID=tu_sid
    export TWILIO_AUTH_TOKEN=tu_token
    export TWILIO_WHATSAPP_FROM=whatsapp:+tu_numero

MONITOREO:
  - El script detectara automaticamente paquetes Deauth
  - Enviara alertas por WhatsApp cuando detecte ataques
  - Guardara un registro en /var/log/deteccion_deauth.log
  - Guardara alertas en /tmp/alertas_deauth.json

DETENER:
  - Presiona Ctrl+C

NOTA: Necesitas una tarjeta WiFi que soporte modo monitor
      y permisos de root (sudo)
""")


if __name__ == "__main__":
    # Verificar permisos
    if os.geteuid() != 0:
        print("ERROR: Este script debe ejecutarse como root (sudo)")
        print("sudo python3 detector_deauth.py")
        sys.exit(1)
    
    # Mostrar ayuda si se pide
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        mostrar_ayuda()
        sys.exit(0)
    
    # Crear detector e iniciar
    detector = DetectorDeauth()
    
    # Manejar señales
    def signal_handler(sig, frame):
        print("\n\nDeteniendo detector...")
        detector.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Iniciar monitoreo
    detector.iniciar_monitoreo()
