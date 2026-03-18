#!/usr/bin/env python3
"""
Agente de Seguridad de Red v3.0 - OPTIMIZADO
Asistente de IA para analisis de seguridad de red local

Compatible con: Windows, Linux, macOS
"""

import os
import sys
import socket
import subprocess
import platform
import json
import re
import ipaddress
import concurrent.futures
import requests
import logging
from datetime import datetime
from typing import List, Dict, Optional, Tuple

# Configurar logging - solo si es posible escribir en el directorio actual
try:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('agente_seguridad.log'),
            logging.StreamHandler()
        ]
    )
except PermissionError:
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
logger = logging.getLogger(__name__)

# Cache para evitar consultas repetidas a macvendors.com
_MAC_CACHE: Dict[str, str] = {}

# Buscar NMAP en Windows
def encontrar_nmap():
    rutas = [
        r"C:\Program Files\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
    ]
    for ruta in rutas:
        if os.path.exists(ruta):
            return os.path.dirname(ruta)
    return None

nmap_path = encontrar_nmap()
if nmap_path:
    os.environ["PATH"] = os.environ["PATH"] + os.pathsep + nmap_path

NMAP_DISPONIBLE = False
try:
    import nmap
    nm = nmap.PortScanner()
    nm.scan("127.0.0.1", "-sn", timeout=3)
    NMAP_DISPONIBLE = True
    logger.info("NMAP detectado y disponible")
except ImportError:
    logger.warning("NMAP no instalado - usando modo fallback")
except Exception as e:
    logger.warning(f"Error al inicializar NMAP: {e}")

class Colores:
    VERDE = ''
    ROJO = ''
    AMARILLO = ''
    AZUL = ''
    RESET = ''
    NEGRITA = ''

class DispositivoBaseDatos:
    MARCAS = {
        # VMs y Dispositivos Virtuales
        "00:50:56": "VMware", "00:0C:29": "VMware", "08:00:27": "VirtualBox",
        "00:15:5D": "Hyper-V", "00:03:FF": "Microsoft Virtual",
        # Raspberry Pi
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi 4", "E4:5F:01": "Raspberry Pi",
        # Apple
        "68:A4:0E": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple", "3C:06:30": "Apple",
        "DC:A6:32": "Apple", "F0:18:98": "Apple", "00:25:00": "Apple", "00:26:08": "Apple",
        # Samsung
        "00:1E:67": "Samsung", "9C:02:98": "Samsung", "00:1E:C7": "Samsung", "F0:EF:86": "Samsung",
        # Dispositivos de Red
        "00:40:8D": "D-Link", "00:1B:21": "Intel", "1C:7E:E5": "D-Link", "5C:D9:98": "D-Link",
        "00:18:E7": "Cisco", "00:21:5C": "Cisco", "00:17:88": "Philips Hue",
        "AC:DE:48": "Google", "64:16:66": "Amazon Echo", "00:1F:F3": "Dell",
        "00:1C:23": "HP", "00:26:C6": "Tenda Router", "00:1A:8A": "Netgear",
        "28:10:7B": "Xiaomi", "34:80:B3": "Xiaomi", "74:23:44": "Xiaomi",
        "00:1D:0F": "TP-Link", "14:CC:20": "TP-Link", "50:C7:BF": "TP-Link",
        "C0:25:E9": "ASUS", "00:0E:A6": "Linksys", "30:B5:C2": "Mercusys",
        # Dispositivos IoT y Smart Home
        "AC:CF:85": "ESP8266/ESP32", "24:D7:EB": "ESP8266", "5C:CF:7F": "ESP8266",
        # Dispositivosseen in scan
        "00:00:CA": "Commscope",  # Switch/Network设备
        "1A:5B:9D": "Private/Unknown",  # Puerto 49152 (Windows)
        "3A:92:AA": "Private/Unknown",  # Dispositivo sin identificar
    }

class AmenazaBaseDatos:
    AMENAZAS = {
        "Mineros": {"puertos": [3333, 4444, 5555, 7777, 8888], "descripcion": "Software de mineria ilegal", "nivel": "medio", "simbolo": "[MINERO]"},
        "Backdoor": {"puertos": [31337, 12345, 54321], "descripcion": "Puerta trasera", "nivel": "alto", "simbolo": "[BACKDOOR]"},
        "RAT": {"puertos": [5900, 5901, 3389], "descripcion": "Acceso remoto", "nivel": "alto", "simbolo": "[RAT]"},
        "FTP": {"puertos": [20, 21], "descripcion": "Archivo sin seguridad", "nivel": "medio", "simbolo": "[FTP]"},
        "Telnet": {"puertos": [23], "descripcion": "Conexion insegura", "nivel": "alto", "simbolo": "[TELNET]"},
        "SMB": {"puertos": [139, 445], "descripcion": "Carpetas compartidas", "nivel": "medio", "simbolo": "[SMB]"},
        "Database": {"puertos": [1433, 1521, 3306, 5432, 27017], "descripcion": "Base de datos expuesta", "nivel": "alto", "simbolo": "[DB]"},
        "Web": {"puertos": [80, 8080], "descripcion": "Pagina web", "nivel": "bajo", "simbolo": "[WEB]"},
        "SSH": {"puertos": [22], "descripcion": "Acceso remoto seguro", "nivel": "bajo", "simbolo": "[SSH]"},
    }

def consultar_mac_vendor(mac: str) -> str:
    """Consulta macvendors.com para obtener el fabricante de una MAC"""
    if not mac:
        return "Unknown"
    
    mac_limpia = mac.upper().replace(':', '').replace('-', '')
    if len(mac_limpia) < 6:
        return "Unknown"
    
    oui = mac_limpia[:6]
    
    if oui in _MAC_CACHE:
        return _MAC_CACHE[oui]
    
    try:
        url = f"https://api.macvendors.com/{oui}"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            vendor = response.text.strip()
            _MAC_CACHE[oui] = vendor
            return vendor
        elif response.status_code == 404:
            _MAC_CACHE[oui] = "Unknown"
            return "Unknown"
    except Exception:
        pass
    
    return "Unknown"

class AgenteSeguridadRed:
    def __init__(self):
        self.sistema = platform.system()
        self.dispositivos_encontrados = []
        self.historial_analisis = []
        self.nm = nmap.PortScanner() if NMAP_DISPONIBLE else None
        self.MAX_TRABAJADORES = 50  # Hilos paralelos
        
        self.PUERTOS_COMUNES = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            445: "SMB", 993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP",
            5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-ALT",
            8443: "HTTPS-ALT", 8888: "HTTP-ALT", 27017: "MongoDB",
            21: "FTP", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP",
            68: "DHCP", 69: "TFTP", 110: "POP3", 119: "NNTP", 123: "NTP",
            135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
            161: "SNMP", 162: "SNMPTRAP", 194: "IRC", 389: "LDAP", 465: "SMTPS",
            514: "Syslog", 587: "SMTP-SUB", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 5901: "VNC-1", 5902: "VNC-2",
            6379: "Redis", 8080: "HTTP-ALT", 8443: "HTTPS-ALT", 8888: "HTTP-ALT",
            9000: "SonarQube", 9090: "Prometheus", 9200: "Elasticsearch", 27017: "MongoDB",
            27018: "MongoDB", 27019: "MongoDB", 3333: "Miner-1", 5555: "Miner-2",
            7777: "Miner-3", 8888: "Miner-4", 9100: "Printer"
        }
        
    def limpiar_pantalla(self):
        os.system('cls' if self.sistema == 'Windows' else 'clear')
    
    def banner(self):
        nmap_ver = nmap.__version__ if NMAP_DISPONIBLE else "NO INSTALADO"
        print(f"""
=================================================================
      AGENTE DE SEGURIDAD DE RED v3.0 (OPTIMIZADO)
      Tu protector digital de la red local
=================================================================
[+] Sistema: {self.sistema}
[+] Modo: NMAP
=================================================================
""")
    
    def verificar_nmap(self) -> bool:
        return NMAP_DISPONIBLE
    
    def obtener_ip_local(self) -> str:
        """Obtiene la direccion IP local de la máquina"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ip = s.getsockname()[0]
            logger.debug(f"IP local detectada: {ip}")
            return ip
        except OSError as e:
            logger.error(f"Error al obtener IP local: {e}")
            return "127.0.0.1"
    
    def obtener_gateway(self) -> str:
        """Obtiene la IP del gateway/router de la red local"""
        if self.sistema == "Windows":
            try:
                resultado = subprocess.run(
                    ["route", "print", "0.0.0.0"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                for linea in resultado.stdout.split('\n'):
                    if '0.0.0.0' in linea and '192.168.' in linea:
                        for parte in linea.split():
                            if parte.startswith('192.168.'):
                                logger.debug(f"Gateway Windows: {parte}")
                                return parte
            except (subprocess.SubprocessError, OSError) as e:
                logger.error(f"Error al obtener gateway en Windows: {e}")
        else:
            try:
                resultado = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True,
                    text=True,
                    timeout=3
                )
                match = re.search(r'(\d+\.\d+\.\d+\.\d+)', resultado.stdout)
                if match:
                    logger.debug(f"Gateway Linux/Mac: {match.group(1)}")
                    return match.group(1)
            except (subprocess.SubprocessError, OSError) as e:
                logger.error(f"Error al obtener gateway en Linux/Mac: {e}")
        return ""
    
    def calcular_red(self, ip: str, mascara: int = 24) -> List[str]:
        """Calcula el rango de IPs de una red dado una IP y máscara"""
        try:
            red = ipaddress.ip_network(f"{ip}/{mascara}", strict=False)
            hosts = [str(ip) for ip in red.hosts()]
            logger.debug(f"Red calculada: {len(hosts)} hosts")
            return hosts
        except ValueError as e:
            logger.error(f"Error al calcular red: {e}")
            return []
    
    def identificar_dispositivo(self, mac: str) -> Dict:
        if not mac:
            return {"tipo": "Desconocido", "marca": "Unknown", "categoria": "unknown"}
        mac_prefix = mac.replace(':', '').upper()[:6]
        for prefijo, desc in DispositivoBaseDatos.MARCAS.items():
            if prefijo.replace(':', '').upper() == mac_prefix:
                cat = "router" if "Router" in desc or "Cisco" in desc or "Netgear" in desc or "TP-Link" in desc else "computadora"
                return {"tipo": "Dispositivo", "marca": desc, "categoria": cat}
        
        vendor = consultar_mac_vendor(mac)
        
        if vendor != "Unknown":
            cat = "router" if any(r in vendor.lower() for r in ["router", "gateway", "cisco", "netgear", "tp-link", "linksys", "ubiquiti"]) else "dispositivo"
            return {"tipo": "Dispositivo", "marca": vendor, "categoria": cat}
        
        return {"tipo": "Desconocido", "marca": "Unknown", "categoria": "unknown"}
    
    def detectar_amenazas(self, puertos: List[int]) -> Dict:
        amenazas = {"encontradas": [], "nivel": "bajo", "emoji": "[OK]"}
        puertos_set = set(puertos)
        
        for nombre, datos in AmenazaBaseDatos.AMENAZAS.items():
            if any(p in puertos_set for p in datos["puertos"]):
                amenazas["encontradas"].append({
                    "tipo": nombre, "descripcion": datos["descripcion"],
                    "nivel": datos["nivel"], "simbolo": datos["simbolo"],
                    "puertos": [p for p in puertos_set if p in datos["puertos"]]
                })
        
        if any(a["nivel"] == "alto" for a in amenazas["encontradas"]):
            amenazas["nivel"] = "alto"
            amenazas["emoji"] = "[PELIGRO]"
        elif any(a["nivel"] == "medio" for a in amenazas["encontradas"]):
            amenazas["nivel"] = "medio"
            amenazas["emoji"] = "[CUIDADO]"
        
        return amenazas
    
    def escanear_ping_rapido(self, ip: str) -> bool:
        """Verifica si una IP responde a ping"""
        param = "-n" if self.sistema == "Windows" else "-c"
        try:
            resultado = subprocess.run(
                ["ping", param, "1", "-w", "200", ip],
                capture_output=True,
                timeout=1
            )
            return resultado.returncode == 0
        except (subprocess.SubprocessError, OSError) as e:
            logger.debug(f"Error ping a {ip}: {e}")
            return False
    
    def escanear_puerto_rapido(self, ip: str, puerto: int) -> bool:
        """Verifica si un puerto está abierto en una IP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)
                resultado = sock.connect_ex((ip, puerto))
            return resultado == 0
        except OSError as e:
            logger.debug(f"Error escaneo puerto {puerto} en {ip}: {e}")
            return False
    
    def escanear_dispositivo_rapido(self, ip: str, gateway: str) -> Dict:
        """Escaneo rapido de un dispositivo"""
        puertos_comunes = [21, 22, 23, 80, 443, 445, 3306, 3389, 8080]
        
        puertos_abiertos = []
        for puerto in puertos_comunes:
            if self.escanear_puerto_rapido(ip, puerto):
                puertos_abiertos.append(puerto)
        
        mac = ""
        if ip != self.obtener_ip_local():
            try:
                if self.sistema == "Windows":
                    resultado = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=1)
                else:
                    resultado = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=1)
                match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', resultado.stdout)
                mac = match.group().replace('-', ':').upper() if match else ""
            except:
                pass
        
        dispositivo_info = self.identificar_dispositivo(mac)
        amenazas = self.detectar_amenazas(puertos_abiertos)
        
        return {
            "ip": ip, "mac": mac, "estado": "up",
            "sistema": "Desconocido", "puertos": puertos_abiertos,
            "servicios": {}, "dispositivo": dispositivo_info,
            "amenazas": amenazas, "fecha": datetime.now().isoformat(),
            "es_gateway": ip == gateway
        }
    
    def escanear_nmap_rapido(self, ip: str) -> Dict:
        """Escaneo NMAP rapido"""
        try:
            self.nm.scan(ip, arguments="-sT -T5 -F -O", timeout=15)
            
            if ip in self.nm.all_hosts():
                estado = self.nm[ip].state()
                puertos = []
                servicios = {}
                os_info = "Desconocido"
                
                if 'tcp' in self.nm[ip]:
                    for puerto, info in self.nm[ip]['tcp'].items():
                        puertos.append(puerto)
                        servicios[puerto] = {"nombre": info.get('name', 'unknown')}
                
                try:
                    if 'osmatch' in self.nm[ip] and self.nm[ip]['osmatch']:
                        os_info = self.nm[ip]['osmatch'][0]['name'].split(',')[0]
                except:
                    pass
                
                return {"ip": ip, "estado": estado, "puertos": puertos, "servicios": servicios, "sistema": os_info}
        except:
            pass
        
        return {"ip": ip, "estado": "down", "puertos": [], "servicios": {}, "sistema": "Desconocido"}
    
    def escanear_red_local(self) -> List[Dict]:
        print(f"\n{Colores.AZUL}{Colores.NEGRITA}[BUSCAR] ESCANEANDO TU RED (MODO RAPIDO)...{Colores.RESET}\n")
        
        ip_local = self.obtener_ip_local()
        gateway = self.obtener_gateway()
        
        print(f"Tu IP: {ip_local}")
        print(f"Tu Router: {gateway}")
        
        if NMAP_DISPONIBLE:
            print("\nEscaneo rapido con NMAP...\n")
            
            try:
                rango = f"{ip_local.rsplit('.', 1)[0]}.0/24"
                # Escaneo unico y rapido
                self.nm.scan(hosts=rango, arguments="-sn -T5 --max-retries 1", timeout=30)
                
                hosts = self.nm.all_hosts()
                print(f"Dispositivos encontrados: {len(hosts)}")
                
                # Escanear puertos en paralelo
                dispositivos = []
                
                def escanear_host(host):
                    return self.escanear_nmap_rapido(host)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    resultados = list(executor.map(escanear_host, hosts))
                
                for scan in resultados:
                    if scan.get("estado") == "up":
                        mac = ""
                        try:
                            if self.sistema == "Windows":
                                resultado = subprocess.run(["arp", "-a", scan["ip"]], capture_output=True, text=True, timeout=1)
                            else:
                                resultado = subprocess.run(["arp", "-n", scan["ip"]], capture_output=True, text=True, timeout=1)
                            match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', resultado.stdout)
                            mac = match.group().replace('-', ':').upper() if match else ""
                        except:
                            pass
                        
                        dispositivo_info = self.identificar_dispositivo(mac)
                        amenazas = self.detectar_amenazas(scan.get("puertos", []))
                        os_detectado = scan.get("sistema", "Desconocido")
                        
                        dispositivo = {
                            "ip": scan["ip"], "mac": mac, "estado": "up",
                            "sistema": os_detectado, "puertos": scan.get("puertos", []),
                            "servicios": scan.get("servicios", {}),
                            "dispositivo": dispositivo_info, "amenazas": amenazas,
                            "fecha": datetime.now().isoformat(),
                            "es_gateway": scan["ip"] == gateway
                        }
                        dispositivos.append(dispositivo)
                        print(f"  {amenazas['emoji']} {scan['ip']} - {dispositivo_info['marca']} ({os_detectado})")
                
                self.dispositivos_encontrados = dispositivos
                print(f"\n{Colores.VERDE}[OK] Escaneo completado: {len(dispositivos)} dispositivos{Colores.RESET}")
                return dispositivos
                
            except Exception as e:
                print(f"Error: {e}")
        
        # Fallback: escaneo con sockets en paralelo
        print("\nEscaneo con sockets en paralelo...\n")
        ips = self.calcular_red(ip_local, 24)
        
        if not ips:
            print(f"{Colores.ROJO}No se pudo determinar la red{Colores.RESET}")
            return []
        
        # Ping paralelo
        print("Buscando dispositivos...")
        
        def verificar_ip(ip):
            return ip if self.escanear_ping_rapido(ip) else None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_TRABAJADORES) as executor:
            ips_activas = list(filter(None, executor.map(verificar_ip, ips)))
        
        print(f"Dispositivos activos: {len(ips_activas)}")
        
        # Escanear puertos en paralelo
        def escanear_ip_final(ip):
            return self.escanear_dispositivo_rapido(ip, gateway)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.MAX_TRABAJADORES) as executor:
            dispositivos = list(executor.map(escanear_ip_final, ips_activas))
        
        for disp in dispositivos:
            print(f"  {disp['amenazas']['emoji']} {disp['ip']} - {disp['dispositivo']['marca']}")
        
        print(f"\n{Colores.VERDE}[OK] Escaneo completado: {len(dispositivos)} dispositivos{Colores.RESET}")
        self.dispositivos_encontrados = dispositivos
        return dispositivos
    
    def escanear_ip_especifica(self, ip: str = None) -> List[Dict]:
        if not ip:
            print(f"\n{Colores.AZUL}Ingresa la IP:{Colores.RESET}")
            ip = input("IP: ").strip()
        
        if not self._validar_ip(ip):
            print(f"{Colores.ROJO}IP invalida{Colores.RESET}")
            return []
        
        print(f"\n{Colores.AZUL}Escaneando {ip}...{Colores.RESET}\n")
        
        if NMAP_DISPONIBLE:
            scan = self.escanear_nmap_rapido(ip)
        else:
            puertos = []
            for p in [21, 22, 23, 80, 443, 445, 3306, 3389, 8080]:
                if self.escanear_puerto_rapido(ip, p):
                    puertos.append(p)
            scan = {"ip": ip, "estado": "up", "puertos": puertos, "servicios": {}}
        
        if scan.get("estado") == "up" or scan.get("puertos"):
            mac = ""
            try:
                if self.sistema == "Windows":
                    resultado = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=1)
                else:
                    resultado = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=1)
                match = re.search(r'([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})', resultado.stdout)
                mac = match.group().replace('-', ':').upper() if match else ""
            except:
                pass
            
            dispositivo_info = self.identificar_dispositivo(mac)
            amenazas = self.detectar_amenazas(scan.get("puertos", []))
            
            dispositivo = {
                "ip": ip, "mac": mac, "estado": "up",
                "sistema": "Desconocido", "puertos": scan.get("puertos", []),
                "servicios": scan.get("servicios", {}),
                "dispositivo": dispositivo_info, "amenazas": amenazas,
                "fecha": datetime.now().isoformat(), "es_gateway": ip == self.obtener_gateway()
            }
            self.dispositivos_encontrados = [dispositivo]
            print(f"{Colores.VERDE}[OK] Completado{Colores.RESET}")
            return [dispositivo]
        
        print(f"{Colores.ROJO}IP no responde{Colores.RESET}")
        return []
    
    def _validar_ip(self, ip: str) -> bool:
        try:
            partes = ip.split('.')
            if len(partes) != 4:
                return False
            return all(0 <= int(p) <= 255 for p in partes)
        except:
            return False
    
    def escanear_gateway(self):
        print(f"\n{Colores.AZUL}[WEB] ESCANEANDO ROUTER{Colores.RESET}\n")
        gateway = self.obtener_gateway()
        if not gateway:
            gateway = input("Ingresa IP del router: ").strip()
        if self._validar_ip(gateway):
            self.escanear_ip_especifica(gateway)
        else:
            print(f"{Colores.ROJO}IP invalida{Colores.RESET}")
    
    def ver_todos_dispositivos(self):
        if not self.dispositivos_encontrados:
            print(f"\n{Colores.AMARILLO}Sin dispositivos. Escanea primero.{Colores.RESET}")
            return
        
        print(f"\n{Colores.AZUL}[DISPOSITIVO] DISPOSITIVOS{Colores.RESET}\n")
        for i, disp in enumerate(self.dispositivos_encontrados, 1):
            emoji = disp["amenazas"]["emoji"] if disp["amenazas"]["encontradas"] else "[OK]"
            router = " (ROUTER)" if disp.get("es_gateway") else ""
            os_info = disp.get("sistema", "Desconocido")
            print(f"{i}. {emoji} {disp['ip']}{router}")
            print(f"   {disp['dispositivo']['marca']} - OS: {os_info} - {len(disp['puertos'])} puertos\n")
    
    def ver_puertos(self, ip: str = None):
        if not self.dispositivos_encontrados:
            print(f"\n{Colores.AMARILLO}Sin dispositivos{Colores.RESET}")
            return
        
        if not ip:
            print(f"{Colores.AZUL}Selecciona:{Colores.RESET}")
            for i, d in enumerate(self.dispositivos_encontrados, 1):
                print(f"  {i}. {d['ip']}")
            try:
                ip = self.dispositivos_encontrados[int(input("\nNumero: ")) - 1]["ip"]
            except:
                return
        
        disp = next((d for d in self.dispositivos_encontrados if d["ip"] == ip), None)
        if disp:
            print(f"\n{Colores.AZUL}Puertos en {ip}:{Colores.RESET}")
            for p in disp["puertos"]:
                nombre = self.PUERTOS_COMUNES.get(p, "Desconocido")
                print(f"  {p}/tcp - {nombre}")
    
    def detectar_sospechosos(self):
        if not self.dispositivos_encontrados:
            print(f"\n{Colores.AMARILLO}Sin dispositivos{Colores.RESET}")
            return
        
        sospechosos = [d for d in self.dispositivos_encontrados if d["amenazas"]["encontradas"]]
        
        if not sospechosos:
            print(f"\n{Colores.VERDE}[OK] Sin problemas{Colores.RESET}")
        else:
            print(f"\n{Colores.ROJO}[CUIDADO] {len(sospechosos)} dispositivos con problemas:{Colores.RESET}\n")
            for d in sospechosos:
                os_info = d.get("sistema", "Desconocido")
                print(f"[PELIGRO] {d['ip']} - {d['dispositivo']['marca']} (OS: {os_info})")
                for a in d['amenazas']['encontradas']:
                    print(f"   {a['simbolo']} {a['tipo']}: {a['descripcion']}")
                print()
    
    def _analizar_mac(self, mac: str, marca: str) -> str:
        """Analiza la MAC y proporciona información detallada"""
        if not mac:
            return "  - Sin MAC visible (posible firewall blocking ARP o dispositivo nuevo)"
        
        oui = mac.replace(':', '').upper()[:6]
        
        info = [f"  - MAC: {mac}"]
        info.append(f"  - OUI (Fabricante): {oui}")
        
        if marca == "Unknown" or "Unknown" in marca:
            info.append("  - Estado: FABRICANTE NO IDENTIFICADO")
            info.append("  - Posibles causas:")
            info.append("    * Fabricante privado o no registrado en IEEE")
            info.append("    * Dispositivo nuevo sin base de datos")
            info.append("    * MAC asignada dinámicamente (DHCP)")
        elif "Private" in marca:
            info.append(f"  - Estado: {marca} (fabricante privado)")
            info.append("  - Nota: Estos fabricantes no comparten su OUI públicamente")
        else:
            info.append(f"  - Fabricante detectado: {marca}")
        
        return "\n".join(info)
    
    def _analizar_puertos(self, puertos: List[int], servicios: Dict) -> str:
        """Analiza los puertos abiertos y sus servicios"""
        if not puertos:
            return "  - Sin puertos abiertos detectados"
        
        info = [f"  - Puertos abiertos: {len(puertos)}"]
        
        # Puertos comunes y su significado
        PUERTOS_COMUNES = {
            22: "SSH (Acceso remoto seguro)",
            23: "Telnet (Acceso remoto inseguro - obsoleto)",
            80: "HTTP (Servidor web sin cifrar)",
            443: "HTTPS (Servidor web seguro)",
            445: "SMB (Compartir archivos Windows)",
            3389: "RDP (Escritorio remoto Windows)",
            3306: "MySQL (Base de datos)",
            5432: "PostgreSQL (Base de datos)",
            8080: "HTTP Proxy (Servidor web alternativo)",
            21: "FTP (Transferencia de archivos sin cifrar)",
            25: "SMTP (Correo saliente)",
            53: "DNS (Servidor de nombres)",
            135: "RPC (Windows - posible vulnerabilidad)",
            139: "NetBIOS (Compartir archivos Windows)",
            49152: "Windows RPC (Servicios del sistema)",
            49153: "Windows RPC",
            49154: "Windows RPC",
        }
        
        for puerto in puertos:
            servicio = servicios.get(puerto, {}).get('nombre', 'desconocido')
            desc = PUERTOS_COMUNES.get(puerto, "")
            info.append(f"    * {puerto}/tcp -> {servicio}" + (f" ({desc})" if desc else ""))
        
        return "\n".join(info)
    
    def _analizar_amenazas(self, amenazas: Dict) -> str:
        """Analiza las amenazas detectadas"""
        if not amenazas.get("encontradas"):
            return "  - Sin amenazas detectadas"
        
        info = [f"  - Nivel de riesgo: {amenazas.get('nivel', 'desconocido').upper()}"]
        info.append("  - Amenazas encontradas:")
        
        for a in amenazas.get("encontradas", []):
            info.append(f"    * {a['simbolo']} {a['tipo']}")
            info.append(f"      Descripcion: {a['descripcion']}")
            info.append(f"      Puertos afectados: {a.get('puertos', [])}")
        
        return "\n".join(info)
    
    def _dar_recomendaciones(self, dispositivo: Dict) -> str:
        """Genera recomendaciones específicas para el dispositivo"""
        recomendaciones = []
        ip = dispositivo.get("ip", "")
        mac = dispositivo.get("mac", "")
        marca = dispositivo.get("dispositivo", {}).get("marca", "")
        puertos = dispositivo.get("puertos", [])
        amenazas = dispositivo.get("amenazas", {})
        
        # Recomendaciones por tipo de dispositivo
        if "router" in dispositivo.get("dispositivo", {}).get("categoria", "").lower():
            recomendaciones.append("  [ROUTER] Este es tu router/gateway:")
            recomendaciones.append("    * Actualiza el firmware regularmente")
            recomendaciones.append("    * Cambia la contrasena por defecto")
            recomendaciones.append("    * Desactiva WPS")
            recomendaciones.append("    * Usa WPA3 o WPA2-AES")
        
        # Recomendaciones por puertos abiertos
        if 23 in puertos:
            recomendaciones.append("  [ALERTA] Telnet detectado (puerto 23):")
            recomendaciones.append("    * Telnet es inseguro - usa SSH en su lugar")
        
        if 21 in puertos:
            recomendaciones.append("  [ALERTA] FTP detectado (puerto 21):")
            recomendaciones.append("    * FTP transfiere datos sin cifrar")
            recomendaciones.append("    * Considera usar SFTP o SCP")
        
        if 445 in puertos:
            recomendaciones.append("  [INFO] SMB detectado (puerto 445):")
            recomendaciones.append("    * Permite compartir archivos en red")
            recomendaciones.append("    * Verifica que no tengas carpetas sensibles compartidas")
        
        if 3389 in puertos:
            recomendaciones.append("  [INFO] RDP detectado (puerto 3389):")
            recomendaciones.append("    * Escritorio remoto activo")
            recomendaciones.append("    * Asegurate de usar contrasenas fuertes")
        
        if 8888 in puertos or 3333 in puertos or 5555 in puertos:
            recomendaciones.append("  [ALERTA] Posible mineria de criptomonedas!")
            recomendaciones.append("    * Estos puertos son usados por malware de mineria")
        
        # Recomendaciones por MAC desconocida
        if not mac:
            recomendaciones.append("  [INFO] Sin MAC visible:")
            recomendaciones.append("    * Puede tener firewall bloqueando ARP")
            recomendaciones.append("    * Es un dispositivo muy nuevo")
        
        if "Unknown" in marca or "Private" in marca:
            recomendaciones.append("  [INFO] Fabricante no identificado:")
            recomendaciones.append("    * Verifica manualmente los dispositivos conectados")
            recomendaciones.append("    * Revisa la lista de dispositivos en tu router")
        
        if not recomendaciones:
            return "  - No hay recomendaciones especificas"
        
        return "\n".join(recomendaciones)
    
    def generar_informe(self, dispositivo: Dict) -> str:
        """Genera un informe de seguridad detallado para un dispositivo"""
        amenazas = dispositivo.get("amenazas", {})
        nivel = amenazas.get("nivel", "bajo")
        
        estado = "[PELIGRO] PELIGRO" if nivel == "alto" else "[CUIDADO] CUIDADO" if nivel == "medio" else "[OK] SEGURO"
        
        es_gateway = dispositivo.get("es_gateway", False)
        gateway_tag = " [PUERTA DE ENLACE]" if es_gateway else ""
        
        return f"""
================================================================================
                    INFORME DE SEGURIDAD - DISPOSITIVO
================================================================================

[DISPOSITIVO]
  - IP: {dispositivo['ip']}{gateway_tag}
  - Tipo: {dispositivo['dispositivo']['tipo']}
  - Fabricante: {dispositivo['dispositivo']['marca']}
  - Categoria: {dispositivo['dispositivo']['categoria']}

[DIRECCION MAC]
{self._analizar_mac(dispositivo.get('mac', ''), dispositivo.get('dispositivo', {}).get('marca', ''))}

[RED]
  - Estado: {dispositivo.get('estado', 'unknown')}
  - Sistema: {dispositivo.get('sistema', 'Desconocido')}

[PUERTOS Y SERVICIOS]
{self._analizar_puertos(dispositivo.get('puertos', []), dispositivo.get('servicios', {}))}

[AMENAZAS]
{self._analizar_amenazas(amenazas)}

[RECOMENDACIONES]
{self._dar_recomendaciones(dispositivo)}

================================================================================
[INFO] RESUMEN: {estado}
Generado: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
================================================================================
"""
    
    def generar_informe_completo(self):
        if not self.dispositivos_encontrados:
            print(f"\n{Colores.AMARILLO}Sin dispositivos{Colores.RESET}")
            return
        
        for disp in self.dispositivos_encontrados:
            print(self.generar_informe(disp))
        
        if input("\nGuardar? (s/n): ").lower() == "s":
            try:
                with open("informe_seguridad.txt", "w", encoding="utf-8") as f:
                    for disp in self.dispositivos_encontrados:
                        f.write(self.generar_informe(disp))
                print(f"{Colores.VERDE}[OK] Guardado{Colores.RESET}")
            except Exception as e:
                print(f"{Colores.ROJO}Error: {e}{Colores.RESET}")
    
    def guardar_historial(self):
        if self.dispositivos_encontrados:
            self.historial_analisis.append({
                "fecha": datetime.now().isoformat(),
                "dispositivos": self.dispositivos_encontrados,
                "total": len(self.dispositivos_encontrados)
            })
            try:
                with open("historial_analisis.json", "w") as f:
                    json.dump(self.historial_analisis, f, indent=2)
            except:
                pass
    
    def ver_historial(self):
        try:
            with open("historial_analisis.json", "r") as f:
                h = json.load(f)
            print(f"\n{Colores.AZUL}[HISTORIAL] HISTORIAL{Colores.RESET}")
            for i, item in enumerate(h, 1):
                print(f"{i}. {item['fecha']} - {item['total']} dispositivos")
        except:
            print(f"{Colores.AMARILLO}Sin historial{Colores.RESET}")
    
    def mostrar_info_sistema(self):
        """Muestra informacion detallada del sistema y red"""
        print(f"\n{Colores.AZUL}[INFO] INFORMACION DEL SISTEMA{Colores.RESET}\n")
        
        ip_local = self.obtener_ip_local()
        gateway = self.obtener_gateway()
        
        print(f"{Colores.NEGRITA}Red Local:{Colores.RESET}")
        print(f"  Tu IP:        {ip_local}")
        print(f"  Gateway/Router: {gateway}")
        
        try:
            import socket
            hostname = socket.gethostname()
            print(f"  Hostname:     {hostname}")
        except:
            pass
        
        print(f"\n{Colores.NEGRITA}Sistema:{Colores.RESET}")
        print(f"  OS:           {self.sistema}")
        print(f"  Python:       {platform.python_version()}")
        
        if NMAP_DISPONIBLE:
            print(f"  NMAP:         {nmap.__version__}")
        else:
            print(f"  NMAP:         No instalado")
        
        print(f"\n{Colores.NEGRITA}Alertas configuradas:{Colores.RESET}")
        
        telegram_token = os.getenv('TELEGRAM_BOT_TOKEN')
        if telegram_token:
            print(f"  Telegram:     Configurado")
        else:
            print(f"  Telegram:     No configurado")
        
        discord_webhook = os.getenv('DISCORD_WEBHOOK_URL')
        if discord_webhook:
            print(f"  Discord:      Configurado")
        else:
            print(f"  Discord:      No configurado")
    
    def menu_principal(self):
        print("""
================================================================================
           MENU - AGENTE DE SEGURIDAD RED v3.0 (OPTIMIZADO)
================================================================================
 1. Escanear red local completa (RAPIDO)
 2. Escanear IP especifica
 3. Ver todos los dispositivos
 4. Ver puertos de un dispositivo
 5. Ver dispositivos con problemas
 6. Generar informe
  7. Ver historial
   8. Info del sistema (IP, red, alertas)
   9. Salir
================================================================================
""")
        print("Selecciona una opcion (1-9): ", end="")
    
    def ejecutar(self):
        self.limpiar_pantalla()
        self.banner()
        
        while True:
            self.menu_principal()
            opcion = input()
            
            if opcion == "1":
                self.escanear_red_local()
                self.guardar_historial()
            elif opcion == "2":
                self.escanear_ip_especifica()
                self.guardar_historial()
            elif opcion == "3":
                self.ver_todos_dispositivos()
            elif opcion == "4":
                self.ver_puertos()
            elif opcion == "5":
                self.detectar_sospechosos()
            elif opcion == "6":
                self.generar_informe_completo()
            elif opcion == "7":
                self.ver_historial()
            elif opcion == "8":
                self.mostrar_info_sistema()
            elif opcion == "9":
                print(f"\n{Colores.VERDE}Gracias!{Colores.RESET}")
                break
            else:
                print(f"{Colores.ROJO}Opcion invalida{Colores.RESET}")
            
            input(f"\n{Colores.AMARILLO}Enter...{Colores.RESET}")
            self.limpiar_pantalla()
    
    # ==================== FUNCIONES DE ALERTAS ====================
    
    def enviar_alerta_telegram(self, mensaje: str) -> bool:
        """Envia alerta por Telegram"""
        try:
            import os
            token = os.getenv('TELEGRAM_BOT_TOKEN')
            chat_id = os.getenv('TELEGRAM_CHAT_ID')
            
            if not token or not chat_id:
                print("[TELEGRAM] No configurado.")
                print("  Linux: export TELEGRAM_BOT_TOKEN='xxx' TELEGRAM_CHAT_ID='xxx'")
                print("  Windows: $env:TELEGRAM_BOT_TOKEN='xxx'")
                return False
            
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            data = {"chat_id": chat_id, "text": mensaje}
            response = requests.post(url, json=data, timeout=10)
            
            if response.status_code == 200:
                print("[TELEGRAM] Alerta enviada")
                return True
            else:
                print(f"[TELEGRAM] Error: {response.status_code}")
                if response.status_code == 401:
                    print("  -> Token o Chat ID incorrecto")
                return False
        except Exception as e:
            print(f"[TELEGRAM] Error: {e}")
            return False
    
    def enviar_alerta_discord(self, mensaje: str) -> bool:
        """Envía alerta por Discord webhook"""
        try:
            import os
            webhook_url = os.getenv('DISCORD_WEBHOOK_URL')
            
            if not webhook_url:
                print("[DISCORD] No configurado. Variable: DISCORD_WEBHOOK_URL")
                return False
            
            data = {"content": mensaje}
            response = requests.post(webhook_url, json=data, timeout=10)
            
            if response.status_code in [200, 204]:
                print("[DISCORD] Alerta enviada")
                return True
            else:
                print(f"[DISCORD] Error: {response.status_code}")
                return False
        except Exception as e:
            print(f"[DISCORD] Error: {e}")
            return False
    
    def enviar_alerta_email(self, asunto: str, cuerpo: str) -> bool:
        """Envía alerta por Email usando SMTP"""
        try:
            import os
            import smtplib
            from email.mime.text import MIMEText
            from email.mime.multipart import MIMEMultipart
            
            smtp_server = os.getenv('SMTP_SERVER')
            smtp_port = os.getenv('SMTP_PORT', '587')
            smtp_user = os.getenv('SMTP_USER')
            smtp_password = os.getenv('SMTP_PASSWORD')
            from_email = os.getenv('FROM_EMAIL')
            to_email = os.getenv('TO_EMAIL')
            
            if not all([smtp_server, smtp_user, smtp_password, from_email, to_email]):
                print("[EMAIL] No configurado. Variables: SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, FROM_EMAIL, TO_EMAIL")
                return False
            
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = asunto
            msg.attach(MIMEText(cuerpo, 'plain'))
            
            server = smtplib.SMTP(smtp_server, int(smtp_port))
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(from_email, to_email, msg.as_string())
            server.quit()
            
            print("[EMAIL] Alerta enviada")
            return True
        except Exception as e:
            print(f"[EMAIL] Error: {e}")
            return False
    
    def enviar_alerta_multiple(self, mensaje: str) -> None:
        """Envía alerta a todos los canales configurados"""
        print("\n[ALERTAS] Enviando a todos los canales...")
        
        # Telegram
        self.enviar_alerta_telegram(mensaje)
        
        # Discord
        self.enviar_alerta_discord(mensaje)
        
        # Email
        self.enviar_alerta_email("Alerta de Seguridad WiFi", mensaje)
    
    def inicializar_base_datos(self) -> bool:
        """Inicializa la base de datos SQLite para logging"""
        try:
            import sqlite3
            
            db_path = "agente_seguridad.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Tabla de escaneos
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS escaneos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha TEXT NOT NULL,
                    tipo TEXT NOT NULL,
                    dispositivos INTEGER,
                    amenazas INTEGER,
                    detalles TEXT
                )
            ''')
            
            # Tabla de alertas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alertas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    fecha TEXT NOT NULL,
                    tipo TEXT NOT NULL,
                    mensaje TEXT,
                    canal TEXT
                )
            ''')
            
            # Tabla de dispositivos detectados
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS dispositivos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    mac TEXT,
                    marca TEXT,
                    primer_visto TEXT,
                    ultimo_visto TEXT,
                    veces_visto INTEGER DEFAULT 1
                )
            ''')
            
            conn.commit()
            conn.close()
            
            logger.info(f"Base de datos inicializada: {db_path}")
            return True
        except Exception as e:
            logger.error(f"Error al inicializar BD: {e}")
            return False
    
    def guardar_escaneo_db(self, tipo: str, dispositivos: int, amenazas: int, detalles: str = "") -> None:
        """Guarda un escaneo en la base de datos"""
        try:
            import sqlite3
            from datetime import datetime
            
            db_path = "agente_seguridad.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO escaneos (fecha, tipo, dispositivos, amenazas, detalles)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), tipo, dispositivos, amenazas, detalles))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error al guardar escaneo: {e}")
    
    def guardar_alerta_db(self, tipo: str, mensaje: str, canal: str) -> None:
        """Guarda una alerta en la base de datos"""
        try:
            import sqlite3
            from datetime import datetime
            
            db_path = "agente_seguridad.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO alertas (fecha, tipo, mensaje, canal)
                VALUES (?, ?, ?, ?)
            ''', (datetime.now().isoformat(), tipo, mensaje, canal))
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error al guardar alerta: {e}")
    
    def ver_estadisticas(self) -> None:
        """Muestra estadísticas de la base de datos"""
        try:
            import sqlite3
            
            db_path = "agente_seguridad.db"
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            print(f"""
================================================================================
                      ESTADISTICAS - AGENTE DE SEGURIDAD
================================================================================
""")
            
            # Total escaneos
            cursor.execute("SELECT COUNT(*) FROM escaneos")
            total_escaneos = cursor.fetchone()[0]
            print(f"Escaneos realizados: {total_escaneos}")
            
            # Ultimo escaneo
            cursor.execute("SELECT fecha, dispositivos, amenazas FROM escaneos ORDER BY id DESC LIMIT 1")
            ultimo = cursor.fetchone()
            if ultimo:
                print(f"Último escaneo: {ultimo[0]}")
                print(f"  Dispositivos: {ultimo[1]}, Amenazas: {ultimo[2]}")
            
            # Total alertas
            cursor.execute("SELECT COUNT(*) FROM alertas")
            total_alertas = cursor.fetchone()[0]
            print(f"Total de alertas: {total_alertas}")
            
            # Alertas por tipo
            cursor.execute("SELECT tipo, COUNT(*) FROM alertas GROUP BY tipo")
            print("\nAlertas por tipo:")
            for tipo, count in cursor.fetchall():
                print(f"  - {tipo}: {count}")
            
            # Dispositivos únicos
            cursor.execute("SELECT COUNT(*) FROM dispositivos")
            total_dispositivos = cursor.fetchone()[0]
            print(f"\nDispositivos únicos detectados: {total_dispositivos}")
            
            conn.close()
        except Exception as e:
            print(f"{Colores.ROJO}Error al obtener estadísticas: {e}{Colores.RESET}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Agente de Seguridad de Red')
    parser.add_argument('--token', '-t', help='Telegram Bot Token')
    parser.add_argument('--chat', '-c', help='Telegram Chat ID')
    args, unknown = parser.parse_known_args()
    
    if args.token:
        import os
        os.environ['TELEGRAM_BOT_TOKEN'] = args.token
    if args.chat:
        import os
        os.environ['TELEGRAM_CHAT_ID'] = args.chat
    
    try:
        AgenteSeguridadRed().ejecutar()
    except KeyboardInterrupt:
        print("\nAdios!")
    except Exception as e:
        print(f"Error: {e}")
