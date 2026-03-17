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
        
        interfaces = self.obtener_interfaces_wifi()
        if interfaces:
            print(f"\n{Colores.NEGRITA}Interfaces WiFi:{Colores.RESET}")
            for iface in interfaces:
                print(f"  {iface['nombre']}: {iface['modo']} ({iface['tipo']})")
        
        print(f"\n{Colores.NEGRITA}Alertas configuradas:{Colores.RESET}")
        if hasattr(self, 'telefono_alerta') and self.telefono_alerta:
            print(f"  WhatsApp:     +{'*' * 8}")
        else:
            print(f"  WhatsApp:     No configurado")
        
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
 9. Detector DEAUTH (Flipper Zero)
10. Salir
================================================================================
""")
        print("Selecciona una opcion (1-10): ", end="")
    
    def _mostrar_adaptadores_recomendados(self):
        """Muestra adaptadores WiFi recomendados para modo monitor"""
        print(f"""
================================================================================
         ADAPTADORES WI-FI RECOMENDADOS PARA MODO MONITOR
================================================================================

{Colores.ROJO}Windows:{Colores.RESET} No soporta modo monitor de forma nativa.
Necesitas un adaptador USB externo:

  ✓ Alfa AWUS036NHA  - Chipset Atheros AR9271 (Recomendado)
  ✓ Alfa AWUS036ACH - Chipset Realtek RTL8812AU
  ✓ TP-Link TL-WN722N v2/v3 - Chipset Atheros
  ✓ Alfa AWUS036NEH - Chipset Realtek RTL8187

{Colores.VERDE}Linux (Kali Linux):{Colores.RESET}
  ✓ Cualquier tarjeta con chipset Atheros (madwifi-ng)
  ✓ Alfa AWUS036NHA
  ✓ Raspberry Pi con adaptador USB

{Colores.AZUL}macOS:{Colores.RESET}
  ✓ Tarjetas internas de MacBook (limitado)
  ✓ Adaptadores externos seleccionados

{Colores.AMARILLO}Nota:{Colores.RESET} Para Raspberry Pi recomiendo:
  - Raspberry Pi 4 con Kali Linux
  - Adaptador WiFi USB Alfa AWUS036NHA

================================================================================
""")
    
    def obtener_interfaces_wifi(self) -> List[Dict]:
        """Obtiene lista de interfaces WiFi disponibles"""
        interfaces = []
        
        if self.sistema == "Windows":
            try:
                resultado = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                for linea in resultado.stdout.split('\n'):
                    if "Nombre" in linea or "Name" in linea:
                        match = re.search(r'(?:Nombre|Name)[\s:]+([^\n]+)', linea)
                        if match:
                            nombre = match.group(1).strip()
                            interfaces.append({
                                "nombre": nombre,
                                "tipo": "WiFi",
                                "modo": "managed"
                            })
            except Exception as e:
                logger.error(f"Error al obtener interfaces Windows: {e}")
        
        elif self.sistema == "Linux":
            try:
                resultado = subprocess.run(
                    ["ip", "link", "show"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                for linea in resultado.stdout.split('\n'):
                    if re.match(r'^\d+:', linea):
                        match = re.search(r'^\d+:\s+(\w+)', linea)
                        if match:
                            nombre = match.group(1)
                            if nombre.startswith('w') or 'wlan' in nombre.lower() or nombre.endswith('mon'):
                                modo_actual = self._obtener_modo_interfaz_linux(nombre)
                                interfaces.append({
                                    "nombre": nombre,
                                    "tipo": "WiFi",
                                    "modo": modo_actual
                                })
            except Exception as e:
                logger.error(f"Error al obtener interfaces Linux: {e}")
        
        elif self.sistema == "Darwin":
            try:
                resultado = subprocess.run(
                    ["airport", "-s"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if resultado.returncode == 0:
                    interfaces.append({
                        "nombre": "en0",
                        "tipo": "WiFi",
                        "modo": "managed"
                    })
            except Exception as e:
                logger.error(f"Error al obtener interfaces macOS: {e}")
        
        return interfaces
    
    def _obtener_modo_interfaz_linux(self, interfaz: str) -> str:
        """Obtiene el modo actual de una interfaz WiFi en Linux"""
        try:
            resultado = subprocess.run(
                ["iw", interfaz, "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if resultado.returncode == 0:
                for linea in resultado.stdout.split('\n'):
                    if 'type' in linea.lower():
                        if 'monitor' in linea.lower():
                            return "monitor"
                        elif 'managed' in linea.lower() or 'station' in linea.lower():
                            return "managed"
                        elif 'ap' in linea.lower() or 'master' in linea.lower():
                            return "ap"
        except:
            pass
        return "unknown"
    
    def verificar_modo_monitor(self, interfaz: str) -> Dict:
        """Verifica si una interfaz soporta modo monitor y su estado actual"""
        resultado = {
            "soporta": False,
            "esta_en_modo_monitor": False,
            "mensaje": ""
        }
        
        if self.sistema == "Linux":
            try:
                resultado_check = subprocess.run(
                    ["iw", interfaz, "info"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if resultado_check.returncode == 0:
                    if "type monitor" in resultado_check.stdout:
                        resultado["soporta"] = True
                        resultado["esta_en_modo_monitor"] = True
                        resultado["mensaje"] = "La interfaz ya está en modo monitor"
                    else:
                        resultado["soporta"] = True
                        resultado["esta_en_modo_monitor"] = False
                        resultado["mensaje"] = "La interfaz soporta modo monitor pero está en modo managed"
                else:
                    resultado["mensaje"] = "La interfaz no soporta modo monitor"
            except:
                resultado["mensaje"] = "No se pudo verificar la interfaz"
        
        elif self.sistema == "Windows":
            resultado["soporta"] = False
            resultado["mensaje"] = "Windows no soporta modo monitor de forma nativa. Usa un adaptador USB externo compatible."
        
        elif self.sistema == "Darwin":
            resultado["soporta"] = True
            resultado["esta_en_modo_monitor"] = False
            resultado["mensaje"] = "MacOS soporta modo monitor pero requiere permisos de root"
        
        return resultado
    
    def _es_root(self) -> bool:
        """Verifica si el programa se ejecuta con permisos de root"""
        try:
            import os
            return os.geteuid() == 0
        except:
            return False
    
    def activar_modo_monitor(self, interfaz: str) -> bool:
        """Activa el modo monitor en una interfaz WiFi"""
        logger.info(f"Activando modo monitor en {interfaz}")
        
        if self.sistema == "Linux":
            if not self._es_root():
                print(f"{Colores.ROJO}[ERROR] Se requieren permisos de root para activar modo monitor{Colores.RESET}")
                print(f"{Colores.AMARILLO}Ejecuta el programa con sudo:{Colores.RESET}")
                print(f"  sudo python3 {os.path.basename(__file__)}")
                return False
            
            try:
                interfaz_nueva = None
                
                subprocess.run(["ip", "link", "set", interfaz, "down"],
                             capture_output=True, timeout=5)
                resultado_iw = subprocess.run(["iw", interfaz, "set", "type", "monitor"],
                             capture_output=True, text=True, timeout=5)
                
                if resultado_iw.returncode != 0:
                    logger.warning(f"iw fallo, intentando con airmon-ng: {resultado_iw.stderr}")
                    resultado_airmon = subprocess.run(["airmon-ng", "start", interfaz],
                                        capture_output=True, text=True, timeout=10)
                    
                    if resultado_airmon.returncode == 0:
                        for linea in resultado_airmon.stdout.split('\n'):
                            if '(mon)' in linea.lower() or 'enabled' in linea.lower():
                                match = re.search(r'(wlan\d+)', linea)
                                if match:
                                    interfaz_nueva = match.group(1)
                                break
                        
                        if not interfaz_nueva:
                            posibles = [interfaz + "mon", interfaz.replace("mon", "")]
                            for posible in posibles:
                                resultado_check = subprocess.run(["ip", "link", "show", posible],
                                            capture_output=True, timeout=5)
                                if resultado_check.returncode == 0:
                                    interfaz_nueva = posible
                                    break
                    else:
                        logger.error(f"airmon-ng fallo: {resultado_airmon.stderr}")
                        return False
                else:
                    resultado_check = subprocess.run(["ip", "link", "show", interfaz],
                                        capture_output=True, timeout=5)
                    if resultado_check.returncode == 0:
                        interfaz_nueva = interfaz
                
                subprocess.run(["ip", "link", "set", interfaz, "up"],
                             capture_output=True, timeout=5)
                
                if interfaz_nueva and interfaz_nueva != interfaz:
                    print(f"{Colores.VERDE}[OK] Modo monitor activado en {interfaz_nueva}{Colores.RESET}")
                else:
                    print(f"{Colores.VERDE}[OK] Modo monitor activado en {interfaz}{Colores.RESET}")
                
                logger.info(f"Modo monitor activado en {interfaz_nueva or interfaz}")
                return True
            except Exception as e:
                logger.error(f"Error al activar modo monitor: {e}")
                print(f"{Colores.ROJO}[ERROR] No se pudo activar modo monitor: {e}{Colores.RESET}")
                return False
        
        elif self.sistema == "Windows":
            print(f"{Colores.ROJO}Windows no soporta modo monitor de forma nativa.{Colores.RESET}")
            print("Usa un adaptador USB WiFi compatible con modo monitor:")
            print("  - Alfa AWUS036NHA (chipset Atheros)")
            print("  - Alfa AWUS036AC (chipset Realtek)")
            print("  - TP-Link TL-WN722N (chipset Atheros)")
            return False
        
        elif self.sistema == "Darwin":
            try:
                subprocess.run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-z"],
                             capture_output=True, timeout=5)
                return True
            except:
                return False
        
        return False
    
    def mostrar_interfaces_wifi(self):
        """Muestra las interfaces WiFi disponibles y su estado"""
        print(f"\n{Colores.AZUL}[WIFI] INTERFACES WI-FI DISPONIBLES{Colores.RESET}\n")
        
        interfaces = self.obtener_interfaces_wifi()
        
        if not interfaces:
            print(f"{Colores.AMARILLO}No se encontraron interfaces WiFi.{Colores.RESET}")
            print("\nPara usar el detector Deauth necesitas:")
            print("  - Linux: Una tarjeta WiFi interna o USB compatible")
            print("  - Windows: Un adaptador USB WiFi externo compatible")
            print("  - Mac: Una MacBook con tarjeta WiFi interna")
            return None
        
        print(f"{'Interfaz':<15} {'Tipo':<10} {'Modo':<15} {'Estado'}")
        print("-" * 55)
        
        for iface in interfaces:
            estado = self.verificar_modo_monitor(iface["nombre"])
            modo_actual = "MONITOR" if estado["esta_en_modo_monitor"] else iface["modo"]
            soporte = "✓ Soporta" if estado["soporta"] else "✗ No soporta"
            print(f"{iface['nombre']:<15} {iface['tipo']:<10} {modo_actual:<15} {soporte}")
        
        return interfaces
    
    def desactivar_modo_monitor(self) -> bool:
        """Desactiva el modo monitor y vuelve a modo managed"""
        print(f"\n{Colores.AZUL}[DESACTIVAR MODO MONITOR]{Colores.RESET}\n")
        
        interfaces = self.obtener_interfaces_wifi()
        if not interfaces:
            print(f"{Colores.AMARILLO}No se encontraron interfaces WiFi.{Colores.RESET}")
            return False
        
        interfaces_monitor = []
        for iface in interfaces:
            estado = self.verificar_modo_monitor(iface["nombre"])
            if estado.get("esta_en_modo_monitor"):
                interfaces_monitor.append(iface["nombre"])
        
        if not interfaces_monitor:
            print(f"{Colores.AMARILLO}No hay interfaces en modo monitor.{Colores.RESET}")
            return False
        
        print(f"{Colores.VERDE}Interfaces en modo monitor:{Colores.RESET}")
        for i, iface in enumerate(interfaces_monitor, 1):
            print(f"  {i}. {iface}")
        
        print("\nSelecciona interfaz para desactivar: ", end="")
        try:
            idx = int(input()) - 1
            if 0 <= idx < len(interfaces_monitor):
                interfaz = interfaces_monitor[idx]
                return self._desactivar_monitor_interface(interfaz)
        except ValueError:
            pass
        
        return False
    
    def _desactivar_monitor_interface(self, interfaz: str) -> bool:
        """Desactiva el modo monitor en una interfaz especifica"""
        logger.info(f"Desactivando modo monitor en {interfaz}")
        
        if self.sistema == "Linux":
            try:
                interfaz_original = self._detectar_interfaz_original(interfaz)
                
                subprocess.run(["ip", "link", "set", interfaz, "down"],
                             capture_output=True, timeout=5)
                subprocess.run(["iw", interfaz, "set", "type", "managed"],
                             capture_output=True, timeout=5)
                subprocess.run(["ip", "link", "set", interfaz, "up"],
                             capture_output=True, timeout=5)
                
                if interfaz_original and interfaz_original != interfaz:
                    subprocess.run(["ip", "link", "set", interfaz, "name", interfaz_original],
                                 capture_output=True, timeout=5)
                    print(f"{Colores.VERDE}[OK] Interfaz renombrada a {interfaz_original} y modo managed activado{Colores.RESET}")
                else:
                    print(f"{Colores.VERDE}[OK] Modo monitor desactivado, modo managed activado{Colores.RESET}")
                
                logger.info(f"Modo monitor desactivado en {interfaz}")
                return True
            except Exception as e:
                logger.error(f"Error al desactivar modo monitor: {e}")
                print(f"{Colores.ROJO}[ERROR] No se pudo desactivar modo monitor: {e}{Colores.RESET}")
                return False
        
        elif self.sistema == "Windows":
            print(f"{Colores.ROJO}Windows no soporta modo monitor de forma nativa.{Colores.RESET}")
            return False
        
        elif self.sistema == "Darwin":
            try:
                subprocess.run(["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-z"],
                             capture_output=True, timeout=5)
                print(f"{Colores.VERDE}[OK] Modo monitor desactivado{Colores.RESET}")
                return True
            except Exception as e:
                logger.error(f"Error al desactivar modo monitor en macOS: {e}")
                return False
        
        return False
    
    def _detectar_interfaz_original(self, interfaz: str) -> str:
        """Detecta el nombre original de la interfaz (ej: wlan0mon -> wlan0)"""
        if self.sistema != "Linux":
            return interfaz
        
        if interfaz.endswith("mon"):
            return interfaz[:-3]
        
        try:
            resultado = subprocess.run(
                ["iw", interfaz, "info"],
                capture_output=True,
                text=True,
                timeout=5
            )
            for linea in resultado.stdout.split('\n'):
                if 'wiphy' in linea.lower():
                    continue
        except:
            pass
        
        return interfaz
    
    def ver_estado_modo_monitor(self):
        """Muestra el estado actual de las interfaces en modo monitor"""
        print(f"\n{Colores.AZUL}[ESTADO DE MODO MONITOR]{Colores.RESET}\n")
        
        interfaces = self.obtener_interfaces_wifi()
        if not interfaces:
            print(f"{Colores.AMARILLO}No se encontraron interfaces WiFi.{Colores.RESET}")
            return
        
        print(f"{'Interfaz':<15} {'Modo Actual':<15} {'Tipo':<12} {'Soporte'}")
        print("-" * 60)
        
        hay_monitor = False
        for iface in interfaces:
            estado = self.verificar_modo_monitor(iface["nombre"])
            
            if estado.get("esta_en_modo_monitor"):
                modo = f"{Colores.VERDE}MONITOR{Colores.RESET}"
                hay_monitor = True
            else:
                modo = f"{iface['modo'].upper()}"
            
            soporte = f"{Colores.VERDE}✓{Colores.RESET}" if estado.get("soporta") else f"{Colores.ROJO}✗{Colores.RESET}"
            
            print(f"{iface['nombre']:<15} {modo:<15} {iface['tipo']:<12} {soporte}")
            
            if estado.get("esta_en_modo_monitor"):
                print(f"    {Colores.AMARILLO}-> Esta interfaz esta en modo monitor{Colores.RESET}")
        
        print()
        if hay_monitor:
            print(f"{Colores.VERDE}Para desactivar el modo monitor, usa la opcion 3 del menu.{Colores.RESET}")
        else:
            print(f"{Colores.AMARILLO}Ninguna interfaz esta en modo monitor.{Colores.RESET}")
    
    def configurar_alerta_whatsapp(self, telefono: str = None):
        """Configura el numero para alertas WhatsApp"""
        if not telefono:
            print("\n[CONFIGURAR ALERTA WHATSAPP]")
            print("Numero formato: +521234567890")
            telefono = input("Telefono: ").strip()
        
        self.telefono_alerta = telefono
        print(f"[OK] Alerta WhatsApp configurada: {telefono}")
    
    def configurar_alertas(self):
        """Menu para configurar alertas"""
        while True:
            print("""
================================================================================
              CONFIGURAR ALERTAS
================================================================================
1. Configurar Telegram (Gratis - Recomendado)
2. Configurar Discord
3. Configurar Email
4. Probar alertas
5. Volver

================================================================================
""")
            print("Selecciona una opcion (1-5): ", end="")
            opc = input()
            
            if opc == "1":
                print("\n[TELEGRAM]")
                print("PASO 1: Obtener Token")
                print("  1. Busca @BotFather en Telegram")
                print("  2. Envia /newbot")
                print("  3. Dale un nombre (ej: AlertasRed)")
                print("  4. Copia el token (algo como 1234567890:ABCdef...)")
                print("\nPASO 2: Obtener Chat ID")
                print("  1. Busca @userinfobot en Telegram")
                print("  2. Envia cualquier mensaje")
                print("  3. Copia tu Chat ID")
                print("\nCONFIGURAR:")
                print("  Linux/Raspberry Pi:")
                print("    export TELEGRAM_BOT_TOKEN='tu_token'")
                print("    export TELEGRAM_CHAT_ID='tu_chat_id'")
                print("  Windows (PowerShell):")
                print("    $env:TELEGRAM_BOT_TOKEN='tu_token'")
                print("  Ejemplo una linea:")
                print("    TELEGRAM_BOT_TOKEN='xxx' TELEGRAM_CHAT_ID='xxx' sudo python3 agente_red.py")
                input("\nEnter para continuar...")
            
            elif opc == "2":
                print("\n[DISCORD]")
                print("Configura:")
                print("  export DISCORD_WEBHOOK_URL='https://discord.com/api/webhooks/...'")
                input("\nEnter para continuar...")
            
            elif opc == "3":
                print("\n[EMAIL]")
                print("Configura:")
                print("  export SMTP_SERVER='smtp.gmail.com'")
                print("  export SMTP_PORT='587'")
                print("  export SMTP_USER='tu@email.com'")
                print("  export SMTP_PASSWORD='tu_password'")
                print("  export FROM_EMAIL='tu@email.com'")
                print("  export TO_EMAIL='destino@email.com'")
                input("\nEnter para continuar...")
            
            elif opc == "4":
                print("\n[PROBAR ALERTAS]")
                print("Enviando mensaje de prueba a Telegram...")
                self.enviar_alerta_telegram("Prueba desde Agente de Seguridad Red")
            
            elif opc == "5":
                break
    
    def enviar_alerta_whatsapp(self, mensaje: str):
        """Envia alerta por WhatsApp"""
        if not hasattr(self, 'telefono_alerta') or not self.telefono_alerta:
            print("[INFO] WhatsApp no configurado. Usa opcion 5 para configurar.")
            return False
        
        try:
            from twilio.rest import Client
            import os
            
            account_sid = os.getenv('TWILIO_ACCOUNT_SID')
            auth_token = os.getenv('TWILIO_AUTH_TOKEN')
            from_number = os.getenv('TWILIO_WHATSAPP_FROM')
            
            if account_sid and auth_token:
                client = Client(account_sid, auth_token)
                message = client.messages.create(
                    from_=f'whatsapp:{from_number}',
                    body=mensaje,
                    to=f'whatsapp:{self.telefono_alerta}'
                )
                print(f"[WHATSAPP] Alerta enviada: {message.sid}")
                return True
        except Exception as e:
            print(f"[WHATSAPP] Error: {e}")
        
        try:
            api_key = os.getenv('WHATSAPP_API_KEY')
            if not api_key:
                print("[WHATSAPP] No configurado. Establece la variable WHATSAPP_API_KEY")
                print("           o usa Twilio con TWILIO_ACCOUNT_SID y TWILIO_AUTH_TOKEN")
                return False
            api_key = os.getenv('WHATSAPP_API_KEY')
            if api_key:
                url = "https://api.callmebot.com/whatsapp.php"
                params = {
                    'phone': self.telefono_alerta.replace('+', ''),
                    'text': mensaje,
                    'apikey': api_key
                }
                response = requests.get(url, params=params)
                if response.status_code == 200:
                    print(f"[WHATSAPP] Alerta enviada correctamente")
                    return True
        except Exception as e:
            pass
        
        print(f"[WHATSAPP] No se pudo enviar. Verifica la configuracion.")
        return False
    
    def detectar_deauth(self, interfaz: str = None, duracion: int = 10):
        """Detecta ataques Deauth en la red"""
        print(f"\n[DETECTOR DEAUTH - FLIPPER ZERO]")
        print(f"Duracion: {duracion} segundos")
        print(f"Numero de alerta: {getattr(self, 'telefono_alerta', 'No configurado')}")
        
        if self.sistema == "Linux":
            if not self._es_root():
                print(f"\n{Colores.ROJO}[ERROR] Se requieren permisos de root para detectar Deauth{Colores.RESET}")
                print(f"{Colores.AMARILLO}Ejecuta el programa con sudo:{Colores.RESET}")
                print(f"  sudo python3 {os.path.basename(__file__)}")
                return 0
        
        if self.sistema == "Windows":
            print(f"\n{Colores.ROJO}[AVISO] Windows no soporta modo monitor de forma nativa.{Colores.RESET}")
            print("Para usar en Windows necesitas un adaptador USB WiFi externo.")
            print("Usa la opción 'Ver adaptadores recomendados' en el menú.")
            if input("\n¿Continuar de todos modos? (s/n): ").lower() != 's':
                return 0
        
        elif self.sistema != "Linux" and self.sistema != "Darwin":
            print(f"\n{Colores.AMARILLO}[AVISO] Sistema no soportado para detector Deauth{Colores.RESET}")
            return 0
        
        try:
            from scapy.all import Dot11Deauth, Dot11, sniff
        except ImportError:
            print(f"\n{Colores.ROJO}[ERROR] Se requiere instalar scapy:{Colores.RESET}")
            print("  pip install scapy")
            if self.sistema == "Linux":
                print("  sudo apt install python3-scapy")
            return 0
        
        if not interfaz:
            print("\nInterfaces WiFi disponibles:")
            interfaces_wifi = self.obtener_interfaces_wifi()
            
            if interfaces_wifi:
                for i, iface in enumerate(interfaces_wifi):
                    estado = self.verificar_modo_monitor(iface["nombre"])
                    modo = "MONITOR" if estado["esta_en_modo_monitor"] else "managed"
                    soporte = "✓" if estado["soporta"] else "✗"
                    print(f"  {i+1}. {iface['nombre']} - Modo: {modo} {soporte}")
            else:
                print("  No se detectaron interfaces WiFi")
            
            print("\nNota: La interfaz debe estar en modo MONITOR para detectar paquetes Deauth")
            interfaz = input("Ingresa nombre de interfaz (ej: wlan0mon): ").strip()
        
        if self.sistema == "Linux":
            estado = self.verificar_modo_monitor(interfaz)
            if not estado["esta_en_modo_monitor"]:
                print(f"\n{Colores.AMARILLO}[AVISO] {estado['mensaje']}{Colores.RESET}")
                print("Usa la opción 'Activar modo monitor' en el menú primero.")
                if input("\n¿Continuar de todos modos? (s/n): ").lower() != 's':
                    return 0
        
        print(f"\n[*] Monitoreando {interfaz} por {duracion} segundos...")
        print("[*] Presiona Ctrl+C para detener\n")
        
        deauth_count = 0
        dispositivos = set()
        
        def procesar_paquete(pkt):
            nonlocal deauth_count, dispositivos
            
            if pkt.haslayer(Dot11Deauth):
                deauth_count += 1
                try:
                    mac = pkt[Dot11].addr2
                    dispositivos.add(mac)
                except:
                    mac = "Unknown"
                
                if deauth_count == 1:
                    mac_vendor = self.identificar_dispositivo(mac)
                    vendor_name = mac_vendor.get('marca', 'Desconocido')
                    print(f"[ALERTA] Paquete Deauth detectado!")
                    print(f"   MAC: {mac}")
                    print(f"   Fabricante: {vendor_name}")
                    
                    mensaje = f"ALERTA DEAUTH!\n"
                    mensaje += f"Dispositivo: {mac}\n"
                    mensaje += f"Fabricante: {vendor_name}\n"
                    mensaje += f"Red: {self.obtener_ip_local()}\n"
                    mensaje += f"Posible Flipper Zero!"
                    self.enviar_alerta_telegram(mensaje)
        
        try:
            sniff(iface=interfaz, prn=procesar_paquete, timeout=duracion)
        except Exception as e:
            print(f"\n[ERROR] al iniciar sniffing: {e}")
            return 0
        
        print(f"\n[RESULTADO]")
        print(f"Paquetes Deauth: {deauth_count}")
        print(f"Dispositivos sospechosos: {len(dispositivos)}")
        
        if deauth_count > 0:
            print("\n[ATAQUE DEAUTH DETECTADO!]")
            print("Posibles causas:")
            print("  - Flipper Zero")
            print("  - Herramienta de deauth")
            print("  - Router configurado incorrectamente")
            
            mensaje = f"RESUMEN DEAUTH\n"
            mensaje += f"Paquetes: {deauth_count}\n"
            mensaje += f"Dispositivos: {len(dispositivos)}"
            self.enviar_alerta_telegram(mensaje)
        else:
            print("\n[OK] No se detectaron ataques Deauth")
        
        return deauth_count
    
    def modo_monitor(self):
        """Activa el modo monitor para detectar ataques"""
        while True:
            print("""
================================================================================
         MODO MONITOR - DETECTOR DEAUTH (FLIPPER ZERO)
================================================================================

Este modo detecta ataques de desautenticacion WiFi
comunmente usados por Flipper Zero y otras herramientas.

Requerimientos:
- Tarjeta WiFi que soporte modo monitor
- Linux (recomendado) o Mac con permisos de root

Opciones:
1. Ver interfaces WiFi y compatibilidad
2. Activar modo monitor en interfaz
3. Desactivar modo monitor (volver a Managed)
4. Ver estado de modo monitor
5. Iniciar detector Deauth (10 segundos)
6. Iniciar detector Deauth (60 segundos)
7. Configurar alertas (Telegram/WhatsApp)
8. Ayuda - Ver adaptadores recomendados
9. Volver al menu principal

================================================================================
Sistema detectado: {}
================================================================================
""".format(self.sistema))
            print("Selecciona una opcion (1-9): ", end="")
            opc = input()
            
            if opc == "1":
                self.mostrar_interfaces_wifi()
            elif opc == "2":
                interfaces = self.mostrar_interfaces_wifi()
                if interfaces:
                    print(f"\n{Colores.AZUL}Selecciona interfaz para activar modo monitor:{Colores.RESET}")
                    for i, iface in enumerate(interfaces, 1):
                        print(f"  {i}. {iface['nombre']}")
                    try:
                        idx = int(input("\nNumero: ")) - 1
                        if 0 <= idx < len(interfaces):
                            interfaz = interfaces[idx]['nombre']
                            print(f"\n{Colores.AMARILLO}Activando modo monitor en {interfaz}...{Colores.RESET}")
                            if self.activar_modo_monitor(interfaz):
                                print(f"{Colores.VERDE}[OK] Modo monitor activado{Colores.RESET}")
                            else:
                                print(f"{Colores.ROJO}[ERROR] No se pudo activar modo monitor{Colores.RESET}")
                    except ValueError:
                        pass
            elif opc == "3":
                self.desactivar_modo_monitor()
            elif opc == "4":
                self.ver_estado_modo_monitor()
            elif opc == "5":
                self.detectar_deauth(duracion=10)
            elif opc == "6":
                self.detectar_deauth(duracion=60)
            elif opc == "7":
                self.configurar_alertas()
            elif opc == "8":
                self._mostrar_adaptadores_recomendados()
            elif opc == "9":
                break
            
            input(f"\n{Colores.AMARILLO}Enter para continuar...{Colores.RESET}")
    
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
                self.modo_monitor()
            elif opcion == "10":
                print(f"\n{Colores.VERDE}Gracias!{Colores.RESET}")
                break
            else:
                print(f"{Colores.ROJO}Opcion invalida{Colores.RESET}")
            
            input(f"\n{Colores.AMARILLO}Enter...{Colores.RESET}")
            self.limpiar_pantalla()
    
    # ==================== FUNCIONES AVANZADAS DE WI-FI ====================
    
    def gestion_modo_monitor_airmon(self, interfaz: str, accion: str) -> Dict:
        """Gestiona el modo monitor usando airmon-ng (Linux)"""
        resultado = {"exito": False, "interfaz_nueva": interfaz, "mensaje": ""}
        
        if self.sistema != "Linux":
            resultado["mensaje"] = "airmon-ng solo disponible en Linux"
            return resultado
        
        try:
            if accion == "start":
                proceso = subprocess.run(
                    ["airmon-ng", "start", interfaz],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if proceso.returncode == 0:
                    interfaz_mon = f"{interfaz}mon"
                    resultado["exito"] = True
                    resultado["interfaz_nueva"] = interfaz_mon
                    resultado["mensaje"] = f"Modo monitor activado: {interfaz_mon}"
                    logger.info(f"airmon-ng: Modo monitor activado en {interfaz_mon}")
                else:
                    resultado["mensaje"] = f"Error: {proceso.stderr}"
            
            elif accion == "stop":
                proceso = subprocess.run(
                    ["airmon-ng", "stop", interfaz],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if proceso.returncode == 0:
                    resultado["exito"] = True
                    resultado["mensaje"] = f"Modo monitor desactivado: {interfaz}"
                    logger.info(f"airmon-ng: Modo monitor desactivado en {interfaz}")
                else:
                    resultado["mensaje"] = f"Error: {proceso.stderr}"
        
        except FileNotFoundError:
            resultado["mensaje"] = "airmon-ng no instalado. Instala: apt install aircrack-ng"
        except Exception as e:
            resultado["mensaje"] = f"Error: {e}"
            logger.error(f"Error en airmon-ng: {e}")
        
        return resultado
    
    def escanear_wifi_avanzado(self, interfaz: str, duracion: int = 30) -> List[Dict]:
        """Escaneo avanzado de redes WiFi (como airodump)"""
        redes = []
        
        try:
            from scapy.all import Dot11, Dot11Beacon, Dot11ProbeResp, sniff
            
            def procesar_paquete(pkt):
                if pkt.haslayer(Dot11Beacon):
                    try:
                        ssid = pkt[Dot11Beacon].info.decode('utf-8', errors='ignore')
                        bssid = pkt[Dot11].addr2
                        canal = ord(pkt[Dot11Beacon].network_status) if hasattr(pkt[Dot11Beacon], 'network_status') else 0
                        seguridad = "WPA2" if pkt[Dot11Beacon].cap & 0x0010 else "WEP" if pkt[Dot11Beacon].cap & 0x0010 else "Open"
                        
                        if not any(r['bssid'] == bssid for r in redes):
                            redes.append({
                                "ssid": ssid,
                                "bssid": bssid,
                                "canal": canal,
                                "senal": -50,
                                "seguridad": seguridad
                            })
                    except:
                        pass
                
                elif pkt.haslayer(Dot11ProbeResp):
                    try:
                        ssid = pkt[Dot11ProbeResp].info.decode('utf-8', errors='ignore')
                        bssid = pkt[Dot11].addr2
                        
                        if not any(r['bssid'] == bssid for r in redes):
                            redes.append({
                                "ssid": ssid,
                                "bssid": bssid,
                                "canal": 0,
                                "senal": -50,
                                "seguridad": "Open"
                            })
                    except:
                        pass
            
            print(f"[*] Escaneando redes WiFi por {duracion} segundos...")
            sniff(iface=interfaz, prn=procesar_paquete, timeout=duracion)
            
        except ImportError:
            print(f"{Colores.ROJO}Error: Se requiere scapy{Colores.RESET}")
        except Exception as e:
            print(f"{Colores.ROJO}Error en escaneo: {e}{Colores.RESET}")
        
        return redes
    
    def detectar_ataques_wifi_avanzados(self, interfaz: str, duracion: int = 30) -> Dict:
        """Detecta múltiples tipos de ataques WiFi"""
        resultado = {
            "deauth": {"detectado": False, "cantidad": 0, "dispositivos": []},
            "disassoc": {"detectado": False, "cantidad": 0, "dispositivos": []},
            "beacon_flood": {"detectado": False, "cantidad": 0, "ssids": []},
            "probe_flood": {"detectado": False, "cantidad": 0, "dispositivos": []},
            "resumen": []
        }
        
        try:
            from scapy.all import Dot11, Dot11Deauth, Dot11Disasoc, Dot11Beacon, Dot11ProbeReq, sniff
            
            deauth_count = 0
            disassoc_count = 0
            beacon_count = 0
            probe_count = 0
            dispositivos_deauth = set()
            ssids_beacon = set()
            dispositivos_probe = set()
            
            def procesar_paquete(pkt):
                nonlocal deauth_count, disassoc_count, beacon_count, probe_count
                
                # Deauth
                if pkt.haslayer(Dot11Deauth):
                    deauth_count += 1
                    try:
                        dispositivos_deauth.add(pkt[Dot11].addr2)
                    except:
                        pass
                
                # Disassoc
                if pkt.haslayer(Dot11Disasoc):
                    disassoc_count += 1
                    try:
                        dispositivos_deauth.add(pkt[Dot11].addr2)
                    except:
                        pass
                
                # Beacon Flood (muchos beacon en poco tiempo)
                if pkt.haslayer(Dot11Beacon):
                    beacon_count += 1
                    try:
                        ssid = pkt[Dot11Beacon].info.decode('utf-8', errors='ignore')
                        ssids_beacon.add(ssid)
                    except:
                        pass
                
                # Probe Request Flood
                if pkt.haslayer(Dot11ProbeReq):
                    probe_count += 1
                    try:
                        dispositivos_probe.add(pkt[Dot11].addr2)
                    except:
                        pass
            
            print(f"[*] Monitoreando ataques por {duracion} segundos...")
            sniff(iface=interfaz, prn=procesar_paquete, timeout=duracion)
            
            # Analizar resultados
            if deauth_count > 5:
                resultado["deauth"]["detectado"] = True
                resultado["deauth"]["cantidad"] = deauth_count
                resultado["deauth"]["dispositivos"] = list(dispositivos_deauth)
                resultado["resumen"].append(f"ATAQUE DEAUTH: {deauth_count} paquetes")
            
            if disassoc_count > 5:
                resultado["disassoc"]["detectado"] = True
                resultado["disassoc"]["cantidad"] = disassoc_count
                resultado["disassoc"]["dispositivos"] = list(dispositivos_deauth)
                resultado["resumen"].append(f"ATAQUE DISASSOC: {disassoc_count} paquetes")
            
            if beacon_count > 50:
                resultado["beacon_flood"]["detectado"] = True
                resultado["beacon_flood"]["cantidad"] = beacon_count
                resultado["beacon_flood"]["ssids"] = list(ssids_beacon)[:10]
                resultado["resumen"].append(f"BEACON FLOOD: {beacon_count} paquetes")
            
            if probe_count > 20:
                resultado["probe_flood"]["detectado"] = True
                resultado["probe_flood"]["cantidad"] = probe_count
                resultado["probe_flood"]["dispositivos"] = list(dispositivos_probe)
                resultado["resumen"].append(f"PROBE FLOOD: {probe_count} paquetes")
            
        except ImportError:
            print(f"{Colores.ROJO}Error: Se requiere scapy{Colores.RESET}")
        except Exception as e:
            print(f"{Colores.ROJO}Error en detección: {e}{Colores.RESET}")
        
        return resultado
    
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
    try:
        AgenteSeguridadRed().ejecutar()
    except KeyboardInterrupt:
        print("\nAdios!")
    except Exception as e:
        print(f"Error: {e}")
