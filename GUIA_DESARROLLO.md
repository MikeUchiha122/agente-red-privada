# 📚 GUÍA DE DESARROLLO
## Agente de Seguridad de Red v3.0

---

## 1. Visión General del Proyecto

### 1.1 Descripción

El **Agente de Seguridad de Red** es una herramienta de análisis de seguridad de red local desarrollada en Python. Su propósito es:

1. **Descubrir dispositivos** conectados a una red doméstica o de oficina
2. **Identificar fabricantes** de dispositivos mediante sus direcciones MAC
3. **Detectar vulnerabilidades** como puertos abiertos, servicios inseguros, malware de minería
4. **Generar informes** detallados con recomendaciones de seguridad

### 1.2 Arquitectura

```
┌─────────────────────────────────────────────────────────────┐
│                    AGENTE DE SEGURIDAD RED                  │
├─────────────────────────────────────────────────────────────┤
│  Módulo de Escaneo (NMAP/Sockets/Ping)                    │
│  ├── Escaneo de red (descubrir hosts)                      │
│  ├── Escaneo de puertos                                    │
│  └── Identificación de servicios                           │
├─────────────────────────────────────────────────────────────┤
│  Módulo de Análisis                                         │
│  ├── Identificación de dispositivos (MAC)                 │
│  ├── Detección de amenazas                                 │
│  └── Generación de informes                                │
├─────────────────────────────────────────────────────────────┤
│  Módulo de Alertas (Opcional)                               │
│  ├── WhatsApp (Twilio/CallMeBot)                          │
│  └── Logging estructurado                                  │
└─────────────────────────────────────────────────────────────┘
```

### 1.3 Tecnologías Usadas

| Tecnología | Uso |
|-----------|-----|
| Python 3.8+ | Lenguaje principal |
| python-nmap | Escaneo avanzado de puertos |
| scapy | Captura de paquetes (modo monitor) |
| requests | Consultas HTTP a APIs |
| socket | Escaneo de puertos básico |
| concurrent.futures | Escaneo paralelo |

---

## 2. Estructura del Código

### 2.1 Archivos del Proyecto

```
agente-red-privada/
├── agente_red.py           # Programa principal (1200+ líneas)
├── escanear_rapido.py      # Script de ejecución automática
├── test_agente_red.py      # Suite de pruebas unitarias (44 tests)
├── MANUAL_USUARIO.md       # Manual para usuarios finales
├── GUIA_DESARROLLO.md      # Este archivo
├── README.md               # Documentación general
├── requirements.txt        # Dependencias
└── agente_seguridad.db     # Base de datos SQLite
```

---

## 3. Análisis del Código Fuente

### 3.1 Imports y Configuración Inicial

```python
#!/usr/bin/env python3
"""
Agente de Seguridad de Red v3.0 - OPTIMIZADO
Asistente de IA para analisis de seguridad de red local

Compatible con: Windows, Linux, macOS
"""
```

**Propósito**: Shebang y docstring del módulo que indica:
- Nombre del programa
- Versión (v3.0 - OPTIMIZADO)
- Propósito (asistente de análisis de seguridad)
- Compatibilidad (Windows, Linux, macOS)

---

```python
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
```

**Imports organizados por categoría:**

| Categoría | Módulos | Propósito |
|-----------|---------|-----------|
| Sistema | os, sys, platform | Operaciones del sistema |
| Red | socket, subprocess | Conexiones y comandos |
| Datos | json, datetime | Serialización y fechas |
| Utilidades | re, ipaddress | Regex y IPs |
| Concurrencia | concurrent.futures | Hilos paralelos |
| HTTP | requests | Consultas a APIs |
| Logging | logging | Registro de operaciones |
| Tipos | typing | Type hints |

---

```python
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
```

**Propósito**: Configurar el sistema de logging para:
- Registrar todas las operaciones en `agente_seguridad.log`
- Mostrar mensajes en consola
- Manejar el caso donde no se puede escribir en el directorio actual (evitar errores en tests)

**Mejora respecto a versión anterior**: El código anterior solo usaba `print()` lo cual no es apropiaddo para producción.

---

```python
# Cache para evitar consultas repetidas a macvendors.com
_MAC_CACHE: Dict[str, str] = {}
```

**Propósito**: Cache global para almacenar resultados de consultas a la API de macvendors.com.

**Ventaja**: Evita consultas repetidas para el mismo OUI, reduciendo latencia y uso de la API.

---

```python
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
```

**Propósito**: 
1. Buscar la instalación de NMAP en rutas comunes de Windows
2. Agregar NMAP al PATH del sistema
3. Intentar importar y verificar que NMAP funciona
4. Establecer la variable global `NMAP_DISPONIBLE`

**Manejo de errores**:
- `ImportError`: NMAP no instalado
- `Exception`: Error al inicializar (ej: timeout)

**Fallback**: Si NMAP no está disponible, el programa usa sockets y ping como alternativa.

---

### 3.2 Clases de Datos

```python
class Colores:
    VERDE = ''
    ROJO = ''
    AMARILLO = ''
    AZUL = ''
    RESET = ''
    NEGRITA = ''
```

**Propósito**: Clase de constantes para colorar la salida de consola.

**Nota**: Actualmente está vacía (cadenas vacías). Podría implementarse usando códigos ANSI para colores.

---

```python
class DispositivoBaseDatos:
    MARCAS = {
        # VMs y Dispositivos Virtuales
        "00:50:56": "VMware", "00:0C:29": "VMware", "08:00:27": "VirtualBox",
        "00:15:5D": "Hyper-V", "00:03:FF": "Microsoft Virtual",
        # Raspberry Pi
        "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi 4", "E4:5F:01": "Raspberry Pi",
        # Apple
        "68:A4:0E": "Apple", "F0:18:98": "Apple", "A4:83:E7": "Apple", "3C:06:30": "Apple",
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
        # Dispositivos IoT
        "AC:CF:85": "ESP8266/ESP32", "24:D7:EB": "ESP8266", "5C:CF:7F": "ESP8266",
        # Dispositivos observados
        "00:00:CA": "Commscope",
        "1A:5B:9D": "Private/Unknown",
        "3A:92:AA": "Private/Unknown",
    }
```

**Propósito**: Base de datos de prefijos OUI (primeros 6 dígitos de MAC) para identificar fabricantes.

**Organización**:
- VMs y dispositivos virtuales
- Raspberry Pi
- Apple
- Samsung
- Dispositivos de red (routers, switches)
- IoT (ESP8266, ESP32)
- Dispositivos observados en escaneos reales

---

```python
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
```

**Propósito**: Base de datos de amenazas conocidas con:
- **Puertos**: Lista de puertos asociados a la amenaza
- **descripcion**: Explicación de qué es la amenaza
- **nivel**: Riesgo (alto, medio, bajo)
- **simbolo**: Código visual para mostrar en pantalla

---

### 3.3 Funciones Auxiliares

```python
def consultar_mac_vendor(mac: str) -> str:
    """Consulta macvendors.com para obtener el fabricante de una MAC"""
    if not mac:
        return "Unknown"
    
    # Limpiar la MAC: quitar dos puntos y guiones, convertir a mayúsculas
    mac_limpia = mac.upper().replace(':', '').replace('-', '')
    if len(mac_limpia) < 6:
        return "Unknown"
    
    # Obtener el OUI (primeros 6 caracteres)
    oui = mac_limpia[:6]
    
    # Verificar si ya tenemos el resultado en cache
    if oui in _MAC_CACHE:
        return _MAC_CACHE[oui]
    
    try:
        # Consultar la API de macvendors.com
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
```

**Propósito**: Consultar la API de macvendors.com para obtener el fabricante de una MAC unknown.

**Algoritmo**:
1. Validar que la MAC no esté vacía
2. Limpiar la MAC (quitar separadores)
3. Extraer el OUI (primeros 6 caracteres)
4. Verificar cache (evitar consultas repetidas)
5. Consultar la API con timeout de 5 segundos
6. Cachear el resultado
7. Devolver "Unknown" si no se encuentra

---

### 3.4 Clase Principal: AgenteSeguridadRed

```python
class AgenteSeguridadRed:
    def __init__(self):
        self.sistema = platform.system()  # Windows, Linux, Darwin
        self.dispositivos_encontrados = []  # Lista de dispositivos
        self.historial_analisis = []  # Historial de escaneos
        self.nm = nmap.PortScanner() if NMAP_DISPONIBLE else None
        self.MAX_TRABAJADORES = 50  # Hilos paralelos
```

**Atributos de instancia:**
- `sistema`: Sistema operativo (importante para comandos específicos)
- `dispositivos_encontrados`: Almacena el último escaneo
- `historial_analisis`: Lista de todos los escaneos realizados
- `nm`: Instancia de NMAP (None si no está disponible)
- `MAX_TRABAJADORES`: Número de hilos para escaneo paralelo

---

```python
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
```

**Propósito**: Obtener la dirección IP local de la máquina.

**Cómo funciona**:
1. Crea un socket UDP (no necesita conectarse realmente)
2. Conecta a un servidor externo (8.8.8.8:80)
3. Obtiene la IP local del socket
4. Usa context manager (`with`) para cerrar automáticamente

**Manejo de errores**: Si falla, devuelve 127.0.0.1 como fallback.

---

```python
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
                # Parsear la salida del comando route
                for linea in resultado.stdout.split('\n'):
                    if '0.0.0.0' in linea and '192.168.' in linea:
                        for parte in linea.split():
                            if parte.startswith('192.168.'):
                                logger.debug(f"Gateway Windows: {parte}")
                                return parte
            except (subprocess.SubprocessError, OSError) as e:
                logger.error(f"Error al obtener gateway en Windows: {e}")
        else:
            # Linux/Mac: usar el comando ip
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
```

**Propósito**: Encontrar la IP del router/gateway de la red.

**Diferencias por sistema**:
- **Windows**: Usa el comando `route print` y busca la línea con 0.0.0.0 y 192.168.x.x
- **Linux/Mac**: Usa `ip route show default` y extrae la IP con regex

---

```python
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
```

**Propósito**: Calcular todas las IPs disponibles en una red.

**Usa**: Módulo `ipaddress` de Python para cálculos precisos de red.

**Ejemplo**: Para 192.168.0.1/24 devuelve 192.168.0.1 a 192.168.0.254

---

```python
    def identificar_dispositivo(self, mac: str) -> Dict:
        """Identifica el fabricante y tipo de dispositivo por su MAC"""
        if not mac:
            return {"tipo": "Desconocido", "marca": "Unknown", "categoria": "unknown"}
        
        mac_prefix = mac.replace(':', '').upper()[:6]
        
        # 1. Buscar en la base de datos local
        for prefijo, desc in DispositivoBaseDatos.MARCAS.items():
            prefijo_limpio = prefijo.replace(':', '').upper()
            if prefijo_limpio == mac_prefix:
                # Determinar categoría (router vs computadora)
                cat = "router" if "Router" in desc or "Cisco" in desc or "Netgear" in desc or "TP-Link" in desc else "computadora"
                return {"tipo": "Dispositivo", "marca": desc, "categoria": cat}
        
        # 2. Si no encuentra, consultar macvendors.com
        vendor = consultar_mac_vendor(mac)
        
        if vendor != "Unknown":
            cat = "router" if any(r in vendor.lower() for r in ["router", "gateway", "cisco", "netgear", "tp-link", "linksys", "ubiquiti"]) else "dispositivo"
            return {"tipo": "Dispositivo", "marca": vendor, "categoria": cat}
        
        return {"tipo": "Desconocido", "marca": "Unknown", "categoria": "unknown"}
```

**Propósito**: Identificar el fabricante y tipo de dispositivo.

**Algoritmo de 3 pasos**:
1. Verificar si la MAC está en la base de datos local
2. Si no, consultar macvendors.com
3. Si neither works, return "Unknown"

**Categorización**: Los routers se identifican por palabras clave en el nombre del fabricante.

---

```python
    def detectar_amenazas(self, puertos: List[int]) -> Dict:
        """Detecta amenazas basadas en puertos abiertos"""
        amenazas = {"encontradas": [], "nivel": "bajo", "emoji": "[OK]"}
        puertos_set = set(puertos)
        
        # Verificar cada amenaza en la base de datos
        for nombre, datos in AmenazaBaseDatos.AMENAZAS.items():
            if any(p in puertos_set for p in datos["puertos"]):
                amenazas["encontradas"].append({
                    "tipo": nombre,
                    "descripcion": datos["descripcion"],
                    "nivel": datos["nivel"],
                    "simbolo": datos["simbolo"],
                    "puertos": [p for p in puertos_set if p in datos["puertos"]]
                })
        
        # Determinar el nivel de amenaza overall
        if any(a["nivel"] == "alto" for a in amenazas["encontradas"]):
            amenazas["nivel"] = "alto"
            amenazas["emoji"] = "[PELIGRO]"
        elif any(a["nivel"] == "medio" for a in amenazas["encontradas"]):
            amenazas["nivel"] = "medio"
            amenazas["emoji"] = "[CUIDADO]"
        
        return amenazas
```

**Propósito**: Analizar los puertos abiertos y detectar amenazas de seguridad.

**Algoritmo**:
1. Crear un set de los puertos para búsqueda O(1)
2. Por cada amenaza en la DB, verificar si alguno de sus puertos está abierto
3. Agregar las amenazas encontradas a la lista
4. Determinar el nivel overall (si hay amenazas alto = alto, sino medio = medio)

---

### 3.5 Métodos de Escaneo

```python
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
```

**Propósito**: Verificar si una IP está activa usando ping.

**Diferencias Windows/Linux**:
- Windows: usa `-n 1` (número de pings)
- Linux/Mac: usa `-c 1` (count)

---

```python
    def escanear_puerto_rapido(self, ip: str, puerto: int) -> bool:
        """Verifica si un puerto está abierto en una IP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.2)  # 200ms timeout
                resultado = sock.connect_ex((ip, puerto))
            return resultado == 0
        except OSError as e:
            logger.debug(f"Error escaneo puerto {puerto} en {ip}: {e}")
            return False
```

**Propósito**: Verificar si un puerto específico está abierto.

**Usa**: Socket TCP con timeout de 200ms.

---

```python
    def escanear_red_local(self) -> List[Dict]:
        """Escanea toda la red local en busca de dispositivos"""
        print(f"\n{Colores.AZUL}{Colores.NEGRITA}[BUSCAR] ESCANEANDO TU RED (MODO RAPIDO)...{Colores.RESET}\n")
        
        ip_local = self.obtener_ip_local()
        gateway = self.obtener_gateway()
        
        print(f"Tu IP: {ip_local}")
        print(f"Tu Router: {gateway}")
        
        if NMAP_DISPONIBLE:
            # ===== MODO NMAP =====
            print("\nEscaneo rapido con NMAP...\n")
            
            try:
                rango = f"{ip_local.rsplit('.', 1)[0]}.0/24"
                # Escaneo SYN rápido (-sn: solo detección, sin puertos)
                self.nm.scan(hosts=rango, arguments="-sn -T5 --max-retries 1", timeout=30)
                
                hosts = self.nm.all_hosts()
                print(f"Dispositivos encontrados: {len(hosts)}")
                
                # Escanear puertos en paralelo usando ThreadPoolExecutor
                dispositivos = []
                
                def escanear_host(host):
                    return self.escanear_nmap_rapido(host)
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    resultados = list(executor.map(escanear_host, hosts))
                
                # Procesar resultados
                for scan in resultados:
                    if scan.get("estado") == "up":
                        # Obtener MAC usando ARP
                        mac = self._obtener_mac(scan["ip"])
                        dispositivo_info = self.identificar_dispositivo(mac)
                        amenazas = self.detectar_amenazas(scan.get("puertos", []))
                        
                        dispositivo = {
                            "ip": scan["ip"],
                            "mac": mac,
                            "estado": "up",
                            "sistema": "Desconocido",
                            "puertos": scan.get("puertos", []),
                            "servicios": scan.get("servicios", {}),
                            "dispositivo": dispositivo_info,
                            "amenazas": amenazas,
                            "fecha": datetime.now().isoformat(),
                            "es_gateway": scan["ip"] == gateway
                        }
                        dispositivos.append(dispositivo)
                        print(f"  {amenazas['emoji']} {scan['ip']} - {dispositivo_info['marca']}")
                
                self.dispositivos_encontrados = dispositivos
                print(f"\n{Colores.VERDE}[OK] Escaneo completado: {len(dispositivos)} dispositivos{Colores.RESET}")
                return dispositivos
                
            except Exception as e:
                logger.error(f"Error en escaneo NMAP: {e}")
        
        # ===== MODO FALLBACK (sin NMAP) =====
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
```

**Propósito**: El método principal de escaneo de red.

**Dos modos de operación**:
1. **Modo NMAP** (preferido): Más rápido y preciso, usa escaneo SYN
2. **Modo Fallback**: Usa ping y sockets si NMAP no está disponible

**Optimizaciones**:
- Uso de `ThreadPoolExecutor` para escaneo paralelo
- Límite de 20 workers para NMAP, 50 para fallback
- Timeout configurados para no bloquear

---

### 3.6 Generación de Informes

```python
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
```

**Propósito**: Generar explicación detallada de la MAC para el informe.

**Información incluida**:
- La MAC completa
- El OUI (prefijo)
- Posibles causas si es Unknown
- Fabricante si se identificó

---

```python
    def _analizar_puertos(self, puertos: List[int], servicios: Dict) -> str:
        """Analiza los puertos abiertos y sus servicios"""
        if not puertos:
            return "  - Sin puertos abiertos detectados"
        
        info = [f"  - Puertos abiertos: {len(puertos)}"]
        
        # Diccionario de puertos comunes con descripciones
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
        }
        
        for puerto in puertos:
            servicio = servicios.get(puerto, {}).get('nombre', 'desconocido')
            desc = PUERTOS_COMUNES.get(puerto, "")
            info.append(f"    * {puerto}/tcp -> {servicio}" + (f" ({desc})" if desc else ""))
        
        return "\n".join(info)
```

**Propósito**: Proporcionar información detallada de cada puerto abierto.

**Incluye**:
- Número total de puertos
- Puerto + servicio detectado
- Descripción del servicio (qué hace)

---

```python
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
```

**Propósito**: Generar recomendaciones de seguridad específicas para cada dispositivo.

**Tipos de recomendaciones**:
- Por tipo de dispositivo (router vs computadora)
- Por puertos abiertos (Telnet, FTP, SMB, RDP)
- Por amenazas detectadas (minería)
- Por MAC no identificada

---

```python
    def generar_informe(self, dispositivo: Dict) -> str:
        """Genera un informe de seguridad detallado para un dispositivo"""
        # ... (reune toda la información y formatea)
        return f"""
================================================================================
                    INFORME DE SEGURIDAD - DISPOSITIVO
================================================================================
...
"""
```

**Propósito**: Generar el informe final combinando todas las funciones anteriores.

---

## 4. Sistema de Logging

### 4.1 Niveles de Log

| Nivel | Uso |
|-------|-----|
| DEBUG | Información detallada para debugging |
| INFO | Eventos normales del sistema |
| WARNING | Algo no预期 pero no crítico |
| ERROR | Errores que afectan funcionalidad |
| CRITICAL | Errores graves que requieren atención inmediata |

### 4.2 Archivos de Log

- `agente_seguridad.log` - Log principal de operaciones

---

## 5. Pruebas

### 5.1 Suite de Tests (test_agente_red.py)

```python
class TestValidadores(unittest.TestCase):
    def test_validar_ip_valida(self):
        from agente_red import AgenteSeguridadRed
        agente = AgenteSeguridadRed()
        self.assertTrue(agente._validar_ip("192.168.1.1"))

class TestIdentificacion(unittest.TestCase):
    def test_identificar_apple(self):
        from agente_red import AgenteSeguridadRed
        agente = AgenteSeguridadRed()
        resultado = agente.identificar_dispositivo("68:A4:0E:AA:BB:CC")
        self.assertIn("Apple", resultado["marca"])

class TestDeteccionAmenazas(unittest.TestCase):
    def test_detectar_telnet(self):
        from agente_red import AgenteSeguridadRed
        agente = AgenteSeguridadRed()
        resultado = agente.detectar_amenazas([23])
        self.assertTrue(len(resultado["encontradas"]) > 0)
```

**Tests incluidos**:
- Validación de IPs
- Identificación de dispositivos
- Detección de amenazas
- Cálculo de red
- Generación de informes

---

## 6. Mejores Prácticas Implementadas

### 6.1 Manejo de Errores

```python
# ❌ MALO: Exceptor vacío
except:
    pass

# ✅ BUENO: Excepción específica
except OSError as e:
    logger.error(f"Error de red: {e}")

# ✅ MUY BUENO: Multiple exceptions
except (subprocess.SubprocessError, OSError) as e:
    logger.error(f"Error al obtener gateway: {e}")
```

### 6.2 Context Managers

```python
# ❌ MALO: Cerrar manualmente
sock = socket.socket(...)
sock.connect(...)
sock.close()  # Se puede olvidar

# ✅ BUENO: Context manager
with socket.socket(...) as sock:
    sock.connect(...)
# Se cierra automáticamente
```

### 6.3 Type Hints

```python
# ✅ BUENO: Type hints completos
def escanear_puerto_rapido(self, ip: str, puerto: int) -> bool:
    ...

# ✅ BUENO: Imports de typing
from typing import List, Dict, Optional, Tuple

_MAC_CACHE: Dict[str, str] = {}
```

### 6.4 Docstrings

```python
# ✅ BUENO: Docstrings en funciones públicas
def obtener_ip_local(self) -> str:
    """Obtiene la direccion IP local de la máquina"""
    ...
```

---

## 7. Future Enhancements

Posibles mejoras para versiones futuras:

1. **Interfaz Gráfica (GUI)**: Usar Tkinter o PyQt
2. **Base de datos**: SQLite para historial persistente
3. **Notificaciones**: Email, Telegram, Discord
4. **Escaneo programado**: Cron jobs para escaneos automáticos
5. **Reportes HTML**: Generar reportes visuales
6. **Integración con router**: API del router para ver clientes

---

## 8. Contribuir al Proyecto

### Pasos para contribuir:

1. Fork del repositorio
2. Crear una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit de cambios (`git commit -m 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear un Pull Request

### Estándares de código:
- Usar type hints
- Agregar docstrings
- Mantener compatibilidad con Python 3.8+
- Agregar tests para nuevas funcionalidades

---

## 9. Funciones Avanzadas de WiFi

### 9.1 Gestión de Modo Monitor (airmon-ng)

```python
def gestion_modo_monitor_airmon(self, interfaz: str, accion: str) -> Dict:
    """Gestiona el modo monitor usando airmon-ng (Linux)"""
```

**Propósito**: Usa airmon-ng para activar/desactivar modo monitor

**Acciones**: `start` | `stop`

**Retorna**: `{exito, interfaz_nueva, mensaje}`

---

### 9.2 Escaneo WiFi Avanzado

```python
def escanear_wifi_avanzado(self, interfaz: str, duracion: int = 30) -> List[Dict]:
    """Escaneo avanzado de redes WiFi (como airodump)"""
```

**Retorna**: Lista de redes con:
- `ssid`: Nombre de la red
- `bssid`: MAC del router
- `canal`: Canal WiFi
- `senal`: Intensidad de señal
- `seguridad`: Tipo (WPA2/WEP/Open)

---

## 10. Sistema de Alertas

### 10.1 Alertas Múltiples

| Método | Función | Variable de entorno |
|--------|---------|---------------------|
| WhatsApp | `enviar_alerta_whatsapp()` | `TWILIO_*`, `WHATSAPP_API_KEY` |
| Telegram | `enviar_alerta_telegram()` | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` |
| Discord | `enviar_alerta_discord()` | `DISCORD_WEBHOOK_URL` |
| Email | `enviar_alerta_email()` | `SMTP_*`, `FROM_EMAIL`, `TO_EMAIL` |

### 10.2 Alerta Multiple

```python
def enviar_alerta_multiple(self, mensaje: str) -> None:
    """Envía alerta a todos los canales configurados"""
```

---

## 11. Base de Datos SQLite

### 11.1 Inicialización

```python
def inicializar_base_datos(self) -> bool:
    """Inicializa la base de datos SQLite para logging"""
```

**Tablas creadas**:
- `escaneos`: Registro de escaneos
- `alertas`: Historial de alertas
- `dispositivos`: Dispositivos únicos

### 11.2 Métodos de Logging

```python
def guardar_escaneo_db(self, tipo: str, dispositivos: int, amenazas: int, detalles: str) -> None
def guardar_alerta_db(self, tipo: str, mensaje: str, canal: str) -> None
def ver_estadisticas(self) -> None
```

---

## 12. Tests

### Total de Tests: 44

| Clase | Tests | Descripción |
|-------|-------|-------------|
| TestNMAPImport | 1 | Verifica NMAP |
| TestValidadores | 2 | IPs válidas/inválidas |
| TestIdentificacion | 3 | MAC de dispositivos |
| TestDeteccionAmenazas | 4 | Detección de amenazas |
| TestCalculoRed | 1 | Cálculo de red |
| TestInforme | 1 | Generación de informes |
| TestInterfacesWiFi | 4 | Interfaces WiFi |
| TestAnalisisInformes | 11 | Análisis detallado |
| TestFuncionesAvanzadas | 12 | Funciones avanzadas |

---

## 13. Variables de Entorno

```bash
# Redes
NMAP_PATH=caminho/a/nmap

# WhatsApp
TWILIO_ACCOUNT_SID=xxx
TWILIO_AUTH_TOKEN=xxx
TWILIO_WHATSAPP_FROM=whatsapp:+1234567890
WHATSAPP_API_KEY=xxx

# Telegram
TELEGRAM_BOT_TOKEN=xxx
TELEGRAM_CHAT_ID=xxx

# Discord
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx

# Email
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu@email.com
SMTP_PASSWORD=xxx
FROM_EMAIL=tu@email.com
TO_EMAIL=destino@email.com
```

---

## 14. Contribuir al Proyecto

### Pasos para contribuir:

1. Fork del repositorio
2. Crear una rama (`git checkout -b feature/nueva-funcionalidad`)
3. Commit de cambios (`git commit -m 'Agregar nueva funcionalidad'`)
4. Push a la rama (`git push origin feature/nueva-funcionalidad`)
5. Crear un Pull Request

### Estándares de código:
- Usar type hints
- Agregar docstrings
- Mantener compatibilidad con Python 3.8+
- Agregar tests para nuevas funcionalidades
- Ejecutar tests antes de commit: `python test_agente_red.py`

---

## 15. Licencia y Credits

**Autor:** Miguel Ángel Ramírez Galicia (MikeUchiha122)

**Licencia:** Uso educativo

**Agradecimientos:**
- Comunidad de seguridad de redes
- Creadores de NMAP
- API macvendors.com
- Documentación Scapy
- Wiki de Aircrack-ng

---

*Documento generado automáticamente - Guía de Desarrollo v3.1*