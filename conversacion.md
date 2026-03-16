# Conversación: Agente de Seguridad de Red v3.0

## Resumen del Proyecto

Se creó un agente de seguridad de red llamado **agente-seguridad-red** con las siguientes características:

### Funcionalidades implementadas:
1. ✅ Escaneo de red local
2. ✅ Escaneo de IP específica
3. ✅ Escaneo del gateway/router
4. ✅ Ver dispositivos encontrados
5. ✅ Ver puertos abiertos
6. ✅ Detectar dispositivos sospechosos/peligrosos
7. ✅ Análisis de tráfico de red
8. ✅ Generar informes detallados (entendibles para niños)
9. ✅ Ver historial de análisis
10. ✅ Información del sistema
11. ✅ Detector de ataques Deauth (para Raspberry Pi)

### Tecnologías usadas:
- **NMAP** - Para escaneo avanzado de puertos y detección de servicios
- **Ping** - Método alternativo de detección de dispositivos
- **Socket TCP** - Escaneo de puertos
- **ARP** - Obtención de direcciones MAC
- **Scapy** - Captura de paquetes para detección Deauth

### Base de datos de amenazas:
- Mineros de criptomonedas
- Backdoors (puertas traseras)
- RAT (Acceso Remoto)
- FTP inseguro
- Telnet
- SMB
- Bases de datos expuestas
- Servicios web
- SSH
- **Ataques Deauth** (detección de dispositivos como Flipper Zero, ESP32, etc.)

### Identificación de dispositivos por MAC:
- Apple, Samsung, Intel, Dell, HP, ASUS
- Routers: Cisco, Netgear, TP-Link, Linksys, Tenda
- Dispositivos IoT: Google, Amazon Echo, Philips Hue
- Cámaras: AXIS
- VMs: VMware, VirtualBox, Hyper-V
- Raspberry Pi

### Instalación realizada:
1. Se instaló `python-nmap` (librería Python)
2. Se descargó el instalador de NMAP para Windows

---

## Para Desplegar en Raspberry Pi (Kali Linux)

### Archivos preparados para la Pi:

1. **`detector_deauth.py`** - Script de monitoreo continuo de ataques Deauth
2. **`detector_deauth.service`** - Servicio systemd para auto-inicio

### Ubicación del proyecto en Windows:
`C:\agente-seguridad-red\`

### Archivos creados:
- `agente_red.py` - Programa principal (Windows)
- `test_agente_red.py` - Suite de tests (12 tests)
- `detector_deauth.py` - Detector Deauth para Raspberry Pi
- `detector_deauth.service` - Servicio systemd
- `ejecutar.bat` - Lanzador para Windows
- `README.md` - Documentación principal
- `README_DEAUTH.md` - Documentación del detector Deauth
- `requirements.txt` - Dependencias
- `.gitignore` - Archivos ignorados
- `conversacion.md` - Esta conversación

---

## Pasos para ejecutar en Raspberry Pi

### 1. Copiar archivos a la Raspberry Pi:
```bash
# Desde tu computadora, copia los archivos:
scp C:\agente-seguridad-red\detector_deauth.py pi@<IP_RASPBERRY>:~
scp C:\agente-seguridad-red\detector_deauth.service pi@<IP_RASPBERRY>:~
scp C:\agente-seguridad-red\requirements.txt pi@<IP_RASPBERRY>:~
```

### 2. Instalar dependencias en la Raspberry Pi:
```bash
ssh pi@<IP_RASPBERRY>
pip3 install scapy twilio requests
```

### 3. Configurar tarjeta WiFi en modo monitor:
```bash
sudo airmon-ng start wlan0
```

### 4. Ejecutar el detector:
```bash
sudo python3 detector_deauth.py
```

### 5. Para auto-inicio con systemd:
```bash
sudo cp detector_deauth.service /etc/systemd/system/
sudo systemctl enable detector_deauth
sudo systemctl start detector_deauth
```

---

## Configuración de Alertas WhatsApp

**Número configurado:** +525545106780

### Opción 1: CallMeBot (Gratis)
- Enviar mensaje al +34 644 92 93 89 con texto "I AGREE"
- Obtener API key del chat

### Opción 2: Twilio (Pagado)
- Crear cuenta en twilio.com
- Obtener SID, Auth Token y número de WhatsApp

---

## Notas de la conversación

- El usuario pidió que el informe sea entendible para niños de 5 años
- Se solicitó basar el proyecto en NMAP
- Se instalaron las dependencias necesarias
- El programa funciona con fallback si NMAP no está instalado
- Se agregó detección de ataques Deauth (NO solo Flipper Zero, cualquier dispositivo)
- El detector analiza patrones de ataque: ataques dirigidos, ataques masivos, fabricantes afectados

---

## Redescubierto en el escaneo:
- 10 dispositivos encontrados en 192.168.0.x
- Amenazas potenciales: SMB en 192.168.0.4, posible minero en 192.168.0.5
