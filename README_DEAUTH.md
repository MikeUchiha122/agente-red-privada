# ⚠️ DETECTOR DEAUTH - TEMPORALMENTE DESHABILITADO

> **Nota:** Esta función está temporalmente deshabilitada en el menú principal.
> Puedes habilitarla nuevamente después de investigar más sobre los requisitos de modo monitor.

---

## Detecta ataques de:

### Dispositivos que pueden hacer Deauth:
- **Flipper Zero**
- **ESP32/ESP8266 Deauther**
- **WiFi Deauther** (Python)
- **Aircrack-ng**
- **Wifite**
- **MDK3**
- **Reaver**
- **Fern WiFi Cracker**
- **Bettercap**
- **WiFi Pumpkin**
- **Evil Twin AP**
- **Router comprometido**
- **Cualquier dispositivo con capacidad de inyección WiFi**

### Detecta:
- Ataques Deauth (desautenticación)
- Ataques Disassoc
- Ataques Beacon Flood
- Probe Request Flood
- Rouge APs

## Para instalar en tu Raspberry Pi con Kali Linux:

### Paso 1: Copiar archivos
Copia estos archivos a tu Raspberry Pi:
- `detector_deauth.py`
- `detector_deauth.service`

### Paso 2: Instalar dependencias
```bash
sudo apt update
sudo apt install python3-pip aircrack-ng
pip3 install scapy requests twilio
```

### Paso 3: Activar modo monitor
```bash
# Ver interfaces
iwconfig

# Activar modo monitor
sudo airmon-ng start wlan0

# La interfaz cambiara a wlan0mon
```

### Paso 4: Configurar WhatsApp (opcional)

**Opcion 1 - CallMeBot (gratis):**
1. Ve a https://www.callmebot.com/
2. Registra tu numero de WhatsApp
3. Obtén tu API key
4. Configura:
```bash
export WHATSAPP_API_KEY=tu_api_key
```

**Opcion 2 - Twilio (mas configurable):**
1. Crea cuenta en twilio.com
2. Obtén Account SID, Auth Token
3. Configura:
```bash
export TWILIO_ACCOUNT_SID=tu_sid
export TWILIO_AUTH_TOKEN=tu_token
export TWILIO_WHATSAPP_FROM=whatsapp:+tu_numero
```

### Paso 5: Ejecutar

**Manual:**
```bash
sudo python3 detector_deauth.py
```

**Como servicio (se inicia automaticamente):**
```bash
sudo cp detector_deauth.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable detector_deauth
sudo systemctl start detector_deauth

# Ver estado
sudo systemctl status detector_deauth

# Ver logs
sudo journalctl -u detector_deauth -f
```

### Uso

1. El detector Monitorea continuamente la red WiFi
2. Detecta paquetes Deauth (ataques de desconexion)
3. Envia alerta WhatsApp cuando detecta ataque
4. Registra todo en `/var/log/deteccion_deauth.log`

### Alertas

Cuando detecte un ataque Deauth, recibiras un mensaje como:

```
ALERTA DE SEGURIDAD

ATAQUE DEAUTH DETECTADO!
Red: 192.168.1.100
Interfaz: wlan0mon
Dispositivos sospechosos: 3
Ultimo MAC: AA:BB:CC:DD:EE:FF
Total paquetes: 15

POSIBLE FLIPPER ZERO O ATAQUE WiFi!
```

### Configuracion

Edita las variables al inicio de `detector_deauth.py`:
- `TELEFONO_ALERTA` - Tu numero (+525545106780)
- `INTERFAZ` - Interfaz WiFi (wlan0mon)
- `UMBRAL_DEAUTH` - Paquetes para considerar ataque
- `TIEMPO_ENTRE_ALERTAS` - Minutos entre alertas

### Notas

- Necesitas permisos de root (sudo)
- Tarjeta WiFi debe soportar modo monitor
- Kali Linux ya viene con aircrack-ng instalado
- Funciona 24/7 como servicio
