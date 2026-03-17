# Conversación - Agente de Seguridad de Red

## Resumen del Proyecto

**Agente de Seguridad de Red** - Herramienta de análisis y protección de redes locales.

### Características principales:
- Escaneo de red local con NMAP
- Detección de amenazas (mineros, backdoors, RAT, telnet, SMB, FTP, databases)
- Detector Deauth (Flipper Zero)
- Alertas por Telegram
- Identificación de dispositivos por MAC
- Sistema operativo detectado por NMAP
- Base de datos SQLite

---

## Comandos importantes

### Instalación (Kali Linux / Raspberry Pi)
```bash
sudo apt update
sudo apt install python3 python3-pip nmap
sudo pip install --break-system-packages python-nmap requests scapy
```

### Ejecución
```bash
# Con alertas Telegram
sudo python3 agente_red.py -t 'TOKEN' -c 'CHAT_ID'

# O con variables de entorno
export TELEGRAM_BOT_TOKEN='token'
export TELEGRAM_CHAT_ID='id'
sudo python3 agente_red.py
```

### Menú principal
1. Escanear red local completa (RÁPIDO)
2. Escanear IP específica
3. Ver todos los dispositivos
4. Ver puertos de un dispositivo
5. Ver dispositivos con problemas
6. Generar informe
7. Ver historial
8. Info del sistema (IP, red, alertas)
9. Detector DEAUTH (Flipper Zero)
10. Salir

### Menú Detector DEAUTH
1. Ver interfaces WiFi y compatibilidad
2. Activar modo monitor en interfaz
3. Desactivar modo monitor (volver a Managed)
4. Ver estado de modo monitor
5. Iniciar detector Deauth (10 segundos)
6. Iniciar detector Deauth (60 segundos)
7. Configurar alertas (Telegram)
8. Ver adaptadores recomendados
9. Volver

---

## Telegram Bot Setup

1. Busca **@BotFather** en Telegram
2. Envia `/newbot`
3. Dale un nombre (ej: AlertasSeguridad)
4. Copia el token
5. Busca **@userinfobot**
6. Envia cualquier mensaje
7. Copia tu Chat ID

**Bot Token:** 8654414868:AAEGc_vGz_a4WsYaWoc32hRwG1uzWxF3alA
**Chat ID:** 1299293428

---

## Errores comunes y soluciones

| Error | Solución |
|-------|----------|
| "externally-managed-environment" | Usar `--break-system-packages` |
| "Permission denied" para modo monitor | Ejecutar con `sudo` |
| "No module named 'scapy'" | `sudo pip install --break-system-packages scapy` |
| Error 401 en Telegram | Token incorrecto - verificar con @BotFather |
| Error 400 en Telegram | Chat ID incorrecto o bot no iniciado con /start |

---

## Raspberry Pi

- IP: 192.168.0.18
- VNC: 5901
- Usuario: mikegalicia

---

## Archivos del proyecto

- `agente_red.py` - Programa principal
- `detector_deauth.py` - Detector de ataques Deauth
- `test_agente_red.py` - 44 tests unitarios
- `README.md` - Documentación principal
- `MANUAL_USUARIO.md` - Manual de usuario
- `demo.py` - Demo para portafolio
- `conversacion.md` - Esta conversación

---

## GitHub

Repositorio: https://github.com/MikeUchiha122/agente-red-privada

---

## Notas

- El proyecto funciona en Windows, Linux, macOS y Raspberry Pi
- Para modo monitor se requiere Linux con permisos root
- Tarjetas WiFi recomendadas: Alfa AWUS036NHA, TP-Link TL-WN722N
- Telegram es el canal de alertas recomendado (gratis y rápido)
- Los argumentos CLI (-t, -c) permiten pasar el token sin sudo
