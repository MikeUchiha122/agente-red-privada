# 🔒 Agente de Seguridad de Red v1.0

[![Tests](https://github.com/MikeUchiha122/agente-red-privada/actions/workflows/tests.yml/badge.svg)](https://github.com/MikeUchiha122/agente-red-privada/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Windows](https://img.shields.io/badge/Windows-Soportado-green)
![Linux](https://img.shields.io/badge/Linux-Soportado-green)
![macOS](https://img.shields.io/badge/macOS-Soportado-green)
[![Invítame un café](https://img.shields.io/badge/Invítame%20un%20café-Gracias!-orange)](https://paypal.me/MikeUchiha122)

---

## 🤔 ¿Qué es esto?

Es un **agente de inteligencia artificial** que te ayuda a analizar y proteger tu red local doméstica o de oficina.

**¿Qué puede hacer?**

| Función | Descripción |
|---------|-------------|
| 🔍 Escanear red | Encuentra todos los dispositivos conectados a tu WiFi |
| 📱 Ver dispositivos | Muestra IP, nombre y sistema de cada dispositivo |
| 🔌 Ver puertos | Revisa qué puertos abiertos tiene cada dispositivo |
| ⚠️ Detectar sospechosos | Identifica dispositivos con riesgos de seguridad |
| 📊 Analizar tráfico | Muestra las conexiones activas de tu PC |
| 💡 Generar soluciones | Crea recomendaciones de seguridad personalizadas |

**Para quién es:** Para principiantes que quieren aprender sobre seguridad de redes y proteger su red doméstica.

---

## ⚠️ Aviso Legal

> **IMPORTANTE:** Este herramienta es solo para **uso educativo y defensivo**.
> - ✅ Escanear TU PROPIA red doméstica
> - ✅ Aprender sobre seguridad de redes
> - ✅ Proteger tus dispositivos
> - ❌ NO escanear redes ajenas sin permiso
> - ❌ NO usar para dañar o acceder sin autorización

---

## 📋 Requisitos

Antes de comenzar, necesitas:

### 1. Python instalado

**Windows:**
- Descarga Python desde: https://www.python.org/downloads/
- ⚠️ **Importante:** Marca la opción "Add Python to PATH"
- Verifica ejecutando: `python --version`

**Linux (Ubuntu/Debian):**
```bash
sudo apt update
sudo apt install python3 python3-pip
python3 --version
```

**macOS:**
```bash
brew install python3
python3 --version
```

### 2. Acceso como administrador (importante)

**Windows:**
- Abre PowerShell como **Administrador**
- Click derecho en PowerShell → "Ejecutar como administrador"

**Linux/Mac:**
- Algunos escaneos necesitan permisos de superusuario:
```bash
sudo python3 agente_red.py
```

---

## 🚀 Instalación - Paso a Paso

### Paso 1: Descargar el código

**Opción A: Clonar con Git (recomendado)**
```bash
git clone https://github.com/MikeUchiha122/agente-red-privada.git
cd agente-red-privada
```

**Opción B: Descargar manualmente**
1. Ve a: https://github.com/MikeUchiha122/agente-red-privada
2. Click en botón verde "Code"
3. Click en "Download ZIP"
4. Extrae el archivo
5. Abre la carpeta en terminal

### Paso 2: Instalar dependencias

#### Windows
1. Descarga Python desde: https://www.python.org/downloads/
2. ⚠️ **Importante:** Marca "Add Python to PATH"
3. Abre PowerShell o CMD en la carpeta del proyecto
4. Ejecuta:
```powershell
pip install python-nmap requests
```

#### Linux (Ubuntu, Debian, Kali)
```bash
# Instalacion basica
sudo apt update
sudo apt install python3 python3-pip nmap

# Con entorno virtual (recomendado para Kali Linux 2024+)
python3 -m venv venv
source venv/bin/activate
pip install python-nmap requests

# Para detector Deauth (requiere sudo)
sudo pip install --break-system-packages python-nmap requests scapy
```

#### macOS
```bash
# Con Homebrew
brew install python3 nmap
pip3 install python-nmap requests
```

#### Raspberry Pi (Kali Linux)
```bash
# Instalacion completa
sudo apt update
sudo apt install python3 python3-pip nmap

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install python-nmap requests scapy twilio

# EJECUTAR CON SUDO (para modo monitor)
sudo python3 agente_red.py
```

### Paso 3: ¡Listo! Ejecutar el programa

**Windows:**
```powershell
python agente_red.py
```

**Linux/macOS:**
```bash
python3 agente_red.py
```

**Linux/Raspberry Pi (para detector Deauth):**
```bash
sudo python3 agente_red.py
```

---

## 📖 Cómo Usar - Guía para Principiantes

### Primer uso: Escanear tu red

1. Ejecuta el programa: `python agente_red.py`
2. Verás el menú principal
3. Escribe `1` y presiona Enter
4. El programa escaneará tu red local
5. ¡Espera! Puede tomar 1-3 minutos

### Entendiendo los resultados

```
📍 192.168.1.1
   Hostname: router.local
   Sistema: Router/Dispositivo de red
   Puertos: [80, 443]
   Riesgo: BAJO
```

- **IP:** La dirección del dispositivo en tu red
- **Hostname:** El nombre del dispositivo
- **Sistema:** Qué tipo de dispositivo es (Windows, Linux, Router)
- **Puertos:** Servicios que están activos
- **Riesgo:** Nivel de seguridad (BAJO/MEDIO/ALTO)

### Puertos comunes y su significado

| Puerto | Nombre | Significado |
|--------|--------|-------------|
| 80 | HTTP | Página web (sin cifrar) |
| 443 | HTTPS | Página web (segura) |
| 22 | SSH | Acceso remoto seguro |
| 21 | FTP | Transferencia de archivos |
| 23 | Telnet | Acceso remoto (inseguro!) |
| 445 | SMB | Compartir archivos Windows |
| 3389 | RDP | Escritorio remoto Windows |
| 53 | DNS | Nombres de dominio |

---

## 🔧 Solución de Problemas

### Errores Comunes en Kali Linux / Raspberry Pi

**Error: "externally-managed-environment"**
```
× This environment is externally managed
```
**Solución:** Usa `--break-system-packages`:
```bash
sudo pip install --break-system-packages python-nmap requests scapy twilio
```

**Error: "Could not find a version that satisfies the requirement request"**
- Causa: Typo - el paquete se llama `requests` (plural), no `request`
- Solución: `pip install python-nmap requests`

**Error: "Se requieren permisos de root"**
- Causa: Modo monitor necesita permisos de root
- Solución: `sudo python3 agente_red.py`

**Error: "No module named 'twilio'"**
- Solución: `sudo pip install --break-system-packages twilio`

**Error: "command failed: Operation not permitted"**
- Causa: Sin permisos para cambiar modo de interfaz WiFi
- Solución: Ejecuta con `sudo`

### "Python no se reconoce como comando"

**Windows:**
1. Busca "Variables de entorno" en Windows
2. Click en "Editar variables de entorno del sistema"
3. Click en "Variables de entorno"
4. Busca "Path" en variables del sistema
5. Edita y agrega: `C:\Users\TU_USUARIO\AppData\Local\Programs\Python\Python313`

O simplemente reinstala Python marcando "Add Python to PATH"

### "Permission denied" (Permiso denegado)

**Linux/Mac:**
```bash
sudo python3 agente_red.py
```

### El escaneo no encuentra dispositivos

- Verifica que estés conectado a WiFi
- Asegúrate de ser administrador
- Algunos routers bloquean escaneos. Intenta desde otra red

### Error de codificación en Windows

Si ves errores con tildes o caracteres especiales, el programa maneja esto automáticamente.

---

## 📁 Estructura del Proyecto

```
agente-red-privada/
├── agente_red.py           # Programa principal
├── detector_deauth.py      # Detector de ataques Deauth (Raspberry Pi)
├── escanear_rapido.py       # Script de escaneo automático
├── test_agente_red.py      # Tests unitarios
├── historial_analisis.json # Historial de escaneos
├── agente_seguridad.db     # Base de datos SQLite
├── informe_seguridad.txt   # Informes generados
├── README.md               # Este archivo
├── MANUAL_USUARIO.md       # Manual de usuario
├── GUIA_DESARROLLO.md      # Guía de desarrollo
├── requirements.txt        # Dependencias
├── detector_deauth.service # Servicio systemd
├── ejecutar.bat            # Lanzador Windows
└── .gitignore              # Archivos ignorados por Git
```
agente-red-privada/
├── agente_red.py           # Programa principal
├── detector_deauth.py      # Detector de ataques Deauth (Raspberry Pi)
├── escanear_rapido.py       # Script de escaneo automático
├── test_agente_red.py      # Tests unitarios
├── historial_analisis.json # Historial de escaneos
├── informe_seguridad.txt   # Informes generados
├── README.md               # Este archivo
├── README_DEAUTH.md        # Documentación detector Deauth
├── requirements.txt        # Dependencias
├── detector_deauth.service # Servicio systemd
├── ejecutar.bat            # Lanzador Windows
└── .gitignore              # Archivos ignorados por Git
```

---

## 🤖 Funciones del Agente

### 1. Escanear Red Local
Envía "pings" a todas las IPs de tu red para ver cuáles están activas.

### 2. Detectar Puertos Abiertos
Verifica qué servicios están corriendo en cada dispositivo.

### 3. Analisis de Seguridad
El agente revisa si los puertos abiertos son peligrosos y da recomendaciones.

### 4. Generador de Soluciones
Crea un plan personalizado para mejorar la seguridad de cada dispositivo.

### 5. Identificación de Dispositivos por MAC
- Base de datos local de fabricantes conocidos (Apple, Samsung, VMware, etc.)
- Consulta automática a **macvendors.com** para dispositivos Unknown
- Cache para evitar consultas repetidas

### 6. Detector de Ataques Deauth
Detecta ataques de desautenticación WiFi (Flipper Zero, ESP32, etc.)
- Monitoreo continuo de paquetes Deauth
- Alertas por WhatsApp (Twilio o CallMeBot)
- Análisis de patrones de ataque

### 7. Logging y Métricas
- Registro de todas las operaciones en `agente_seguridad.log`
- Manejo robusto de errores
- Fallback automático si NMAP no está disponible

### 8. Informes Detallados
- Análisis completo de cada dispositivo
- Explicación de puertos abiertos y servicios
- Recomendaciones personalizadas de seguridad
- Análisis de MAC (fabricante, OUI, causas de Unknown)

### 9. Funciones Avanzadas WiFi (Linux)
- Integración con airmon-ng para modo monitor
- Detección de múltiples ataques: Deauth, Disassoc, Beacon Flood, Probe Flood
- Escaneo de redes WiFi (como airodump-ng)
- Verificación de compatibilidad de tarjetas

### 10. Alertas Múltiples
- WhatsApp (Twilio/CallMeBot)
- Telegram
- Discord (Webhook)
- Email (SMTP)
- Base de datos SQLite para logging

### 11. Estadísticas
- Historial de escaneos en SQLite
- Contador de alertas por tipo
- Dispositivos únicos detectados

---

## 📊 Ejemplo de Uso

```
╔══════════════════════════════════════════════════════════╗
║           MENÚ PRINCIPAL - AGENTE DE SEGURIDAD RED           ║
╠══════════════════════════════════════════════════════════╣
║  1. 🔍 Escanear red local                                  ║
║  2. 📱 Escanear IP especifica                               ║
║  3. 📱 Ver todos los dispositivos                          ║
║  4. 🔌 Ver puertos de un dispositivo                       ║
║  5. ⚠️  Ver dispositivos con problemas                      ║
║  6. 📊 Generar informe                                     ║
║  7. 📜 Ver historial                                       ║
║  8. ℹ️  Info del sistema                                    ║
║  9. 🔐 Detector DEAUTH                                      ║
║ 10. 🚪 Salir                                               ║
╚══════════════════════════════════════════════════════════╝

Selecciona una opción: 1

━━━ ESCANEANDO TU RED (MODO RAPIDO) ━━━

Tu IP: 192.168.0.105
Tu Router: 192.168.0.1

Escaneo rapido con NMAP...

Dispositivos encontrados: 9

  [OK] 192.168.0.1 - Commscope (ROUTER)
  [OK] 192.168.0.2 - Google, Inc.
  [CUIDADO] 192.168.0.8 - Amazon Technologies
  [OK] 192.168.0.15 - Private/Unknown

[OK] Escaneo completado: 9 dispositivos
```

---

## 🔒 Consejos de Seguridad

1. **Cambia la contraseña de tu WiFi** cada 6 meses
2. **Actualiza el firmware** de tu router
3. **Desactiva WPS** en tu router (es vulnerable)
4. **Usa WPA3** o WPA2-AES en tu red WiFi
5. **No compartas contraseñas** de tu red
6. **Revisa regularmente** qué dispositivos están conectados

---

## 📝 Historial y Reportes

El agente guarda:
- `historial_analisis.json` - Registro de todos los escaneos
- `informe_seguridad.txt` - Informes de seguridad detallados generados
- `agente_seguridad.log` - Log de operaciones (creado automáticamente)
- `agente_seguridad.db` - Base de datos SQLite con historial y estadísticas

### Variables de Entorno para Alertas

**Opciones de configuracion (todas opcionales):**

#### Telegram (RECOMENDADO - Gratis y rapido)

**Paso 1: Obtener Bot Token**
1. Abre Telegram y busca **@BotFather**
2. Envia `/newbot`
3. Sigue las instrucciones y dale un nombre (ej: "AlertasSeguridad")
4. Te dare un token como: `1234567890:ABCdefGHIjklMNOpqrsTUVwxyz`

**Paso 2: Obtener Chat ID**
1. Busca **@userinfobot** en Telegram
2. Envia cualquier mensaje
3. Te mostrara tu Chat ID (numero largo)

**Configuracion por sistema:**

**Linux/Raspberry Pi:**
```bash
export TELEGRAM_BOT_TOKEN='1234567890:ABCdefGHIjklMNOpqrsTUVwxyz'
export TELEGRAM_CHAT_ID='123456789'
```

**Windows (PowerShell):**
```powershell
$env:TELEGRAM_BOT_TOKEN="1234567890:ABCdefGHIjklMNOpqrsTUVwxyz"
$env:TELEGRAM_CHAT_ID="123456789"
```

**Windows (CMD):**
```cmd
set TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
set TELEGRAM_CHAT_ID=123456789
```

**macOS:**
```bash
export TELEGRAM_BOT_TOKEN='1234567890:ABCdefGHIjklMNOpqrsTUVwxyz'
export TELEGRAM_CHAT_ID='123456789'
```

**Ejecutar con variables (una sola linea):**

Linux/Raspberry Pi:
```bash
TELEGRAM_BOT_TOKEN='tu_token' TELEGRAM_CHAT_ID='tu_id' sudo python3 agente_red.py
```

Windows PowerShell:
```powershell
$env:TELEGRAM_BOT_TOKEN="tu_token"; $env:TELEGRAM_CHAT_ID="tu_id"; python agente_red.py
```

#### WhatsApp (Requiere cuenta Twilio o CallMeBot)

**Opcion A - Twilio (Pagado):**
```bash
TWILIO_ACCOUNT_SID=xxx
TWILIO_AUTH_TOKEN=xxx
TWILIO_WHATSAPP_FROM=whatsapp:+1234567890
```

**Opcion B - CallMeBot (Gratis con limitaciones):**
```bash
WHATSAPP_API_KEY=xxx
```
Registrate en https://www.callmebot.com/

#### Discord (Gratis)

```bash
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/xxx
```

#### Email (SMTP)

```bash
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=tu@email.com
SMTP_PASSWORD=xxx
FROM_EMAIL=tu@email.com
TO_EMAIL=destino@email.com
```

**Nota:** En Linux puedes guardar las variables en `~/.bashrc` para que se carguen automaticamente.

### Generación de Informes

Los informes incluyen:
- Información del dispositivo (IP, fabricante, categoría)
- Análisis de MAC (OUI, posibles causas de Unknown)
- Puertos abiertos con descripción de servicios
- Amenazas detectadas con nivel de riesgo
- Recomendaciones personalizadas de seguridad

---

## 🛠️ Estándares de Código

El proyecto sigue las siguientes buenas prácticas:

| Estándar | Descripción |
|----------|-------------|
| **Type Hints** | Anotaciones de tipo en funciones principales |
| **Docstrings** | Documentación en funciones públicas |
| **Manejo de errores** | Excepciones específicas (no `except:` vacíos) |
| **Logging** | Sistema de logs estructurado para debugging |
| **Context managers** | Uso de `with` para recursos (sockets, archivos) |
| **Validación** | Validación de entradas (IPs, MACs, teléfonos) |
| **Cache** | caching de consultas externas para rendimiento |

---

## 🙋‍♂️ Autor

**Miguel Ángel Ramírez Galicia**  
[@MikeUchiha122](https://github.com/MikeUchiha122)

---

## 📄 Licencia

Este proyecto es de uso educativo. Úsalo con responsabilidad.

---

*¿Te fue útil? Invítame un café: https://paypal.me/MikeUchiha122* ☕
