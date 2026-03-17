# 📖 MANUAL DE USUARIO
## Agente de Seguridad de Red v3.0

---

## 🌟 Introducción

El **Agente de Seguridad de Red** es una herramienta que te ayuda a:
- 🔍 Escanear tu red local y encontrar todos los dispositivos conectados
- 🔌 Ver qué puertos están abiertos en cada dispositivo
- ⚠️ Detectar amenazas de seguridad (malware, minérios, backdoors)
- 📊 Generar informes detallados con recomendaciones

**¿Para quién es?**
- Personas que quieren proteger su red doméstica
- Administradores de redes pequeñas
- Entusiastas de la seguridad informática

---

## 🚀 Instalación

### Requisitos
- Python 3.8 o superior
- Opcional: NMAP instalado para escaneo avanzado

### Pasos

#### Windows:
1. Descarga Python desde https://www.python.org/downloads/
2. ⚠️ **Importante**: Marca "Add Python to PATH"
3. Instala dependencias (opcional):
   ```bash
   pip install python-nmap requests
   ```

#### Linux/Mac:
```bash
sudo apt update
sudo apt install python3 python3-pip nmap
sudo pip3 install python-nmap requests scapy twilio
```

**PARA USAR DETECTOR DEAUTH - SE REQUIERE sudo:**
```bash
sudo pip3 install python-nmap requests scapy twilio
```

### Ejecutar el programa

**Windows:**
```bash
python agente_red.py
```

**Linux/Mac:**
```bash
sudo python3 agente_red.py
```

---

## 📋 Menú Principal

Al ejecutar el programa verás este menú:

```
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
 8. Info del sistema
 9. Detector DEAUTH (Flipper Zero)
10. Salir
================================================================================
```

---

## 📌 Guía de Uso

### 1. Escanear Red Local Completa
Esta opción escanea toda tu red y encuentra todos los dispositivos conectados.

**Qué hace:**
- Detecta tu IP local y la IP de tu router
- Escanear todos los dispositivos en tu red (192.168.x.x)
- Identifica el fabricante de cada dispositivo por su MAC
- Detecta puertos abiertos y posibles amenazas

**Cuánto tiempo toma:** 1-3 minutos depending on network size

**Resultado típico:**
```
[OK] Escaneo completado: 9 dispositivos
  [OK] 192.168.0.1 - Commscope (ROUTER)
  [OK] 192.168.0.8 - Amazon Technologies
  [CUIDADO] 192.168.0.15 - Unknown
```

---

### 2. Escanear IP Específica
Si conoces la IP de un dispositivo, puedes escanearlo directamente.

**Cuándo usarlo:**
- Cuando quieres analizar un dispositivo específico
- Cuando ves un dispositivo sospechoso en tu router

**Cómo usarlo:**
1. Selecciona opción 2
2. Ingresa la IP (ej: 192.168.0.50)
3. El programa analizará ese dispositivo

---

### 3. Ver Todos los Dispositivos
Muestra la lista de todos los dispositivos encontrados en el último escaneo.

**Información por dispositivo:**
- IP
- Fabricante (Apple, Samsung, etc.)
- Número de puertos abiertos
- Si es tu router (ROUTER)

---

### 5. Ver Puertos de un Dispositivo
Muestra los puertos abiertos de un dispositivo específico.

**Puertos comunes:**
| Puerto | Servicio | Significado |
|--------|----------|-------------|
| 22 | SSH | Acceso remoto seguro |
| 80 | HTTP | Página web |
| 443 | HTTPS | Página web segura |
| 445 | SMB | Archivos compartidos Windows |
| 3389 | RDP | Escritorio remoto |

---

### 6. Ver Dispositivos con Problemas
Muestra solo los dispositivos que tienen amenazas detectadas.

**Niveles de amenaza:**
- 🔴 **ALTO**: Backdoors, Telnet, Bases de datos expuestas
- 🟡 **MEDIO**: SMB, FTP, Mineros
- 🟢 **BAJO**: SSH, HTTP, HTTPS

---

### 7. Generar Informe
Genera un informe detallado de seguridad.

**El informe incluye:**
- Información del dispositivo (IP, MAC, fabricante)
- Análisis de la MAC (por qué es Unknown si lo es)
- Puertos abiertos con descripción
- Amenazas detectadas
- **Recomendaciones personalizadas**

**Cómo guardar:**
- El programa pregunta si deseas guardar
- Se guarda en `informe_seguridad.txt`

---

### 8. Ver Historial
Muestra los escaneos anteriores realizados.

**Información guardada:**
- Fecha del escaneo
- Número de dispositivos encontrados

---

### 9. Info del Sistema
Muestra información de tu conexión:
- Tu IP local
- IP del router/gateway

---

### 9. Detector DEAUTH (Flipper Zero)
**Submenú con opciones:**

```
1. Ver interfaces WiFi y compatibilidad   - Muestra tarjetas disponibles
2. Activar modo monitor                  - Activa modo promiscuo (iw/airmon-ng)
3. Desactivar modo monitor               - Vuelve a modo Managed
4. Ver estado de modo monitor            - Muestra estado actual
5. Iniciar detector Deauth (10s)         - Detecta ataques durante 10 seg
6. Iniciar detector Deauth (60s)         - Detecta ataques durante 60 seg
7. Configurar WhatsApp                    - Configura alertas
8. Ver adaptadores recomendados          - Lista de hardware compatible
9. Volver al menú principal
```

**Tipos de ataques detectados:**
- **Deauth**: Paquetes de desconexión WiFi (Flipper Zero)
- **Disassoc**: Desasociación de dispositivos
- **Beacon Flood**: Inundación de paquetes beacon
- **Probe Flood**: Inundación de probe requests

**Nombres de interfaz en Linux:**
- Algunos sistemas usan `wlan0mon` (airmon-ng)
- Otros usan `wlan0` (iw)
- El programa detecta automáticamente el nombre correcto

**Por qué necesita modo monitor:**
Las tarjetas WiFi normales solo reciben paquetes dirigidos a ellas. En modo monitor capturan TODOS los paquetes de la red, incluyendo los de desautenticación.

**Compatibilidad por sistema:**

| Sistema | Soporte | Requisitos |
|---------|---------|------------|
| Linux | ✓ Completo | Tarjeta con chipset Atheros, airmon-ng |
| Windows | ✗ No nativo | Adaptador USB externo |
| Mac | ✓ Limitado | Permisos de root |

**Adaptadores recomendados:**
- Alfa AWUS036NHA (Atheros) - Mejor opción
- TP-Link TL-WN722N v2/v3
- Raspberry Pi con Kali Linux

---

### 10. Escaneo WiFi Avanzado
Escanea redes WiFi cercanas mostrando:
- SSID (nombre de la red)
- BSSID (MAC del router)
- Canal
- Nivel de señal
- Tipo de seguridad (WPA2/WEP/Open)

---

### 11. Alertas Múltiples
El sistema puede enviar alertas por múltiples canales:

| Canal | Configuración |
|-------|----------------|
| WhatsApp | Twilio o CallMeBot API |
| Telegram | Bot Token + Chat ID |
| Discord | Webhook URL |
| Email | SMTP (Gmail, Outlook, etc.) |

---

### 12. Estadísticas
Muestra métricas del sistema:
- Total de escaneos realizados
- Dispositivos únicos detectados
- Alertas por tipo
- Historial en base de datos SQLite

---

## 📊 Entendiendo los Resultados

### Niveles de Seguridad

| Emoji | Significado |
|-------|-------------|
| [OK] | Seguro - Sin problemas detectados |
| [CUIDADO] | Precaución - Tiene algunos puertos abiertos |
| [PELIGRO] | Peligro - Amenaza seria detectada |

### Tipos de Amenazas

| Símbolo | Amenaza | Descripción |
|---------|---------|-------------|
| [MINERO] | Minería | Software de minería de criptomonedas |
| [BACKDOOR] | Backdoor | Puerta trasera - acceso no autorizado |
| [RAT] | RAT | Acceso remoto malicioso |
| [TELNET] | Telnet | Conexión insegura |
| [SMB] | SMB | Compartir archivos (posible vulnerabilidad) |
| [FTP] | FTP | Transferencia de archivos sin cifrar |
| [WEB] | Web | Servidor web |
| [DB] | Database | Base de datos expuesta |

---

## 🔧 Solución de Problemas

### "No encuentra dispositivos"
1. Verifica que estás conectado a la red WiFi
2. Ejecuta como administrador (Windows: PowerShell como admin)
3. Verifica que NMAP esté instalado

### "Python no se reconoce"
1. Reinicia tu computadora después de instalar Python
2. O verifica que Python esté en tu PATH

### "Permission denied"
- En Linux/Mac usa: `sudo python3 agente_red.py`

---

## 📁 Archivos Generados

| Archivo | Descripción |
|---------|-------------|
| `historial_analisis.json` | Registro de todos los escaneos |
| `informe_seguridad.txt` | Informes detallados |
| `agente_seguridad.log` | Log de operaciones |

---

## 🛡️ Consejos de Seguridad

1. **Cambia tu contraseña WiFi** cada 6 meses
2. **Actualiza el firmware** de tu router
3. **Desactiva WPS** en tu router
4. **Usa WPA3** o WPA2-AES
5. **No compartas contraseñas** de tu red
6. **Revisa regularmente** qué dispositivos están conectados

---

## ⚠️ Aviso Legal

> Este herramienta es solo para **uso educativo y defensivo**.
> - ✅ Escanear TU PROPIA red doméstica
> - ✅ Aprender sobre seguridad de redes
> - ✅ Proteger tus dispositivos
> - ❌ NO escanear redes ajenas sin permiso
> - ❌ NO usar para dañar o acceder sin autorización

---

## 📄 Información del Proyecto

**Versión:** 3.0 (Optimizado)

**Autor:** Miguel Ángel Ramírez Galicia (MikeUchiha122)

**Licencia:** Uso educativo

**GitHub:** https://github.com/MikeUchiha122/agente-red-privada

---

*¿Te fue útil? Invítame un café: https://paypal.me/MikeUchiha122* ☕