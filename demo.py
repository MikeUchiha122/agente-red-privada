#!/usr/bin/env python3
"""
Demo del Agente de Seguridad de Red
Para portafolio - Version sin pausa
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agente_red import AgenteSeguridadRed

def print_header(titulo):
    print(f"\n{'='*70}")
    print(f"  {titulo}")
    print('='*70)

def print_section(titulo):
    print(f"\n{'='*70}")
    print(f"  {titulo}")
    print('='*70)

def run_demo():
    print("""
================================================================================
                                                                          [REDSEC]
     
     AGENTE DE SEGURIDAD DE RED v3.1
     
     Portafolio - Demostracion Completa
     
     Autor: Miguel Angel Ramirez Galicia
     GitHub: @MikeUchiha122
     
================================================================================
""")
    
    # 1. Menú Principal
    print_section("1. MENU PRINCIPAL")
    print("""
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
    """)
    
    # 2. Identificación de Dispositivos
    print_section("2. IDENTIFICACION DE DISPOSITIVOS POR MAC")
    
    agente = AgenteSeguridadRed()
    macs_ejemplo = [
        ("68:A4:0E:AA:BB:CC", "Apple"),
        ("00:1A:8A:AA:BB:CC", "Netgear Router"),
        ("F0:18:98:CC:DD:EE", "Apple Device"),
        ("3A:92:AA:58:51:0B", "Private/Unknown"),
    ]
    
    print("MAC Address              Fabricante Detectado")
    print("-" * 50)
    for mac, esperado in macs_ejemplo:
        resultado = agente.identificar_dispositivo(mac)
        print(f"{mac:<22} {resultado['marca']}")
    
    print("\n[INFO] Base de datos local + API macvendors.com")
    
    # 3. Detección de Amenazas
    print_section("3. DETECCION DE AMENAZAS")
    
    escenarios = [
        ("Servidor vulnerable", [21, 23, 445]),
        ("PC normal", [22, 80, 443]),
        ("Posible minero", [8888, 3333]),
        ("DB expuesta", [3306, 5432]),
    ]
    
    print("Escenario                Puertos           Nivel")
    print("-" * 55)
    for nombre, puertos in escenarios:
        resultado = agente.detectar_amenazas(puertos)
        print(f"{nombre:<22} {str(puertos):<15} {resultado['nivel'].upper()} {resultado['emoji']}")
    
    print("\n[AMENAZAS] Mineros, Backdoors, RAT, Telnet, SMB, FTP, Database")
    
    # 4. Informe Detallado
    print_section("4. GENERACION DE INFORMES")
    
    dispositivo = {
        "ip": "192.168.0.8",
        "mac": "98:22:6E:13:C6:D0",
        "estado": "up",
        "sistema": "Linux",
        "puertos": [8888],
        "servicios": {8888: {"nombre": "desconocido"}},
        "dispositivo": {"tipo": "Dispositivo", "marca": "Amazon Technologies Inc.", "categoria": "dispositivo"},
        "amenazas": {"encontradas": [{"tipo": "Mineros", "descripcion": "Software de mineria ilegal", "nivel": "medio", "simbolo": "[MINERO]", "puertos": [8888]}], "nivel": "medio", "emoji": "[CUIDADO]"},
        "es_gateway": False
    }
    
    print(agente.generar_informe(dispositivo))
    
    # 5. Modo Monitor
    print_section("5. DETECTOR DEAUTH Y MODO MONITOR")
    print("""
FUNCIONES:
  - Verificacion de tarjetas WiFi
  - Activacion de modo monitor (iw/airmon-ng)
  - Detectar Beacon Flood, Probe Flood
  - Integracion con airmon-ng (Linux)

SUBMENU:
 1. Ver interfaces WiFi y compatibilidad
 2. Activar modo monitor en interfaz
 3. Configurar WhatsApp para alertas
 4. Ver adaptadores recomendados

ADAPTADORES COMPATIBLES:
  [Linux]   Alfa AWUS036NHA, TP-Link TL-WN722N, Raspberry Pi
  [Windows] Adaptador USB externo (no nativo)
  [Mac]     Tarjetas internas (limitado)
    """)
    
    # 6. Sistema de Alertas
    print_section("6. SISTEMA DE ALERTAS")
    print("""
CANALES DE ALERTA:
   [OK] Telegram    - Bot API (Gratis - Recomendado)

CONFIGURAR TELEGRAM:
   1. Busca @BotFather en Telegram
   2. Envia /newbot y sigue instrucciones
   3. Copia el token
   4. Busca @userinfobot y toma tu Chat ID

EJECUTAR CON ALERTAS:
   Linux: python3 agente_red.py -t 'token' -c 'chat_id'
   sudo python3 agente_red.py -t 'token' -c 'chat_id'  (para modo monitor)
   Windows: python agente_red.py -t "token" -c "chat_id"

BASE DE DATOS:
   [OK] SQLite - Logging de escaneos y alertas
   [OK] Estadisticas - Historial de amenazas
     """)
    
    # 7. Tecnologías
    print_section("7. TECNOLOGIAS Y HERRAMIENTAS")
    print("""
Lenguaje:        Python 3.8+
Escaneo:         NMAP / Sockets / Ping
Captura packets: Scapy
APIs:            macvendors.com
Alertas:         Twilio, Telegram, Discord, SMTP
Database:        SQLite
Testing:         unittest (44 tests)
    """)
    
    # 8. Estadísticas
    print_section("8. ESTADISTICAS DEL PROYECTO")
    print("""
Lineas de codigo:    1250+
Tests unitarios:     44
Funciones:           30+
Documentacion:       3 archivos (README, Manual, Guia)
    """)
    
    print("""
================================================================================
                      [OK] DEMO COMPLETADA
================================================================================

GitHub:  https://github.com/MikeUchiha122/agente-red-privada
Demo:    python demo.py
Tests:   python test_agente_red.py

================================================================================
""")

if __name__ == "__main__":
    run_demo()