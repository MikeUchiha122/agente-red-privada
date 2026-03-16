#!/usr/bin/env python3
"""Script para ejecutar escaneo automatico"""

import os
import sys

# Agregar NMAP al PATH
if sys.platform == "win32":
    nmap_path = r"C:\Program Files\Nmap"
    if os.path.exists(nmap_path):
        os.environ["PATH"] = os.environ["PATH"] + os.pathsep + nmap_path

from agente_red import AgenteSeguridadRed

def main():
    agente = AgenteSeguridadRed()
    agente.limpiar_pantalla()
    agente.banner()
    
    print("\nEjecutando escaneo automatico de red local...\n")
    
    # Ejecutar escaneo
    agente.escanear_red_local()
    agente.guardar_historial()
    
    print("\n" + "="*60)
    print("ESCANEO COMPLETADO")
    print("="*60)
    
    # Mostrar dispositivos
    print("\n")
    agente.ver_todos_dispositivos()
    
    # Mostrar dispositivos con problemas
    print("\n")
    agente.detectar_sospechosos()
    
    # Generar informe
    print("\n")
    agente.generar_informe_completo()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nEscaneo interrumpido")
    except Exception as e:
        print(f"\nError: {e}")
    
    print("\nPresiona Enter para salir...")
    input()
