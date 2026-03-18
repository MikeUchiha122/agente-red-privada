# agente-red-privada — Contexto para Claude Code

## Proyecto
Agente de seguridad de red en Python (agente_red.py), detección de dispositivos, análisis de red WiFi, monitorización de tráfico.

## Memory
Tienes acceso a memoria persistente via Engram (MCP tools: mem_save, mem_search, etc.).

### Cuándo guardar memoria (mem_save):
- Después de corregir un bug
- Después de añadir una nueva función de detección
- Cuando tomes una decisión de arquitectura
- Cuando descubras un nuevo patrón de ataque
- Cuando cambies la estructura de tests

### Cuándo buscar en memoria (mem_search):
- Al empezar una sesión nueva ("¿qué hice la última vez con X?")
- Antes de tocar una función que ya modificaste antes
- Si el agente menciona "recuerda" o "recordar"

### Al empezar sesión:
Llama mem_context para recuperar el estado de la sesión anterior.

### Al terminar sesión:
Llama mem_session_summary SIEMPRE antes de terminar. No es opcional.

---

## Comandos CLI útiles

```bash
# Ver lo que Engram recuerda de este proyecto
engram search "agente red privada"

# Ver contexto de sesiones recientes
engram context

# Ver estadísticas
engram stats

# Guardar una memoria
engram remember "Añadí detección de dispositivos ARP"

# Buscar memorias
engram recall "detección de dispositivos"
```
