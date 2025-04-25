import sys
import os
import json
import datetime
import requests
from dotenv import load_dotenv

# Añadir el directorio raíz del proyecto al path para poder importar desde src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.ai_engine.packet_analyzer import PacketAnalyzer
from src.data_processing.storage_manager import StorageManager

# Función para serializar objetos datetime
def json_serial(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def query_claude(query, context, api_key):
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    
    # Preparar el contexto
    context_str = json.dumps(context, default=json_serial)
    
    full_query = f"""
    Consulta del usuario: {query}
    
    Contexto disponible (datos del tráfico de red):
    ```json
    {context_str}
    ```
    
    Basándote en la consulta y el contexto proporcionado, genera una respuesta detallada sobre el tráfico de red.
    """
    
    system_prompt = """
    Eres un asistente especializado en ciberseguridad y análisis de tráfico de red.
    Tu tarea es analizar datos de tráfico de red e identificar posibles amenazas o problemas de seguridad.
    
    Debes proporcionar respuestas precisas, técnicas y útiles basadas en los datos disponibles.
    
    - Cuando proporciones respuestas numéricas, incluye estadísticas y métricas relevantes.
    - Cuando identifiques amenazas, clasifícalas por severidad y proporciona recomendaciones.
    - Organiza la información de forma clara y estructurada.
    - Tu objetivo es ayudar a usuarios sin experiencia avanzada en ciberseguridad a entender su tráfico de red.
    """
    
    data = {
        "model": "claude-3-opus-20240229",
        "max_tokens": 2000,
        "messages": [{"role": "user", "content": full_query}],
        "system": system_prompt
    }
    
    response = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers=headers,
        data=json.dumps(data, default=json_serial)
    )
    
    if response.status_code == 200:
        result = response.json()
        return result['content'][0]['text']
    else:
        return f"Error: {response.status_code}, {response.text}"

def main():
    load_dotenv()
    api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("API_KEY_OPENAI")
    
    if not api_key:
        api_key = input("Ingrese su API key de Claude: ")
    
    # Comprobar argumentos
    interactive_mode = "--interactive" in sys.argv
    if interactive_mode:
        # Remover --interactive de los argumentos para procesamiento
        sys.argv.remove("--interactive")
    
    db_path = sys.argv[1] if len(sys.argv) > 1 else "databases/database_20250418_141938.db"
    query = sys.argv[2] if len(sys.argv) > 2 else "Dame un resumen inicial del tráfico de red"
    
    print(f"Analizando base de datos: {db_path}")
    
    # Inicializar analizador
    analyzer = PacketAnalyzer(db_path)
    storage = StorageManager(db_path)
    
    # Obtener datos para la consulta
    session = None
    sessions = storage.get_all_sessions()
    if sessions:
        session = sessions[0]  # La sesión más reciente
    
    if not session:
        print("No se encontraron sesiones en la base de datos.")
        return
    
    # Analizar la sesión
    print(f"Analizando sesión: {session['id']}")
    session_analysis = analyzer.analyze_session(session["id"])
    
    # Obtener estadísticas básicas
    protocol_stats = storage.get_protocol_statistics()
    top_talkers = storage.get_top_talkers(limit=5)
    
    # Preparar contexto
    context = {
        "session_analysis": session_analysis,
        "protocol_statistics": protocol_stats,
        "top_talkers": top_talkers
    }
    
    # Modo interactivo
    if interactive_mode:
        print("\nModo interactivo activado. Escribe 'salir' para terminar.")
        
        # Primera consulta (la proporcionada por argumento o por defecto)
        print(f"Consultando a Claude: {query}")
        response = query_claude(query, context, api_key)
        print("\nRESPUESTA:\n" + "="*80)
        print(response)
        print("="*80)
        
        # Bucle interactivo
        while True:
            user_query = input("\nConsulta> ")
            if user_query.lower() in ['salir', 'exit', 'quit']:
                print("Saliendo del modo interactivo...")
                break
                
            if not user_query.strip():
                continue
                
            print(f"Consultando a Claude: {user_query}")
            response = query_claude(user_query, context, api_key)
            print("\nRESPUESTA:\n" + "="*80)
            print(response)
            print("="*80)
    else:
        # Modo normal (una sola consulta)
        print(f"Consultando a Claude: {query}")
        response = query_claude(query, context, api_key)
        print("\nRESPUESTA:\n" + "="*80)
        print(response)
        print("="*80)

if __name__ == "__main__":
    main()