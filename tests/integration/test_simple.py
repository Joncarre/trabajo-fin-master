import sys
import os
import json
import datetime
from dotenv import load_dotenv
import requests

# Añadir directorio raíz al path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Función para serializar objetos datetime
def json_serial(obj):
    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

def query_claude(query, api_key):
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json"
    }
    
    data = {
        "model": "claude-3-opus-20240229",
        "max_tokens": 1000,
        "messages": [{"role": "user", "content": query}],
        "system": "Eres un asistente especializado en ciberseguridad que analiza tráfico de red."
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
    
    query = "Dame un resumen del tráfico de red" if len(sys.argv) < 2 else sys.argv[1]
    
    print(f"Consultando: {query}")
    response = query_claude(query, api_key)
    print("\nRESPUESTA:\n" + "="*80)
    print(response)
    print("="*80)

if __name__ == "__main__":
    main()