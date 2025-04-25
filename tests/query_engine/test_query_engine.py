# tests/test_query_engine.py

import os
import sys
import argparse
from dotenv import load_dotenv

# Añadir directorio raíz al path para importar módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.query_engine import NaturalLanguageQueryEngine

def main():
    # Cargar variables de entorno
    load_dotenv()
    
    # Configurar parser de argumentos
    parser = argparse.ArgumentParser(description="Prueba del motor de consultas en lenguaje natural")
    
    parser.add_argument("--db", type=str, default="databases/network_data.db",
                        help="Ruta a la base de datos SQLite")
    
    parser.add_argument("--query", type=str,
                        help="Consulta en lenguaje natural")
    
    parser.add_argument("--interactive", action="store_true",
                        help="Modo interactivo para consultas")
    
    args = parser.parse_args()
    
    # Verificar que la base de datos existe
    if not os.path.exists(args.db):
        print(f"Error: La base de datos {args.db} no existe.")
        
        # Buscar bases de datos disponibles
        database_dir = "databases"
        if os.path.exists(database_dir):
            db_files = [f for f in os.listdir(database_dir) if f.endswith('.db')]
            
            if db_files:
                print("\nBases de datos disponibles:")
                for i, db_file in enumerate(db_files, 1):
                    print(f"  {i}. {os.path.join(database_dir, db_file)}")
                
                try:
                    selection = int(input("\nSeleccione una base de datos (número): "))
                    if 1 <= selection <= len(db_files):
                        args.db = os.path.join(database_dir, db_files[selection-1])
                        print(f"Usando base de datos: {args.db}")
                    else:
                        print("Selección inválida. Saliendo.")
                        return
                except ValueError:
                    print("Entrada inválida. Saliendo.")
                    return
            else:
                print("No se encontraron bases de datos disponibles en el directorio 'databases'.")
                return
        else:
            print("El directorio 'databases' no existe.")
            return
    
    # Obtener API key desde variables de entorno
    api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("API_KEY_OPENAI")
    if not api_key:
        print("No se encontró la API key en las variables de entorno.")
        api_key = input("Por favor, ingrese su API key de Claude/Anthropic: ")
        if not api_key:
            print("Error: API key no proporcionada.")
            return
    
    # Inicializar el motor de consultas
    print(f"Inicializando motor de consultas con base de datos: {args.db}")
    query_engine = NaturalLanguageQueryEngine(args.db, api_key)
    
    # Procesar una consulta específica
    if args.query:
        print(f"\nConsulta: {args.query}")
        print("\nProcesando consulta...")
        
        try:
            response = query_engine.process_query(args.query)
            print("\n" + "=" * 80)
            print("RESPUESTA:")
            print("=" * 80)
            print(response)
            print("=" * 80)
        except Exception as e:
            print(f"Error al procesar la consulta: {e}")
    
    # Modo interactivo
    if args.interactive:
        print("\n" + "=" * 80)
        print("MODO INTERACTIVO DE CONSULTAS")
        print("Escriba 'salir' o 'exit' para finalizar")
        print("=" * 80)
        
        while True:
            try:
                query = input("\nConsulta > ")
                
                if query.lower() in ['salir', 'exit', 'quit']:
                    break
                
                if not query.strip():
                    continue
                
                print("\nProcesando consulta...")
                response = query_engine.process_query(query)
                
                print("\n" + "=" * 80)
                print("RESPUESTA:")
                print("=" * 80)
                print(response)
                print("=" * 80)
                
            except KeyboardInterrupt:
                print("\nSaliendo del modo interactivo...")
                break
            except Exception as e:
                print(f"Error al procesar la consulta: {e}")
    
    print("\n¡Prueba completada!")

if __name__ == "__main__":
    main()