# tests/batch_query_test.py
import os
import sys
import json
from dotenv import load_dotenv

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.query_engine import NaturalLanguageQueryEngine

def run_batch_test(db_path):
    # Cargar variables de entorno
    load_dotenv()
    
    # Obtener API key
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        print("Error: API key de Claude no encontrada.")
        return
    
    # Lista de consultas de prueba
    test_queries = [
        "¿Ha habido algún intento de ataque en las últimas 24 horas?",
        "Muestra los 5 hosts más activos en la red",
        "¿Cuál es la distribución de tráfico por protocolo?",
        "¿Se ha detectado algún escaneo de puertos?",
        "Dame un resumen del tráfico de red",
        "¿Cuáles son los puertos más utilizados?",
        "¿Hay alguna anomalía TCP?",
        "¿Cuál es el tráfico UDP en la última hora?"
    ]
    
    # Inicializar motor de consultas
    print(f"Inicializando motor de consultas con base de datos: {db_path}")
    query_engine = NaturalLanguageQueryEngine(db_path, api_key)
    
    # Crear directorio para resultados si no existe
    results_dir = "test_results"
    os.makedirs(results_dir, exist_ok=True)
    
    # Nombre de archivo para resultados
    timestamp = os.path.basename(db_path).replace('.db', '')
    results_file = os.path.join(results_dir, f"query_test_{timestamp}.txt")
    
    # Ejecutar consultas y guardar resultados
    with open(results_file, 'w', encoding='utf-8') as f:
        for i, query in enumerate(test_queries, 1):
            print(f"\nProcesando consulta {i}/{len(test_queries)}: {query}")
            
            try:
                # Procesar la consulta
                response = query_engine.process_query(query)
                
                # Escribir resultados
                f.write(f"CONSULTA {i}: {query}\n")
                f.write("="*80 + "\n")
                f.write(response + "\n")
                f.write("="*80 + "\n\n")
                
                print(f"Respuesta guardada en {results_file}")
                
            except Exception as e:
                error_msg = f"Error en consulta {i}: {str(e)}"
                print(error_msg)
                f.write(f"{error_msg}\n\n")
    
    print(f"\nPrueba por lotes completada. Resultados guardados en: {results_file}")

if __name__ == "__main__":
    # Seleccionar base de datos
    database_dir = "databases"
    if not os.path.exists(database_dir):
        print("Error: Directorio 'databases' no encontrado.")
        sys.exit(1)
    
    db_files = [f for f in os.listdir(database_dir) if f.endswith('.db')]
    
    if not db_files:
        print("Error: No se encontraron bases de datos SQLite en el directorio 'databases'.")
        sys.exit(1)
    
    print("Bases de datos disponibles:")
    for i, db_file in enumerate(db_files, 1):
        print(f"  {i}. {db_file}")
    
    try:
        selection = int(input("\nSeleccione una base de datos (número): "))
        if 1 <= selection <= len(db_files):
            db_path = os.path.join(database_dir, db_files[selection-1])
            run_batch_test(db_path)
        else:
            print("Selección inválida.")
    except ValueError:
        print("Entrada inválida.")