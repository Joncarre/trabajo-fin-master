# tests/benchmark_query_engine.py
import os
import sys
import time
import json
from statistics import mean, stdev
from dotenv import load_dotenv

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.query_engine import NaturalLanguageQueryEngine

def run_benchmark(db_path, context_file=None, iterations=3):
    """
    Ejecuta un benchmark del motor de consultas.
    
    Args:
        db_path (str): Ruta a la base de datos
        context_file (str, optional): Archivo de contexto
        iterations (int): Número de iteraciones para cada consulta
    """
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
        "Dame un resumen del tráfico de red"
    ]
    
    # Inicializar motor de consultas
    print(f"Inicializando motor de consultas con base de datos: {db_path}")
    query_engine = NaturalLanguageQueryEngine(db_path, api_key, context_file=context_file)
    
    # Resultados del benchmark
    benchmark_results = {
        "database": db_path,
        "context_file": context_file,
        "iterations": iterations,
        "queries": []
    }
    
    # Ejecutar benchmark
    for query in test_queries:
        print(f"\nProbando consulta: {query}")
        
        query_times = []
        total_tokens = 0
        
        for i in range(iterations):
            print(f"  Iteración {i+1}/{iterations}...")
            
            start_time = time.time()
            
            try:
                response = query_engine.process_query(query)
                
                # Calcular tiempo de ejecución
                end_time = time.time()
                execution_time = end_time - start_time
                query_times.append(execution_time)
                
                # Estimar tokens (aproximado)
                tokens = len(response.split()) * 1.3  # Estimación simple
                total_tokens += tokens
                
                print(f"  ✓ Completado en {execution_time:.2f} segundos")
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
        
        # Calcular estadísticas
        if query_times:
            avg_time = mean(query_times)
            std_time = stdev(query_times) if len(query_times) > 1 else 0
            avg_tokens = total_tokens / len(query_times)
            
            # Guardar resultados
            query_result = {
                "query": query,
                "average_time": avg_time,
                "std_deviation": std_time,
                "average_tokens": avg_tokens,
                "all_times": query_times
            }
            
            benchmark_results["queries"].append(query_result)
            
            print(f"  Promedio: {avg_time:.2f} segundos (±{std_time:.2f}), ~{avg_tokens:.0f} tokens")
    
    # Calcular resultados globales
    all_times = [time for q in benchmark_results["queries"] for time in q["all_times"]]
    benchmark_results["global_average_time"] = mean(all_times) if all_times else 0
    benchmark_results["global_std_deviation"] = stdev(all_times) if len(all_times) > 1 else 0
    
    # Guardar resultados en archivo
    timestamp = int(time.time())
    results_file = f"test_results/benchmark_{timestamp}.json"
    os.makedirs(os.path.dirname(results_file), exist_ok=True)
    
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(benchmark_results, f, indent=2)
    
    print(f"\nBenchmark completado. Resultados guardados en: {results_file}")
    print(f"Tiempo promedio de respuesta: {benchmark_results['global_average_time']:.2f} segundos")

if __name__ == "__main__":
    # Verificar argumentos
    if len(sys.argv) < 2:
        print("Uso: python benchmark_query_engine.py <db_path> [context_file] [iterations]")
        sys.exit(1)
    
    db_path = sys.argv[1]
    context_file = sys.argv[2] if len(sys.argv) > 2 else None
    iterations = int(sys.argv[3]) if len(sys.argv) > 3 else 3
    
    run_benchmark(db_path, context_file, iterations)