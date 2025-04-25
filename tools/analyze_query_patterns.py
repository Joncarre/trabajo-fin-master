# tools/analyze_query_patterns.py
import os
import sys
import json
import re
from collections import defaultdict

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.query_engine.query_processor import QueryProcessor

def extract_patterns_from_logs(log_dir="query_logs"):
    """
    Extrae patrones de consultas de los logs para mejorar el procesador.
    """
    if not os.path.exists(log_dir):
        print(f"Error: Directorio {log_dir} no encontrado.")
        return
    
    # Inicializar procesador
    processor = QueryProcessor()
    
    # Contadores
    total_queries = 0
    successful_matches = 0
    failed_matches = 0
    
    # Recopilar consultas por intención
    queries_by_intent = defaultdict(list)
    unrecognized_queries = []
    
    # Procesar archivos de log
    for filename in os.listdir(log_dir):
        if filename.startswith("query_detail_") and filename.endswith(".json"):
            file_path = os.path.join(log_dir, filename)
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    log_data = json.load(f)
                
                query = log_data.get("original_query", "")
                expected_intent = log_data.get("processed_query", {}).get("intent", "")
                
                total_queries += 1
                
                # Procesar consulta con el procesador actual
                result = processor.process_query(query)
                actual_intent = result.get("intent", "")
                
                # Verificar si coincide con la intención esperada
                if actual_intent == expected_intent:
                    if actual_intent != "consulta_general":
                        successful_matches += 1
                        queries_by_intent[actual_intent].append(query)
                else:
                    failed_matches += 1
                    if expected_intent != "consulta_general":
                        # Solo registrar si la intención esperada no era general
                        unrecognized_queries.append({
                            "query": query,
                            "expected_intent": expected_intent,
                            "actual_intent": actual_intent
                        })
                    
            except Exception as e:
                print(f"Error al procesar archivo {filename}: {e}")
    
    # Mostrar estadísticas
    print(f"Total de consultas analizadas: {total_queries}")
    print(f"Consultas reconocidas correctamente: {successful_matches} ({successful_matches/total_queries*100:.1f}%)")
    print(f"Consultas no reconocidas: {failed_matches} ({failed_matches/total_queries*100:.1f}%)")
    
    # Mostrar ejemplos de consultas por intención
    print("\nConsultas por intención:")
    for intent, queries in queries_by_intent.items():
        print(f"\n{intent.upper()} ({len(queries)} consultas):")
        for i, query in enumerate(queries[:5], 1):
            print(f"  {i}. {query}")
        if len(queries) > 5:
            print(f"  ... y {len(queries) - 5} más")
    
    # Mostrar consultas no reconocidas
    if unrecognized_queries:
        print("\nConsultas no reconocidas correctamente:")
        for i, entry in enumerate(unrecognized_queries[:10], 1):
            print(f"  {i}. '{entry['query']}' -> Esperado: {entry['expected_intent']}, Detectado: {entry['actual_intent']}")
        if len(unrecognized_queries) > 10:
            print(f"  ... y {len(unrecognized_queries) - 10} más")
    
    # Generar patrones de regEx basados en las consultas reconocidas
    print("\nPatrones sugeridos para mejorar el reconocimiento:")
    generate_regex_patterns(queries_by_intent)
    
    # Guardar resultados
    output_file = "query_pattern_analysis.json"
    results = {
        "statistics": {
            "total_queries": total_queries,
            "successful_matches": successful_matches,
            "failed_matches": failed_matches
        },
        "queries_by_intent": {k: v for k, v in queries_by_intent.items()},
        "unrecognized_queries": unrecognized_queries
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\nResultados guardados en: {output_file}")

def generate_regex_patterns(queries_by_intent):
    """
    Genera patrones de expresiones regulares basados en consultas reconocidas.
    """
    for intent, queries in queries_by_intent.items():
        if len(queries) < 3:
            continue  # Necesitamos al menos 3 ejemplos para generar un patrón
        
        print(f"\nPatrones para '{intent}':")
        
        # Encontrar palabras comunes
        common_words = set(queries[0].lower().split())
        for query in queries[1:]:
            common_words &= set(query.lower().split())
        
        # Eliminar palabras muy comunes (stop words)
        stop_words = {'el', 'la', 'los', 'las', 'un', 'una', 'unos', 'unas', 'y', 'o', 'a', 'de', 'en', 'por'}
        common_words -= stop_words
        
        if common_words:
            print(f"  Palabras clave: {', '.join(common_words)}")
            
            # Generar patrón básico
            pattern = r'(?:' + '|'.join(common_words) + r')'
            print(f"  Patrón básico: r'{pattern}'")
            
            # Probar el patrón
            matches = 0
            for query in queries:
                if re.search(pattern, query.lower()):
                    matches += 1
            
            print(f"  Efectividad: {matches}/{len(queries)} consultas ({matches/len(queries)*100:.1f}%)")
            
            # Sugerir un patrón mejorado si la efectividad no es 100%
            if matches < len(queries):
                print("  Sugerencia de mejora: Analizar manualmente las consultas no detectadas")

if __name__ == "__main__":
    log_dir = sys.argv[1] if len(sys.argv) > 1 else "query_logs"
    extract_patterns_from_logs(log_dir)