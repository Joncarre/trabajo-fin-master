# tests/evaluate_queries.py
import os
import sys
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.query_engine.query_processor import QueryProcessor

def evaluate_query_processor():
    # Lista de consultas de prueba con intenciones esperadas
    test_cases = [
        {"query": "¿Ha habido algún intento de ataque en las últimas 24 horas?", "expected_intent": "anomalias_recientes"},
        {"query": "Muestra los 5 hosts más activos", "expected_intent": "top_talkers"},
        {"query": "¿Cuál es la distribución de tráfico por protocolo?", "expected_intent": "trafico_por_protocolo"},
        {"query": "¿Se ha detectado algún escaneo de puertos?", "expected_intent": "escaneos_puertos"},
        {"query": "Analiza la actividad de la IP 192.168.1.1", "expected_intent": "actividad_ip_especifica"},
        {"query": "¿Cuáles son las amenazas más graves detectadas?", "expected_intent": "amenazas_por_severidad"},
        {"query": "Dame un resumen del tráfico", "expected_intent": "resumen_trafico"},
        {"query": "¿Cuáles son los puertos TCP más utilizados?", "expected_intent": "puertos_activos"},
        {"query": "¿Qué pasó en las últimas 2 horas?", "expected_intent": "actividad_periodo"},
        {"query": "Muestra el tráfico de la última semana", "expected_intent": "actividad_periodo"},
        # Añade más casos de prueba aquí
    ]
    
    # Inicializar procesador de consultas
    processor = QueryProcessor()
    
    # Resultados de la evaluación
    results = {
        "passed": 0,
        "failed": 0,
        "details": []
    }
    
    # Procesar cada consulta
    for case in test_cases:
        query = case["query"]
        expected_intent = case["expected_intent"]
        
        # Procesar la consulta
        result = processor.process_query(query)
        actual_intent = result.get("intent", "")
        
        # Verificar si la intención detectada coincide con la esperada
        passed = actual_intent == expected_intent
        
        # Guardar resultados
        case_result = {
            "query": query,
            "expected_intent": expected_intent,
            "actual_intent": actual_intent,
            "passed": passed,
            "parameters": result.get("parameters", {})
        }
        
        results["details"].append(case_result)
        
        if passed:
            results["passed"] += 1
        else:
            results["failed"] += 1
    
    # Calcular precisión
    total_cases = len(test_cases)
    accuracy = (results["passed"] / total_cases) * 100 if total_cases > 0 else 0
    
    # Mostrar resultados
    print(f"Evaluación del procesador de consultas:")
    print(f"Total de casos: {total_cases}")
    print(f"Pasados: {results['passed']}")
    print(f"Fallidos: {results['failed']}")
    print(f"Precisión: {accuracy:.2f}%")
    
    print("\nDetalles de casos fallidos:")
    for case in results["details"]:
        if not case["passed"]:
            print(f"  - Query: '{case['query']}'")
            print(f"    Esperado: '{case['expected_intent']}', Detectado: '{case['actual_intent']}'")
    
    # Guardar resultados en archivo
    results_file = "test_results/query_processor_evaluation.json"
    os.makedirs(os.path.dirname(results_file), exist_ok=True)
    
    with open(results_file, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    
    print(f"\nResultados detallados guardados en: {results_file}")

if __name__ == "__main__":
    evaluate_query_processor()