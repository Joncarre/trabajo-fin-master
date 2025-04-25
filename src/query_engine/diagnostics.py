# src/query_engine/diagnostics.py
import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional

class QueryDiagnostics:
    """
    Sistema de diagnóstico para registrar y analizar consultas y respuestas.
    Útil para mejorar patrones y optimizar el motor de consultas.
    """
    
    def __init__(self, log_dir="query_logs"):
        """
        Inicializa el sistema de diagnóstico.
        
        Args:
            log_dir (str): Directorio para guardar registros
        """
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        self.logger = logging.getLogger("QueryDiagnostics")
        self.logger.setLevel(logging.INFO)
        
        # Configurar handler para archivo
        log_file = os.path.join(log_dir, f"query_log_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = logging.FileHandler(log_file)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        
        # Evitar duplicar handlers
        if not self.logger.handlers:
            self.logger.addHandler(file_handler)
    
    def log_query(self, query: str, processed_query: Dict[str, Any], 
                 results: Dict[str, Any], response: str) -> None:
        """
        Registra una consulta completa con su procesamiento y respuesta.
        
        Args:
            query (str): Consulta original
            processed_query (Dict): Consulta procesada
            results (Dict): Resultados de la ejecución
            response (str): Respuesta generada
        """
        # Crear registro
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "original_query": query,
            "processed_query": {
                "intent": processed_query.get("intent", ""),
                "parameters": processed_query.get("parameters", {})
            },
            "execution_results": {
                "result_type": results.get("result_type", ""),
                "time_period": results.get("time_period", "")
            },
            "response_length": len(response)
        }
        
        # Guardar registro detallado en archivo JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        detail_file = os.path.join(self.log_dir, f"query_detail_{timestamp}.json")
        
        full_log = {
            "original_query": query,
            "processed_query": processed_query,
            "execution_results": results,
            "response": response
        }
        
        with open(detail_file, 'w', encoding='utf-8') as f:
            json.dump(full_log, f, indent=2, ensure_ascii=False)
        
        # Registrar resumen en el log
        log_message = (f"Query: '{query}' | Intent: {processed_query.get('intent', '')} | "
                      f"Result type: {results.get('result_type', '')} | "
                      f"Detail file: {os.path.basename(detail_file)}")
        self.logger.info(log_message)
    
    def analyze_intents(self) -> Dict[str, int]:
        """
        Analiza la distribución de intenciones detectadas.
        
        Returns:
            Dict: Conteo de cada intención
        """
        intent_counts = {}
        
        # Recorrer archivos de detalle
        for filename in os.listdir(self.log_dir):
            if filename.startswith("query_detail_") and filename.endswith(".json"):
                file_path = os.path.join(self.log_dir, filename)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        log_data = json.load(f)
                    
                    # Extraer intención
                    intent = log_data.get("processed_query", {}).get("intent", "unknown")
                    
                    # Actualizar contador
                    if intent in intent_counts:
                        intent_counts[intent] += 1
                    else:
                        intent_counts[intent] = 1
                        
                except Exception as e:
                    self.logger.error(f"Error al analizar archivo {filename}: {e}")
        
        return intent_counts
    
    def find_failed_queries(self) -> List[Dict[str, Any]]:
        """
        Identifica consultas que no fueron procesadas correctamente.
        
        Returns:
            List: Lista de consultas problemáticas
        """
        failed_queries = []
        
        # Recorrer archivos de detalle
        for filename in os.listdir(self.log_dir):
            if filename.startswith("query_detail_") and filename.endswith(".json"):
                file_path = os.path.join(self.log_dir, filename)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        log_data = json.load(f)
                    
                    # Verificar si hay error o la intención es desconocida
                    processed_query = log_data.get("processed_query", {})
                    results = log_data.get("execution_results", {})
                    
                    is_failed = False
                    failure_reason = ""
                    
                    if processed_query.get("intent", "") == "consulta_general":
                        # Posible falla en la detección de intención
                        is_failed = True
                        failure_reason = "Intención no reconocida"
                    
                    if "error" in results:
                        is_failed = True
                        failure_reason = f"Error en ejecución: {results['error']}"
                    
                    if is_failed:
                        failed_queries.append({
                            "query": log_data.get("original_query", ""),
                            "file": filename,
                            "failure_reason": failure_reason
                        })
                        
                except Exception as e:
                    self.logger.error(f"Error al analizar archivo {filename}: {e}")
        
        return failed_queries
    
    def export_analysis(self, output_file="query_analysis.json") -> None:
        """
        Exporta un análisis completo de las consultas registradas.
        
        Args:
            output_file (str): Archivo de salida para el análisis
        """
        # Contar intenciones
        intent_counts = self.analyze_intents()
        
        # Encontrar consultas fallidas
        failed_queries = self.find_failed_queries()
        
        # Generar estadísticas de parámetros
        parameter_stats = self._analyze_parameters()
        
        # Compilar análisis
        analysis = {
            "timestamp": datetime.now().isoformat(),
            "total_queries": sum(intent_counts.values()),
            "intent_distribution": intent_counts,
            "failed_queries": {
                "count": len(failed_queries),
                "details": failed_queries
            },
            "parameter_statistics": parameter_stats
        }
        
        # Guardar análisis
        output_path = os.path.join(self.log_dir, output_file)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(analysis, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Análisis exportado a: {output_path}")
    
    def _analyze_parameters(self) -> Dict[str, Any]:
        """
        Analiza los parámetros extraídos de las consultas.
        
        Returns:
            Dict: Estadísticas de parámetros
        """
        # Inicializar estadísticas
        param_stats = {
            "time_parameters": {
                "count": 0,
                "periods": {}
            },
            "protocol_parameters": {
                "count": 0,
                "protocols": {}
            },
            "ip_parameters": {
                "count": 0,
                "examples": []
            }
        }
        
        # Recorrer archivos de detalle
        for filename in os.listdir(self.log_dir):
            if filename.startswith("query_detail_") and filename.endswith(".json"):
                file_path = os.path.join(self.log_dir, filename)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        log_data = json.load(f)
                    
                    # Extraer parámetros
                    parameters = log_data.get("processed_query", {}).get("parameters", {})
                    
                    # Analizar parámetros de tiempo
                    if "time_period" in parameters:
                        param_stats["time_parameters"]["count"] += 1
                        
                        period = parameters["time_period"]
                        if period in param_stats["time_parameters"]["periods"]:
                            param_stats["time_parameters"]["periods"][period] += 1
                        else:
                            param_stats["time_parameters"]["periods"][period] = 1
                    
                    # Analizar parámetros de protocolo
                    if "protocols" in parameters:
                        param_stats["protocol_parameters"]["count"] += 1
                        
                        for protocol in parameters["protocols"]:
                            if protocol in param_stats["protocol_parameters"]["protocols"]:
                                param_stats["protocol_parameters"]["protocols"][protocol] += 1
                            else:
                                param_stats["protocol_parameters"]["protocols"][protocol] = 1
                    
                    # Analizar parámetros de IP
                    if "ip_address" in parameters:
                        param_stats["ip_parameters"]["count"] += 1
                        
                        # Guardar algunos ejemplos (máximo 10)
                        if len(param_stats["ip_parameters"]["examples"]) < 10:
                            param_stats["ip_parameters"]["examples"].append(parameters["ip_address"])
                        
                except Exception as e:
                    self.logger.error(f"Error al analizar parámetros en {filename}: {e}")
        
        return param_stats