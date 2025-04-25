# src/query_engine/__init__.py

# Utilizar importaciones relativas para evitar problemas con los paths
from .query_processor import QueryProcessor
from .query_executor import QueryExecutor
from .language_model import LLMClient
from .response_formatter import ResponseFormatter
from .diagnostics import QueryDiagnostics
from .context_enhancer import ContextEnhancer

class NaturalLanguageQueryEngine:
    """
    Motor de consultas en lenguaje natural para analizar tráfico de red.
    Integra el procesamiento de consultas, ejecución, y formateo de respuestas.
    """
    
    def __init__(self, db_path, api_key=None, model="claude-3-opus-20240229", 
                context_file=None, enable_diagnostics=True):
        """
        Inicializa el motor de consultas en lenguaje natural.
        
        Args:
            db_path (str): Ruta a la base de datos SQLite
            api_key (str, optional): API key para Claude
            model (str): Modelo de Claude a utilizar
            context_file (str, optional): Archivo con contexto organizacional
            enable_diagnostics (bool): Activar sistema de diagnóstico
        """
        self.query_processor = QueryProcessor()
        self.query_executor = QueryExecutor(db_path)
        self.llm_client = LLMClient(api_key, model)
        self.response_formatter = ResponseFormatter()
        self.context_enhancer = ContextEnhancer(context_file)
        
        # Inicializar sistema de diagnóstico
        self.enable_diagnostics = enable_diagnostics
        if enable_diagnostics:
            self.diagnostics = QueryDiagnostics()
    
    def process_query(self, query: str):
        """
        Procesa una consulta en lenguaje natural y devuelve una respuesta.
        
        Args:
            query (str): Consulta en lenguaje natural
            
        Returns:
            str: Respuesta en lenguaje natural
        """
        # Paso 1: Procesar la consulta para determinar la intención
        processed_query = self.query_processor.process_query(query)
        
        # Paso 2: Ejecutar la consulta para obtener los datos
        query_results = self.query_executor.execute_query(processed_query)
        
        # Paso 3: Formatear los resultados
        formatted_results = self.response_formatter.format_response(query_results)
        
        # Paso 4: Mejorar resultados con contexto organizacional
        enhanced_results = self.context_enhancer.enhance_response(formatted_results)
        
        # Paso 5: Generar respuesta en lenguaje natural con Claude
        context = {
            "processed_query": processed_query,
            "query_results": enhanced_results
        }
        
        # Sistema de prompt personalizado para ayudar a Claude a generar la respuesta
        system_prompt = """
        Eres un asistente especializado en ciberseguridad que analiza tráfico de red.
        Tu objetivo es explicar los hallazgos del análisis de tráfico de red de forma clara y concisa:
        
        1. Utiliza un lenguaje claro y preciso, evitando jerga técnica innecesaria.
        2. Comienza siempre con un resumen de los hallazgos más importantes.
        3. Organiza la información por importancia, destacando anomalías y amenazas primero.
        4. Explica brevemente por qué ciertos hallazgos son importantes o merecen atención.
        5. Utiliza un tono informativo y profesional, pero accesible para usuarios no técnicos.
        6. Cuando menciones datos numéricos, proporciona contexto para que sean comprensibles.
        7. Si no hay problemas significativos, comunícalo claramente sin crear alarmas innecesarias.
        8. Adapta tus recomendaciones al contexto organizacional proporcionado.
        
        Tu respuesta debe ser útil tanto para administradores de red como para usuarios sin experiencia técnica.
        """
        
        response = self.llm_client.process_query(query, context, system_prompt)
        
        # Registrar diagnóstico si está habilitado
        if self.enable_diagnostics:
            self.diagnostics.log_query(query, processed_query, enhanced_results, response)
        
        return response

__all__ = ['NaturalLanguageQueryEngine', 'QueryProcessor', 'QueryExecutor', 'LLMClient', 'ResponseFormatter']