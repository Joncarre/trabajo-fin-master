# src/query_engine/language_model.py
import os
import json
import requests
import logging
from typing import Dict, Any, List, Optional, Union
import anthropic
import inspect
import datetime

# Codificador personalizado para serializar objetos datetime a formato ISO 8601 en JSON
class DateTimeEncoder(json.JSONEncoder):
    """
    A custom JSON encoder class for handling `datetime.datetime` and `datetime.date` objects.

    This encoder converts `datetime` and `date` objects into ISO 8601 formatted strings
    when serializing to JSON. If the object is not a `datetime` or `date` instance, the
    default serialization behavior is used.

    Methods:
        default(obj):
            Overrides the default method of `json.JSONEncoder` to handle `datetime`
            and `date` objects by returning their ISO 8601 string representation.
    """
    """Encoder personalizado para manejar objetos datetime en JSON"""
    def default(self, obj):
        if isinstance(obj, (datetime.datetime, datetime.date)):
            return obj.isoformat()
        return super().default(obj)

# Cliente principal para interactuar con modelos de lenguaje de Anthropic (Claude)
class LLMClient:
    """
    Cliente para interactuar con modelos de lenguaje (Claude)
    """
    def __init__(self, api_key=None, model="claude-3-opus-20240229"):
        """
        Inicializa el cliente de modelo de lenguaje.
        
        Args:
            api_key (str, optional): API key para Claude. Si es None, se usa la variable de entorno ANTHROPIC_API_KEY
            model (str): Modelo de Claude a utilizar
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY") or os.getenv("API_KEY_OPENAI")
        if not self.api_key:
            raise ValueError("Se requiere una API key para Claude. Establece la variable de entorno ANTHROPIC_API_KEY o pásala como parámetro.")
        self.model = model
        self.logger = logging.getLogger("LLMClient")
        
        # Initialize Anthropic client with proper version handling
        self._initialize_client()

    # Método para inicializar el cliente Anthropic con manejo de diferentes versiones de la biblioteca
    def _initialize_client(self):
        """
        Initialize the Anthropic client with proper version handling
        """
        try:
            # Basic initialization attempt using direct import approach
            # without any extra parameters that might cause issues
            self.client = anthropic.Anthropic(api_key=self.api_key)
            self.logger.info("Anthropic client initialized successfully")
            
        except TypeError as e:
            self.logger.warning(f"Modern Anthropic client initialization failed: {e}. Trying older client.")
            try:
                # Try the older client pattern
                self.client = anthropic.Client(api_key=self.api_key)
                self.logger.info("Anthropic client initialized successfully (using older Client class)")
                
            except Exception as e2:
                self.logger.error(f"All client initialization methods failed. Latest error: {e2}")
                
                # Last resort: Direct API access without using the client classes
                self.logger.warning("Falling back to direct API implementation")
                self.client = DummyAnthropicClient(self.api_key, self.model, self.logger)
    # Método principal para procesar consultas con el modelo de lenguaje y contexto adicional
    def process_query(self, query: str, context: Dict[str, Any], system_prompt: str = None) -> str:
        """
        Procesa una consulta en lenguaje natural usando Claude.
        """
        try:
            # Preparar el sistema de prompt por defecto si no se proporciona uno
            if system_prompt is None:
                system_prompt = self._build_default_system_prompt()
            
            # Preparar el mensaje con contexto
            query_with_context = self._prepare_query_with_context(query, context)
            
            # Llamar a la API de Claude - usar try/except para manejar diferentes versiones
            try:
                # Verificar si estamos usando la clase moderna o la de respaldo
                if isinstance(self.client, DummyAnthropicClient):
                    response = self.client.messages.create(
                        model=self.model,
                        system=system_prompt,
                        messages=[{"role": "user", "content": query_with_context}],
                        max_tokens=2000
                    )
                else:
                    # Intentar con la API moderna primero
                    response = self.client.messages.create(
                        model=self.model,
                        system=system_prompt,
                        messages=[{"role": "user", "content": query_with_context}],
                        max_tokens=2000
                    )
                
                # Extraer la respuesta
                return response.content[0].text
                
            except AttributeError:
                # Para versiones antiguas del cliente
                self.logger.info("Usando método alternativo de API")
                response = self.client.completion(
                    prompt=f"\n\nHuman: {query_with_context}\n\nAssistant:",
                    stop_sequences=["\n\nHuman:"],
                    model=self.model,
                    max_tokens_to_sample=2000
                )
                return response.completion
                
        except Exception as e:
            self.logger.error(f"Error al procesar consulta con Claude: {e}")
            return f"Error al procesar la consulta: {str(e)}"
        
    # Método para generar el prompt de sistema que especifica el rol del asistente en ciberseguridad
    def _build_default_system_prompt(self) -> str:
        """
        Construye el prompt de sistema por defecto para Claude.
        """
        return """
        Eres un asistente especializado en ciberseguridad y análisis de tráfico de red.
        Tu tarea es analizar datos de tráfico de red e identificar posibles amenazas o problemas de seguridad.
        
        Debes proporcionar respuestas precisas, técnicas y útiles basadas en los datos disponibles.
        
        - Cuando proporciones respuestas numéricas, incluye estadísticas y métricas relevantes.
        - Cuando identifiques amenazas, clasifícalas por severidad y proporciona recomendaciones.
        - Organiza la información de forma clara y estructurada.
        - Si los datos son insuficientes para responder con certeza, indica qué información adicional sería necesaria.
        - Evita usar jerga excesivamente técnica. Explica los conceptos en términos claros y comprensibles.
        - Tu objetivo es ayudar a usuarios sin experiencia avanzada en ciberseguridad a entender su tráfico de red.
        """
    
    # Método para estructurar la consulta con el contexto relevante en formato JSON para el modelo de lenguaje
    def _prepare_query_with_context(self, query: str, context: Dict[str, Any]) -> str:
        """
        Prepara la consulta incorporando el contexto relevante en un formato estructurado.
        """
        # Convertir el contexto a formato de texto estructurado con el encoder personalizado
        context_str = json.dumps(context, indent=2, cls=DateTimeEncoder)
        
        # Preparar el mensaje completo
        full_query = f"""
        Consulta del usuario: {query}
        
        Contexto disponible:
        ```json
        {context_str}
        ```
        
        Basándote en la consulta y el contexto proporcionado, genera una respuesta detallada.
        """
        
        return full_query


# Cliente de respaldo cuando el cliente oficial de Anthropic falla en su inicialización
class DummyAnthropicClient:
    """A fallback client implementation when the official client fails to initialize"""
    
    def __init__(self, api_key, model, logger):
        self.api_key = api_key
        self.model = model
        self.logger = logger
        self.messages = DummyMessagesAPI(api_key, model, logger)
    
class DummyMessagesAPI:
    """A simple implementation of the messages API for Anthropic"""
    
    def __init__(self, api_key, model, logger):
        self.api_key = api_key
        self.default_model = model
        self.logger = logger
        self.base_url = "https://api.anthropic.com/v1/messages"
    
    def create(self, model=None, system=None, messages=None, max_tokens=2000):
        """Direct API implementation of Anthropic's message creation"""
        try:
            model = model or self.default_model
            headers = {
                "Content-Type": "application/json",
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01"
            }
            
            data = {
                "model": model,
                "max_tokens": max_tokens,
                "messages": messages
            }
            
            if system:
                data["system"] = system
                
            # Usar DateTimeEncoder para manejar objetos datetime
            response = requests.post(
                self.base_url,
                headers=headers,
                data=json.dumps(data, cls=DateTimeEncoder)
            )
            
            if response.status_code != 200:
                error_msg = f"API request failed with status {response.status_code}: {response.text}"
                self.logger.error(error_msg)
                return DummyResponse(error_msg)
                
            result = response.json()
            return DummyResponse(result.get("content", [{"text": "No response text"}])[0]["text"])
            
        except Exception as e:
            self.logger.error(f"Error in direct API call: {e}")
            return DummyResponse(f"Error processing request: {str(e)}")

class DummyResponse:
    """A simple class to mimic the response structure of Anthropic's client"""
    
    def __init__(self, text):
        self.content = [DummyContent(text)]

class DummyContent:
    """A simple class to mimic the content structure of Anthropic's response"""
    
    def __init__(self, text):
        self.text = text