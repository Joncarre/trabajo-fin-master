# src/query_engine/query_processor.py
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional

class QueryProcessor:
    """
    Procesa consultas en lenguaje natural para determinar la intención y los parámetros.
    """
    
    def __init__(self):
        """Inicializa el procesador de consultas."""
        self.logger = logging.getLogger("QueryProcessor")
        
        # Definir patrones de consultas comunes
        self.query_patterns = {
            "anomalias_recientes": [
                r"(?:ha habido|hubo|hay|detecta(?:ste|ron)?|encuentra|muestra) (?:alguna )?anomal(?:ía|ias)",
                r"anomal(?:ía|ias)(?:.*?)(?:reciente|última|pasad)",
                r"(?:última|reciente)s? anomal(?:ía|ias)",
            ],
            "amenazas_por_severidad": [
                r"(?:muestra|lista|encuentra|detecta) (?:las )?amenazas (?:por|según) severidad",
                r"amenazas (?:más )?(?:grave|severa|crítica|importante)s",
                r"(?:cuál|cuáles) (?:es|son) (?:la|las) (?:amenaza|anomalía)s? (?:más )?(?:grave|severa|crítica|importante)"
            ],
            "escaneos_puertos": [
                r"(?:ha habido|hubo|hay|detecta(?:ste|ron)?|encuentra|muestra) (?:algún )?escaneo de puertos",
                r"escaneo(?:s)? de puerto(?:s)?",
                r"han escaneado (?:mis|los) puertos"
            ],
            "top_talkers": [
                r"(?:hosts|ips|direcciones) (?:más )?activ(?:o|a)s",
                r"(?:quién|quiénes|qué ips) (?:genera|generan|produce|producen) (?:más|mayor) tráfico",
                r"top talkers"
            ],
            "trafico_por_protocolo": [
                r"(?:distribución|porcentaje|proporción) (?:de|del) (?:tráfico|paquetes) (?:por|según) protocolo",
                r"(?:cuánto|qué) tráfico (?:hay|existe) (?:por|de cada) protocolo",
            ],
            "puertos_activos": [
                r"puertos (?:más )?(?:usados|utilizados|activos|comunes)",
                r"(?:qué|cuáles) (?:son los|) puertos (?:más )?(?:usados|utilizados|activos|comunes)"
            ],
            "actividad_ip_especifica": [
                r"(?:información|datos|actividad|tráfico) (?:de|sobre|para) (?:la )?ip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                r"analiza(?:r)? (?:la )?ip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                r"(?:qué|que) (?:hace|está haciendo|ha hecho) la ip (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            ],
            "resumen_trafico": [
                r"(?:resumen|panorama|visión general|overview) (?:del|de) tráfico",
                r"(?:resumen|resume|sintetiza|muestra) (?:el|los) (?:dato|datos) (?:del|de) tráfico",
                r"(?:cómo|como) (?:está|es) (?:el|mi) tráfico (?:de red|)"
            ],
            "actividad_periodo": [
                r"tráfico (?:en|de|durante) (?:la|el)? últim(?:a|o)s? (\d+) (?:hora|horas|minuto|minutos|día|días|semana|semanas)",
                r"actividad (?:en|de|durante) (?:la|el)? últim(?:a|o)s? (\d+) (?:hora|horas|minuto|minutos|día|días|semana|semanas)",
                r"(?:qué|que) (?:ha ocurrido|ha pasado|ocurrió|pasó) (?:en|durante) (?:la|el)? últim(?:a|o)s? (\d+) (?:hora|horas|minuto|minutos|día|días|semana|semanas)"
            ]
        }
    
    def process_query(self, query: str) -> Dict[str, Any]:
        """
        Procesa una consulta para determinar la intención y los parámetros.
        
        Args:
            query (str): Consulta en lenguaje natural
            
        Returns:
            Dict: Contiene la intención y los parámetros extraídos
        """
        # Normalizar la consulta (minúsculas, sin acentos, etc.)
        normalized_query = self._normalize_query(query)
        
        # Determinar la intención
        intent, params = self._determine_intent(normalized_query)
        
        # Extraer parámetros de tiempo
        time_params = self._extract_time_parameters(normalized_query)
        if time_params:
            params.update(time_params)
        
        # Extraer parámetros adicionales
        self._extract_additional_parameters(normalized_query, params)
        
        return {
            "original_query": query,
            "normalized_query": normalized_query,
            "intent": intent,
            "parameters": params
        }
    
    def _normalize_query(self, query: str) -> str:
        """
        Normaliza una consulta para facilitar el procesamiento.
        
        Args:
            query (str): Consulta original
            
        Returns:
            str: Consulta normalizada
        """
        # Convertir a minúsculas
        query = query.lower()
        
        # Eliminar signos de puntuación y caracteres especiales
        query = re.sub(r'[¿¡!.,;:()\[\]{}"\']', ' ', query)
        
        # Reemplazar múltiples espacios por uno solo
        query = re.sub(r'\s+', ' ', query).strip()
        
        return query
    
    def _determine_intent(self, query: str) -> Tuple[str, Dict[str, Any]]:
        """
        Determina la intención principal de la consulta.
        
        Args:
            query (str): Consulta normalizada
            
        Returns:
            Tuple[str, Dict]: Intención detectada y parámetros iniciales
        """
        # Comprobar cada patrón de consulta
        for intent, patterns in self.query_patterns.items():
            for pattern in patterns:
                match = re.search(pattern, query)
                if match:
                    # Extraer parámetros de los grupos capturados
                    params = {}
                    if intent == "actividad_ip_especifica" and match.groups():
                        params["ip_address"] = match.group(1)
                    elif intent == "actividad_periodo" and match.groups():
                        time_value = int(match.group(1))
                        time_unit = self._determine_time_unit(query)
                        params["time_value"] = time_value
                        params["time_unit"] = time_unit
                    
                    return intent, params
        
        # Si no se encuentra ninguna intención específica
        return "consulta_general", {}
    
    def _extract_time_parameters(self, query: str) -> Dict[str, Any]:
        """
        Extrae parámetros de tiempo de la consulta.
        
        Args:
            query (str): Consulta normalizada
            
        Returns:
            Dict: Parámetros de tiempo
        """
        params = {}
        
        # Buscar referencias a periodos de tiempo
        time_patterns = {
            'hour': [r'última hora', r'pasada hora', r'hace una hora'],
            'day': [r'último día', r'pasadas 24 horas', r'últimas 24 horas', r'ayer'],
            'week': [r'última semana', r'pasados 7 días', r'últimos 7 días'],
            'month': [r'último mes', r'pasados 30 días', r'últimos 30 días']
        }
        
        for period, patterns in time_patterns.items():
            for pattern in patterns:
                if pattern in query:
                    end_time = datetime.now()
                    
                    if period == 'hour':
                        start_time = end_time - timedelta(hours=1)
                    elif period == 'day':
                        start_time = end_time - timedelta(days=1)
                    elif period == 'week':
                        start_time = end_time - timedelta(days=7)
                    elif period == 'month':
                        start_time = end_time - timedelta(days=30)
                    
                    params['start_time'] = start_time
                    params['end_time'] = end_time
                    params['time_period'] = period
                    return params
        
        # Buscar números específicos de horas, días, etc.
        time_matches = re.search(r'últim(?:a|o)s? (\d+) (hora|horas|día|días|semana|semanas|mes|meses)', query)
        if time_matches:
            value = int(time_matches.group(1))
            unit = time_matches.group(2)
            
            end_time = datetime.now()
            
            if 'hora' in unit:
                start_time = end_time - timedelta(hours=value)
                period = 'hour'
            elif 'día' in unit:
                start_time = end_time - timedelta(days=value)
                period = 'day'
            elif 'semana' in unit:
                start_time = end_time - timedelta(weeks=value)
                period = 'week'
            elif 'mes' in unit:
                start_time = end_time - timedelta(days=value*30)  # Aproximación
                period = 'month'
            else:
                return params
            
            params['start_time'] = start_time
            params['end_time'] = end_time
            params['time_period'] = period
            params['time_value'] = value
            params['time_unit'] = unit
        
        return params
    
    def _determine_time_unit(self, query: str) -> str:
        """
        Determina la unidad de tiempo mencionada en la consulta.
        
        Args:
            query (str): Consulta normalizada
            
        Returns:
            str: Unidad de tiempo ('hour', 'day', 'week', 'month')
        """
        if any(term in query for term in ['hora', 'horas']):
            return 'hour'
        elif any(term in query for term in ['dia', 'días', 'día']):
            return 'day'
        elif any(term in query for term in ['semana', 'semanas']):
            return 'week'
        elif any(term in query for term in ['mes', 'meses']):
            return 'month'
        else:
            return 'hour'  # Default
    
    def _extract_additional_parameters(self, query: str, params: Dict[str, Any]) -> None:
        """
        Extrae parámetros adicionales de la consulta y los añade al diccionario.
        
        Args:
            query (str): Consulta normalizada
            params (Dict): Diccionario de parámetros a actualizar
        """
        # Extraer protocolos mencionados
        protocol_patterns = {
            'tcp': [r'\btcp\b'],
            'udp': [r'\budp\b'],
            'icmp': [r'\bicmp\b'],
            'http': [r'\bhttp\b'],
            'https': [r'\bhttps\b'],
            'dns': [r'\bdns\b'],
            'ssh': [r'\bssh\b']
        }
        
        mentioned_protocols = []
        for protocol, patterns in protocol_patterns.items():
            for pattern in patterns:
                if re.search(pattern, query):
                    mentioned_protocols.append(protocol)
        
        if mentioned_protocols:
            params['protocols'] = mentioned_protocols
        
        # Extraer menciones de severidad
        severity_patterns = {
            'high': [r'alta', r'grave', r'crítica', r'críticas', r'severa', r'severas'],
            'medium': [r'media', r'moderada', r'moderadas'],
            'low': [r'baja', r'bajas', r'leve', r'leves']
        }
        
        for severity, patterns in severity_patterns.items():
            for pattern in patterns:
                if pattern in query:
                    params['severity'] = severity
                    break
        
        # Extraer número de resultados deseados
        limit_match = re.search(r'(?:muestra|lista|encuentra|dame|ver|obtener) (?:los|las)? (\d+)', query)
        if limit_match:
            params['limit'] = int(limit_match.group(1))
        
        # Detectar si se pide una visualización
        if any(term in query for term in ['gráfico', 'grafico', 'visualiza', 'visualizar', 'muestra', 'grafica', 'graficar']):
            params['visualization'] = True