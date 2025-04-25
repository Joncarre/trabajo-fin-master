# src/query_engine/context_enhancer.py
import os
import json
from typing import Dict, Any

class ContextEnhancer:
    """
    Mejora las respuestas con contexto organizacional y personalización.
    """
    
    def __init__(self, context_file=None):
        """
        Inicializa el mejorador de contexto.
        
        Args:
            context_file (str, optional): Ruta al archivo JSON con información de contexto
        """
        self.org_context = {}
        
        # Intentar cargar contexto desde archivo
        if context_file and os.path.exists(context_file):
            try:
                with open(context_file, 'r', encoding='utf-8') as f:
                    self.org_context = json.load(f)
            except Exception as e:
                print(f"Error al cargar archivo de contexto: {e}")
        
        # Valores por defecto
        self.default_context = {
            "company_name": "su organización",
            "security_contact": "administrador de seguridad",
            "network_size": "mediana",
            "industry": "general",
            "critical_assets": ["servidores", "bases de datos", "información de usuarios"],
            "security_level": "estándar"
        }
    
    def enhance_response(self, formatted_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mejora los resultados con contexto organizacional.
        
        Args:
            formatted_results (Dict): Resultados formateados
            
        Returns:
            Dict: Resultados mejorados con contexto
        """
        # Combinar contexto por defecto con contexto organizacional
        context = {**self.default_context, **self.org_context}
        
        # Añadir información de contexto a los resultados
        formatted_results["org_context"] = context
        
        # Adaptar recomendaciones según el contexto
        if "threat_level" in formatted_results:
            formatted_results["recommendations"] = self._get_recommendations(
                formatted_results["threat_level"],
                context
            )
        
        return formatted_results
    
    def _get_recommendations(self, threat_level: str, context: Dict[str, Any]) -> str:
        """
        Genera recomendaciones basadas en el nivel de amenaza y el contexto.
        
        Args:
            threat_level (str): Nivel de amenaza detectado
            context (Dict): Contexto organizacional
            
        Returns:
            str: Recomendaciones personalizadas
        """
        industry = context.get("industry", "general")
        security_level = context.get("security_level", "estándar")
        
        # Recomendaciones básicas según nivel de amenaza
        if threat_level == "Crítico":
            return "Activar protocolo de respuesta a incidentes inmediatamente. Aislar sistemas afectados y contactar al equipo de seguridad."
        elif threat_level == "Alto":
            return "Investigar las amenazas detectadas con prioridad alta. Considerar restricciones temporales de acceso a recursos sensibles."
        elif threat_level == "Medio":
            return "Realizar un análisis detallado de las anomalías detectadas y reforzar monitoreo en las próximas 24 horas."
        elif threat_level == "Bajo":
            return "Mantener la vigilancia habitual. Las anomalías detectadas parecen ser de bajo riesgo."
        else:
            return "Continuar con el monitoreo regular de la red."