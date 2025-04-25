# src/query_engine/response_templates.py
"""
Plantillas para la generación de respuestas en lenguaje natural.
Ayuda a estructurar mejor las respuestas para diferentes tipos de consultas.
"""

class ResponseTemplates:
    """Plantillas para diferentes tipos de respuestas."""
    
    @staticmethod
    def anomalias_recientes(results):
        """Plantilla para anomalías recientes."""
        total_anomalies = results.get("total_anomalies", 0)
        time_period = results.get("time_period", "período analizado")
        
        if total_anomalies == 0:
            template = f"""
            No se detectaron anomalías en el {time_period}. El tráfico de red parece normal.
            
            Resumen del tráfico analizado:
            {{traffic_summary}}
            """
        else:
            template = f"""
            Se detectaron {total_anomalies} anomalías en el {time_period}.
            
            Principales tipos de anomalías:
            {{anomalies_summary}}
            
            Estas anomalías podrían indicar actividades sospechosas en la red y deberían investigarse más a fondo.
            
            Resumen del tráfico analizado:
            {{traffic_summary}}
            """
        
        return template
    
    @staticmethod
    def amenazas_por_severidad(results):
        """Plantilla para amenazas por severidad."""
        threat_level = results.get("threat_level", "Bajo")
        time_period = results.get("time_period", "período analizado")
        
        template = f"""
        Nivel general de amenaza: {threat_level} en el {time_period}.
        
        {{threats_by_level}}
        
        Recomendación: {{recommendation}}
        """
        
        return template
    
    @staticmethod
    def escaneos_puertos(results):
        """Plantilla para escaneos de puertos."""
        total_scans = results.get("total_scans", 0)
        time_period = results.get("time_period", "período analizado")
        
        if total_scans == 0:
            template = f"""
            No se detectaron escaneos de puertos en el {time_period}.
            """
        else:
            template = f"""
            Se detectaron {total_scans} posibles escaneos de puertos en el {time_period}.
            
            Detalles de los escaneos:
            {{scan_details}}
            
            Los escaneos de puertos pueden ser indicativos de actividades de reconocimiento previas a un ataque.
            Se recomienda investigar el origen de estos escaneos y revisar las reglas de firewall.
            """
        
        return template
    
    # Añadir más plantillas para otros tipos de consultas...
    
    @staticmethod
    def get_template(intent):
        """
        Obtiene la plantilla correspondiente a una intención.
        
        Args:
            intent (str): Intención de la consulta
            
        Returns:
            callable: Método que genera la plantilla
        """
        if hasattr(ResponseTemplates, intent):
            return getattr(ResponseTemplates, intent)
        else:
            return ResponseTemplates.default_template
    
    @staticmethod
    def default_template(results):
        """Plantilla por defecto."""
        return """
        Resultados del análisis de tráfico de red:
        
        {summary}
        
        {details}
        """