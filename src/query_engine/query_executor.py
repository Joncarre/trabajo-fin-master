# src/query_engine/query_executor.py
import logging
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

from src.data_processing.storage_manager import StorageManager
from src.ai_engine.packet_analyzer import PacketAnalyzer

class QueryExecutor:
    """
    Ejecuta consultas interpretadas en operaciones concretas sobre la base de datos
    y el analizador de paquetes.
    """
    
    def __init__(self, db_path: str):
        """
        Inicializa el ejecutor de consultas.
        
        Args:
            db_path (str): Ruta a la base de datos SQLite
        """
        self.logger = logging.getLogger("QueryExecutor")
        self.storage = StorageManager(db_path)
        self.analyzer = PacketAnalyzer(db_path)
    
    def execute_query(self, query_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta procesada.
        
        Args:
            query_info (Dict): Información de la consulta procesada
            
        Returns:
            Dict: Resultados de la consulta
        """
        intent = query_info.get('intent', 'consulta_general')
        params = query_info.get('parameters', {})
        
        # Determinar el método de ejecución basado en la intención
        if hasattr(self, f"_execute_{intent}"):
            executor_method = getattr(self, f"_execute_{intent}")
            return executor_method(params)
        else:
            # Método genérico para consultas no reconocidas
            return self._execute_consulta_general(params)
    
    def _execute_anomalias_recientes(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta sobre anomalías recientes.
        """
        # Definir periodo de tiempo si no está en los parámetros
        if 'start_time' not in params:
            params['end_time'] = datetime.now()
            params['start_time'] = params['end_time'] - timedelta(hours=24)
        
        # Buscar anomalías
        anomalies = self.analyzer.search_anomalies(
            start_time=params['start_time'].timestamp(),
            end_time=params['end_time'].timestamp(),
            min_severity=params.get('min_severity', 0.3)
        )
        
        # Obtener estadísticas básicas
        protocol_stats = self.storage.get_protocol_statistics(
            start_time=params['start_time'],
            end_time=params['end_time']
        )
        
        # Obtener las principales IPs activas
        top_talkers = self.storage.get_top_talkers(
            start_time=params['start_time'],
            end_time=params['end_time'],
            limit=5
        )
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "anomalias_recientes",
            "anomalies": anomalies,
            "total_anomalies": len(anomalies),
            "time_period": time_period_str,
            "protocol_statistics": protocol_stats,
            "top_talkers": top_talkers,
            "query_params": params
        }
    
    def _execute_amenazas_por_severidad(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta sobre amenazas ordenadas por severidad.
        """
        # Definir periodo de tiempo si no está en los parámetros
        if 'start_time' not in params:
            params['end_time'] = datetime.now()
            params['start_time'] = params['end_time'] - timedelta(days=7)
        
        # Buscar anomalías
        anomalies = self.analyzer.search_anomalies(
            start_time=params['start_time'].timestamp(),
            end_time=params['end_time'].timestamp()
        )
        
        # Ordenar por severidad
        anomalies.sort(key=lambda x: x.get('severity', 0), reverse=True)
        
        # Limitar resultados si se especifica
        limit = params.get('limit', 10)
        anomalies = anomalies[:limit]
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "amenazas_por_severidad",
            "anomalies": anomalies,
            "total_anomalies": len(anomalies),
            "time_period": time_period_str,
            "query_params": params
        }
    
    def _execute_escaneos_puertos(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta sobre escaneos de puertos.
        """
        # Definir periodo de tiempo si no está en los parámetros
        if 'start_time' not in params:
            params['end_time'] = datetime.now()
            params['start_time'] = params['end_time'] - timedelta(days=1)
        
        # Detectar escaneos de puertos
        port_scans = self.analyzer.detect_port_scans(
            timeframe=(params['start_time'].timestamp(), params['end_time'].timestamp()),
            threshold=params.get('threshold', 10)
        )
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "escaneos_puertos",
            "port_scans": port_scans,
            "total_scans": len(port_scans),
            "time_period": time_period_str,
            "query_params": params
        }
    
    def _execute_top_talkers(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta sobre los hosts más activos.
        """
        # Definir periodo de tiempo si no está en los parámetros
        if 'start_time' not in params:
            params['end_time'] = datetime.now()
            params['start_time'] = params['end_time'] - timedelta(hours=24)
        
        # Obtener top talkers
        top_talkers = self.analyzer.get_top_talkers(
            n=params.get('limit', 10),
            by_bytes=True,
            protocol=params.get('protocol'),
            timeframe=(params['start_time'].timestamp(), params['end_time'].timestamp())
        )
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "top_talkers",
            "top_talkers": top_talkers,
            "time_period": time_period_str,
            "query_params": params
        }
    
    def _execute_trafico_por_protocolo(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta sobre distribución de tráfico por protocolo.
        """
        # Definir periodo de tiempo si no está en los parámetros
        if 'start_time' not in params:
            params['end_time'] = datetime.now()
            params['start_time'] = params['end_time'] - timedelta(hours=24)
        
        # Obtener estadísticas de protocolo
        protocol_stats = self.storage.get_protocol_statistics(
            start_time=params['start_time'],
            end_time=params['end_time']
        )
        
        # Calcular porcentajes
        total_packets = sum(protocol_stats.values())
        protocol_percentages = {}
        
        if total_packets > 0:
            for protocol, count in protocol_stats.items():
                protocol_percentages[protocol] = (count / total_packets) * 100
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "trafico_por_protocolo",
            "protocol_statistics": protocol_stats,
            "protocol_percentages": protocol_percentages,
            "total_packets": total_packets,
            "time_period": time_period_str,
            "query_params": params
        }
    
    def _execute_puertos_activos(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta sobre puertos más activos.
        """
        # Definir periodo de tiempo si no está en los parámetros
        if 'start_time' not in params:
            params['end_time'] = datetime.now()
            params['start_time'] = params['end_time'] - timedelta(hours=24)
        
        # Obtener puertos TCP activos
        tcp_ports = self.storage.get_top_ports(
            protocol='tcp',
            limit=params.get('limit', 10),
            start_time=params['start_time'],
            end_time=params['end_time']
        )
        
        # Obtener puertos UDP activos
        udp_ports = self.storage.get_top_ports(
            protocol='udp',
            limit=params.get('limit', 10),
            start_time=params['start_time'],
            end_time=params['end_time']
        )
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "puertos_activos",
            "tcp_ports": tcp_ports,
            "udp_ports": udp_ports,
            "time_period": time_period_str,
            "query_params": params
        }
    
    def _execute_actividad_ip_especifica(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta sobre actividad de una IP específica.
        """
        ip_address = params.get('ip_address')
        if not ip_address:
            return {"error": "No se especificó una dirección IP"}
        
        # Definir periodo de tiempo si no está en los parámetros
        if 'start_time' not in params:
            params['end_time'] = datetime.now()
            params['start_time'] = params['end_time'] - timedelta(days=1)
        
        # Analizar patrones de comunicación para esta IP
        communication_patterns = self.analyzer.analyze_communication_patterns(
            ip_address=ip_address,
            timeframe=(params['start_time'].timestamp(), params['end_time'].timestamp())
        )
        
        # Obtener paquetes relacionados con esta IP
        packets = self.storage.query_packets(
            src_ip=ip_address,
            dst_ip=ip_address,
            start_time=params['start_time'],
            end_time=params['end_time'],
            limit=params.get('limit', 100)
        )
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "actividad_ip_especifica",
            "ip_address": ip_address,
            "communication_patterns": communication_patterns,
            "total_packets": len(packets),
            "packets_sample": packets[:10],  # Limitar muestra
            "time_period": time_period_str,
            "query_params": params
        }
    
    def _execute_resumen_trafico(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta sobre resumen general del tráfico.
        """
        # Definir periodo de tiempo si no está en los parámetros
        if 'start_time' not in params:
            params['end_time'] = datetime.now()
            params['start_time'] = params['end_time'] - timedelta(hours=24)
        
        # Obtener la sesión más reciente para analizar
        session = None
        all_sessions = self.storage.get_all_sessions()
        if all_sessions:
            session = all_sessions[0]  # La más reciente
        
        if not session:
            return {"error": "No hay sesiones disponibles para analizar"}
        
        # Analizar la sesión
        session_analysis = self.analyzer.analyze_session(session["id"])
        
        # Obtener estadísticas básicas
        protocol_stats = self.storage.get_protocol_statistics(
            start_time=params['start_time'],
            end_time=params['end_time']
        )
        
        # Obtener las principales IPs activas
        top_talkers = self.storage.get_top_talkers(
            start_time=params['start_time'],
            end_time=params['end_time'],
            limit=5
        )
        
        # Buscar anomalías recientes
        anomalies = self.analyzer.search_anomalies(
            start_time=params['start_time'].timestamp(),
            end_time=params['end_time'].timestamp(),
            min_severity=0.5  # Solo las más importantes
        )
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "resumen_trafico",
            "session_analysis": session_analysis,
            "protocol_statistics": protocol_stats,
            "top_talkers": top_talkers,
            "recent_anomalies": anomalies[:5],  # Limitar a 5
            "total_anomalies": len(anomalies),
            "time_period": time_period_str,
            "query_params": params
        }
    
    def _execute_actividad_periodo(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta sobre actividad en un periodo específico.
        """
        # Verificar que tenemos parámetros de tiempo
        if 'start_time' not in params:
            if 'time_value' in params and 'time_unit' in params:
                # Calcular el periodo basado en valor y unidad
                params['end_time'] = datetime.now()
                
                if params['time_unit'] == 'hour':
                    params['start_time'] = params['end_time'] - timedelta(hours=params['time_value'])
                elif params['time_unit'] == 'day':
                    params['start_time'] = params['end_time'] - timedelta(days=params['time_value'])
                elif params['time_unit'] == 'week':
                    params['start_time'] = params['end_time'] - timedelta(weeks=params['time_value'])
                elif params['time_unit'] == 'month':
                    params['start_time'] = params['end_time'] - timedelta(days=30 * params['time_value'])
            else:
                # Por defecto, último día
                params['end_time'] = datetime.now()
                params['start_time'] = params['end_time'] - timedelta(days=1)
        
        # Obtener protocolos si se especifican
        protocols = params.get('protocols', None)
        
        # Obtener estadísticas de protocolo
        protocol_stats = self.storage.get_protocol_statistics(
            start_time=params['start_time'],
            end_time=params['end_time']
        )
        
        # Obtener las principales IPs activas
        top_talkers = self.storage.get_top_talkers(
            start_time=params['start_time'],
            end_time=params['end_time'],
            limit=5
        )
        
        # Buscar anomalías en el periodo especificado
        anomalies = self.analyzer.search_anomalies(
            start_time=params['start_time'].timestamp(),
            end_time=params['end_time'].timestamp(),
            protocols=protocols
        )
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "actividad_periodo",
            "protocol_statistics": protocol_stats,
            "top_talkers": top_talkers,
            "anomalies": anomalies,
            "total_anomalies": len(anomalies),
            "time_period": time_period_str,
            "query_params": params
        }
    
    def _execute_consulta_general(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ejecuta una consulta general no clasificada.
        Devuelve información básica que podría ser relevante.
        """
        # Definir periodo de tiempo si no está en los parámetros
        if 'start_time' not in params:
            params['end_time'] = datetime.now()
            params['start_time'] = params['end_time'] - timedelta(hours=24)
        
        # Obtener la sesión más reciente
        session = None
        all_sessions = self.storage.get_all_sessions()
        if all_sessions:
            session = all_sessions[0]  # La más reciente
        
        # Obtener estadísticas básicas
        protocol_stats = self.storage.get_protocol_statistics(
            start_time=params['start_time'],
            end_time=params['end_time']
        )
        
        # Obtener las principales IPs activas
        top_talkers = self.storage.get_top_talkers(
            start_time=params['start_time'],
            end_time=params['end_time'],
            limit=5
        )
        
        # Buscar anomalías recientes
        anomalies = self.analyzer.search_anomalies(
            start_time=params['start_time'].timestamp(),
            end_time=params['end_time'].timestamp(),
            min_severity=0.5  # Solo las más importantes
        )
        
        # Preparar respuesta
        time_period_str = self._format_time_period(params)
        
        return {
            "result_type": "consulta_general",
            "session_info": session,
            "protocol_statistics": protocol_stats,
            "top_talkers": top_talkers,
            "recent_anomalies": anomalies[:3],  # Limitar a 3
            "total_anomalies": len(anomalies),
            "time_period": time_period_str,
            "query_params": params
        }
    
    def _format_time_period(self, params: Dict[str, Any]) -> str:
        """
        Formatea un periodo de tiempo para mostrar en la respuesta.
        
        Args:
            params (Dict): Parámetros con start_time y end_time
            
        Returns:
            str: Descripción del periodo de tiempo
        """
        if 'start_time' not in params or 'end_time' not in params:
            return "periodo no especificado"
        
        start_time = params['start_time']
        end_time = params['end_time']
        
        # Formato para fechas
        date_format = "%d/%m/%Y %H:%M:%S"
        
        # Calcular la diferencia
        delta = end_time - start_time
        
        if delta.days == 0:
            # Menos de un día
            hours = delta.seconds // 3600
            if hours <= 1:
                return f"última hora (desde {start_time.strftime(date_format)})"
            else:
                return f"últimas {hours} horas (desde {start_time.strftime(date_format)})"
        elif delta.days == 1:
            return f"último día (desde {start_time.strftime(date_format)})"
        elif delta.days < 7:
            return f"últimos {delta.days} días (desde {start_time.strftime(date_format)})"
        elif delta.days < 30:
            weeks = delta.days // 7
            return f"últimas {weeks} semanas (desde {start_time.strftime(date_format)})"
        elif delta.days < 365:
            months = delta.days // 30
            return f"últimos {months} meses (desde {start_time.strftime(date_format)})"
        else:
            years = delta.days // 365
            return f"últimos {years} años (desde {start_time.strftime(date_format)})"