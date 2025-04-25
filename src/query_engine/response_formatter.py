# src/query_engine/response_formatter.py
import json
import logging
from typing import Dict, List, Any, Optional
# Añadir al inicio de response_formatter.py:
from src.query_engine.response_templates import ResponseTemplates

class ResponseFormatter:
    """
    Formatea los resultados de las consultas en respuestas legibles para humanos.
    """
    
    def __init__(self):
        """Inicializa el formateador de respuestas."""
        self.logger = logging.getLogger("ResponseFormatter")
    
    def format_response(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea los resultados en una respuesta estructurada.
        
        Args:
            results (Dict): Resultados de la consulta
            
        Returns:
            Dict: Respuesta formateada
        """
        # Determinar el tipo de resultado
        result_type = results.get("result_type", "consulta_general")
        
        # Ejecutar el método de formateo apropiado basado en el tipo
        if hasattr(self, f"_format_{result_type}"):
            formatter_method = getattr(self, f"_format_{result_type}")
            formatted_response = formatter_method(results)
        else:
            # Método por defecto
            formatted_response = self._format_consulta_general(results)
        
        # Añadir metadatos comunes
        formatted_response["time_period"] = results.get("time_period", "")
        
        # Obtener plantilla para ese tipo de respuesta
        template_generator = ResponseTemplates.get_template(result_type)
        formatted_response["response_template"] = template_generator(results)
        
        return formatted_response
    
    def _format_anomalias_recientes(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de anomalías recientes.
        """
        anomalies = results.get("anomalies", [])
        total_anomalies = results.get("total_anomalies", 0)
        
        # Agrupar anomalías por tipo
        anomalies_by_type = {}
        for anomaly in anomalies:
            anomaly_type = anomaly.get("type", "Desconocido")
            if anomaly_type not in anomalies_by_type:
                anomalies_by_type[anomaly_type] = []
            anomalies_by_type[anomaly_type].append(anomaly)
        
        # Formatear anomalías para mejor legibilidad
        formatted_anomalies = []
        for type_name, anomaly_list in anomalies_by_type.items():
            formatted_type = {
                "type": type_name,
                "count": len(anomaly_list),
                "anomalies": self._simplify_anomalies(anomaly_list)
            }
            formatted_anomalies.append(formatted_type)
        
        # Ordenar por cantidad
        formatted_anomalies.sort(key=lambda x: x["count"], reverse=True)
        
        # Añadir resumen de tráfico
        protocol_stats = results.get("protocol_statistics", {})
        
        # Formatear respuesta
        return {
            "summary": f"Se detectaron {total_anomalies} anomalías en el período analizado.",
            "detected_anomalies": formatted_anomalies,
            "traffic_summary": {
                "protocols": protocol_stats,
                "total_packets": sum(protocol_stats.values()) if protocol_stats else 0
            }
        }
    
    def _format_amenazas_por_severidad(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de amenazas por severidad.
        """
        anomalies = results.get("anomalies", [])
        total_anomalies = results.get("total_anomalies", 0)
        
        # Clasificar por nivel de severidad
        severity_levels = {
            "critical": [],  # 0.8 - 1.0
            "high": [],      # 0.6 - 0.8
            "medium": [],    # 0.4 - 0.6
            "low": []        # 0.0 - 0.4
        }
        
        for anomaly in anomalies:
            severity = anomaly.get("severity", 0)
            
            if severity >= 0.8:
                severity_levels["critical"].append(anomaly)
            elif severity >= 0.6:
                severity_levels["high"].append(anomaly)
            elif severity >= 0.4:
                severity_levels["medium"].append(anomaly)
            else:
                severity_levels["low"].append(anomaly)
        
        # Formatear amenazas por nivel
        formatted_threats = {}
        for level, threats in severity_levels.items():
            if threats:
                formatted_threats[level] = {
                    "count": len(threats),
                    "threats": self._simplify_anomalies(threats)
                }
        
        # Determinar nivel general de amenaza
        if severity_levels["critical"]:
            threat_level = "Crítico"
        elif severity_levels["high"]:
            threat_level = "Alto"
        elif severity_levels["medium"]:
            threat_level = "Medio"
        elif severity_levels["low"]:
            threat_level = "Bajo"
        else:
            threat_level = "Sin amenazas"
        
        return {
            "summary": f"Nivel general de amenaza: {threat_level}. Se encontraron {total_anomalies} amenazas.",
            "threat_level": threat_level,
            "threats_by_severity": formatted_threats
        }
    
    def _format_escaneos_puertos(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de escaneos de puertos.
        """
        port_scans = results.get("port_scans", [])
        total_scans = results.get("total_scans", 0)
        
        # Simplificar la información de cada escaneo
        simplified_scans = []
        for scan in port_scans:
            simplified_scan = {
                "source_ip": scan.get("source_ip", "Desconocido"),
                "target_ip": scan.get("target_ip", "Desconocido"),
                "unique_ports": scan.get("unique_ports_scanned", 0),
                "scan_type": scan.get("scan_type", "Desconocido"),
                "severity": scan.get("severity", 0),
                "start_time": scan.get("start_time", ""),
                "duration_seconds": scan.get("duration_seconds", 0)
            }
            simplified_scans.append(simplified_scan)
        
        # Ordenar por severidad
        simplified_scans.sort(key=lambda x: x["severity"], reverse=True)
        
        return {
            "summary": f"Se detectaron {total_scans} posibles escaneos de puertos.",
            "port_scans": simplified_scans
        }
    
    def _format_top_talkers(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de hosts más activos.
        """
        top_talkers = results.get("top_talkers", {})
        
        # Formatear cada categoría de top talkers
        formatted_talkers = {}
        
        if "by_source" in top_talkers:
            source_ips = []
            for ip, stats in top_talkers["by_source"].items():
                source_ips.append({
                    "ip": ip,
                    "packets": stats.get("packets", 0),
                    "bytes": stats.get("bytes", 0)
                })
            formatted_talkers["top_sources"] = source_ips
        
        if "by_destination" in top_talkers:
            dest_ips = []
            for ip, stats in top_talkers["by_destination"].items():
                dest_ips.append({
                    "ip": ip,
                    "packets": stats.get("packets", 0),
                    "bytes": stats.get("bytes", 0)
                })
            formatted_talkers["top_destinations"] = dest_ips
        
        if "by_total_activity" in top_talkers:
            total_activity = []
            for ip, stats in top_talkers["by_total_activity"].items():
                total_activity.append({
                    "ip": ip,
                    "packets": stats.get("packets", 0),
                    "bytes": stats.get("bytes", 0)
                })
            formatted_talkers["most_active_hosts"] = total_activity
        
        # Determinar el host más activo
        most_active_ip = None
        most_active_packets = 0
        
        if "by_total_activity" in top_talkers and top_talkers["by_total_activity"]:
            for ip, stats in top_talkers["by_total_activity"].items():
                packets = stats.get("packets", 0)
                if packets > most_active_packets:
                    most_active_packets = packets
                    most_active_ip = ip
        
        summary = "Análisis de hosts más activos en la red."
        if most_active_ip:
            summary = f"El host más activo es {most_active_ip} con {most_active_packets} paquetes."
        
        return {
            "summary": summary,
            "top_talkers": formatted_talkers
        }
    
    def _format_trafico_por_protocolo(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de distribución de tráfico por protocolo.
        """
        protocol_stats = results.get("protocol_statistics", {})
        protocol_percentages = results.get("protocol_percentages", {})
        total_packets = results.get("total_packets", 0)
        
        # Formatear datos de protocolos
        protocol_data = []
        for protocol, count in protocol_stats.items():
            percentage = protocol_percentages.get(protocol, 0)
            protocol_data.append({
                "protocol": protocol.upper(),
                "count": count,
                "percentage": round(percentage, 2)
            })
        
        # Ordenar por recuento
        protocol_data.sort(key=lambda x: x["count"], reverse=True)
        
        # Identificar protocolo dominante
        dominant_protocol = None
        if protocol_data:
            dominant_protocol = protocol_data[0]["protocol"]
        
        summary = f"Análisis de {total_packets} paquetes por protocolo."
        if dominant_protocol:
            summary = f"El protocolo dominante es {dominant_protocol} ({protocol_data[0]['percentage']}% del tráfico)."
        
        return {
            "summary": summary,
            "total_packets": total_packets,
            "protocol_distribution": protocol_data
        }
    
    def _format_puertos_activos(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de puertos más activos.
        """
        tcp_ports = results.get("tcp_ports", [])
        udp_ports = results.get("udp_ports", [])
        
        # Añadir información de servicios comunes
        common_services = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            21: "FTP",
            25: "SMTP",
            53: "DNS",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Alt"
        }
        
        # Formatear puertos TCP
        tcp_data = []
        for port, count in tcp_ports:
            service = common_services.get(port, f"Puerto {port}")
            tcp_data.append({
                "port": port,
                "service": service,
                "count": count
            })
        
        # Formatear puertos UDP
        udp_data = []
        for port, count in udp_ports:
            service = common_services.get(port, f"Puerto {port}")
            udp_data.append({
                "port": port,
                "service": service,
                "count": count
            })
        
        # Determinar el puerto más activo
        most_active_port = None
        most_active_count = 0
        most_active_protocol = None
        
        for port, count in tcp_ports:
            if count > most_active_count:
                most_active_count = count
                most_active_port = port
                most_active_protocol = "TCP"
        
        for port, count in udp_ports:
            if count > most_active_count:
                most_active_count = count
                most_active_port = port
                most_active_protocol = "UDP"
        
        # Elaborar resumen
        summary = "Análisis de puertos más activos en la red."
        if most_active_port:
            service = common_services.get(most_active_port, f"Puerto {most_active_port}")
            summary = f"El puerto más activo es {most_active_protocol}/{most_active_port} ({service}) con {most_active_count} conexiones."
        
        return {
            "summary": summary,
            "tcp_ports": tcp_data,
            "udp_ports": udp_data
        }
    
    def _format_actividad_ip_especifica(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de actividad de una IP específica.
        """
        ip_address = results.get("ip_address", "Desconocida")
        communication_patterns = results.get("communication_patterns", {})
        total_packets = results.get("total_packets", 0)
        
        # Determinar si la IP actúa principalmente como cliente o servidor
        role = "desconocido"
        role_confidence = 0
        
        if "ip_specific_analysis" in communication_patterns:
            analysis = communication_patterns["ip_specific_analysis"]
            traffic_summary = analysis.get("traffic_summary", {})
            
            as_source = traffic_summary.get("as_source", 0)
            as_destination = traffic_summary.get("as_destination", 0)
            
            if as_source > 0 or as_destination > 0:
                source_ratio = as_source / (as_source + as_destination)
                
                if source_ratio > 0.8:
                    role = "cliente"
                    role_confidence = source_ratio
                elif source_ratio < 0.2:
                    role = "servidor"
                    role_confidence = 1 - source_ratio
                else:
                    role = "cliente y servidor"
                    role_confidence = 0.5
        
        # Extraer servicios utilizados y ofrecidos
        services = {}
        if "ip_specific_analysis" in communication_patterns:
            services = communication_patterns["ip_specific_analysis"].get("services", {})
        
        # Formatear comunicaciones principales
        communications = {}
        if "ip_specific_analysis" in communication_patterns and "communications" in communication_patterns["ip_specific_analysis"]:
            communications = communication_patterns["ip_specific_analysis"]["communications"]
        
        # Preparar resumen
        summary = f"Análisis de actividad para la IP {ip_address}."
        if role != "desconocido":
            summary = f"La IP {ip_address} actúa principalmente como {role} con una confianza del {role_confidence:.0%}."
        
        return {
            "summary": summary,
            "ip_address": ip_address,
            "total_packets": total_packets,
            "role": {
                "type": role,
                "confidence": role_confidence
            },
            "services": services,
            "communications": communications
        }
    
    def _format_resumen_trafico(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de resumen general del tráfico.
        """
        session_analysis = results.get("session_analysis", {})
        protocol_stats = results.get("protocol_statistics", {})
        top_talkers = results.get("top_talkers", {})
        recent_anomalies = results.get("recent_anomalies", [])
        total_anomalies = results.get("total_anomalies", 0)
        
        # Extraer resumen de la sesión si está disponible
        session_summary = {}
        if "summary" in session_analysis:
            session_summary = session_analysis["summary"]
        
        # Determinar nivel de riesgo
        risk_level = "Bajo"
        risk_score = 0
        
        if "risk_score" in session_analysis:
            risk_score = session_analysis["risk_score"].get("global_score", 0)
            risk_level = session_analysis["risk_score"].get("risk_level", "Bajo")
        
        # Preparar resumen de protocolos
        protocol_summary = []
        total_packets = sum(protocol_stats.values()) if protocol_stats else 0
        
        for protocol, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            protocol_summary.append({
                "protocol": protocol.upper(),
                "count": count,
                "percentage": round(percentage, 2)
            })
        
        # Preparar resumen de hosts activos
        hosts_summary = {
            "sources": [],
            "destinations": []
        }
        
        if "source" in top_talkers:
            for ip, count in top_talkers["source"][:5]:
                hosts_summary["sources"].append({
                    "ip": ip,
                    "packets": count
                })
        
        if "destination" in top_talkers:
            for ip, count in top_talkers["destination"][:5]:
                hosts_summary["destinations"].append({
                    "ip": ip,
                    "packets": count
                })
        
        # Resumen de anomalías
        anomalies_summary = []
        for anomaly in recent_anomalies:
            anomalies_summary.append({
                "type": anomaly.get("type", "Desconocido"),
                "severity": anomaly.get("severity", 0),
                "description": anomaly.get("description", "Sin descripción")
            })
        
        # Preparar resumen general
        summary = f"Resumen del tráfico: {total_packets} paquetes analizados."
        if risk_level != "Bajo" and total_anomalies > 0:
            summary = f"Nivel de riesgo {risk_level} con {total_anomalies} anomalías detectadas."
        
        return {
            "summary": summary,
            "traffic_overview": {
                "total_packets": total_packets,
                "protocols": protocol_summary,
                "risk_level": risk_level,
                "risk_score": risk_score,
                "anomalies_count": total_anomalies
            },
            "top_hosts": hosts_summary,
            "recent_anomalies": anomalies_summary
        }
    
    def _format_actividad_periodo(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de actividad en un periodo específico.
        """
        protocol_stats = results.get("protocol_statistics", {})
        top_talkers = results.get("top_talkers", {})
        anomalies = results.get("anomalies", [])
        total_anomalies = results.get("total_anomalies", 0)
        
        # Calcular total de paquetes
        total_packets = sum(protocol_stats.values()) if protocol_stats else 0
        
        # Formatear datos de protocolos
        protocol_data = []
        for protocol, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            protocol_data.append({
                "protocol": protocol.upper(),
                "count": count,
                "percentage": round(percentage, 2)
            })
        
        # Formatear hosts más activos
        hosts_data = {
            "sources": [],
            "destinations": []
        }
        
        if "source" in top_talkers:
            for ip, count in top_talkers["source"][:5]:
                hosts_data["sources"].append({
                    "ip": ip,
                    "packets": count
                })
        
        if "destination" in top_talkers:
            for ip, count in top_talkers["destination"][:5]:
                hosts_data["destinations"].append({
                    "ip": ip,
                    "packets": count
                })
        
        # Formatear anomalías
        anomalies_data = self._simplify_anomalies(anomalies)
        
        # Preparar resumen
        summary = f"Análisis de actividad: {total_packets} paquetes en el periodo."
        if total_anomalies > 0:
            summary = f"En el periodo analizado se detectaron {total_anomalies} anomalías en {total_packets} paquetes."
        
        return {
            "summary": summary,
            "traffic_summary": {
                "total_packets": total_packets,
                "protocol_distribution": protocol_data
            },
            "top_hosts": hosts_data,
            "anomalies": {
                "count": total_anomalies,
                "details": anomalies_data
            }
        }
    
    def _format_consulta_general(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Formatea resultados de una consulta general.
        """
        session_info = results.get("session_info", {})
        protocol_stats = results.get("protocol_statistics", {})
        top_talkers = results.get("top_talkers", {})
        recent_anomalies = results.get("recent_anomalies", [])
        total_anomalies = results.get("total_anomalies", 0)
        
        # Calcular total de paquetes
        total_packets = sum(protocol_stats.values()) if protocol_stats else 0
        
        # Formatear información de la sesión
        session_data = {}
        if session_info:
            session_data = {
                "id": session_info.get("id"),
                "start_time": session_info.get("start_time"),
                "end_time": session_info.get("end_time"),
                "packet_count": session_info.get("packet_count", 0),
                "capture_file": session_info.get("capture_file")
            }
        
        # Formatear datos de protocolos
        protocol_data = []
        for protocol, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            protocol_data.append({
                "protocol": protocol.upper(),
                "count": count,
                "percentage": round(percentage, 2)
            })
        
        # Formatear hosts más activos
        hosts_data = {
            "sources": [],
            "destinations": []
        }
        
        if "source" in top_talkers:
            for ip, count in top_talkers["source"]:
                hosts_data["sources"].append({
                    "ip": ip,
                    "packets": count
                })
        
        if "destination" in top_talkers:
            for ip, count in top_talkers["destination"]:
                hosts_data["destinations"].append({
                    "ip": ip,
                    "packets": count
                })
        
        # Simplificar anomalías
        simplified_anomalies = self._simplify_anomalies(recent_anomalies)
        
        # Preparar resumen general
        summary = f"Resumen general: {total_packets} paquetes analizados."
        if total_anomalies > 0:
            summary = f"Se detectaron {total_anomalies} anomalías en el tráfico analizado ({total_packets} paquetes)."
        
        return {
            "summary": summary,
            "session": session_data,
            "traffic_summary": {
                "total_packets": total_packets,
                "protocol_distribution": protocol_data
            },
            "top_hosts": hosts_data,
            "anomalies": simplified_anomalies
        }
    
    def _simplify_anomalies(self, anomalies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Simplifica la información de anomalías para mostrar solo los campos más relevantes.
        
        Args:
            anomalies (List): Lista de anomalías
            
        Returns:
            List: Lista de anomalías simplificadas
        """
        simplified = []
        
        for anomaly in anomalies:
            simple_anomaly = {
                "type": anomaly.get("type", "Desconocido"),
                "severity": anomaly.get("severity", 0),
                "description": anomaly.get("description", "Sin descripción")
            }
            
            # Añadir información específica según el tipo
            if "source_ip" in anomaly:
                simple_anomaly["source_ip"] = anomaly["source_ip"]
            
            if "target_ip" in anomaly:
                simple_anomaly["target_ip"] = anomaly["target_ip"]
            
            if "first_seen" in anomaly:
                simple_anomaly["first_seen"] = anomaly["first_seen"]
            
            if "last_seen" in anomaly:
                simple_anomaly["last_seen"] = anomaly["last_seen"]
            
            simplified.append(simple_anomaly)
        
        return simplified