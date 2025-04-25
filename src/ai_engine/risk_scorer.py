# src/ai_engine/risk_scorer.py
# Este script define la clase RiskScorer, que calcula una puntuación de riesgo para eventos detectados en la red. Utiliza factores de riesgo predefinidos y componentes ponderados para determinar el nivel de riesgo global y por componentes.

import pandas as pd
import numpy as np
from datetime import datetime
import logging

class RiskScorer:
    """
    Sistema de puntuación de riesgo para eventos detectados en la red.
    Asigna valores de riesgo a diferentes tipos de anomalías y patrones.
    """
    
    def __init__(self):
        """Inicializa el puntuador de riesgo"""
        self.logger = logging.getLogger("RiskScorer")
        
        # Definir factores de riesgo para diferentes tipos de eventos
        self.risk_factors = {
            # Factores para anomalías TCP
            "TCP Flag Anomaly": 0.7,
            "TCP Reset Flood": 0.6,
            "NULL scan": 0.8,
            "FIN scan": 0.8,
            "XMAS scan": 0.9,
            "SYN scan": 0.7,
            "SYN-FIN": 0.8,
            
            # Factores para anomalías ICMP
            "ICMP Flood": 0.6,
            "ICMP Ping Sweep": 0.5,
            "ICMP Sweep": 0.4,
            
            # Factores para anomalías de tráfico
            "Traffic Spike": 0.3,
            "Traffic Drop": 0.2,
            
            # Factores para anomalías de fragmentación
            "Fragment Flood": 0.6,
            "Suspicious Fragmentation": 0.7
        }
        
        # Pesos para diferentes componentes del riesgo
        self.component_weights = {
            "anomaly_count": 0.3,        # Número de anomalías
            "max_severity": 0.4,         # Severidad máxima de anomalías
            "pattern_complexity": 0.2,    # Complejidad de patrones detectados
            "time_factor": 0.1           # Factor temporal (más reciente = más riesgo)
        }
    
    def calculate_risk(self, df, anomalies, patterns):
        """
        Calcula puntuación de riesgo global basada en anomalías y patrones detectados.
        
        Args:
            df (pandas.DataFrame): DataFrame con los paquetes
            anomalies (list): Lista de anomalías detectadas
            patterns (dict): Patrones detectados en el tráfico
            
        Returns:
            dict: Puntuación de riesgo global y por componentes
        """
        if df.empty or not anomalies:
            return {"global_score": 0.0, "components": {}, "risk_level": "Sin riesgo"}
        
        # Calcular componentes de riesgo
        anomaly_count_score = self._calculate_anomaly_count_score(anomalies)
        max_severity_score = self._calculate_max_severity_score(anomalies)
        pattern_complexity_score = self._calculate_pattern_complexity_score(patterns)
        time_factor_score = self._calculate_time_factor_score(anomalies)
        
        # Calcular riesgo global ponderado
        global_score = (
            anomaly_count_score * self.component_weights["anomaly_count"] +
            max_severity_score * self.component_weights["max_severity"] +
            pattern_complexity_score * self.component_weights["pattern_complexity"] +
            time_factor_score * self.component_weights["time_factor"]
        )
        
        # Normalizar a un rango de 0-1
        global_score = min(1.0, max(0.0, global_score))
        
        # Determinar nivel de riesgo
        risk_level = self._determine_risk_level(global_score)
        
        # Preparar resultados
        components = {
            "anomaly_count": {
                "score": float(anomaly_count_score),
                "weight": float(self.component_weights["anomaly_count"]),
                "description": f"Basado en {len(anomalies)} anomalías detectadas"
            },
            "max_severity": {
                "score": float(max_severity_score),
                "weight": float(self.component_weights["max_severity"]),
                "description": "Basado en la severidad máxima de anomalías"
            },
            "pattern_complexity": {
                "score": float(pattern_complexity_score),
                "weight": float(self.component_weights["pattern_complexity"]),
                "description": "Basado en la complejidad de los patrones detectados"
            },
            "time_factor": {
                "score": float(time_factor_score),
                "weight": float(self.component_weights["time_factor"]),
                "description": "Basado en la proximidad temporal de las anomalías"
            }
        }
        
        # Identificar las principales amenazas
        top_threats = self._identify_top_threats(anomalies)
        
        return {
            "global_score": float(global_score),
            "components": components,
            "risk_level": risk_level,
            "top_threats": top_threats
        }
    
    def _calculate_anomaly_count_score(self, anomalies):
        """
        Calcula puntuación basada en el número de anomalías detectadas.
        """
        # Logaritmo para suavizar el efecto de muchas anomalías
        if not anomalies:
            return 0.0
            
        count = len(anomalies)
        
        # Escala logarítmica para normalizar
        score = min(1.0, np.log10(count + 1) / 2)
        
        return score
    
    def _calculate_max_severity_score(self, anomalies):
        """
        Calcula puntuación basada en la severidad máxima de las anomalías.
        """
        if not anomalies:
            return 0.0
            
        # Extraer severidades y aplicar factores de riesgo
        weighted_severities = []
        
        for anomaly in anomalies:
            base_severity = anomaly.get('severity', 0.0)
            
            # Aplicar factor de riesgo específico si existe
            anomaly_type = anomaly.get('type', '')
            subtype = anomaly.get('subtype', '')
            
            # Buscar el factor de riesgo más específico
            risk_factor = 1.0  # Factor por defecto
            
            if subtype in self.risk_factors:
                risk_factor = self.risk_factors[subtype]
            elif anomaly_type in self.risk_factors:
                risk_factor = self.risk_factors[anomaly_type]
            
            weighted_severity = base_severity * risk_factor
            weighted_severities.append(weighted_severity)
        
        # Tomar el máximo
        if weighted_severities:
            return max(weighted_severities)
        else:
            return 0.0
    
    def _calculate_pattern_complexity_score(self, patterns):
        """
        Calcula puntuación basada en la complejidad de los patrones detectados.
        """
        if not patterns:
            return 0.0
            
        # Inicializar factores de complejidad
        complexity_factors = []
        
        # Analizar patrones de comunicación
        if 'communication_patterns' in patterns:
            comm_patterns = patterns['communication_patterns']
            
            # Número de pares de comunicación
            if 'top_communication_pairs' in comm_patterns:
                n_pairs = len(comm_patterns['top_communication_pairs'])
                pair_factor = min(1.0, n_pairs / 20)  # Normalizar
                complexity_factors.append(pair_factor)
            
            # Número de servidores potenciales
            if 'potential_servers' in comm_patterns:
                n_servers = len(comm_patterns['potential_servers'])
                server_factor = min(1.0, n_servers / 10)
                complexity_factors.append(server_factor)
        
        # Analizar patrones de protocolo
        if 'protocol_patterns' in patterns:
            proto_patterns = patterns['protocol_patterns']
            
            # Diversidad de protocolos
            if 'distribution' in proto_patterns:
                n_protocols = len(proto_patterns['distribution'])
                protocol_factor = min(1.0, n_protocols / 5)
                complexity_factors.append(protocol_factor)
                
            # Complejidad TCP
            if 'tcp' in proto_patterns and proto_patterns['tcp']:
                tcp_patterns = proto_patterns['tcp']
                
                if 'top_services' in tcp_patterns:
                    n_tcp_services = len(tcp_patterns['top_services'])
                    tcp_service_factor = min(1.0, n_tcp_services / 10)
                    complexity_factors.append(tcp_service_factor)
        
        # Si no hay factores, retornar 0
        if not complexity_factors:
            return 0.0
        
        # Promedio de factores de complejidad
        return sum(complexity_factors) / len(complexity_factors)
    
    def _calculate_time_factor_score(self, anomalies):
        """
        Calcula factor temporal basado en cuán recientes son las anomalías.
        """
        if not anomalies:
            return 0.0
            
        # Obtener el timestamp actual
        current_time = datetime.now().timestamp()
        
        # Extraer los timestamps de las anomalías
        last_seen_times = []
        
        for anomaly in anomalies:
            if 'last_seen' in anomaly:
                last_seen_times.append(anomaly['last_seen'])
        
        if not last_seen_times:
            return 0.0
        
        # Obtener el más reciente
        most_recent = max(last_seen_times)
        
        # Calcular la diferencia en horas
        time_diff_hours = (current_time - most_recent) / 3600
        
        # Factor temporal: más alto para anomalías recientes
        # 1.0 para anomalías en la última hora, decae exponencialmente
        time_factor = np.exp(-time_diff_hours / 24)  # Decae en 24 horas
        
        return time_factor
    
    def _determine_risk_level(self, score):
        """
        Determina el nivel de riesgo basado en la puntuación global.
        """
        if score < 0.2:
            return "Bajo"
        elif score < 0.4:
            return "Moderado"
        elif score < 0.6:
            return "Elevado"
        elif score < 0.8:
            return "Alto"
        else:
            return "Crítico"
    
    def _identify_top_threats(self, anomalies, max_threats=3):
        """
        Identifica las principales amenazas basadas en severidad y tipo.
        """
        if not anomalies:
            return []
            
        # Ordenar anomalías por severidad
        sorted_anomalies = sorted(anomalies, key=lambda x: x.get('severity', 0), reverse=True)
        
        # Seleccionar las principales amenazas
        top_threats = []
        
        for anomaly in sorted_anomalies[:max_threats]:
            threat = {
                "type": anomaly.get('type', 'Desconocido'),
                "description": anomaly.get('description', 'Sin descripción'),
                "severity": float(anomaly.get('severity', 0)),
                "details": {}
            }
            
            # Añadir detalles relevantes según el tipo de amenaza
            if anomaly.get('type') == 'TCP Flag Anomaly':
                threat['details'] = {
                    "source_ip": anomaly.get('source_ip', ''),
                    "subtype": anomaly.get('subtype', ''),
                    "targets": len(anomaly.get('targets', [])),
                    "packet_count": anomaly.get('packet_count', 0)
                }
            elif 'Flood' in anomaly.get('type', ''):
                threat['details'] = {
                    "source_ip": anomaly.get('source_ip', ''),
                    "target_ip": anomaly.get('target_ip', ''),
                    "packet_count": anomaly.get('packet_count', 0),
                    "packets_per_second": anomaly.get('packets_per_second', 0)
                }
            elif 'scan' in anomaly.get('type', '').lower():
                threat['details'] = {
                    "source_ip": anomaly.get('source_ip', ''),
                    "unique_ports": anomaly.get('unique_ports', 0),
                    "targets": anomaly.get('target_count', 0)
                }
            
            top_threats.append(threat)
        
        return top_threats