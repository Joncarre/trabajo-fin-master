# src/ai_engine/anomaly_detector.py
# Este script define una clase para detectar anomalías en el tráfico de red.
# La clase utiliza pandas para manejar datos y numpy para cálculos numéricos.

import pandas as pd
import numpy as np
from datetime import datetime, timedelta

class AnomalyDetector:
    """
    Detecta anomalías en el tráfico de red basándose en patrones conocidos
    y análisis estadístico.
    """
    
    def __init__(self):
        """Inicializa el detector de anomalías"""
        # Definir umbrales y configuraciones
        self.tcp_flag_combinations = {
            0: "NULL scan (ningún flag activo)",
            1: "FIN scan (solo flag FIN)",
            2: "SYN scan (solo flag SYN)",
            3: "SYN-FIN (combinación inválida)",
            41: "XMAS scan (FIN+PSH+URG)"
        }
        
        # Flags TCP como valores binarios
        # FIN = 1, SYN = 2, RST = 4, PSH = 8, ACK = 16, URG = 32
        self.tcp_flags = {
            'FIN': 1,
            'SYN': 2,
            'RST': 4,
            'PSH': 8,
            'ACK': 16,
            'URG': 32
        }
    
    def detect_anomalies(self, df):
        """
        Detecta anomalías en un DataFrame de paquetes.
        
        Args:
            df (pandas.DataFrame): DataFrame con los paquetes a analizar
            
        Returns:
            list: Lista de anomalías detectadas
        """
        anomalies = []
        
        # Detectar diferentes tipos de anomalías
        tcp_anomalies = self._detect_tcp_anomalies(df)
        icmp_anomalies = self._detect_icmp_anomalies(df)
        traffic_anomalies = self._detect_traffic_anomalies(df)
        fragment_anomalies = self._detect_fragment_anomalies(df)
        
        # Combinar todas las anomalías
        anomalies.extend(tcp_anomalies)
        anomalies.extend(icmp_anomalies)
        anomalies.extend(traffic_anomalies)
        anomalies.extend(fragment_anomalies)
        
        # Ordenar anomalías por severidad
        anomalies.sort(key=lambda x: x.get('severity', 0), reverse=True)
        
        return anomalies
    
    def _detect_tcp_anomalies(self, df):
        """
        Detecta anomalías específicas del protocolo TCP.
        """
        anomalies = []
        
        # Filtrar solo paquetes TCP
        tcp_df = df[df['protocol'] == 'TCP'].copy()
        if tcp_df.empty:
            return anomalies
        
        # Verificar combinaciones sospechosas de flags TCP
        for flags_value, description in self.tcp_flag_combinations.items():
            suspicious_packets = tcp_df[tcp_df['flags'] == flags_value]
            
            if not suspicious_packets.empty:
                unique_sources = suspicious_packets['src_ip'].unique()
                
                for src_ip in unique_sources:
                    source_packets = suspicious_packets[suspicious_packets['src_ip'] == src_ip]
                    unique_destinations = source_packets['dst_ip'].unique()
                    unique_ports = source_packets['dst_port'].nunique()
                    
                    # Determinar la severidad basada en el número de objetivos
                    severity = min(0.9, (len(unique_destinations) * unique_ports) / 100)
                    
                    if flags_value in [0, 1, 41]:  # Escaneos NULL, FIN o XMAS
                        severity = min(1.0, severity + 0.3)  # Aumentar severidad para estas técnicas
                    
                    anomaly = {
                        'type': 'TCP Flag Anomaly',
                        'subtype': description,
                        'source_ip': src_ip,
                        'targets': list(unique_destinations),
                        'unique_ports': int(unique_ports),
                        'packet_count': len(source_packets),
                        'first_seen': source_packets['timestamp'].min(),
                        'last_seen': source_packets['timestamp'].max(),
                        'severity': float(severity),
                        'description': f"Posible {description} detectado desde {src_ip} hacia {len(unique_destinations)} destinos y {unique_ports} puertos únicos"
                    }
                    
                    anomalies.append(anomaly)
        
        # Detectar Reset Floods (muchos paquetes RST en poco tiempo)
        if 'flags' in tcp_df.columns:
            # Filtrar paquetes con flag RST (valor 4)
            rst_packets = tcp_df[tcp_df['flags'] & self.tcp_flags['RST'] > 0]
            
            if len(rst_packets) > 10:  # Umbral arbitrario
                # Agrupar por origen
                grouped = rst_packets.groupby('src_ip')
                
                for src_ip, group in grouped:
                    if len(group) > 20:  # Muchos RST desde un mismo origen
                        unique_destinations = group['dst_ip'].nunique()
                        
                        # Calcular la densidad temporal (paquetes por segundo)
                        time_span = (group['timestamp'].max() - group['timestamp'].min())
                        if time_span > 0:
                            packets_per_second = len(group) / time_span
                            
                            if packets_per_second > 2:  # Umbral de densidad
                                severity = min(0.8, packets_per_second / 20)
                                
                                anomaly = {
                                    'type': 'TCP Reset Flood',
                                    'source_ip': src_ip,
                                    'packet_count': len(group),
                                    'unique_destinations': int(unique_destinations),
                                    'packets_per_second': float(packets_per_second),
                                    'first_seen': group['timestamp'].min(),
                                    'last_seen': group['timestamp'].max(),
                                    'severity': float(severity),
                                    'description': f"Posible TCP Reset Flood desde {src_ip}: {len(group)} paquetes RST a {unique_destinations} destinos ({packets_per_second:.2f} paquetes/segundo)"
                                }
                                
                                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_icmp_anomalies(self, df):
        """
        Detecta anomalías específicas del protocolo ICMP.
        """
        anomalies = []
        
        # Filtrar solo paquetes ICMP
        icmp_df = df[df['protocol'] == 'ICMP'].copy()
        if icmp_df.empty:
            return anomalies
        
        # Detectar posible ICMP flood (muchos paquetes ICMP en poco tiempo)
        grouped = icmp_df.groupby(['src_ip', 'dst_ip'])
        
        for (src_ip, dst_ip), group in grouped:
            # Calcular paquetes por segundo
            time_span = (group['timestamp'].max() - group['timestamp'].min())
            
            if len(group) > 10 and time_span > 0:  # Al menos 10 paquetes
                packets_per_second = len(group) / time_span
                
                if packets_per_second > 5:  # Umbral de flood
                    severity = min(0.9, packets_per_second / 50)
                    
                    # Verificar el tipo de ICMP
                    icmp_types = group['type'].value_counts().to_dict() if 'type' in group.columns else {}
                    icmp_type_desc = ', '.join([f"tipo {t}" for t in icmp_types.keys()])
                    
                    anomaly = {
                        'type': 'ICMP Flood',
                        'source_ip': src_ip,
                        'target_ip': dst_ip,
                        'packet_count': len(group),
                        'packets_per_second': float(packets_per_second),
                        'icmp_types': icmp_types,
                        'first_seen': group['timestamp'].min(),
                        'last_seen': group['timestamp'].max(),
                        'severity': float(severity),
                        'description': f"Posible ICMP Flood desde {src_ip} hacia {dst_ip}: {len(group)} paquetes ({packets_per_second:.2f}/s) de {icmp_type_desc}"
                    }
                    
                    anomalies.append(anomaly)
        
        # Detectar ICMP sweep (ping a múltiples hosts)
        for src_ip, group in icmp_df.groupby('src_ip'):
            unique_destinations = group['dst_ip'].nunique()
            
            if unique_destinations > 5:  # Umbral arbitrario
                # Buscar si son pings (ICMP tipo 8)
                icmp_types = group['type'].value_counts().to_dict() if 'type' in group.columns else {}
                has_ping = 8 in icmp_types
                
                severity = min(0.7, unique_destinations / 50)
                
                anomaly_type = "ICMP Ping Sweep" if has_ping else "ICMP Sweep"
                
                anomaly = {
                    'type': anomaly_type,
                    'source_ip': src_ip,
                    'target_count': int(unique_destinations),
                    'packet_count': len(group),
                    'icmp_types': icmp_types,
                    'first_seen': group['timestamp'].min(),
                    'last_seen': group['timestamp'].max(),
                    'severity': float(severity),
                    'description': f"Posible {anomaly_type} desde {src_ip} a {unique_destinations} objetivos diferentes"
                }
                
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_traffic_anomalies(self, df):
        """
        Detecta anomalías generales en el tráfico, como picos y patrones inusuales.
        """
        anomalies = []
        
        if df.empty or len(df) < 10:
            return anomalies
            
        # Agrupar por ventanas de tiempo (por ejemplo, cada minuto)
        if df['timestamp'].dtype == 'object':  # Es un string
            df['minute'] = pd.to_datetime(df['timestamp']).dt.floor('min')
        else:  # Es un número (Unix timestamp)
            df['minute'] = pd.to_datetime(df['timestamp'], unit='s').dt.floor('min')
        traffic_by_minute = df.groupby('minute').size()
        
        if len(traffic_by_minute) < 3:  # Necesitamos al menos 3 minutos para análisis
            return anomalies
        
        # Calcular estadísticas básicas
        mean_packets = traffic_by_minute.mean()
        std_packets = traffic_by_minute.std()
        
        # Detectar picos de tráfico (más de 3 desviaciones estándar)
        if std_packets > 0:
            threshold = mean_packets + 3 * std_packets
            
            spikes = traffic_by_minute[traffic_by_minute > threshold]
            
            for minute, packet_count in spikes.items():
                # Filtrar paquetes de ese minuto
                minute_packets = df[df['minute'] == minute]
                
                # Calcular estadísticas por protocolo
                protocol_counts = minute_packets['protocol'].value_counts().to_dict()
                
                # Calcular los principales orígenes y destinos
                top_sources = minute_packets['src_ip'].value_counts().head(3).to_dict()
                top_destinations = minute_packets['dst_ip'].value_counts().head(3).to_dict()
                
                # Z-score para determinar qué tan inusual es
                z_score = (packet_count - mean_packets) / std_packets
                severity = min(0.95, z_score / 10)  # Normalizar a un máximo de 0.95
                
                anomaly = {
                    'type': 'Traffic Spike',
                    'time': minute,
                    'packet_count': int(packet_count),
                    'average_packets': float(mean_packets),
                    'z_score': float(z_score),
                    'protocol_distribution': protocol_counts,
                    'top_sources': top_sources,
                    'top_destinations': top_destinations,
                    'severity': float(severity),
                    'description': f"Pico de tráfico inusual a las {minute}: {packet_count} paquetes ({z_score:.2f} desviaciones estándar sobre la media)"
                }
                
                anomalies.append(anomaly)
                
        # Buscar caídas repentinas de tráfico
        if mean_packets > 10 and std_packets > 0:  # Solo si hay suficiente tráfico base
            low_threshold = max(1, mean_packets - 2 * std_packets)
            
            # Identificar minutos con tráfico inusualmente bajo
            dips = traffic_by_minute[(traffic_by_minute < low_threshold) & (traffic_by_minute > 0)]
            
            for minute, packet_count in dips.items():
                # Solo considerar si hay minutos anteriores con tráfico normal
                previous_minutes = traffic_by_minute.index < minute
                
                if any(previous_minutes) and traffic_by_minute[previous_minutes].mean() > low_threshold:
                    z_score = (mean_packets - packet_count) / std_packets
                    severity = min(0.7, z_score / 10)  # Menos severo que un pico
                    
                    anomaly = {
                        'type': 'Traffic Drop',
                        'time': minute,
                        'packet_count': int(packet_count),
                        'average_packets': float(mean_packets),
                        'z_score': float(z_score),
                        'severity': float(severity),
                        'description': f"Caída repentina de tráfico a las {minute}: solo {packet_count} paquetes ({z_score:.2f} desviaciones estándar bajo la media)"
                    }
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_fragment_anomalies(self, df):
        """
        Detecta anomalías relacionadas con fragmentación de paquetes.
        """
        anomalies = []
        
        # Verificar si tenemos información de fragmentación
        if 'fragmented' not in df.columns:
            return anomalies
        
        # Filtrar paquetes fragmentados
        fragmented_df = df[df['fragmented'] == True].copy()
        
        if fragmented_df.empty:
            return anomalies
            
        # Agrupar por IP origen
        for src_ip, group in fragmented_df.groupby('src_ip'):
            # Si hay muchos paquetes fragmentados de un mismo origen
            if len(group) > 20:
                unique_destinations = group['dst_ip'].nunique()
                
                # Calcular la densidad temporal
                time_span = (group['timestamp'].max() - group['timestamp'].min())
                if time_span > 0:
                    fragments_per_second = len(group) / time_span
                    
                    # Solo alertar si la densidad es alta
                    if fragments_per_second > 2:
                        severity = min(0.8, fragments_per_second / 20)
                        
                        anomaly = {
                            'type': 'Fragment Flood',
                            'source_ip': src_ip,
                            'fragment_count': len(group),
                            'unique_destinations': int(unique_destinations),
                            'fragments_per_second': float(fragments_per_second),
                            'first_seen': group['timestamp'].min(),
                            'last_seen': group['timestamp'].max(),
                            'severity': float(severity),
                            'description': f"Posible Fragment Flood desde {src_ip}: {len(group)} fragmentos a {unique_destinations} destinos ({fragments_per_second:.2f} fragmentos/segundo)"
                        }
                        
                        anomalies.append(anomaly)
                        
        # Buscar fragmentos sospechosos (muy pequeños o con offset extraño)
        if 'fragment_offset' in df.columns:
            suspicious_fragments = df[(df['fragmented'] == True) & 
                                      ((df['fragment_offset'] > 0) & (df['length'] < 100))]
            
            if not suspicious_fragments.empty:
                for src_ip, group in suspicious_fragments.groupby('src_ip'):
                    if len(group) > 5:  # Al menos algunos paquetes sospechosos
                        unique_destinations = group['dst_ip'].nunique()
                        
                        severity = min(0.75, len(group) / 50)
                        
                        anomaly = {
                            'type': 'Suspicious Fragmentation',
                            'source_ip': src_ip,
                            'fragment_count': len(group),
                            'unique_destinations': int(unique_destinations),
                            'first_seen': group['timestamp'].min(),
                            'last_seen': group['timestamp'].max(),
                            'severity': float(severity),
                            'description': f"Fragmentación sospechosa desde {src_ip}: {len(group)} fragmentos pequeños con offset inusual"
                        }
                        
                        anomalies.append(anomaly)
        
        return anomalies