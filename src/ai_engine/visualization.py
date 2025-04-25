# Este script contiene la clase Visualizer, que se encarga de generar visualizaciones para datos de tráfico de red.
# La clase incluye métodos para crear gráficos de distribución de protocolos, actividad por puertos, comunicaciones entre IPs, etc.

import pandas as pd
import numpy as np
import json
import logging
from collections import defaultdict

class Visualizer:
    """
    Generador de visualizaciones para datos de tráfico de red.
    Prepara datos en formato adecuado para ser representados gráficamente.
    """
    
    def __init__(self):
        """Inicializa el visualizador"""
        self.logger = logging.getLogger("Visualizer")
        
        # Mapeo de puertos comunes a servicios
        self.port_to_service = {
            20: "FTP Data",
            21: "FTP Control",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            8080: "HTTP-Alt"
        }
    
    def protocol_distribution(self, df):
        """
        Genera datos para gráfico de distribución de protocolos.
        
        Args:
            df (pandas.DataFrame): DataFrame con los paquetes
            
        Returns:
            dict: Datos para visualización de distribución de protocolos
        """
        if df.empty:
            return {"error": "No hay datos disponibles"}
            
        # Obtener conteo por protocolo
        protocol_counts = df['protocol'].value_counts().to_dict()
        
        # Preparar datos para gráfico circular
        data = []
        total = sum(protocol_counts.values())
        
        for protocol, count in protocol_counts.items():
            percentage = (count / total) * 100
            data.append({
                "protocol": protocol,
                "count": int(count),
                "percentage": float(percentage)
            })
        
        # Ordenar de mayor a menor
        data.sort(key=lambda x: x['count'], reverse=True)
        
        return {
            "chart_type": "pie",
            "title": "Distribución de Protocolos",
            "data": data,
            "total_packets": int(total)
        }
    
    def port_activity(self, df):
        """
        Genera datos para gráfico de actividad por puertos.
        
        Args:
            df (pandas.DataFrame): DataFrame con los paquetes
            
        Returns:
            dict: Datos para visualización de actividad por puertos
        """
        if df.empty or 'dst_port' not in df.columns:
            return {"error": "No hay datos de puertos disponibles"}
            
        # Filtrar sólo TCP y UDP
        tcp_udp_df = df[df['protocol'].isin(['TCP', 'UDP'])]
        
        if tcp_udp_df.empty:
            return {"error": "No hay datos TCP/UDP disponibles"}
            
        # Obtener conteo por puerto destino
        port_counts = tcp_udp_df['dst_port'].value_counts().head(15).to_dict()
        
        # Preparar datos con nombres de servicios
        data = []
        for port, count in port_counts.items():
            try:
                port_int = int(port)
                service = self.port_to_service.get(port_int, f"Puerto {port_int}")
                
                # Determinar el protocolo predominante para este puerto
                port_df = tcp_udp_df[tcp_udp_df['dst_port'] == port]
                protocol = port_df['protocol'].value_counts().idxmax()
                
                data.append({
                    "port": int(port),
                    "service": service,
                    "protocol": protocol,
                    "count": int(count)
                })
            except (ValueError, TypeError):
                # En caso de valores no numéricos
                pass
        
        # Ordenar de mayor a menor
        data.sort(key=lambda x: x['count'], reverse=True)
        
        return {
            "chart_type": "bar",
            "title": "Puertos más Activos",
            "data": data
        }
    
    def ip_communications(self, df):
        """
        Genera datos para visualización de comunicaciones entre IPs.
        
        Args:
            df (pandas.DataFrame): DataFrame con los paquetes
            
        Returns:
            dict: Datos para visualización de comunicaciones
        """
        if df.empty:
            return {"error": "No hay datos disponibles"}
            
        # Crear pares origen-destino
        df['pair'] = df['src_ip'] + ' → ' + df['dst_ip']
        
        # Top pares de comunicación
        top_pairs = df['pair'].value_counts().head(10).to_dict()
        
        # Preparar datos para el gráfico
        nodes = set()
        links = []
        
        for pair, count in top_pairs.items():
            src, dst = pair.split(' → ')
            nodes.add(src)
            nodes.add(dst)
            
            links.append({
                "source": src,
                "target": dst,
                "value": int(count)
            })
        
        # Convertir set a lista para nodos
        node_list = []
        for ip in nodes:
            # Contar paquetes enviados y recibidos
            sent = len(df[df['src_ip'] == ip])
            received = len(df[df['dst_ip'] == ip])
            
            node_list.append({
                "id": ip,
                "packets_sent": int(sent),
                "packets_received": int(received),
                "total_activity": int(sent + received)
            })
        
        # Ordenar nodos por actividad total
        node_list.sort(key=lambda x: x['total_activity'], reverse=True)
        
        return {
            "chart_type": "network",
            "title": "Principales Comunicaciones entre IPs",
            "nodes": node_list,
            "links": links
        }
    
    def traffic_over_time(self, df, interval='minute'):
        """
        Genera datos para gráfico de tráfico a lo largo del tiempo.
        
        Args:
            df (pandas.DataFrame): DataFrame con los paquetes
            interval (str): Intervalo de tiempo ('second', 'minute', 'hour', 'day')
            
        Returns:
            dict: Datos para visualización de tráfico temporal
        """
        if df.empty:
            return {"error": "No hay datos disponibles"}
            
        # Convertir timestamp a datetime
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # Agrupar por intervalo de tiempo
        if interval == 'second':
            grouped = df.groupby(pd.Grouper(key='datetime', freq='S'))
        elif interval == 'minute':
            grouped = df.groupby(pd.Grouper(key='datetime', freq='min'))
        elif interval == 'hour':
            grouped = df.groupby(pd.Grouper(key='datetime', freq='H'))
        else:  # 'day'
            grouped = df.groupby(pd.Grouper(key='datetime', freq='D'))
        
        # Contar paquetes por intervalo
        time_series = grouped.size()
        
        # Generar series por protocolo
        protocol_series = {}
        
        for protocol in df['protocol'].unique():
            protocol_df = df[df['protocol'] == protocol]
            if not protocol_df.empty:
                protocol_grouped = protocol_df.groupby(pd.Grouper(key='datetime', freq=interval[0].upper()))
                protocol_series[protocol] = protocol_grouped.size()
        
        # Preparar datos para gráfico
        data = []
        
        for timestamp, count in time_series.items():
            entry = {
                "timestamp": timestamp.isoformat(),
                "total": int(count)
            }
            
            # Añadir conteos por protocolo
            for protocol, series in protocol_series.items():
                if timestamp in series:
                    entry[protocol] = int(series[timestamp])
                else:
                    entry[protocol] = 0
                    
            data.append(entry)
        
        return {
            "chart_type": "line",
            "title": f"Tráfico por {interval}",
            "data": data,
            "protocols": list(protocol_series.keys())
        }
    
    def anomaly_timeline(self, anomalies):
        """
        Genera datos para visualización de anomalías en línea de tiempo.
        
        Args:
            anomalies (list): Lista de anomalías detectadas
            
        Returns:
            dict: Datos para visualización de anomalías
        """
        if not anomalies:
            return {"error": "No hay anomalías disponibles"}
            
        # Agrupar anomalías por tipo
        anomalies_by_type = defaultdict(list)
        
        for anomaly in anomalies:
            anomaly_type = anomaly.get('type', 'Desconocido')
            
            # Extraer timestamp como punto único o rango
            if 'timestamp' in anomaly:
                timestamp = anomaly['timestamp']
                end_timestamp = timestamp  # Mismo valor para punto único
            elif 'first_seen' in anomaly and 'last_seen' in anomaly:
                timestamp = anomaly['first_seen']
                end_timestamp = anomaly['last_seen']
            else:
                continue  # Sin información temporal
            
            # Extraer información relevante
            severity = anomaly.get('severity', 0)
            description = anomaly.get('description', 'Sin descripción')
            
            # Crear entrada para visualización
            entry = {
                "start_time": timestamp,
                "end_time": end_timestamp,
                "severity": float(severity),
                "description": description
            }
            
            # Añadir detalles específicos según tipo
            if 'source_ip' in anomaly:
                entry['source_ip'] = anomaly['source_ip']
            
            anomalies_by_type[anomaly_type].append(entry)
        
        # Preparar datos para visualización
        timeline_data = []
        
        for anomaly_type, entries in anomalies_by_type.items():
            # Ordenar por timestamp
            sorted_entries = sorted(entries, key=lambda x: x['start_time'])
            
            timeline_data.append({
                "type": anomaly_type,
                "events": sorted_entries,
                "count": len(sorted_entries)
            })
        
        # Ordenar por número de eventos
        timeline_data.sort(key=lambda x: x['count'], reverse=True)
        
        return {
            "chart_type": "timeline",
            "title": "Línea de Tiempo de Anomalías",
            "data": timeline_data
        }