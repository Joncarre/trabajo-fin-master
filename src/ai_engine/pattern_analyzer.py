# Este script contiene la clase PatternAnalyzer, que se encarga de analizar patrones de comunicación y comportamiento en el tráfico de red.
# Utiliza pandas para manejar datos y numpy para cálculos numéricos. También incluye funciones para detectar patrones temporales, de comunicación y de protocolos en los datos de tráfico.

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
from collections import defaultdict, Counter

class PatternAnalyzer:
    """
    Analiza patrones de comunicación y comportamiento en el tráfico de red.
    """
    
    def __init__(self):
        """Inicializa el analizador de patrones"""
        self.logger = logging.getLogger("PatternAnalyzer")
        
        # Definir puertos comunes para servicios
        self.common_ports = {
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
    
    def analyze_patterns(self, df):
        """
        Analiza patrones generales en el tráfico de red.
        
        Args:
            df (pandas.DataFrame): DataFrame con los paquetes a analizar
            
        Returns:
            dict: Resultados del análisis de patrones
        """
        if df.empty:
            return {}
        
        # Analizamos varios aspectos del tráfico
        time_patterns = self._analyze_time_patterns(df)
        communication_patterns = self._analyze_communication_patterns(df)
        protocol_patterns = self._analyze_protocol_patterns(df)
        
        # Unimos todos los resultados
        results = {
            "time_patterns": time_patterns,
            "communication_patterns": communication_patterns,
            "protocol_patterns": protocol_patterns
        }
        
        return results
    
    def _analyze_time_patterns(self, df):
        """
        Analiza patrones temporales en el tráfico.
        """
        if df.empty:
            return {}
            
        # Convertir timestamp a datetime para análisis temporal
        # Verificar el tipo de datos de timestamp
        if df['timestamp'].dtype == 'object':  # Es un string
            df['datetime'] = pd.to_datetime(df['timestamp'])
        else:  # Es un número (Unix timestamp)
            df['datetime'] = pd.to_datetime(df['timestamp'], unit='s')
        
        # Extraer componentes de tiempo
        df['hour'] = df['datetime'].dt.hour
        df['minute'] = df['datetime'].dt.minute
        df['day_of_week'] = df['datetime'].dt.dayofweek  # 0=Monday, 6=Sunday
        
        # Análisis por hora
        hourly_traffic = df.groupby('hour').size()
        peak_hour = hourly_traffic.idxmax()
        min_hour = hourly_traffic.idxmin()
        
        # Análisis por día de la semana
        daily_traffic = df.groupby('day_of_week').size()
        peak_day = daily_traffic.idxmax()
        min_day = daily_traffic.idxmin()
        
        # Convertir día numérico a nombre
        days = ['Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado', 'Domingo']
        peak_day_name = days[peak_day]
        min_day_name = days[min_day]
        
        # Detectar periodicidad (patrones repetitivos)
        traffic_by_minute = df.groupby([df['datetime'].dt.date, df['datetime'].dt.hour, df['datetime'].dt.minute]).size()
        
        # Calculamos la autocorrelación para detectar ciclos
        if len(traffic_by_minute) > 10:
            autocorr = traffic_by_minute.autocorr(lag=1)
            has_periodicity = abs(autocorr) > 0.7
        else:
            has_periodicity = False
            autocorr = 0
        
        # Preparar resultados
        time_patterns = {
            "peak_hour": {
                "hour": int(peak_hour),
                "traffic": int(hourly_traffic[peak_hour])
            },
            "min_hour": {
                "hour": int(min_hour),
                "traffic": int(hourly_traffic[min_hour])
            },
            "peak_day": {
                "day": peak_day_name,
                "traffic": int(daily_traffic[peak_day])
            },
            "min_day": {
                "day": min_day_name,
                "traffic": int(daily_traffic[min_day])
            },
            "hourly_distribution": hourly_traffic.to_dict(),
            "daily_distribution": {days[i]: int(val) for i, val in daily_traffic.items()},
            "periodicity": {
                "detected": has_periodicity,
                "autocorrelation": float(autocorr)
            }
        }
        
        return time_patterns
    
    def _analyze_communication_patterns(self, df, focus_ip=None):
        """
        Analiza patrones de comunicación entre hosts.
        
        Args:
            df (pandas.DataFrame): DataFrame con los paquetes
            focus_ip (str, optional): IP específica a analizar en detalle
            
        Returns:
            dict: Patrones de comunicación
        """
        if df.empty:
            return {}
            
        # Crear pares origen-destino
        df['pair'] = df['src_ip'] + ' → ' + df['dst_ip']
        
        # Top pares de comunicación
        top_pairs = df['pair'].value_counts().head(10).to_dict()
        
        # Identificar servidores potenciales (muchas conexiones entrantes)
        potential_servers = defaultdict(int)
        
        for _, row in df.iterrows():
            if 'dst_port' in row and pd.notna(row['dst_port']):
                port = int(row['dst_port'])
                if port < 1024 or port in self.common_ports:  # Puerto de servicio conocido
                    potential_servers[row['dst_ip']] += 1
        
        # Convertir a diccionario ordenado
        potential_servers = dict(sorted(potential_servers.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Identificar clientes potenciales (muchas conexiones salientes)
        potential_clients = defaultdict(int)
        
        for _, row in df.iterrows():
            if 'dst_port' in row and pd.notna(row['dst_port']):
                port = int(row['dst_port'])
                if port < 1024 or port in self.common_ports:  # Puerto de servicio conocido
                    potential_clients[row['src_ip']] += 1
        
        # Convertir a diccionario ordenado
        potential_clients = dict(sorted(potential_clients.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Análisis detallado para una IP específica si se proporciona
        ip_specific_analysis = {}
        if focus_ip:
            # Filtrar tráfico relacionado con esa IP
            ip_df = df[(df['src_ip'] == focus_ip) | (df['dst_ip'] == focus_ip)]
            
            if not ip_df.empty:
                # Analizar como origen
                as_source = ip_df[ip_df['src_ip'] == focus_ip]
                
                # Analizar como destino
                as_destination = ip_df[ip_df['dst_ip'] == focus_ip]
                
                # Servicios utilizados (puertos destino cuando es origen)
                used_services = {}
                if not as_source.empty and 'dst_port' in as_source.columns:
                    for port, count in as_source['dst_port'].value_counts().head(10).items():
                        port_int = int(port)
                        service_name = self.common_ports.get(port_int, f"Puerto {port_int}")
                        used_services[service_name] = int(count)
                
                # Servicios ofrecidos (puertos destino cuando es destino)
                offered_services = {}
                if not as_destination.empty and 'dst_port' in as_destination.columns:
                    for port, count in as_destination['dst_port'].value_counts().head(10).items():
                        port_int = int(port)
                        service_name = self.common_ports.get(port_int, f"Puerto {port_int}")
                        offered_services[service_name] = int(count)
                
                # Comunicaciones más frecuentes
                top_communications = {}
                
                # Como origen
                if not as_source.empty:
                    top_destinations = as_source['dst_ip'].value_counts().head(5).to_dict()
                    top_communications["as_source"] = {
                        "destinations": top_destinations,
                        "total_packets_sent": len(as_source)
                    }
                
                # Como destino
                if not as_destination.empty:
                    top_sources = as_destination['src_ip'].value_counts().head(5).to_dict()
                    top_communications["as_destination"] = {
                        "sources": top_sources,
                        "total_packets_received": len(as_destination)
                    }
                
                # Compilar análisis específico
                ip_specific_analysis = {
                    "traffic_summary": {
                        "total_packets": len(ip_df),
                        "as_source": len(as_source),
                        "as_destination": len(as_destination)
                    },
                    "services": {
                        "used": used_services,
                        "offered": offered_services
                    },
                    "communications": top_communications,
                    "protocols": ip_df['protocol'].value_counts().to_dict() if 'protocol' in ip_df.columns else {}
                }
        
        # Compilar resultados del análisis de comunicación
        communication_patterns = {
            "top_communication_pairs": top_pairs,
            "potential_servers": potential_servers,
            "potential_clients": potential_clients
        }
        
        # Añadir análisis específico si se realizó
        if ip_specific_analysis:
            communication_patterns["ip_specific_analysis"] = ip_specific_analysis
        
        return communication_patterns
    
    def _analyze_protocol_patterns(self, df):
        """
        Analiza patrones específicos de protocolos.
        """
        if df.empty:
            return {}
            
        # Distribución general de protocolos
        protocol_dist = df['protocol'].value_counts().to_dict()
        
        # Análisis específico para cada protocolo
        tcp_analysis = {}
        udp_analysis = {}
        icmp_analysis = {}
        
        # Análisis TCP
        tcp_df = df[df['protocol'] == 'TCP']
        if not tcp_df.empty:
            # Puertos TCP más comunes
            if 'dst_port' in tcp_df.columns:
                top_tcp_ports = tcp_df['dst_port'].value_counts().head(10).to_dict()
                
                # Mapear puertos a servicios conocidos
                top_tcp_services = {}
                for port, count in top_tcp_ports.items():
                    port_int = int(port)
                    service_name = self.common_ports.get(port_int, f"Puerto {port_int}")
                    top_tcp_services[service_name] = int(count)
                
                # Analizar flags TCP si están disponibles
                tcp_flags = None
                if 'flags' in tcp_df.columns:
                    # Contar diferentes combinaciones de flags
                    flag_counts = tcp_df['flags'].value_counts().head(10).to_dict()
                    
                    # Traducir valores numéricos a nombres de flags
                    flags_map = {
                        1: "FIN",
                        2: "SYN",
                        4: "RST",
                        8: "PSH", 
                        16: "ACK",
                        32: "URG",
                        18: "SYN-ACK",
                        24: "PSH-ACK",
                        17: "FIN-ACK",
                        41: "FIN-PSH-URG (XMAS)"
                    }
                    
                    translated_flags = {}
                    for flag_val, count in flag_counts.items():
                        flag_name = flags_map.get(flag_val, f"Flags {flag_val}")
                        translated_flags[flag_name] = int(count)
                    
                    tcp_flags = translated_flags
                
                tcp_analysis = {
                    "top_services": top_tcp_services,
                    "flags_distribution": tcp_flags,
                    "total_packets": len(tcp_df)
                }
        
        # Análisis UDP
        udp_df = df[df['protocol'] == 'UDP']
        if not udp_df.empty:
            # Puertos UDP más comunes
            if 'dst_port' in udp_df.columns:
                top_udp_ports = udp_df['dst_port'].value_counts().head(10).to_dict()
                
                # Mapear puertos a servicios conocidos
                top_udp_services = {}
                for port, count in top_udp_ports.items():
                    port_int = int(port)
                    service_name = self.common_ports.get(port_int, f"Puerto {port_int}")
                    top_udp_services[service_name] = int(count)
                
                udp_analysis = {
                    "top_services": top_udp_services,
                    "total_packets": len(udp_df)
                }
        
        # Análisis ICMP
        icmp_df = df[df['protocol'] == 'ICMP']
        if not icmp_df.empty:
            # Tipos de ICMP
            icmp_types = {}
            if 'type' in icmp_df.columns:
                # Mapeo de tipos ICMP comunes
                icmp_type_names = {
                    0: "Echo Reply",
                    3: "Destination Unreachable",
                    5: "Redirect",
                    8: "Echo Request (Ping)",
                    11: "Time Exceeded"
                }
                
                for icmp_type, count in icmp_df['type'].value_counts().items():
                    type_name = icmp_type_names.get(icmp_type, f"Tipo {icmp_type}")
                    icmp_types[type_name] = int(count)
            
            icmp_analysis = {
                "type_distribution": icmp_types,
                "total_packets": len(icmp_df)
            }
        
        # Compilar análisis de protocolos
        protocol_patterns = {
            "distribution": protocol_dist,
            "tcp": tcp_analysis,
            "udp": udp_analysis,
            "icmp": icmp_analysis
        }
        
        return protocol_patterns

    def analyze_communication_patterns(self, df, focus_ip=None):
        """
        Método público para analizar patrones de comunicación.
        
        Args:
            df (pandas.DataFrame): DataFrame con los paquetes
            focus_ip (str, optional): IP específica a analizar en detalle
            
        Returns:
            dict: Análisis detallado de patrones de comunicación
        """
        return self._analyze_communication_patterns(df, focus_ip)