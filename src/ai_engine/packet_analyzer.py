# src/ai_engine/packet_analyzer.py

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import logging
import sqlite3

from src.data_processing.storage_manager import StorageManager
from src.ai_engine.anomaly_detector import AnomalyDetector
from src.ai_engine.pattern_analyzer import PatternAnalyzer
from src.ai_engine.risk_scorer import RiskScorer
from src.ai_engine.visualization import Visualizer

class PacketAnalyzer:
    """
    Clase principal para el análisis avanzado de paquetes de red.
    Coordina los diferentes componentes de análisis y proporciona
    una interfaz unificada para consultas avanzadas.
    """

    def __init__(self, db_path):
        """
        Inicializa el analizador de paquetes.
        
        Args:
            db_path (str): Ruta a la base de datos SQLite
        """
        self.db_path = db_path
        self.storage = StorageManager(db_path)
        self.anomaly_detector = AnomalyDetector()
        self.pattern_analyzer = PatternAnalyzer()
        self.risk_scorer = RiskScorer()
        self.visualizer = Visualizer()
        self.logger = self._setup_logger()
        
    def _setup_logger(self):
        """Configura el sistema de logging"""
        logger = logging.getLogger("PacketAnalyzer")
        logger.setLevel(logging.INFO)
        
        # Evitar duplicar handlers si ya existen
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        
        return logger
    
    def get_connection(self):
        """Obtiene una conexión a la base de datos"""
        return sqlite3.connect(self.db_path)
    
    def analyze_session(self, session_id):
        """
        Analiza una sesión de captura completa.
        
        Args:
            session_id (str): ID de la sesión a analizar
            
        Returns:
            dict: Resultados del análisis incluyendo anomalías, patrones y puntuación de riesgo
        """
        self.logger.info(f"Analizando sesión: {session_id}")
        
        # Obtener los datos de la sesión
        with self.get_connection() as conn:
            # Obtener metadatos de la sesión
            session_metadata = self.storage.get_session_metadata(session_id)
            
            # Obtener paquetes de la sesión como DataFrame
            packets_df = self._load_session_packets(conn, session_id)
            
            if packets_df.empty:
                return {"error": "No hay paquetes en esta sesión"}
            
            # Realizar análisis
            anomalies = self.anomaly_detector.detect_anomalies(packets_df)
            patterns = self.pattern_analyzer.analyze_patterns(packets_df)
            risk_score = self.risk_scorer.calculate_risk(packets_df, anomalies, patterns)
            
            # Generar visualizaciones básicas
            protocol_dist = self.visualizer.protocol_distribution(packets_df)
            port_activity = self.visualizer.port_activity(packets_df)
            ip_communications = self.visualizer.ip_communications(packets_df)
            
            # Compilar resultados
            results = {
                "session_info": session_metadata,
                "summary": self._generate_summary(packets_df),
                "anomalies": anomalies,
                "patterns": patterns,
                "risk_score": risk_score,
                "visualizations": {
                    "protocol_distribution": protocol_dist,
                    "port_activity": port_activity,
                    "ip_communications": ip_communications
                }
            }
            
            return results
    
    def _load_session_packets(self, conn, session_id):
        """
        Carga los paquetes de una sesión en un DataFrame para su análisis.
        
        Args:
            conn: Conexión a la base de datos
            session_id (str): ID de la sesión
            
        Returns:
            pandas.DataFrame: DataFrame con los paquetes de la sesión
        """
        # Consulta adaptada para tu esquema de base de datos
        query = """
        SELECT p.*, 
           t.flags, t.window_size, t.seq_num as seq_number, t.ack_num as ack_number,
           u.length,
           i.type, i.code
        FROM ip_packets p
        LEFT JOIN tcp_data t ON p.id = t.packet_id
        LEFT JOIN udp_data u ON p.id = u.packet_id
        LEFT JOIN icmp_data i ON p.id = i.packet_id
        WHERE p.capture_id = ?
        ORDER BY p.timestamp
        """
        
        try:
            df = pd.read_sql_query(query, conn, params=(session_id,))
            return df
        except Exception as e:
            self.logger.error(f"Error al cargar paquetes: {e}")
            return pd.DataFrame()
        
    def _generate_summary(self, packets_df):
        """
        Genera un resumen del tráfico analizado.
        
        Args:
            packets_df (pandas.DataFrame): DataFrame con los paquetes
            
        Returns:
            dict: Resumen del tráfico
        """
        total_packets = len(packets_df)
        
        # Contar por protocolo
        if 'protocol' in packets_df.columns:
            protocol_counts = packets_df['protocol'].value_counts().to_dict()
        else:
            protocol_counts = {}
        
        # Calcular duración de la captura
        duration = 0
        if not packets_df.empty and 'timestamp' in packets_df.columns:
            start_time = packets_df['timestamp'].min()
            end_time = packets_df['timestamp'].max()
            
            # Comprobar si son strings y convertirlos a datetime para poder restar
            if isinstance(start_time, str) and isinstance(end_time, str):
                start_datetime = pd.to_datetime(start_time)
                end_datetime = pd.to_datetime(end_time)
                # Calcular la diferencia en segundos
                duration = (end_datetime - start_datetime).total_seconds()
            else:
                # Si son números, simplemente restar
                duration = end_time - start_time
        
        # Top IPs origen y destino
        top_src_ips = {}
        top_dst_ips = {}
        if 'src_ip' in packets_df.columns:
            top_src_ips = packets_df['src_ip'].value_counts().head(5).to_dict()
        if 'dst_ip' in packets_df.columns:
            top_dst_ips = packets_df['dst_ip'].value_counts().head(5).to_dict()
        
        # Puertos más usados (para TCP/UDP)
        top_src_ports = {}
        top_dst_ports = {}
        if 'src_port' in packets_df.columns and 'dst_port' in packets_df.columns:
            tcp_udp_df = packets_df[packets_df['protocol'].isin([6, 17])]  # TCP=6, UDP=17
            if not tcp_udp_df.empty:
                top_src_ports = tcp_udp_df['src_port'].value_counts().head(5).to_dict()
                top_dst_ports = tcp_udp_df['dst_port'].value_counts().head(5).to_dict()
        
        return {
            "total_packets": total_packets,
            "protocol_distribution": protocol_counts,
            "duration_seconds": duration,
            "top_source_ips": top_src_ips,
            "top_destination_ips": top_dst_ips,
            "top_source_ports": top_src_ports,
            "top_destination_ports": top_dst_ports
        }
    
    def search_anomalies(self, start_time=None, end_time=None, min_severity=None, 
                        protocols=None, ip_addresses=None):
        """
        Busca anomalías en el tráfico según criterios específicos.
        
        Args:
            start_time (datetime, optional): Tiempo de inicio para la búsqueda
            end_time (datetime, optional): Tiempo de fin para la búsqueda
            min_severity (float, optional): Puntuación mínima de severidad (0-1)
            protocols (list, optional): Lista de protocolos a filtrar
            ip_addresses (list, optional): Lista de direcciones IP a filtrar
            
        Returns:
            list: Lista de anomalías detectadas que cumplen los criterios
        """
        # Implementar la lógica de búsqueda de anomalías
        with self.get_connection() as conn:
            # Construir la consulta en función de los parámetros
            base_query = """
            SELECT p.*, 
                   t.flags, t.window_size, t.seq_num as seq_number, t.ack_num as ack_number,
                   u.length,
                   i.type, i.code
            FROM ip_packets p
            LEFT JOIN tcp_data t ON p.id = t.packet_id
            LEFT JOIN udp_data u ON p.id = u.packet_id
            LEFT JOIN icmp_data i ON p.id = i.packet_id
            WHERE 1=1
            """
            
            params = []
            
            # Añadir filtros a la consulta
            if start_time:
                base_query += " AND p.timestamp >= ?"
                params.append(start_time)
            
            if end_time:
                base_query += " AND p.timestamp <= ?"
                params.append(end_time)
            
            if protocols:
                proto_numbers = []
                for proto in protocols:
                    if proto.lower() == 'tcp':
                        proto_numbers.append(6)
                    elif proto.lower() == 'udp':
                        proto_numbers.append(17)
                    elif proto.lower() == 'icmp':
                        proto_numbers.append(1)
                
                if proto_numbers:
                    placeholders = ", ".join(["?" for _ in proto_numbers])
                    base_query += f" AND p.protocol IN ({placeholders})"
                    params.extend(proto_numbers)
            
            if ip_addresses:
                ip_placeholders = ", ".join(["?" for _ in ip_addresses])
                base_query += f" AND (p.src_ip IN ({ip_placeholders}) OR p.dst_ip IN ({ip_placeholders}))"
                params.extend(ip_addresses * 2)
            
            base_query += " ORDER BY p.timestamp"
            
            try:
                df = pd.read_sql_query(base_query, conn, params=params)
                if df.empty:
                    return []
                
                # Detectar anomalías en los datos filtrados
                anomalies = self.anomaly_detector.detect_anomalies(df)
                
                # Filtrar por severidad si es necesario
                if min_severity is not None:
                    anomalies = [a for a in anomalies if a.get('severity', 0) >= min_severity]
                
                return anomalies
            
            except Exception as e:
                self.logger.error(f"Error en búsqueda de anomalías: {e}")
                return []
    
    def analyze_communication_patterns(self, ip_address=None, timeframe=None):
        """
        Analiza patrones de comunicación para una IP específica o en general.
        
        Args:
            ip_address (str, optional): Dirección IP a analizar
            timeframe (tuple, optional): Tupla (inicio, fin) para el análisis
            
        Returns:
            dict: Resultados del análisis de patrones de comunicación
        """
        # Implementar análisis de patrones de comunicación
        with self.get_connection() as conn:
            query_conditions = []
            params = []
            
            base_query = """
            SELECT p.*, 
                   t.flags, t.window_size, t.seq_num as seq_number, t.ack_num as ack_number,
                   u.length,
                   i.type, i.code
            FROM ip_packets p
            LEFT JOIN tcp_data t ON p.id = t.packet_id
            LEFT JOIN udp_data u ON p.id = u.packet_id
            LEFT JOIN icmp_data i ON p.id = i.packet_id
            WHERE 1=1
            """
            
            if ip_address:
                query_conditions.append("(p.src_ip = ? OR p.dst_ip = ?)")
                params.extend([ip_address, ip_address])
            
            if timeframe:
                start_time, end_time = timeframe
                query_conditions.append("p.timestamp BETWEEN ? AND ?")
                params.extend([start_time, end_time])
            
            if query_conditions:
                base_query += " AND " + " AND ".join(query_conditions)
            
            base_query += " ORDER BY p.timestamp"
            
            try:
                df = pd.read_sql_query(base_query, conn, params=params)
                if df.empty:
                    return {"error": "No hay datos para analizar con estos criterios"}
                
                return self.pattern_analyzer.analyze_communication_patterns(df, ip_address)
            
            except Exception as e:
                self.logger.error(f"Error en análisis de patrones: {e}")
                return {"error": f"Error en análisis: {str(e)}"}
    
    def get_top_talkers(self, n=10, by_bytes=True, protocol=None, timeframe=None):
        """
        Obtiene los hosts más activos de la red.
        
        Args:
            n (int): Número de hosts a retornar
            by_bytes (bool): Si es True, ordena por bytes, si no por paquetes
            protocol (str, optional): Filtrar por protocolo específico
            timeframe (tuple, optional): Tupla (inicio, fin) para el análisis
            
        Returns:
            dict: Top talkers con estadísticas
        """
        # Implementar obtención de hosts más activos
        with self.get_connection() as conn:
            conditions = []
            params = []
            
            base_query = """
            SELECT src_ip, dst_ip, SUM(length) as total_bytes, COUNT(*) as packet_count
            FROM ip_packets p
            WHERE 1=1
            """
            
            if protocol:
                proto_num = None
                if protocol.lower() == 'tcp':
                    proto_num = 6
                elif protocol.lower() == 'udp':
                    proto_num = 17
                elif protocol.lower() == 'icmp':
                    proto_num = 1
                
                if proto_num:
                    conditions.append("protocol = ?")
                    params.append(proto_num)
            
            if timeframe:
                start_time, end_time = timeframe
                conditions.append("timestamp BETWEEN ? AND ?")
                params.extend([start_time, end_time])
            
            if conditions:
                base_query += " AND " + " AND ".join(conditions)
            
            base_query += " GROUP BY src_ip, dst_ip"
            
            if by_bytes:
                base_query += " ORDER BY total_bytes DESC"
            else:
                base_query += " ORDER BY packet_count DESC"
            
            base_query += f" LIMIT {n}"
            
            try:
                df = pd.read_sql_query(base_query, conn, params=params)
                
                # Transformar a formato más amigable
                top_talkers = {
                    "by_source": {},
                    "by_destination": {},
                    "by_total_activity": {}
                }
                
                # Agrupar por origen
                src_group = df.groupby('src_ip').agg({'total_bytes': 'sum', 'packet_count': 'sum'})
                for ip, row in src_group.iterrows():
                    top_talkers["by_source"][ip] = {
                        "bytes": int(row['total_bytes']),
                        "packets": int(row['packet_count'])
                    }
                
                # Agrupar por destino
                dst_group = df.groupby('dst_ip').agg({'total_bytes': 'sum', 'packet_count': 'sum'})
                for ip, row in dst_group.iterrows():
                    top_talkers["by_destination"][ip] = {
                        "bytes": int(row['total_bytes']),
                        "packets": int(row['packet_count'])
                    }
                
                # Actividad total (origen + destino)
                ip_list = pd.concat([
                    df[['src_ip', 'total_bytes', 'packet_count']].rename(columns={'src_ip': 'ip'}),
                    df[['dst_ip', 'total_bytes', 'packet_count']].rename(columns={'dst_ip': 'ip'})
                ])
                
                total_group = ip_list.groupby('ip').agg({'total_bytes': 'sum', 'packet_count': 'sum'})
                total_group = total_group.sort_values('total_bytes' if by_bytes else 'packet_count', ascending=False).head(n)
                
                for ip, row in total_group.iterrows():
                    top_talkers["by_total_activity"][ip] = {
                        "bytes": int(row['total_bytes']),
                        "packets": int(row['packet_count'])
                    }
                
                return top_talkers
                
            except Exception as e:
                self.logger.error(f"Error al obtener top talkers: {e}")
                return {"error": f"Error: {str(e)}"}

    def detect_port_scans(self, timeframe=None, threshold=10):
        """
        Detecta posibles escaneos de puertos en la red.
        
        Args:
            timeframe (tuple, optional): Tupla (inicio, fin) para la detección
            threshold (int): Número mínimo de puertos únicos para considerar un escaneo
            
        Returns:
            list: Lista de posibles escaneos detectados
        """
        # Implementar detección de escaneos de puertos
        with self.get_connection() as conn:
            conditions = []
            params = []
            
            base_query = """
            SELECT p.src_ip, p.dst_ip, t.dst_port, p.timestamp, t.flags
            FROM ip_packets p
            JOIN tcp_data t ON p.id = t.packet_id
            WHERE p.protocol = 6
            """
            
            if timeframe:
                start_time, end_time = timeframe
                conditions.append("p.timestamp BETWEEN ? AND ?")
                params.extend([start_time, end_time])
            
            if conditions:
                base_query += " AND " + " AND ".join(conditions)
            
            try:
                df = pd.read_sql_query(base_query, conn, params=params)
                if df.empty:
                    return []
                
                # Detectar escaneos de puertos
                potential_scans = []
                
                # Agrupar por IP origen y destino
                grouped = df.groupby(['src_ip', 'dst_ip'])
                
                for (src_ip, dst_ip), group in grouped:
                    # Contar puertos únicos
                    unique_ports = group['dst_port'].nunique()
                    
                    # Si el número de puertos únicos supera el umbral, es sospechoso
                    if unique_ports >= threshold:
                        # Verificar si hay patrones de flags típicos de escaneos
                        has_syn_scan = False
                        has_fin_scan = False
                        has_null_scan = False
                        has_xmas_scan = False
                        
                        if 'flags' in group.columns:
                            # SYN scan: solo flag SYN activo (valor 2)
                            has_syn_scan = (group['flags'] == 2).any()
                            
                            # FIN scan: solo flag FIN activo (valor 1)
                            has_fin_scan = (group['flags'] == 1).any()
                            
                            # NULL scan: ningún flag activo (valor 0)
                            has_null_scan = (group['flags'] == 0).any()
                            
                            # XMAS scan: flags FIN, PSH, URG activos (valor 41)
                            has_xmas_scan = (group['flags'] == 41).any()
                        
                        scan_type = []
                        if has_syn_scan:
                            scan_type.append("SYN scan")
                        if has_fin_scan:
                            scan_type.append("FIN scan")
                        if has_null_scan:
                            scan_type.append("NULL scan")
                        if has_xmas_scan:
                            scan_type.append("XMAS scan")
                        
                        if not scan_type:
                            scan_type = ["Posible escaneo de puertos"]
                        
                        # Añadir a la lista de escaneos potenciales
                        scan_info = {
                            "source_ip": src_ip,
                            "target_ip": dst_ip,
                            "unique_ports_scanned": int(unique_ports),
                            "start_time": group['timestamp'].min(),
                            "end_time": group['timestamp'].max(),
                            "duration_seconds": (group['timestamp'].max() - group['timestamp'].min()),
                            "scan_type": ", ".join(scan_type),
                            "severity": min(1.0, unique_ports / 100)  # Puntuación de severidad basada en número de puertos
                        }
                        
                        potential_scans.append(scan_info)
                
                # Ordenar por severidad
                potential_scans.sort(key=lambda x: x['severity'], reverse=True)
                
                return potential_scans
                
            except Exception as e:
                self.logger.error(f"Error en detección de escaneos: {e}")
                return []