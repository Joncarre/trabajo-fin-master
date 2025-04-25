"""
Módulo para gestionar el almacenamiento de datos procesados de capturas de red.
Proporciona funcionalidades para guardar, consultar y gestionar los datos
de paquetes procesados.
"""

import os
import json
import sqlite3
import datetime
import logging
from typing import Dict, List, Any, Optional, Tuple, Union

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("storage_manager")

class StorageManager:
    """
    Gestiona el almacenamiento y recuperación de datos procesados de paquetes de red.
    Utiliza SQLite como backend para almacenamiento eficiente y consultas rápidas.
    """
    
    def __init__(self, db_file: str = "network_data.db", retention_days: int = 30):
        """
        Inicializa el gestor de almacenamiento.
        
        Args:
            db_file: Ruta al archivo de base de datos SQLite
            retention_days: Número de días que se deben conservar los datos
        """        # Asegurar que la ruta de la base de datos sea absoluta y exista
        if os.path.isabs(db_file):
            # Si es ruta absoluta, usarla directamente
            self.db_file = db_file
        else:
            # Si es ruta relativa, intentar resolver respecto a diferentes ubicaciones
            potential_paths = [
                db_file,  # Como se proporcionó
                os.path.join(os.getcwd(), db_file),  # Relativo al directorio de trabajo actual
                os.path.join(os.path.dirname(__file__), '..', '..', db_file),  # Relativo a la raíz del proyecto
                # Si solo contiene el nombre del archivo, buscarlo en databases/
                os.path.join(os.getcwd(), "databases", os.path.basename(db_file))
            ]
            
            # Intentar encontrar el archivo en alguna de las rutas potenciales
            found = False
            for path in potential_paths:
                if os.path.exists(path):
                    self.db_file = path
                    found = True
                    break
            
            # Si no se encontró, usar la ruta original (puede fallar pero mostrará un error más claro)
            if not found:
                self.db_file = db_file
                
        # Crear el directorio contenedor si no existe
        db_dir = os.path.dirname(self.db_file)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
            
        self.retention_days = retention_days
        self._init_database()
        logger.info(f"StorageManager inicializado con base de datos: {self.db_file}")
    
    def _init_database(self) -> None:
        """Inicializa la estructura de la base de datos si no existe."""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Crear tabla para metadatos de capturas
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS captures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_file TEXT NOT NULL,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                packet_count INTEGER DEFAULT 0,
                description TEXT
            )
            ''')
            
            # Crear tabla para paquetes IP (capa 3)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_id INTEGER NOT NULL,
                timestamp TIMESTAMP NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                protocol INTEGER,
                version INTEGER,
                ttl INTEGER,
                identification INTEGER,
                header_length INTEGER,
                has_options INTEGER DEFAULT 0,
                fragmented INTEGER DEFAULT 0,
                fragment_offset INTEGER,
                length INTEGER,
                flags TEXT,
                additional_data TEXT,
                FOREIGN KEY (capture_id) REFERENCES captures(id)
            )
            ''')
            
            # Crear tabla para datos TCP (capa 4)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS tcp_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                seq_num INTEGER,
                ack_num INTEGER,
                window_size INTEGER,
                flags TEXT,
                has_options INTEGER DEFAULT 0,
                options TEXT,
                anomalies TEXT,
                FOREIGN KEY (packet_id) REFERENCES ip_packets(id)
            )
            ''')
            
            # Crear tabla para datos UDP (capa 4)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS udp_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                length INTEGER,
                FOREIGN KEY (packet_id) REFERENCES ip_packets(id)
            )
            ''')
            
            # Crear tabla para datos ICMP (capa 4)
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS icmp_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER NOT NULL,
                type INTEGER NOT NULL,
                code INTEGER,
                type_name TEXT,
                FOREIGN KEY (packet_id) REFERENCES ip_packets(id)
            )
            ''')
            
            # Crear índices para mejorar rendimiento de búsqueda
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_packets_src ON ip_packets(src_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_packets_dst ON ip_packets(dst_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_packets_timestamp ON ip_packets(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_tcp_ports ON tcp_data(src_port, dst_port)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_udp_ports ON udp_data(src_port, dst_port)')
            
            conn.commit()
            conn.close()
            logger.info("Estructura de base de datos inicializada correctamente")
            
        except sqlite3.Error as e:
            logger.error(f"Error al inicializar la base de datos: {e}")
            raise
    
    def start_capture_session(self, capture_file: str, description: str = None) -> int:
        """
        Inicia una nueva sesión de captura en la base de datos.
        
        Args:
            capture_file: Ruta al archivo de captura
            description: Descripción opcional de la captura
            
        Returns:
            ID de la sesión de captura
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute(
                'INSERT INTO captures (capture_file, start_time, description) VALUES (?, ?, ?)',
                (capture_file, datetime.datetime.now(), description)
            )
            
            capture_id = cursor.lastrowid
            conn.commit()
            conn.close()
            
            logger.info(f"Iniciada nueva sesión de captura con ID: {capture_id}")
            return capture_id
            
        except sqlite3.Error as e:
            logger.error(f"Error al iniciar sesión de captura: {e}")
            raise
    
    def end_capture_session(self, capture_id: int, packet_count: int) -> bool:
        """
        Finaliza una sesión de captura existente.
        
        Args:
            capture_id: ID de la sesión de captura
            packet_count: Número de paquetes capturados
            
        Returns:
            True si se actualizó correctamente, False en caso contrario
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute(
                'UPDATE captures SET end_time = ?, packet_count = ? WHERE id = ?',
                (datetime.datetime.now(), packet_count, capture_id)
            )
            
            conn.commit()
            conn.close()
            
            logger.info(f"Finalizada sesión de captura {capture_id} con {packet_count} paquetes")
            return True
            
        except sqlite3.Error as e:
            logger.error(f"Error al finalizar sesión de captura: {e}")
            return False
    
    def store_processed_packets(self, capture_id: int, processed_packets: List[Dict[str, Any]]) -> int:
        """
        Almacena paquetes procesados en la base de datos.
        
        Args:
            capture_id: ID de la sesión de captura
            processed_packets: Lista de paquetes procesados (formato dict)
            
        Returns:
            Número de paquetes almacenados
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            stored_count = 0
            
            for packet in processed_packets:
                # Extraer información de capa 3 (IP)
                layer3 = packet.get('layer3', {})
                layer4 = packet.get('layer4', {})
                
                if not layer3:
                    continue  # Saltar paquetes sin información de capa 3
                
                # Insertar datos IP (capa 3)
                cursor.execute('''
                INSERT INTO ip_packets (
                    capture_id, timestamp, src_ip, dst_ip, protocol, version,
                    ttl, identification, header_length, has_options, 
                    fragmented, fragment_offset, length, flags, additional_data
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    capture_id,
                    packet.get('timestamp'),
                    layer3.get('src_ip', '0.0.0.0'),
                    layer3.get('dst_ip', '0.0.0.0'),
                    self._get_protocol_number(layer4.get('protocol')),
                    layer3.get('version', 4),
                    layer3.get('ttl', 0) if 'ttl' in layer3 else layer3.get('hop_limit', 0),
                    layer3.get('identification', 0),
                    layer3.get('header_length', 0),
                    1 if layer3.get('has_options') else 0,
                    1 if layer3.get('fragmented') else 0,
                    layer3.get('fragment_offset', 0),
                    packet.get('length', 0),
                    json.dumps(layer3.get('flags', {})),
                    json.dumps({k: v for k, v in layer3.items() if k not in [
                        'src_ip', 'dst_ip', 'version', 'ttl', 'hop_limit', 
                        'identification', 'header_length', 'has_options',
                        'fragmented', 'fragment_offset', 'flags'
                    ]})
                ))
                
                packet_id = cursor.lastrowid
                
                # Insertar datos de capa 4 según el protocolo
                if layer4.get('protocol') == 'tcp':
                    self._store_tcp_data(cursor, packet_id, layer4)
                elif layer4.get('protocol') == 'udp':
                    self._store_udp_data(cursor, packet_id, layer4)
                elif layer4.get('protocol') == 'icmp':
                    self._store_icmp_data(cursor, packet_id, layer4)
                
                stored_count += 1
            
            conn.commit()
            conn.close()
            
            logger.info(f"Almacenados {stored_count} paquetes para la captura {capture_id}")
            return stored_count
            
        except sqlite3.Error as e:
            logger.error(f"Error al almacenar paquetes: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return 0
    
    def _store_tcp_data(self, cursor, packet_id: int, layer4: Dict[str, Any]) -> None:
        """Almacena datos específicos de TCP."""
        cursor.execute('''
        INSERT INTO tcp_data (
            packet_id, src_port, dst_port, seq_num, ack_num,
            window_size, flags, has_options, options, anomalies
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            packet_id,
            layer4.get('src_port', 0),
            layer4.get('dst_port', 0),
            layer4.get('seq', 0),
            layer4.get('ack', 0),
            layer4.get('window_size', 0),
            json.dumps(layer4.get('flags', {})),
            1 if layer4.get('options') else 0,
            json.dumps(layer4.get('options', {})),
            json.dumps(layer4.get('anomalies', []))
        ))
    
    def _store_udp_data(self, cursor, packet_id: int, layer4: Dict[str, Any]) -> None:
        """Almacena datos específicos de UDP."""
        cursor.execute('''
        INSERT INTO udp_data (
            packet_id, src_port, dst_port, length
        ) VALUES (?, ?, ?, ?)
        ''', (
            packet_id,
            layer4.get('src_port', 0),
            layer4.get('dst_port', 0),
            layer4.get('length', 0)
        ))
    
    def _store_icmp_data(self, cursor, packet_id: int, layer4: Dict[str, Any]) -> None:
        """Almacena datos específicos de ICMP."""
        cursor.execute('''
        INSERT INTO icmp_data (
            packet_id, type, code, type_name
        ) VALUES (?, ?, ?, ?)
        ''', (
            packet_id,
            layer4.get('type', 0),
            layer4.get('code', 0),
            layer4.get('type_name', 'unknown')
        ))
    
    def _get_protocol_number(self, protocol_name: str) -> int:
        """Convierte nombre de protocolo a su número correspondiente."""
        protocol_map = {
            'tcp': 6,
            'udp': 17,
            'icmp': 1,
            'other': 0
        }
        return protocol_map.get(protocol_name.lower() if protocol_name else 'other', 0)
    
    def query_packets(self, 
                      start_time: Optional[datetime.datetime] = None,
                      end_time: Optional[datetime.datetime] = None,
                      src_ip: Optional[str] = None,
                      dst_ip: Optional[str] = None,
                      protocol: Optional[str] = None,
                      port: Optional[int] = None,
                      has_anomalies: Optional[bool] = None,
                      limit: int = 1000) -> List[Dict[str, Any]]:
        """
        Consulta paquetes según diversos criterios.
        
        Args:
            start_time: Tiempo de inicio para filtrar
            end_time: Tiempo de fin para filtrar
            src_ip: Dirección IP origen
            dst_ip: Dirección IP destino
            protocol: Protocolo (tcp, udp, icmp)
            port: Puerto (origen o destino)
            has_anomalies: Si tiene anomalías detectadas
            limit: Límite de resultados
            
        Returns:
            Lista de paquetes que coinciden con los criterios
        """
        try:
            conn = sqlite3.connect(self.db_file)
            # Habilitar diccionarios en vez de tuplas para resultados
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            query_parts = ['SELECT p.* FROM ip_packets p']
            params = []
            
            # Uniones condicionales según los filtros
            if protocol == 'tcp' or has_anomalies or port:
                query_parts.append('LEFT JOIN tcp_data t ON p.id = t.packet_id')
            if protocol == 'udp' or port:
                query_parts.append('LEFT JOIN udp_data u ON p.id = u.packet_id')
            if protocol == 'icmp':
                query_parts.append('LEFT JOIN icmp_data i ON p.id = i.packet_id')
            
            # Construir cláusula WHERE
            where_clauses = []
            
            if start_time:
                where_clauses.append('p.timestamp >= ?')
                params.append(start_time)
            
            if end_time:
                where_clauses.append('p.timestamp <= ?')
                params.append(end_time)
            
            if src_ip:
                where_clauses.append('p.src_ip = ?')
                params.append(src_ip)
            
            if dst_ip:
                where_clauses.append('p.dst_ip = ?')
                params.append(dst_ip)
            
            if protocol:
                proto_num = self._get_protocol_number(protocol)
                where_clauses.append('p.protocol = ?')
                params.append(proto_num)
            
            if port:
                port_clause = []
                if protocol == 'tcp' or not protocol:
                    port_clause.append('(t.src_port = ? OR t.dst_port = ?)')
                    params.extend([port, port])
                if protocol == 'udp' or not protocol:
                    port_clause.append('(u.src_port = ? OR u.dst_port = ?)')
                    params.extend([port, port])
                if port_clause:
                    where_clauses.append('(' + ' OR '.join(port_clause) + ')')
            
            if has_anomalies:
                where_clauses.append("t.anomalies != '[]' AND t.anomalies IS NOT NULL")
            
            if where_clauses:
                query_parts.append('WHERE ' + ' AND '.join(where_clauses))
            
            # Añadir orden y límite
            query_parts.append('ORDER BY p.timestamp DESC LIMIT ?')
            params.append(limit)
            
            # Construir y ejecutar la consulta final
            final_query = ' '.join(query_parts)
            cursor.execute(final_query, params)
            
            # Convertir resultados a diccionarios
            results = []
            for row in cursor.fetchall():
                packet_dict = dict(row)
                
                # Obtener datos específicos del protocolo
                protocol_num = packet_dict.get('protocol', 0)
                protocol_name = self._get_protocol_name(protocol_num)
                
                if protocol_name == 'tcp':
                    self._add_tcp_data(conn, packet_dict)
                elif protocol_name == 'udp':
                    self._add_udp_data(conn, packet_dict)
                elif protocol_name == 'icmp':
                    self._add_icmp_data(conn, packet_dict)
                
                results.append(packet_dict)
            
            conn.close()
            return results
            
        except sqlite3.Error as e:
            logger.error(f"Error al consultar paquetes: {e}")
            if conn:
                conn.close()
            return []
    
    def _get_protocol_name(self, protocol_num: int) -> str:
        """Convierte número de protocolo a nombre."""
        protocol_map = {
            6: 'tcp',
            17: 'udp',
            1: 'icmp',
            0: 'other'
        }
        return protocol_map.get(protocol_num, 'other')
    
    def _add_tcp_data(self, conn, packet_dict: Dict[str, Any]) -> None:
        """Añade datos TCP al diccionario del paquete."""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM tcp_data WHERE packet_id = ?', (packet_dict['id'],))
        tcp_data = cursor.fetchone()
        
        if tcp_data:
            # Convertir las columnas que contienen JSON
            tcp_dict = dict(tcp_data)
            if 'flags' in tcp_dict and tcp_dict['flags']:
                tcp_dict['flags'] = json.loads(tcp_dict['flags'])
            if 'options' in tcp_dict and tcp_dict['options']:
                tcp_dict['options'] = json.loads(tcp_dict['options'])
            if 'anomalies' in tcp_dict and tcp_dict['anomalies']:
                tcp_dict['anomalies'] = json.loads(tcp_dict['anomalies'])
            
            packet_dict['tcp_data'] = tcp_dict
    
    def _add_udp_data(self, conn, packet_dict: Dict[str, Any]) -> None:
        """Añade datos UDP al diccionario del paquete."""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM udp_data WHERE packet_id = ?', (packet_dict['id'],))
        udp_data = cursor.fetchone()
        
        if udp_data:
            packet_dict['udp_data'] = dict(udp_data)
    
    def _add_icmp_data(self, conn, packet_dict: Dict[str, Any]) -> None:
        """Añade datos ICMP al diccionario del paquete."""
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM icmp_data WHERE packet_id = ?', (packet_dict['id'],))
        icmp_data = cursor.fetchone()
        
        if icmp_data:
            packet_dict['icmp_data'] = dict(icmp_data)
    
    def get_protocol_statistics(self, 
                              start_time: Optional[datetime.datetime] = None,
                              end_time: Optional[datetime.datetime] = None) -> Dict[str, int]:
        """
        Obtiene estadísticas de protocolos usados en un período de tiempo.
        
        Args:
            start_time: Tiempo de inicio para filtrar
            end_time: Tiempo de fin para filtrar
            
        Returns:
            Diccionario con conteos de paquetes por protocolo
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            query = 'SELECT protocol, COUNT(*) as count FROM ip_packets'
            params = []
            
            where_clauses = []
            if start_time:
                where_clauses.append('timestamp >= ?')
                params.append(start_time)
            
            if end_time:
                where_clauses.append('timestamp <= ?')
                params.append(end_time)
            
            if where_clauses:
                query += ' WHERE ' + ' AND '.join(where_clauses)
            
            query += ' GROUP BY protocol'
            
            cursor.execute(query, params)
            
            results = {}
            for protocol_num, count in cursor.fetchall():
                protocol_name = self._get_protocol_name(protocol_num)
                results[protocol_name] = count
            
            conn.close()
            return results
            
        except sqlite3.Error as e:
            logger.error(f"Error al obtener estadísticas de protocolos: {e}")
            if conn:
                conn.close()
            return {}
    
    def get_top_talkers(self, 
                       limit: int = 10, 
                       start_time: Optional[datetime.datetime] = None,
                       end_time: Optional[datetime.datetime] = None) -> Dict[str, List[Tuple[str, int]]]:
        """
        Obtiene las IPs que generan más tráfico (origen y destino).
        
        Args:
            limit: Número máximo de resultados
            start_time: Tiempo de inicio para filtrar
            end_time: Tiempo de fin para filtrar
            
        Returns:
            Diccionario con listas de IPs más activas como origen y destino
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            results = {'source': [], 'destination': []}
            
            # Query para IPs origen
            query = 'SELECT src_ip, COUNT(*) as count FROM ip_packets'
            params = []
            
            where_clauses = []
            if start_time:
                where_clauses.append('timestamp >= ?')
                params.append(start_time)
            
            if end_time:
                where_clauses.append('timestamp <= ?')
                params.append(end_time)
            
            if where_clauses:
                query += ' WHERE ' + ' AND '.join(where_clauses)
            
            query += ' GROUP BY src_ip ORDER BY count DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            
            for ip, count in cursor.fetchall():
                results['source'].append((ip, count))
            
            # Query similar para IPs destino
            query = 'SELECT dst_ip, COUNT(*) as count FROM ip_packets'
            params = []
            
            where_clauses = []
            if start_time:
                where_clauses.append('timestamp >= ?')
                params.append(start_time)
            
            if end_time:
                where_clauses.append('timestamp <= ?')
                params.append(end_time)
            
            if where_clauses:
                query += ' WHERE ' + ' AND '.join(where_clauses)
            
            query += ' GROUP BY dst_ip ORDER BY count DESC LIMIT ?'
            params.append(limit)
            
            cursor.execute(query, params)
            
            for ip, count in cursor.fetchall():
                results['destination'].append((ip, count))
            
            conn.close()
            return results
            
        except sqlite3.Error as e:
            logger.error(f"Error al obtener top talkers: {e}")
            if conn:
                conn.close()
            return {'source': [], 'destination': []}
    
    def get_top_ports(self, 
                    protocol: str = 'tcp', 
                    limit: int = 10,
                    start_time: Optional[datetime.datetime] = None,
                    end_time: Optional[datetime.datetime] = None) -> List[Tuple[int, int]]:
        """
        Obtiene los puertos más utilizados para un protocolo específico.
        
        Args:
            protocol: Protocolo ('tcp' o 'udp')
            limit: Número máximo de resultados
            start_time: Tiempo de inicio para filtrar
            end_time: Tiempo de fin para filtrar
            
        Returns:
            Lista de tuplas (puerto, conteo) ordenada por conteo descendente
        """
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            if protocol.lower() not in ('tcp', 'udp'):
                logger.warning(f"Protocolo no soportado para análisis de puertos: {protocol}")
                return []
            
            # Determinar tabla y protocolo a usar
            if protocol.lower() == 'tcp':
                table = 'tcp_data'
                proto_num = 6
            else:  # UDP
                table = 'udp_data'
                proto_num = 17
            
            # Unir con ip_packets para poder filtrar por timestamp
            query = f'''
            SELECT port, COUNT(*) as count FROM (
                SELECT src_port as port FROM {table} d 
                JOIN ip_packets p ON d.packet_id = p.id 
                WHERE p.protocol = ?
            '''
            
            params = [proto_num]
            
            # Añadir filtros de tiempo si existen
            if start_time:
                query += ' AND p.timestamp >= ?'
                params.append(start_time)
            
            if end_time:
                query += ' AND p.timestamp <= ?'
                params.append(end_time)
            
            # Unir con puertos destino
            query += f'''
            UNION ALL
            SELECT dst_port as port FROM {table} d 
            JOIN ip_packets p ON d.packet_id = p.id 
            WHERE p.protocol = ?
            '''
            
            params.append(proto_num)
            
            # Añadir filtros de tiempo para la segunda parte
            if start_time:
                query += ' AND p.timestamp >= ?'
                params.append(start_time)
            
            if end_time:
                query += ' AND p.timestamp <= ?'
                params.append(end_time)
            
            query += '''
            )
            GROUP BY port
            ORDER BY count DESC
            LIMIT ?
            '''
            
            params.append(limit)
            
            cursor.execute(query, params)
            
            results = []
            for port, count in cursor.fetchall():
                results.append((port, count))
            
            conn.close()
            return results
            
        except sqlite3.Error as e:
            logger.error(f"Error al obtener top puertos: {e}")
            if conn:
                conn.close()
            return []
    
    def get_anomaly_statistics(self,
                             start_time: Optional[datetime.datetime] = None,
                             end_time: Optional[datetime.datetime] = None) -> Dict[str, int]:
        """
        Obtiene estadísticas de anomalías detectadas.
        
        Args:
            start_time: Tiempo de inicio para filtrar
            end_time: Tiempo de fin para filtrar
            
        Returns:
            Diccionario con tipos de anomalías y sus conteos
        """
        try:
            conn = sqlite3.connect(self.db_file)
            conn.create_function("JSON_EXTRACT", 2, self._json_extract)
            cursor = conn.cursor()
            
            query = '''
            SELECT t.anomalies, COUNT(*) as count
            FROM tcp_data t
            JOIN ip_packets p ON t.packet_id = p.id
            WHERE t.anomalies IS NOT NULL AND t.anomalies != '[]'
            '''
            
            params = []
            
            if start_time:
                query += ' AND p.timestamp >= ?'
                params.append(start_time)
            
            if end_time:
                query += ' AND p.timestamp <= ?'
                params.append(end_time)
            
            query += ' GROUP BY t.anomalies'
            
            cursor.execute(query, params)
            
            results = {}
            for anomalies_json, count in cursor.fetchall():
                try:
                    anomalies = json.loads(anomalies_json)
                    for anomaly in anomalies:
                        if anomaly in results:
                            results[anomaly] += count
                        else:
                            results[anomaly] = count
                except (json.JSONDecodeError, TypeError):
                    logger.warning(f"Error al decodificar anomalías: {anomalies_json}")
            
            conn.close()
            return results
            
        except sqlite3.Error as e:
            logger.error(f"Error al obtener estadísticas de anomalías: {e}")
            if conn:
                conn.close()
            return {}
    
    def _json_extract(self, json_str, path):
        """Función helper para extraer valores de JSON en SQLite."""
        try:
            data = json.loads(json_str)
            return data.get(path)
        except:
            return None
        
    def get_all_sessions(self):
        """
        Obtiene todas las sesiones de captura disponibles en la base de datos.
        
        Returns:
            List[Dict]: Lista de diccionarios con información de las sesiones
        """
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row  # Para obtener resultados como diccionarios
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, capture_file, start_time, end_time, packet_count, description
            FROM captures
            ORDER BY start_time DESC
            ''')
            
            sessions = [dict(row) for row in cursor.fetchall()]
            conn.close()
            
            return sessions
            
        except sqlite3.Error as e:
            logger.error(f"Error al obtener sesiones de captura: {e}")
            if conn:
                conn.close()
            return []
    def get_session_metadata(self, session_id):
        """
        Obtiene los metadatos de una sesión de captura específica.
        
        Args:
            session_id (int): ID de la sesión
            
        Returns:
            dict: Metadatos de la sesión o None si no se encuentra
        """
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row  # Para obtener resultados como diccionarios
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, capture_file, start_time, end_time, packet_count, description
            FROM captures
            WHERE id = ?
            ''', (session_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                metadata = dict(row)
                return metadata
            else:
                logger.warning(f"No se encontró la sesión con ID: {session_id}")
                return None
            
        except sqlite3.Error as e:
            logger.error(f"Error al obtener metadatos de sesión: {e}")
            if conn:
                conn.close()
            return None
    
    def cleanup_old_data(self) -> int:
        """
        Elimina datos antiguos según la política de retención.
        
        Returns:
            Número de registros eliminados
        """
        try:
            if self.retention_days <= 0:
                logger.info("Retención de datos desactivada, no se eliminará nada")
                return 0
            
            # Calcular fecha límite
            cutoff_date = datetime.datetime.now() - datetime.timedelta(days=self.retention_days)
            
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Identificar capturas antiguas
            cursor.execute(
                'SELECT id FROM captures WHERE start_time < ?',
                (cutoff_date,)
            )
            
            old_capture_ids = [row[0] for row in cursor.fetchall()]
            
            if not old_capture_ids:
                logger.info("No hay datos antiguos para eliminar")
                conn.close()
                return 0
            
            # Contar registros a eliminar
            cursor.execute(
                'SELECT COUNT(*) FROM ip_packets WHERE capture_id IN ({})'.format(
                    ','.join('?' * len(old_capture_ids))
                ),
                old_capture_ids
            )
            
            total_records = cursor.fetchone()[0]
            
            # Iniciar transacción para eliminar datos
            conn.execute('BEGIN TRANSACTION')
            
            # Eliminar registros relacionados primero (capa 4)
            for capture_id in old_capture_ids:
                # Obtener IDs de paquetes a eliminar
                cursor.execute(
                    'SELECT id FROM ip_packets WHERE capture_id = ?',
                    (capture_id,)
                )
                
                packet_ids = [row[0] for row in cursor.fetchall()]
                
                if packet_ids:
                    # Eliminar datos TCP
                    cursor.execute(
                        'DELETE FROM tcp_data WHERE packet_id IN ({})'.format(
                            ','.join('?' * len(packet_ids))
                        ),
                        packet_ids
                    )
                    
                    # Eliminar datos UDP
                    cursor.execute(
                        'DELETE FROM udp_data WHERE packet_id IN ({})'.format(
                            ','.join('?' * len(packet_ids))
                        ),
                        packet_ids
                    )
                    
                    # Eliminar datos ICMP
                    cursor.execute(
                        'DELETE FROM icmp_data WHERE packet_id IN ({})'.format(
                            ','.join('?' * len(packet_ids))
                        ),
                        packet_ids
                    )
                
                # Eliminar paquetes IP de esta captura
                cursor.execute(
                    'DELETE FROM ip_packets WHERE capture_id = ?',
                    (capture_id,)
                )
                
                # Eliminar registro de captura
                cursor.execute(
                    'DELETE FROM captures WHERE id = ?',
                    (capture_id,)
                )
            
            conn.commit()
            conn.close()
            
            logger.info(f"Eliminados {total_records} registros antiguos según política de retención")
            return total_records
            
        except sqlite3.Error as e:
            logger.error(f"Error al limpiar datos antiguos: {e}")
            if conn:
                conn.rollback()
                conn.close()
            return 0