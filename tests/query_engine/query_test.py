# Este script es un ejemplo de cómo utilizar el analizador de paquetes avanzado para analizar sesiones de red, detectar anomalías, escaneos de puertos y patrones de comunicación.

import os
import sqlite3
import json
import datetime
import sys
import argparse

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.data_processing.storage_manager import StorageManager
from tabulate import tabulate  # Si no está instalado: pip install tabulate
from colorama import init, Fore, Style  # Si no está instalado: pip install colorama

# Inicializar colorama para dar formato al texto en la consola
init()

def print_header(title):
    """Imprime un encabezado formateado."""
    print(f"\n{Fore.CYAN}{'=' * 80}")
    print(f" {title}")
    print(f"{'=' * 80}{Style.RESET_ALL}")

def print_section(title):
    """Imprime un título de sección formateado."""
    print(f"\n{Fore.GREEN}{'-' * 40}")
    print(f" {title}")
    print(f"{'-' * 40}{Style.RESET_ALL}")

def print_subsection(title):
    """Imprime un título de subsección formateado."""
    print(f"\n{Fore.YELLOW}{title}{Style.RESET_ALL}")

def format_ip_port(ip, port):
    """Formatea una dirección IP y puerto de manera legible."""
    if port:
        return f"{ip}:{port}"
    return ip

def format_timestamp(timestamp):
    """Formatea una marca de tiempo para mejor legibilidad."""
    if not timestamp:
        return "N/A"
    try:
        dt = datetime.datetime.fromisoformat(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except:
        return timestamp

def get_db_statistics(db_file):
    """Obtiene estadísticas generales de la base de datos."""
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    stats = {}
    
    # Obtener conteo de tablas
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    stats["tables"] = len(tables)
    
    # Obtener conteos por tabla
    for table in tables:
        table_name = table[0]
        cursor.execute(f"SELECT COUNT(*) FROM {table_name};")
        count = cursor.fetchone()[0]
        stats[f"{table_name}_count"] = count
    
    conn.close()
    return stats

def query_advanced_db_info(specific_db_file=None):
    """
    Realiza consultas avanzadas a la base de datos y muestra los resultados de manera estructurada.
    
    Args:
        specific_db_file (str, optional): Ruta específica a la base de datos a utilizar.
                                         Si se proporciona, se usará esta base de datos en lugar
                                         de buscar automáticamente una.
    """
    db_file = None
    
    # Si se especificó un archivo específico, usarlo directamente
    if specific_db_file:
        if os.path.exists(specific_db_file):
            db_file = specific_db_file
        else:
            # Si no existe como ruta absoluta, intentar en el directorio databases
            database_dir = "databases"
            if not os.path.exists(database_dir):
                database_dir = os.path.join("..", "databases")
            
            potential_path = os.path.join(database_dir, specific_db_file)
            if os.path.exists(potential_path):
                db_file = potential_path
            else:
                print(f"{Fore.RED}No se encontró la base de datos especificada: {specific_db_file}{Style.RESET_ALL}")
                return
    else:
        # Comportamiento original: buscar automáticamente
        database_dir = "databases"
        if not os.path.exists(database_dir):
            database_dir = os.path.join("..", "databases")  # Intenta un nivel arriba
            if not os.path.exists(database_dir):
                print(f"{Fore.RED}No se encontró el directorio 'databases'.{Style.RESET_ALL}")
                return
        
        # Buscar archivos de base de datos en el directorio databases
        db_files = [f for f in os.listdir(database_dir) if f.endswith('.db')]
        
        if not db_files:
            print(f"{Fore.RED}No se encontraron archivos de base de datos en el directorio '{database_dir}'.{Style.RESET_ALL}")
            return
        
        # Si hay múltiples bases de datos, usar la que tenga un tamaño no cero
        for f in db_files:
            file_path = os.path.join(database_dir, f)
            if os.path.getsize(file_path) > 0:
                db_file = file_path
                break
        
        if not db_file:
            print(f"{Fore.RED}No se encontraron bases de datos válidas en '{database_dir}'.{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}Usando base de datos: {db_file} ({os.path.getsize(db_file)/1024:.2f} KB){Style.RESET_ALL}")
    
    try:
        # Crear instancia del gestor de almacenamiento
        storage = StorageManager(db_file)
        
        # SECCIÓN 1: INFORMACIÓN GENERAL DE LA BASE DE DATOS
        print_header("INFORMACIÓN GENERAL DE LA BASE DE DATOS")
        
        # Estadísticas básicas de la base de datos
        db_stats = get_db_statistics(db_file)
        
        print_section("Estadísticas de la Base de Datos")
        stats_table = []
        stats_table.append(["Tablas", db_stats.get("tables", 0)])
        stats_table.append(["Capturas", db_stats.get("captures_count", 0)])
        stats_table.append(["Paquetes IP", db_stats.get("ip_packets_count", 0)])
        stats_table.append(["Datos TCP", db_stats.get("tcp_data_count", 0)])
        stats_table.append(["Datos UDP", db_stats.get("udp_data_count", 0)])
        stats_table.append(["Datos ICMP", db_stats.get("icmp_data_count", 0)])
        
        print(tabulate(stats_table, headers=["Métrica", "Valor"], tablefmt="pretty"))
        
        # Sesiones de captura
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM captures;")
        captures = cursor.fetchall()
        conn.close()
        
        if captures:
            print_section("Sesiones de Captura")
            capture_table = []
            for capture in captures:
                capture_dict = dict(capture)
                start_time = format_timestamp(capture_dict.get("start_time"))
                end_time = format_timestamp(capture_dict.get("end_time"))
                duration = "N/A"
                if capture_dict.get("start_time") and capture_dict.get("end_time"):
                    try:
                        start = datetime.datetime.fromisoformat(capture_dict.get("start_time"))
                        end = datetime.datetime.fromisoformat(capture_dict.get("end_time"))
                        duration = str(end - start)
                    except:
                        pass
                
                capture_table.append([
                    capture_dict.get("id"),
                    os.path.basename(capture_dict.get("capture_file", "")),
                    start_time,
                    duration,
                    capture_dict.get("packet_count", 0)
                ])
            
            print(tabulate(capture_table, 
                          headers=["ID", "Archivo", "Inicio", "Duración", "Paquetes"], 
                          tablefmt="pretty"))
        
        # SECCIÓN 2: ANÁLISIS DE PROTOCOLOS
        print_header("ANÁLISIS DE PROTOCOLOS")
        
        # Distribución de protocolos
        print_section("Distribución de Protocolos")
        protocol_stats = storage.get_protocol_statistics()
        
        total_packets = sum(protocol_stats.values())
        protocol_table = []
        
        for protocol, count in sorted(protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            protocol_table.append([
                protocol.upper(),
                count,
                f"{percentage:.2f}%"
            ])
        
        print(tabulate(protocol_table, 
                      headers=["Protocolo", "Paquetes", "Porcentaje"], 
                      tablefmt="pretty"))
        
        # Análisis detallado TCP
        if 'tcp' in protocol_stats and protocol_stats['tcp'] > 0:
            print_section("Análisis Detallado TCP")
            
            # Puertos TCP más comunes
            print_subsection("Puertos TCP Más Comunes")
            tcp_ports = storage.get_top_ports(protocol='tcp', limit=10)
            
            port_table = []
            for port, count in tcp_ports:
                percentage = (count / protocol_stats['tcp'] * 100) if protocol_stats['tcp'] > 0 else 0
                service = get_service_name(port)
                port_table.append([
                    port,
                    service,
                    count,
                    f"{percentage:.2f}%"
                ])
            
            print(tabulate(port_table, 
                          headers=["Puerto", "Servicio", "Conexiones", "Porcentaje"], 
                          tablefmt="pretty"))
            
            # Distribución de flags TCP
            print_subsection("Distribución de Flags TCP")
            
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT flags, COUNT(*) as count 
                FROM tcp_data 
                GROUP BY flags 
                ORDER BY count DESC 
                LIMIT 10;
            """)
            flags_data = cursor.fetchall()
            conn.close()
            
            flags_table = []
            for flags_json, count in flags_data:
                try:
                    flags_dict = json.loads(flags_json)
                    flags_str = ", ".join([flag for flag, value in flags_dict.items() if value])
                    if not flags_str:
                        flags_str = "None"
                    
                    flags_table.append([
                        flags_str,
                        count,
                        f"{count/protocol_stats['tcp']*100:.2f}%"
                    ])
                except:
                    flags_table.append([
                        "Error al parsear",
                        count,
                        f"{count/protocol_stats['tcp']*100:.2f}%"
                    ])
            
            print(tabulate(flags_table, 
                          headers=["Flags Activos", "Paquetes", "Porcentaje"], 
                          tablefmt="pretty"))
        
        # Análisis detallado UDP
        if 'udp' in protocol_stats and protocol_stats['udp'] > 0:
            print_section("Análisis Detallado UDP")
            
            # Puertos UDP más comunes
            print_subsection("Puertos UDP Más Comunes")
            udp_ports = storage.get_top_ports(protocol='udp', limit=10)
            
            port_table = []
            for port, count in udp_ports:
                percentage = (count / protocol_stats['udp'] * 100) if protocol_stats['udp'] > 0 else 0
                service = get_service_name(port)
                port_table.append([
                    port,
                    service,
                    count,
                    f"{percentage:.2f}%"
                ])
            
            print(tabulate(port_table, 
                          headers=["Puerto", "Servicio", "Paquetes", "Porcentaje"], 
                          tablefmt="pretty"))
        
        # Análisis detallado ICMP
        if 'icmp' in protocol_stats and protocol_stats['icmp'] > 0:
            print_section("Análisis Detallado ICMP")
            
            # Tipos ICMP
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT type, type_name, COUNT(*) as count 
                FROM icmp_data 
                GROUP BY type, type_name 
                ORDER BY count DESC;
            """)
            icmp_data = cursor.fetchall()
            conn.close()
            
            if icmp_data:
                icmp_table = []
                for icmp_type, type_name, count in icmp_data:
                    percentage = (count / protocol_stats['icmp'] * 100) if protocol_stats['icmp'] > 0 else 0
                    icmp_table.append([
                        icmp_type,
                        type_name if type_name else "Unknown",
                        count,
                        f"{percentage:.2f}%"
                    ])
                
                print(tabulate(icmp_table, 
                              headers=["Tipo", "Descripción", "Paquetes", "Porcentaje"], 
                              tablefmt="pretty"))
        
        # SECCIÓN 3: ANÁLISIS DE SEGURIDAD
        print_header("ANÁLISIS DE SEGURIDAD")
        
        # Anomalías detectadas
        print_section("Anomalías Detectadas")
        anomaly_stats = storage.get_anomaly_statistics()
        
        if anomaly_stats:
            anomaly_table = []
            for anomaly, count in sorted(anomaly_stats.items(), key=lambda x: x[1], reverse=True):
                anomaly_desc = get_anomaly_description(anomaly)
                anomaly_table.append([
                    anomaly,
                    anomaly_desc,
                    count
                ])
            
            print(tabulate(anomaly_table, 
                          headers=["Anomalía", "Descripción", "Ocurrencias"], 
                          tablefmt="pretty"))
            
            # Ejemplos de paquetes con anomalías
            print_subsection("Ejemplos de Paquetes con Anomalías")
            
            anomalous_packets = storage.query_packets(has_anomalies=True, limit=5)
            if anomalous_packets:
                anomaly_examples = []
                for packet in anomalous_packets:
                    tcp_data = packet.get('tcp_data', {})
                    anomalies = tcp_data.get('anomalies', [])
                    if isinstance(anomalies, str):
                        try:
                            anomalies = json.loads(anomalies)
                        except:
                            anomalies = []
                    
                    src_port = tcp_data.get('src_port', '?')
                    dst_port = tcp_data.get('dst_port', '?')
                    
                    anomaly_examples.append([
                        packet.get('id'),
                        format_timestamp(packet.get('timestamp')),
                        f"{packet.get('src_ip')}:{src_port}",
                        f"{packet.get('dst_ip')}:{dst_port}",
                        ", ".join(anomalies)
                    ])
                
                print(tabulate(anomaly_examples, 
                              headers=["ID", "Timestamp", "Origen", "Destino", "Anomalías"], 
                              tablefmt="pretty"))
        else:
            print("No se detectaron anomalías en los paquetes capturados.")
        
        # TTL anormales (posibles técnicas de evasión)
        print_section("Valores TTL Inusuales")
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # TTL bajos (posible indicador de traceroute o escaneo)
        cursor.execute("""
            SELECT ttl, COUNT(*) as count 
            FROM ip_packets 
            WHERE ttl < 20 AND ttl > 0
            GROUP BY ttl 
            ORDER BY count DESC;
        """)
        low_ttl_data = cursor.fetchall()
        
        if low_ttl_data:
            ttl_table = []
            for ttl, count in low_ttl_data:
                ttl_table.append([
                    ttl,
                    count,
                    "Posible traceroute/escaneo o host muy cercano"
                ])
            
            print(tabulate(ttl_table, 
                          headers=["TTL", "Paquetes", "Observación"], 
                          tablefmt="pretty"))
        else:
            print("No se detectaron valores TTL inusuales.")
        
        conn.close()
        
        # SECCIÓN 4: ANÁLISIS DE COMUNICACIONES
        print_header("ANÁLISIS DE COMUNICACIONES")
        
        # Hosts más activos
        print_section("Hosts Más Activos")
        top_talkers = storage.get_top_talkers(limit=10)
        
        # Direcciones origen más activas
        print_subsection("IPs Origen Más Activas")
        source_table = []
        for ip, count in top_talkers['source']:
            source_table.append([
                ip,
                count,
                identify_ip_type(ip)
            ])
        
        print(tabulate(source_table, 
                      headers=["Dirección IP", "Paquetes Enviados", "Tipo"], 
                      tablefmt="pretty"))
        
        # Direcciones destino más activas
        print_subsection("IPs Destino Más Activas")
        dest_table = []
        for ip, count in top_talkers['destination']:
            dest_table.append([
                ip,
                count,
                identify_ip_type(ip)
            ])
        
        print(tabulate(dest_table, 
                      headers=["Dirección IP", "Paquetes Recibidos", "Tipo"], 
                      tablefmt="pretty"))
        
        # Pares de comunicación más comunes
        print_section("Pares de Comunicación Más Comunes")
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT src_ip, dst_ip, COUNT(*) as count 
            FROM ip_packets 
            GROUP BY src_ip, dst_ip 
            ORDER BY count DESC 
            LIMIT 10;
        """)
        pairs = cursor.fetchall()
        conn.close()
        
        if pairs:
            pairs_table = []
            for src_ip, dst_ip, count in pairs:
                pairs_table.append([
                    src_ip,
                    dst_ip,
                    count,
                    f"{identify_ip_type(src_ip)} → {identify_ip_type(dst_ip)}"
                ])
            
            print(tabulate(pairs_table, 
                          headers=["IP Origen", "IP Destino", "Paquetes", "Tipo"], 
                          tablefmt="pretty"))
        
        # Combinaciones puerto-protocolo más comunes
        print_section("Combinaciones Puerto-Protocolo Más Comunes")
        
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        # Puertos destino TCP
        cursor.execute("""
            SELECT t.dst_port, COUNT(*) as count 
            FROM tcp_data t 
            JOIN ip_packets p ON t.packet_id = p.id 
            GROUP BY t.dst_port 
            ORDER BY count DESC 
            LIMIT 5;
        """)
        tcp_ports = cursor.fetchall()
        
        # Puertos destino UDP
        cursor.execute("""
            SELECT u.dst_port, COUNT(*) as count 
            FROM udp_data u 
            JOIN ip_packets p ON u.packet_id = p.id 
            GROUP BY u.dst_port 
            ORDER BY count DESC 
            LIMIT 5;
        """)
        udp_ports = cursor.fetchall()
        
        conn.close()
        
        port_protocol_table = []
        
        for port, count in tcp_ports:
            service = get_service_name(port)
            port_protocol_table.append([
                port,
                "TCP",
                count,
                service
            ])
        
        for port, count in udp_ports:
            service = get_service_name(port)
            port_protocol_table.append([
                port,
                "UDP",
                count,
                service
            ])
        
        # Ordenar por recuento descendente
        port_protocol_table.sort(key=lambda x: x[2], reverse=True)
        
        print(tabulate(port_protocol_table[:10], 
                      headers=["Puerto", "Protocolo", "Paquetes", "Servicio Probable"], 
                      tablefmt="pretty"))
        
        # SECCIÓN 5: ANÁLISIS DETALLADO DE PAQUETES
        print_header("ANÁLISIS DETALLADO DE PAQUETES")
        
        # Muestra de paquetes TCP
        if 'tcp' in protocol_stats and protocol_stats['tcp'] > 0:
            print_section("Muestra de Paquetes TCP")
            tcp_packets = storage.query_packets(protocol='tcp', limit=3)
            
            for i, packet in enumerate(tcp_packets, 1):
                print_subsection(f"Paquete TCP #{i} (ID: {packet.get('id')})")
                
                # Información de capa 3
                print(f"  {Fore.BLUE}Información de Capa 3:{Style.RESET_ALL}")
                print(f"    Timestamp: {format_timestamp(packet.get('timestamp'))}")
                print(f"    IP Origen: {packet.get('src_ip')}")
                print(f"    IP Destino: {packet.get('dst_ip')}")
                print(f"    Versión IP: {packet.get('version')}")
                print(f"    TTL: {packet.get('ttl')}")
                
                if 'identification' in packet:
                    print(f"    ID de Paquete: {packet.get('identification')}")
                
                if 'fragmented' in packet:
                    print(f"    Fragmentado: {packet.get('fragmented')}")
                    if packet.get('fragmented') and 'fragment_offset' in packet:
                        print(f"    Offset de Fragmento: {packet.get('fragment_offset')}")
                
                # Información de capa 4 (TCP)
                tcp_data = packet.get('tcp_data', {})
                if tcp_data:
                    print(f"  {Fore.BLUE}Información de Capa 4 (TCP):{Style.RESET_ALL}")
                    print(f"    Puerto Origen: {tcp_data.get('src_port')}")
                    print(f"    Puerto Destino: {tcp_data.get('dst_port')}")
                    
                    if 'seq' in tcp_data:
                        print(f"    Número de Secuencia: {tcp_data.get('seq')}")
                    
                    if 'ack' in tcp_data:
                        print(f"    Número de ACK: {tcp_data.get('ack')}")
                    
                    if 'window_size' in tcp_data:
                        print(f"    Tamaño de Ventana: {tcp_data.get('window_size')}")
                    
                    # Flags TCP
                    if 'flags' in tcp_data:
                        flags = tcp_data.get('flags')
                        if isinstance(flags, str):
                            try:
                                flags = json.loads(flags)
                            except:
                                flags = {}
                        
                        print(f"    Flags TCP: ", end="")
                        if flags:
                            active_flags = [flag for flag, value in flags.items() if value]
                            print(", ".join(active_flags) if active_flags else "None")
                        else:
                            print("None")
                    
                    # Opciones TCP
                    if 'options' in tcp_data:
                        options = tcp_data.get('options')
                        if isinstance(options, str):
                            try:
                                options = json.loads(options)
                            except:
                                options = {}
                        
                        if options:
                            print(f"    Opciones TCP: {', '.join(options.keys())}")
                    
                    # Anomalías
                    if 'anomalies' in tcp_data:
                        anomalies = tcp_data.get('anomalies')
                        if isinstance(anomalies, str):
                            try:
                                anomalies = json.loads(anomalies)
                            except:
                                anomalies = []
                        
                        if anomalies:
                            print(f"    {Fore.RED}Anomalías: {', '.join(anomalies)}{Style.RESET_ALL}")
        
        # Muestra de paquetes UDP
        if 'udp' in protocol_stats and protocol_stats['udp'] > 0:
            print_section("Muestra de Paquetes UDP")
            udp_packets = storage.query_packets(protocol='udp', limit=2)
            
            for i, packet in enumerate(udp_packets, 1):
                print_subsection(f"Paquete UDP #{i} (ID: {packet.get('id')})")
                
                # Información básica
                print(f"  {Fore.BLUE}Información de Capa 3:{Style.RESET_ALL}")
                print(f"    Timestamp: {format_timestamp(packet.get('timestamp'))}")
                print(f"    IP Origen: {packet.get('src_ip')}")
                print(f"    IP Destino: {packet.get('dst_ip')}")
                print(f"    Versión IP: {packet.get('version')}")
                print(f"    TTL: {packet.get('ttl')}")
                
                # Información UDP
                udp_data = packet.get('udp_data', {})
                if udp_data:
                    print(f"  {Fore.BLUE}Información de Capa 4 (UDP):{Style.RESET_ALL}")
                    print(f"    Puerto Origen: {udp_data.get('src_port')}")
                    print(f"    Puerto Destino: {udp_data.get('dst_port')}")
                    
                    if udp_data.get('length'):
                        print(f"    Longitud: {udp_data.get('length')} bytes")
                    
                    # Intentar identificar el servicio
                    dst_port = udp_data.get('dst_port')
                    if dst_port:
                        service = get_service_name(dst_port)
                        if service != "Unknown":
                            print(f"    Servicio Probable: {service}")
        
        # Muestra de paquetes ICMP
        if 'icmp' in protocol_stats and protocol_stats['icmp'] > 0:
            print_section("Muestra de Paquetes ICMP")
            icmp_packets = storage.query_packets(protocol='icmp', limit=2)
            
            for i, packet in enumerate(icmp_packets, 1):
                print_subsection(f"Paquete ICMP #{i} (ID: {packet.get('id')})")
                
                # Información básica
                print(f"  {Fore.BLUE}Información de Capa 3:{Style.RESET_ALL}")
                print(f"    Timestamp: {format_timestamp(packet.get('timestamp'))}")
                print(f"    IP Origen: {packet.get('src_ip')}")
                print(f"    IP Destino: {packet.get('dst_ip')}")
                print(f"    Versión IP: {packet.get('version')}")
                print(f"    TTL: {packet.get('ttl')}")
                
                # Información ICMP
                icmp_data = packet.get('icmp_data', {})
                if icmp_data:
                    print(f"  {Fore.BLUE}Información de Capa 4 (ICMP):{Style.RESET_ALL}")
                    print(f"    Tipo: {icmp_data.get('type')}")
                    print(f"    Nombre del Tipo: {icmp_data.get('type_name', 'Unknown')}")
                    
                    if 'code' in icmp_data:
                        print(f"    Código: {icmp_data.get('code')}")
    
    except Exception as e:
        print(f"{Fore.RED}Error durante la consulta: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

def get_service_name(port):
    """Devuelve el nombre del servicio asociado a un puerto común."""
    common_ports = {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP",
        80: "HTTP",
        110: "POP3",
        119: "NNTP",
        123: "NTP",
        137: "NetBIOS Name",
        138: "NetBIOS Datagram",
        139: "NetBIOS Session",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP Trap",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        636: "LDAPS",
        993: "IMAPS",
        995: "POP3S",
        1080: "SOCKS",
        1433: "MSSQL",
        1521: "Oracle",
        3306: "MySQL",
        3389: "RDP",
        5060: "SIP",
        5061: "SIPS",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate",
        9000: "Jenkins",
        9090: "Management",
        9200: "Elasticsearch",
        27017: "MongoDB"
    }
    
    return common_ports.get(port, "Unknown")

def get_anomaly_description(anomaly):
    """Devuelve una descripción detallada de una anomalía detectada."""
    descriptions = {
        "invalid_flag_combination": "Combinación inválida de flags TCP - posible escaneo o evasión de firewall",
        "null_scan": "Escaneo NULL - paquete TCP sin flags activos, usado para evadir detección",
        "xmas_scan": "Escaneo Xmas - paquete con todas las flags TCP activas, técnica de fingerprinting",
        "fin_scan": "Escaneo FIN - paquete con solo flag FIN, técnica de evasión de firewall"
    }
    
    return descriptions.get(anomaly, "Anomalía desconocida")

def identify_ip_type(ip):
    """Identifica el tipo de dirección IP (privada, pública, multicast, etc.)."""
    if not ip or ip == "0.0.0.0":
        return "Desconocida"
        
    # Comprobar si es IPv6
    if ":" in ip:
        if ip.startswith("fe80:"):
            return "IPv6 Link-Local"
        elif ip.startswith("fc00:") or ip.startswith("fd00:"):
            return "IPv6 Única Local"
        elif ip.startswith("ff"):
            return "IPv6 Multicast"
        elif ip.startswith("2001:0db8:"):
            return "IPv6 Documentación"
        return "IPv6 Pública"
    
    # Procesar IPv4
    parts = ip.split(".")
    if len(parts) != 4:
        return "Formato inválido"
    
    # Direcciones privadas
    if ip.startswith("10.") or ip.startswith("192.168.") or (ip.startswith("172.") and 16 <= int(parts[1]) <= 31):
        return "IPv4 Privada"
    
    # Loopback
    if ip.startswith("127."):
        return "IPv4 Loopback"
    
    # Link-local
    if ip.startswith("169.254."):
        return "IPv4 Link-Local"
    
    # Multicast
    if ip.startswith("224.") or ip.startswith("239."):
        return "IPv4 Multicast"
    
    # Broadcast
    if ip.endswith(".255"):
        return "IPv4 Broadcast"
    
    # Público por defecto
    return "IPv4 Pública"

def parse_arguments():
    """Procesa los argumentos de línea de comandos"""
    parser = argparse.ArgumentParser(description='Herramienta de análisis avanzado de tráfico de red')
    parser.add_argument('--db', '-d', type=str, help='Nombre o ruta del archivo de base de datos a analizar')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    query_advanced_db_info(args.db)