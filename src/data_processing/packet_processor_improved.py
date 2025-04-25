"""
Módulo para procesar paquetes de red y extraer información relevante de las capas 3 y 4.
Se centra en datos de las capas de Red y Transporte del modelo OSI.
Versión mejorada con mejor diagnóstico.
"""

import pyshark
import ipaddress
import datetime
import logging
import json
import os
from typing import Dict, List, Any, Optional, Union

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("packet_processor")

class PacketProcessor:
    """
    Clase para procesar paquetes de red y extraer información relevante.
    Enfocada en las capas 3 (Red) y 4 (Transporte) del modelo OSI.
    """
    
    def __init__(self):
        """Inicializa el procesador de paquetes."""
        self.supported_protocols = {
            'ip', 'ipv6',           # Capa 3
            'tcp', 'udp', 'icmp'    # Capa 4
        }
    
    def _safe_int_conversion(self, value, default=0):
        """
        Convierte un valor a entero de manera segura, manejando notaciones hexadecimales.
        
        Args:
            value: Valor a convertir (puede ser decimal, hexadecimal, etc.)
            default: Valor a devolver en caso de error
            
        Returns:
            Valor convertido a entero o el valor por defecto en caso de error
        """
        if value is None:
            return default
            
        try:
            # Si el valor es una cadena con prefijo '0x', usar base 16
            if isinstance(value, str) and value.lower().startswith('0x'):
                return int(value, 16)
            # Para otros casos, usar conversión estándar
            return int(value)
        except (ValueError, TypeError):
            logger.debug(f"No se pudo convertir '{value}' a entero")
            return default
          def process_pcap_file(self, pcap_file: str) -> List[Dict[str, Any]]:
        """
        Procesa un archivo PCAP y extrae información relevante de cada paquete.
        
        Args:
            pcap_file: Ruta al archivo PCAP a procesar
            
        Returns:
            Lista de diccionarios, cada uno representando un paquete procesado
        """
        try:
            logger.info(f"Procesando archivo PCAP: {pcap_file}")
            
            # Verificar que el archivo existe y es accesible
            if not os.path.exists(pcap_file):
                logger.error(f"El archivo PCAP no existe: {pcap_file}")
                return []
                
            # Verificar tamaño del archivo
            file_size = os.path.getsize(pcap_file)
            logger.info(f"Tamaño del archivo PCAP: {file_size} bytes")
            if file_size == 0:
                logger.error(f"El archivo PCAP está vacío: {pcap_file}")
                return []
            
            # === SOLUCIÓN PARA EL CONFLICTO DEL EVENT LOOP ===
            # En lugar de usar pyshark directamente, utilizamos tshark (el ejecutable de Wireshark)
            # para generar una salida JSON que podamos procesar, evitando el conflicto con el event loop
            
            import subprocess
            import json
            
            logger.info("Usando tshark directamente para procesar el archivo PCAP...")
            
            # Buscar tshark en las ubicaciones comunes
            tshark_paths = [
                "tshark",  # Si está en el PATH
                r"C:\Program Files\Wireshark\tshark.exe",  # Instalación por defecto en Windows
                "/usr/bin/tshark",  # Linux
                "/usr/local/bin/tshark"  # MacOS
            ]
            
            tshark_path = None
            for path in tshark_paths:
                try:
                    # Comprobar si tshark existe en esta ruta
                    result = subprocess.run([path, "-v"], capture_output=True, text=True, check=False)
                    if result.returncode == 0:
                        tshark_path = path
                        logger.info(f"TShark encontrado en: {tshark_path}")
                        break
                except Exception:
                    continue
                    
            if not tshark_path:
                logger.error("No se pudo encontrar tshark en el sistema")
                return []
                
            # Utilizar tshark para extraer datos en formato JSON
            try:
                # Ejecutar tshark para convertir pcap a json
                cmd = [
                    tshark_path, 
                    "-r", pcap_file,  # Leer del archivo pcap
                    "-T", "json",     # Formato de salida JSON
                    "-x",             # Incluir datos hex
                    "-n"              # No resolver nombres
                ]
                
                logger.info(f"Ejecutando comando: {' '.join(cmd)}")
                process = subprocess.run(cmd, capture_output=True, text=True, check=False)
                
                if process.returncode != 0:
                    logger.error(f"Error al ejecutar tshark: {process.stderr}")
                    return []
                    
                # Parsear la salida JSON
                output = process.stdout
                if not output:
                    logger.error("TShark no produjo salida JSON")
                    return []
                    
                # Contamos paquetes en la salida
                packet_data = json.loads(output)
                packet_count = len(packet_data)
                logger.info(f"TShark extrajo {packet_count} paquetes")
                
                if packet_count == 0:
                    logger.error("No se encontraron paquetes en el archivo PCAP")
                    return []
                
            except Exception as e:
                logger.error(f"Error al procesar la salida de tshark: {str(e)}")
                return []
            
            # Procesar los paquetes del JSON
            logger.info("Comenzando procesamiento de paquetes desde JSON...")
            processed_packets = []
            
            for idx, packet_json in enumerate(packet_data):
                try:
                    # Convertir la estructura JSON de tshark a nuestro formato interno
                    processed_packet = self._process_tshark_json_packet(packet_json)
                    if processed_packet:
                        processed_packets.append(processed_packet)
                        
                        # Mostrar progreso cada 100 paquetes
                        if len(processed_packets) % 100 == 0:
                            logger.info(f"Procesados {len(processed_packets)} paquetes...")
                except Exception as e:
                    logger.warning(f"Error al procesar el paquete #{idx}: {str(e)}")
                    continue
            
            logger.info(f"Procesados correctamente {len(processed_packets)} paquetes del archivo {pcap_file}")
            return processed_packets
            
        except Exception as e:
            logger.error(f"Error al procesar el archivo PCAP {pcap_file}: {str(e)}")
            return []
            
    def _process_tshark_json_packet(self, packet_json: Dict) -> Optional[Dict[str, Any]]:
        """
        Procesa un paquete en formato JSON generado por tshark.
        
        Args:
            packet_json: Diccionario con la información del paquete en formato tshark JSON
            
        Returns:
            Diccionario con información del paquete en nuestro formato interno o None
        """
        try:
            # Extraer datos básicos
            layers = packet_json.get("_source", {}).get("layers", {})
            
            # Crear la estructura básica del paquete
            packet_info = {
                'timestamp': layers.get('frame', {}).get('frame.time_epoch'),
                'length': int(layers.get('frame', {}).get('frame.len', 0)),
                'layer3': {},
                'layer4': {}
            }
            
            # Procesar capa IP
            if 'ip' in layers:
                ip_layer = layers['ip']
                packet_info['layer3']['version'] = 4
                packet_info['layer3']['src_ip'] = ip_layer.get('ip.src')
                packet_info['layer3']['dst_ip'] = ip_layer.get('ip.dst')
                packet_info['layer3']['ttl'] = int(ip_layer.get('ip.ttl', 0))
                
                # Más campos IP si están disponibles...
                if 'ip.id' in ip_layer:
                    packet_info['layer3']['identification'] = int(ip_layer.get('ip.id', 0), 16)
                
            elif 'ipv6' in layers:
                ipv6_layer = layers['ipv6']
                packet_info['layer3']['version'] = 6
                packet_info['layer3']['src_ip'] = ipv6_layer.get('ipv6.src')
                packet_info['layer3']['dst_ip'] = ipv6_layer.get('ipv6.dst')
                packet_info['layer3']['hop_limit'] = int(ipv6_layer.get('ipv6.hlim', 0))
                
            else:
                # Sin capa IP, no procesamos este paquete
                return None
            
            # Procesar capas de transporte
            if 'tcp' in layers:
                tcp_layer = layers['tcp']
                packet_info['layer4']['protocol'] = 'tcp'
                packet_info['layer4']['src_port'] = int(tcp_layer.get('tcp.srcport', 0))
                packet_info['layer4']['dst_port'] = int(tcp_layer.get('tcp.dstport', 0))
                
                # Flags TCP
                flags = {}
                if 'tcp.flags' in tcp_layer:
                    tcp_flags = int(tcp_layer.get('tcp.flags', 0), 16)
                    flags['SYN'] = bool(tcp_flags & 0x02)
                    flags['ACK'] = bool(tcp_flags & 0x10)
                    flags['FIN'] = bool(tcp_flags & 0x01)
                    flags['RST'] = bool(tcp_flags & 0x04)
                    flags['PSH'] = bool(tcp_flags & 0x08)
                    flags['URG'] = bool(tcp_flags & 0x20)
                
                packet_info['layer4']['flags'] = flags
                
                # Secuencia y ACK
                if 'tcp.seq' in tcp_layer:
                    packet_info['layer4']['seq'] = int(tcp_layer.get('tcp.seq', 0))
                if 'tcp.ack' in tcp_layer:
                    packet_info['layer4']['ack'] = int(tcp_layer.get('tcp.ack', 0))
                
            elif 'udp' in layers:
                udp_layer = layers['udp']
                packet_info['layer4']['protocol'] = 'udp'
                packet_info['layer4']['src_port'] = int(udp_layer.get('udp.srcport', 0))
                packet_info['layer4']['dst_port'] = int(udp_layer.get('udp.dstport', 0))
                packet_info['layer4']['length'] = int(udp_layer.get('udp.length', 0))
                
            elif 'icmp' in layers:
                icmp_layer = layers['icmp']
                packet_info['layer4']['protocol'] = 'icmp'
                packet_info['layer4']['type'] = int(icmp_layer.get('icmp.type', 0))
                packet_info['layer4']['code'] = int(icmp_layer.get('icmp.code', 0))
                
                # Mapear tipo ICMP a nombre
                icmp_types = {
                    0: 'echo-reply',
                    3: 'destination-unreachable',
                    5: 'redirect',
                    8: 'echo-request',
                    11: 'time-exceeded'
                }
                packet_info['layer4']['type_name'] = icmp_types.get(packet_info['layer4']['type'], 'other')
                
            else:
                # Sin protocolo conocido en capa 4
                packet_info['layer4']['protocol'] = 'other'
            
            return packet_info
        
        except Exception as e:
            logger.warning(f"Error procesando paquete JSON de tshark: {str(e)}")
            return None
    
    def _process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Procesa un paquete individual y extrae información de las capas 3 y 4.
        
        Args:
            packet: Objeto paquete de pyshark
            
        Returns:
            Diccionario con información del paquete o None si no se puede procesar
        """
        # Diccionario base para almacenar información del paquete
        packet_info = {
            'timestamp': packet.sniff_time.isoformat() if hasattr(packet, 'sniff_time') else None,
            'length': self._safe_int_conversion(packet.length) if hasattr(packet, 'length') else None,
            'layer3': {},
            'layer4': {}
        }
        
        # Procesar capa 3 (IP)
        if hasattr(packet, 'ip'):
            self._extract_ipv4_info(packet.ip, packet_info['layer3'])
        elif hasattr(packet, 'ipv6'):
            self._extract_ipv6_info(packet.ipv6, packet_info['layer3'])
        else:
            # Sin información de capa 3 IP, no es relevante para nuestro enfoque
            return None
        
        # Procesar capa 4 (TCP, UDP, ICMP)
        if hasattr(packet, 'tcp'):
            self._extract_tcp_info(packet.tcp, packet_info['layer4'])
            packet_info['layer4']['protocol'] = 'tcp'
        elif hasattr(packet, 'udp'):
            self._extract_udp_info(packet.udp, packet_info['layer4'])
            packet_info['layer4']['protocol'] = 'udp'
        elif hasattr(packet, 'icmp'):
            self._extract_icmp_info(packet.icmp, packet_info['layer4'])
            packet_info['layer4']['protocol'] = 'icmp'
        else:
            # Sin información de capa 4 (TCP/UDP/ICMP), seguimos procesando solo con capa 3
            packet_info['layer4'] = {'protocol': 'other'}
        
        return packet_info
    
    # El resto de los métodos permanecen igual...
    def _extract_ipv4_info(self, ip_layer, target_dict: Dict[str, Any]) -> None:
        """
        Extrae información de la capa IPv4.
        """
        target_dict['version'] = 4
        target_dict['src_ip'] = ip_layer.src
        target_dict['dst_ip'] = ip_layer.dst
        
        if hasattr(ip_layer, 'ttl'):
            target_dict['ttl'] = self._safe_int_conversion(ip_layer.ttl)
        
        if hasattr(ip_layer, 'flags'):
            target_dict['flags'] = ip_layer.flags
            
        if hasattr(ip_layer, 'dsfield'):
            target_dict['dsfield'] = ip_layer.dsfield
            
        # Detectar fragmentación
        if hasattr(ip_layer, 'flags_mf') or hasattr(ip_layer, 'flags_df'):
            target_dict['fragmented'] = hasattr(ip_layer, 'flags_mf') and ip_layer.flags_mf == '1'
            if hasattr(ip_layer, 'fragment_offset'):
                target_dict['fragment_offset'] = self._safe_int_conversion(ip_layer.fragment_offset)
                
        # Añadir campo de identificación IP
        if hasattr(ip_layer, 'id'):
            target_dict['identification'] = self._safe_int_conversion(ip_layer.id)
        
        # Añadir información sobre longitud de cabecera
        if hasattr(ip_layer, 'hdr_len'):
            target_dict['header_length'] = self._safe_int_conversion(ip_layer.hdr_len)
            # Una cabecera de más de 5 palabras (20 bytes) indica presencia de opciones
            if self._safe_int_conversion(ip_layer.hdr_len) > 5:
                target_dict['has_options'] = True
    
    def _extract_ipv6_info(self, ipv6_layer, target_dict: Dict[str, Any]) -> None:
        """
        Extrae información de la capa IPv6.
        """
        target_dict['version'] = 6
        target_dict['src_ip'] = ipv6_layer.src
        target_dict['dst_ip'] = ipv6_layer.dst
        
        if hasattr(ipv6_layer, 'hlim'):
            target_dict['hop_limit'] = self._safe_int_conversion(ipv6_layer.hlim)
            
        if hasattr(ipv6_layer, 'nxt'):
            target_dict['next_header'] = ipv6_layer.nxt
            
        # Añadir información de cabecera y opciones
        if hasattr(ipv6_layer, 'hdr_len'):
            target_dict['header_length'] = self._safe_int_conversion(ipv6_layer.hdr_len)
            
        # Información de flujo
        if hasattr(ipv6_layer, 'flow'):
            target_dict['flow_label'] = ipv6_layer.flow
    
    def _extract_tcp_info(self, tcp_layer, target_dict: Dict[str, Any]) -> None:
        """
        Extrae información de la capa TCP.
        """
        target_dict['src_port'] = self._safe_int_conversion(tcp_layer.srcport)
        target_dict['dst_port'] = self._safe_int_conversion(tcp_layer.dstport)
        
        # Extraer flags TCP
        flags = {}
        flag_fields = ['flags_syn', 'flags_ack', 'flags_fin', 
                     'flags_rst', 'flags_psh', 'flags_urg']
        
        for flag in flag_fields:
            if hasattr(tcp_layer, flag):
                flag_name = flag.split('_')[1].upper()
                flags[flag_name] = tcp_layer.get_field_value(flag) == '1'
        
        target_dict['flags'] = flags
        
        # Extraer información de secuencia
        if hasattr(tcp_layer, 'seq'):
            target_dict['seq'] = self._safe_int_conversion(tcp_layer.seq)
        
        if hasattr(tcp_layer, 'ack'):
            target_dict['ack'] = self._safe_int_conversion(tcp_layer.ack)
        
        if hasattr(tcp_layer, 'window_size'):
            target_dict['window_size'] = self._safe_int_conversion(tcp_layer.window_size)
        
        # Añadir información sobre opciones TCP
        tcp_options = {}
        
        if hasattr(tcp_layer, 'options'):
            for option in tcp_layer.options.split(','):
                option = option.strip()
                if 'timestamp' in option.lower():
                    tcp_options['timestamp'] = True
                if 'window scale' in option.lower():
                    tcp_options['window_scale'] = True
                if 'mss' in option.lower():
                    tcp_options['mss'] = True
        
        if tcp_options:
            target_dict['options'] = tcp_options
        
        # Detectar posibles anomalías
        self._detect_tcp_anomalies(tcp_layer, target_dict)
    
    def _extract_udp_info(self, udp_layer, target_dict: Dict[str, Any]) -> None:
        """
        Extrae información de la capa UDP.
        """
        target_dict['src_port'] = self._safe_int_conversion(udp_layer.srcport)
        target_dict['dst_port'] = self._safe_int_conversion(udp_layer.dstport)
        
        if hasattr(udp_layer, 'length'):
            target_dict['length'] = self._safe_int_conversion(udp_layer.length)
    
    def _extract_icmp_info(self, icmp_layer, target_dict: Dict[str, Any]) -> None:
        """
        Extrae información de la capa ICMP.
        """
        if hasattr(icmp_layer, 'type'):
            target_dict['type'] = self._safe_int_conversion(icmp_layer.type)
            
            # Traducir tipos comunes de ICMP para facilitar el análisis
            icmp_types = {
                0: 'echo-reply',
                3: 'destination-unreachable',
                5: 'redirect',
                8: 'echo-request',
                11: 'time-exceeded'
            }
            
            target_dict['type_name'] = icmp_types.get(self._safe_int_conversion(icmp_layer.type), 'other')
        
        if hasattr(icmp_layer, 'code'):
            target_dict['code'] = self._safe_int_conversion(icmp_layer.code)
    
    def _detect_tcp_anomalies(self, tcp_layer, target_dict: Dict[str, Any]) -> None:
        """
        Detecta posibles anomalías en paquetes TCP.
        """
        anomalies = []
        
        # Comprobar combinaciones inválidas de flags TCP
        flag_attrs = ['flags_syn', 'flags_fin', 'flags_rst']
        flags_present = sum(1 for flag in flag_attrs 
                          if hasattr(tcp_layer, flag) and tcp_layer.get_field_value(flag) == '1')
        
        if flags_present > 1:
            anomalies.append('invalid_flag_combination')
        
        # Paquete sin flags
        all_flags = ['flags_syn', 'flags_ack', 'flags_fin', 'flags_rst', 'flags_psh', 'flags_urg']
        if all(not hasattr(tcp_layer, flag) or tcp_layer.get_field_value(flag) == '0' 
              for flag in all_flags):
            anomalies.append('null_scan')
        
        # Todos los flags activos (Christmas tree scan)
        if all(hasattr(tcp_layer, flag) and tcp_layer.get_field_value(flag) == '1' 
              for flag in all_flags):
            anomalies.append('xmas_scan')
        
        if anomalies:
            target_dict['anomalies'] = anomalies
