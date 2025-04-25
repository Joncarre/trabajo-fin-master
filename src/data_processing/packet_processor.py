"""
Módulo para procesar paquetes de red y extraer información relevante de las capas 3 y 4.
Se centra en datos de las capas de Red y Transporte del modelo OSI.
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
            capture = pyshark.FileCapture(pcap_file)
            
            processed_packets = []
            for packet_number, packet in enumerate(capture):
                try:
                    processed_packet = self._process_packet(packet)
                    if processed_packet:
                        processed_packets.append(processed_packet)
                except Exception as e:
                    logger.warning(f"Error al procesar el paquete #{packet_number}: {str(e)}")
                    continue
            
            logger.info(f"Procesados {len(processed_packets)} paquetes del archivo {pcap_file}")
            return processed_packets
        
        except Exception as e:
            logger.error(f"Error al procesar el archivo PCAP {pcap_file}: {str(e)}")
            return []
    
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
    
    def _extract_ipv4_info(self, ip_layer, target_dict: Dict[str, Any]) -> None:
        """
        Extrae información de la capa IPv4.
        
        Args:
            ip_layer: Capa IP del paquete
            target_dict: Diccionario donde guardar la información extraída
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
        
        Args:
            ipv6_layer: Capa IPv6 del paquete
            target_dict: Diccionario donde guardar la información extraída
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
        
        Args:
            tcp_layer: Capa TCP del paquete
            target_dict: Diccionario donde guardar la información extraída
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
        
        Args:
            udp_layer: Capa UDP del paquete
            target_dict: Diccionario donde guardar la información extraída
        """
        target_dict['src_port'] = self._safe_int_conversion(udp_layer.srcport)
        target_dict['dst_port'] = self._safe_int_conversion(udp_layer.dstport)
        
        if hasattr(udp_layer, 'length'):
            target_dict['length'] = self._safe_int_conversion(udp_layer.length)
    
    def _extract_icmp_info(self, icmp_layer, target_dict: Dict[str, Any]) -> None:
        """
        Extrae información de la capa ICMP.
        
        Args:
            icmp_layer: Capa ICMP del paquete
            target_dict: Diccionario donde guardar la información extraída
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
        
        Args:
            tcp_layer: Capa TCP del paquete
            target_dict: Diccionario donde guardar la información de anomalías
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