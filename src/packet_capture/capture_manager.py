"""
Módulo principal para gestionar la captura de paquetes.
Provee una interfaz unificada para diferentes métodos de captura.
"""

import os
import time
from enum import Enum
from pathlib import Path

from src.packet_capture.tshark_capture import TSharkCapture
from src.packet_capture.utils import get_available_interfaces, get_capture_dir, logger, open_in_wireshark

class CaptureMethod(Enum):
    """Enumera los métodos de captura disponibles."""
    TSHARK = "tshark"

class CaptureManager:
    """
    Clase principal para gestionar la captura de paquetes.
    Proporciona una interfaz unificada para diferentes métodos de captura.
    """
    
    def __init__(self, method=CaptureMethod.TSHARK):
        """
        Inicializa el administrador de captura.
        
        Args:
            method (CaptureMethod): Método de captura a utilizar.
        """
        self.method = method
        self.capture_instance = None
        self.active_captures = {}  # Para gestionar múltiples capturas simultáneas
        logger.info(f"CaptureManager inicializado con método {method.value}")
    
    def list_interfaces(self):
        """
        Lista las interfaces de red disponibles.
        
        Returns:
            list: Lista de interfaces disponibles.
        """
        interfaces = get_available_interfaces()
        logger.info(f"Interfaces disponibles: {interfaces}")
        return interfaces
    
    def start_capture(self, interface=None, output_file=None, packet_count=None,
                     capture_filter=None, display_filter=None, timeout=None,
                     duration=None, capture_id=None):
        """
        Inicia una nueva captura de paquetes.
        
        Args:
            interface (str): Interfaz de red a utilizar.
            output_file (str): Ruta del archivo de salida.
            packet_count (int): Número máximo de paquetes a capturar.
            capture_filter (str): Filtro BPF para aplicar durante la captura.
            display_filter (str): Filtro de visualización (solo para TShark).
            timeout (int): Tiempo máximo de captura en segundos.
            duration (int): Duración específica de la captura en segundos.
            capture_id (str): Identificador único para esta captura.
            
        Returns:
            str: ID de la captura si es exitoso, None en caso contrario.
        """
        try:
            # Generar ID único para esta captura si no se proporciona
            if not capture_id:
                capture_id = f"capture_{int(time.time())}"
            
            # Crear instancia de captura según el método elegido
            if self.method == CaptureMethod.TSHARK:
                capture = TSharkCapture(
                    interface=interface,
                    output_file=output_file,
                    packet_count=packet_count,
                    capture_filter=capture_filter,
                    display_filter=display_filter,
                    timeout=timeout
                )
                
                # Iniciar captura según los parámetros
                if duration:
                    # Si se especifica duración, usar captura a archivo con duración fija
                    result = capture.start_capture_file(duration=duration)
                elif packet_count or timeout:
                    # Si hay límite de paquetes o tiempo, usar modo live
                    result = capture.start_capture_live()
                else:
                    # Sin límites, usar captura a archivo directa
                    result = capture.start_capture_file()
                    
            else:
                logger.error(f"Método de captura no soportado: {self.method}")
                return None
            
            # Guardar la instancia si la captura se inició correctamente
            if result:
                self.active_captures[capture_id] = capture
                logger.info(f"Captura {capture_id} iniciada correctamente")
                return capture_id
            else:
                logger.error(f"Error al iniciar captura {capture_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error al iniciar captura: {str(e)}")
            return None
    
    def stop_capture(self, capture_id):
        """
        Detiene una captura en progreso.
        
        Args:
            capture_id (str): ID de la captura a detener.
            
        Returns:
            str: Ruta del archivo de captura si es exitoso, None en caso contrario.
        """
        if capture_id not in self.active_captures:
            logger.warning(f"No se encontró captura con ID {capture_id}")
            return None
        
        try:
            capture = self.active_captures[capture_id]
            result = capture.stop_capture()
            
            if result:
                # Eliminar la captura de las activas
                del self.active_captures[capture_id]
                logger.info(f"Captura {capture_id} detenida correctamente")
                return result
            else:
                logger.error(f"Error al detener captura {capture_id}")
                return None
                
        except Exception as e:
            logger.error(f"Error al detener captura {capture_id}: {e}")
            return None
    
    def list_active_captures(self):
        """
        Lista las capturas activas.
        
        Returns:
            dict: Diccionario con las capturas activas.
        """
        return {
            id: {
                "method": self.method.value,
                "interface": capture.interface,
                "output_file": capture.output_file
            }
            for id, capture in self.active_captures.items()
        }
    
    def list_capture_files(self):
        """
        Lista los archivos de captura disponibles.
        
        Returns:
            list: Lista de rutas a archivos de captura.
        """
        capture_dir = get_capture_dir()
        capture_files = list(Path(capture_dir).glob("*.pcap"))
        return [str(file) for file in capture_files]
    
    def read_capture_file(self, file_path):
        """
        Lee un archivo de captura.
        
        Args:
            file_path (str): Ruta al archivo de captura.
            
        Returns:
            object: Captura leída (formato depende del método).
        """
        try:
            # Crear instancia temporal para leer el archivo
            if self.method == CaptureMethod.TSHARK:
                capture = TSharkCapture()
            else:
                logger.error(f"Método de captura no soportado: {self.method}")
                return None
            
            return capture.read_capture_file(file_path)
            
        except Exception as e:
            logger.error(f"Error al leer archivo de captura {file_path}: {e}")
            return None
            
    def open_in_wireshark(self, file_path):
        """
        Abre un archivo de captura en Wireshark.
        
        Args:
            file_path (str): Ruta al archivo de captura.
            
        Returns:
            bool: True si se abrió correctamente, False en caso contrario.
        """
        return open_in_wireshark(file_path)