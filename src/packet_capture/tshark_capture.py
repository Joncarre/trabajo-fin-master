import os
import pyshark
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path

from src.packet_capture.utils import get_capture_dir, generate_filename, logger

class TSharkCapture:
    """Clase para manejar capturas de paquetes usando TShark/PyShark."""
    
    def __init__(self, interface=None, output_file=None, packet_count=None, 
                 capture_filter=None, display_filter=None, timeout=None):
        """
        Inicializa una nueva instancia de captura TShark.
        
        Args:
            interface (str): Interfaz de red a utilizar. Si es None, usa la variable de entorno.
            output_file (str): Ruta del archivo de salida. Si es None, genera uno automáticamente.
            packet_count (int): Número máximo de paquetes a capturar. None para capturar indefinidamente.
            capture_filter (str): Filtro BPF para aplicar durante la captura.
            display_filter (str): Filtro de visualización para aplicar después de la captura.
            timeout (int): Tiempo máximo de captura en segundos. None para no tener límite.
        """
        self.interface = interface or os.getenv("CAPTURE_INTERFACE", "eth0")
        self.output_file = output_file
        self.packet_count = packet_count
        self.capture_filter = capture_filter
        self.display_filter = display_filter
        self.timeout = timeout
        self.capture = None
        self.is_capturing = False
        
        # Ruta a TShark (importante para Windows)
        self.tshark_path = os.getenv("TSHARK_PATH", "tshark")
        
        # Si no se especifica archivo de salida, generar uno
        if not self.output_file:
            capture_dir = get_capture_dir()
            self.output_file = os.path.join(capture_dir, generate_filename())
        
        logger.info(f"Captura TShark inicializada en interfaz {self.interface}")
        logger.info(f"Archivo de salida: {self.output_file}")
    
    def start_capture_live(self):
        """Inicia una captura en vivo (interactiva)."""
        try:
            logger.info(f"Iniciando captura en vivo en interfaz {self.interface}")
            
            # Configurar opciones para pyshark
            capture_options = {
                'interface': self.interface,
                'output_file': self.output_file,
                'bpf_filter': self.capture_filter,
                'display_filter': self.display_filter,
                'tshark_path': self.tshark_path  # Usar la ruta específica para Windows
            }
            
            self.capture = pyshark.LiveCapture(**capture_options)
            self.is_capturing = True
            
            # Si hay un límite de paquetes, usamos sniff()
            if self.packet_count:
                logger.info(f"Capturando {self.packet_count} paquetes...")
                self.capture.sniff(packet_count=self.packet_count, timeout=self.timeout)
                self.is_capturing = False
                logger.info(f"Captura completada. Guardado en {self.output_file}")
                return self.output_file
            
            # Si no hay límite, iniciamos sniff en modo no bloqueante
            self.capture.sniff_continuously(packet_count=None)
            return True
            
        except Exception as e:
            logger.error(f"Error al iniciar captura: {e}")
            self.is_capturing = False
            return False
    
    def start_capture_file(self, duration=None):
        """
        Inicia una captura directamente en archivo usando TShark (más eficiente para capturas largas).
        
        Args:
            duration (int): Duración de la captura en segundos.
        
        Returns:
            str: Ruta del archivo de captura si es exitoso, None en caso contrario.
        """
        try:
            command = [self.tshark_path, "-i", self.interface, "-w", self.output_file]
            
            if self.capture_filter:
                command.extend(["-f", self.capture_filter])
            
            if self.packet_count:
                command.extend(["-c", str(self.packet_count)])
            
            if duration:
                command.extend(["-a", f"duration:{duration}"])
            
            logger.info(f"Ejecutando comando: {' '.join(command)}")
            
            if duration:
                # Si hay duración, ejecutar de forma bloqueante
                subprocess.run(command, check=True)
                logger.info(f"Captura completada. Guardado en {self.output_file}")
                return self.output_file
            else:
                # Sin duración, ejecutar en segundo plano
                self.process = subprocess.Popen(command)
                self.is_capturing = True
                logger.info(f"Captura iniciada en proceso {self.process.pid}")
                return True
                
        except subprocess.SubprocessError as e:
            logger.error(f"Error al ejecutar TShark: {e}")
            self.is_capturing = False
            return None
        except Exception as e:
            logger.error(f"Error inesperado al iniciar captura: {e}")
            self.is_capturing = False
            return None
    
    def stop_capture(self):
        """Detiene una captura en progreso."""
        if not self.is_capturing:
            logger.warning("No hay captura activa para detener")
            return False
        
        try:
            if hasattr(self, 'process'):
                # Si estamos usando subproceso directo
                logger.info(f"Deteniendo proceso de captura {self.process.pid}")
                self.process.terminate()
                self.process.wait(timeout=5)
                
            elif self.capture:
                # Si estamos usando pyshark
                logger.info("Deteniendo captura de PyShark")
                self.capture.stop()
            
            self.is_capturing = False
            logger.info(f"Captura detenida. Guardado en {self.output_file}")
            return self.output_file
            
        except Exception as e:
            logger.error(f"Error al detener captura: {e}")
            return None
            
    def read_capture_file(self, file_path=None):
        """
        Lee un archivo de captura para procesar sus paquetes.
        
        Args:
            file_path (str): Ruta al archivo. Si es None, usa el último archivo guardado.
            
        Returns:
            FileCapture: Objeto de captura que se puede iterar.
        """
        file_to_read = file_path or self.output_file
        if not os.path.exists(file_to_read):
            logger.error(f"El archivo de captura {file_to_read} no existe")
            return None
        
        try:
            logger.info(f"Leyendo archivo de captura {file_to_read}")
            file_capture = pyshark.FileCapture(
                file_to_read,
                display_filter=self.display_filter,
                tshark_path=self.tshark_path  # Usar la ruta específica para Windows
            )
            return file_capture
            
        except Exception as e:
            logger.error(f"Error al leer archivo de captura: {e}")
            return None