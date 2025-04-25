import os
import logging
import platform
import subprocess
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("packet_capture.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("packet_capture")

# Cargar variables de entorno
load_dotenv()

def get_capture_dir():
    """Obtiene y crea si es necesario el directorio para guardar capturas."""
    capture_dir = os.getenv("CAPTURE_OUTPUT_DIR", "./captures")
    Path(capture_dir).mkdir(parents=True, exist_ok=True)
    return capture_dir

def generate_filename(prefix="capture", extension="pcap"):
    """Genera un nombre de archivo con timestamp para la captura."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}.{extension}"

def get_available_interfaces():
    """Obtiene una lista de interfaces de red disponibles."""
    if platform.system() == "Windows":
        # En Windows, usar tshark para listar interfaces
        try:
            tshark_path = os.getenv("TSHARK_PATH", "tshark")
            print(f"DEBUG: Intentando ejecutar TShark desde: {tshark_path}")
            
            result = subprocess.run(
                [tshark_path, "-D"], 
                capture_output=True, 
                text=True, 
                check=False  # Cambiado a False para no lanzar excepciones
            )
            
            print(f"DEBUG: Resultado comando: {result.stdout}")
            print(f"DEBUG: Error comando: {result.stderr}")
            
            interfaces = []
            for line in result.stdout.splitlines():
                if line.strip():
                    # Formato: 1. \Device\NPF_{GUID} (Descripción)
                    parts = line.split(".", 1)
                    if len(parts) > 1:
                        interface_info = parts[1].strip()
                        # Extraer descripción amigable entre paréntesis si existe
                        if "(" in interface_info and ")" in interface_info:
                            desc_start = interface_info.find("(") + 1
                            desc_end = interface_info.rfind(")")
                            friendly_name = interface_info[desc_start:desc_end]
                            interfaces.append({
                                "id": interface_info.split(" ")[0].strip(),
                                "name": friendly_name
                            })
                        else:
                            interfaces.append({
                                "id": interface_info.strip(),
                                "name": interface_info.strip()
                            })
            return interfaces
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Error al obtener interfaces: {e}")
            return []
    else:
        # En Linux/MacOS, usar ip o ifconfig (mantenemos este código para compatibilidad)
        try:
            if os.path.exists("/sbin/ip"):
                result = subprocess.run(
                    ["/sbin/ip", "link", "show"], 
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                interfaces = []
                for line in result.stdout.splitlines():
                    if ": " in line:
                        iface = line.split(": ")[1]
                        interfaces.append(iface)
                return interfaces
            else:
                result = subprocess.run(
                    ["ifconfig"], 
                    capture_output=True, 
                    text=True, 
                    check=True
                )
                interfaces = []
                for line in result.stdout.splitlines():
                    if line and not line.startswith(" ") and ":" in line:
                        iface = line.split(":")[0]
                        interfaces.append(iface)
                return interfaces
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            logger.error(f"Error al obtener interfaces: {e}")
            return []

def open_in_wireshark(pcap_file):
    """Abre un archivo PCAP directamente en Wireshark GUI."""
    if not os.path.exists(pcap_file):
        logger.error(f"El archivo {pcap_file} no existe")
        return False
        
    try:
        wireshark_path = os.path.join(os.path.dirname(os.getenv("TSHARK_PATH", "tshark")), "Wireshark.exe")
        if platform.system() == "Windows":
            # Verificar si existe Wireshark.exe en la misma carpeta que tshark.exe
            if os.path.exists(wireshark_path):
                subprocess.Popen([wireshark_path, pcap_file])
                logger.info(f"Abriendo {pcap_file} en Wireshark")
                return True
            else:
                # Intentar ejecutar wireshark directamente (podría estar en el PATH)
                subprocess.Popen(["Wireshark", pcap_file])
                logger.info(f"Abriendo {pcap_file} en Wireshark")
                return True
        else:
            # Para otros sistemas
            subprocess.Popen(["wireshark", pcap_file])
            return True
    except Exception as e:
        logger.error(f"Error al abrir Wireshark: {e}")
        return False