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
        # En Windows, buscar TShark en ubicaciones comunes
        tshark_path = os.getenv("TSHARK_PATH")
        
        # Si no está definido en variables de entorno, buscar en ubicaciones comunes
        if not tshark_path:
            common_paths = [
                "C:\\Program Files\\Wireshark\\tshark.exe",
                "C:\\Program Files (x86)\\Wireshark\\tshark.exe",
                # Añadimos más ubicaciones potenciales
                os.path.expandvars("%ProgramFiles%\\Wireshark\\tshark.exe"),
                os.path.expandvars("%ProgramFiles(x86)%\\Wireshark\\tshark.exe"),
                # Si el usuario tiene Wireshark portable
                os.path.join(os.getcwd(), "Wireshark", "tshark.exe")
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    tshark_path = path
                    logger.info(f"TShark encontrado en: {tshark_path}")
                    break
        
        if not tshark_path:
            # Si no se encontró, usar el comando básico como último recurso
            tshark_path = "tshark"
            logger.warning("No se encontró TShark en ubicaciones comunes. Asegúrate de que Wireshark esté instalado.")
        
        # Intentar ejecutar TShark para listar interfaces
        try:
            logger.info(f"Ejecutando TShark desde: {tshark_path}")
            
            result = subprocess.run(
                [tshark_path, "-D"], 
                capture_output=True, 
                text=True, 
                check=False
            )
            
            if result.returncode != 0:
                logger.error(f"TShark devolvió un código de error: {result.returncode}")
                logger.error(f"Error de TShark: {result.stderr}")
                return []
                
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
                            device_id = interface_info.split(" ")[0].strip()
                            interfaces.append({
                                "id": device_id,
                                "name": friendly_name
                            })
                        else:
                            interfaces.append({
                                "id": interface_info.strip(),
                                "name": interface_info.strip()
                            })
            
            if not interfaces:
                logger.warning("No se encontraron interfaces de red")
                
            return interfaces
            
        except FileNotFoundError:
            logger.error(f"No se encontró el ejecutable de TShark en: {tshark_path}")
            logger.error("Para solucionar este problema, instala Wireshark o establece la variable TSHARK_PATH correctamente.")
            return []
        except PermissionError:
            logger.error(f"Error de permisos al ejecutar TShark. Intenta ejecutar como administrador.")
            return []
        except Exception as e:
            logger.error(f"Error inesperado al obtener interfaces: {str(e)}")
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
        if platform.system() == "Windows":
            # Primero intentar usar la ruta basada en TSHARK_PATH
            tshark_path = os.getenv("TSHARK_PATH")
            wireshark_path = None
            
            if tshark_path and os.path.exists(tshark_path):
                # Si tenemos la ruta de tshark, buscar Wireshark en el mismo directorio
                wireshark_path = os.path.join(os.path.dirname(tshark_path), "Wireshark.exe")
            
            # Si no encontramos Wireshark basado en tshark, buscar en ubicaciones comunes
            if not wireshark_path or not os.path.exists(wireshark_path):
                common_paths = [
                    "C:\\Program Files\\Wireshark\\Wireshark.exe",
                    "C:\\Program Files (x86)\\Wireshark\\Wireshark.exe",
                    os.path.expandvars("%ProgramFiles%\\Wireshark\\Wireshark.exe"),
                    os.path.expandvars("%ProgramFiles(x86)%\\Wireshark\\Wireshark.exe"),
                    os.path.join(os.getcwd(), "Wireshark", "Wireshark.exe")
                ]
                
                for path in common_paths:
                    if os.path.exists(path):
                        wireshark_path = path
                        logger.info(f"Wireshark encontrado en: {wireshark_path}")
                        break
            
            if wireshark_path and os.path.exists(wireshark_path):
                subprocess.Popen([wireshark_path, pcap_file])
                logger.info(f"Abriendo {pcap_file} en Wireshark")
                return True
            else:
                # Último recurso: intentar ejecutar wireshark directamente
                logger.warning("No se encontró Wireshark.exe en ubicaciones comunes. Intentando 'wireshark' en PATH.")
                subprocess.Popen(["Wireshark", pcap_file])
                return True
        else:
            # Para Linux/macOS
            subprocess.Popen(["wireshark", pcap_file])
            return True
    except Exception as e:
        logger.error(f"Error al abrir Wireshark: {e}")
        return False