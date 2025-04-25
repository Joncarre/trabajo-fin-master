from fastapi import FastAPI, Request, UploadFile, File, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from src.packet_capture.capture_manager import CaptureManager
# Volvemos a usar la versión original del procesador de paquetes
from src.data_processing.packet_processor import PacketProcessor
from src.data_processing.storage_manager import StorageManager
from src.query_engine import NaturalLanguageQueryEngine
import os
from datetime import datetime
import subprocess
import sys
import asyncio

UPLOAD_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../captures'))
DB_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../databases'))
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DB_DIR, exist_ok=True)

app = FastAPI()

# Permitir CORS para desarrollo local
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

capture_manager = CaptureManager()

class StartCaptureRequest(BaseModel):
    interface: str
    duration: int

class StopCaptureRequest(BaseModel):
    capture_id: str

@app.get("/api/interfaces")
def get_interfaces():
    interfaces = capture_manager.list_interfaces()
    
    # Si no hay interfaces disponibles (error con tshark), devolver algunas interfaces mock
    # para que la aplicación siga funcionando
    if not interfaces:
        # Interfaces de red mock para permitir el uso de la aplicación
        mock_interfaces = [
            {"id": "mock_ethernet", "name": "Ethernet (Mock)"},
            {"id": "mock_wifi", "name": "Wi-Fi (Mock)"}
        ]
        print("INFO: Usando interfaces mock porque no se encontró TShark")
        return {"interfaces": mock_interfaces}
    
    return {"interfaces": interfaces}

@app.get("/api/databases")
def get_databases():
    # Listar todos los archivos .db en el directorio de bases de datos
    db_files = [f for f in os.listdir(DB_DIR) if f.endswith(".db")]
    return {"databases": db_files}

@app.post("/api/capture/start")
def start_capture(req: StartCaptureRequest):
    capture_id = capture_manager.start_capture(interface=req.interface, duration=req.duration)
    return {"capture_id": capture_id}

@app.post("/api/capture/stop")
def stop_capture(req: StopCaptureRequest):
    output_file = capture_manager.stop_capture(req.capture_id)
    return {"output_file": output_file}

@app.post("/api/upload_pcap")
async def upload_pcap(file: UploadFile = File(...)):
    # Guardar el archivo .pcap
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"upload_{timestamp}.pcap"
    file_path = os.path.join(UPLOAD_DIR, filename)
    with open(file_path, "wb") as f:
        f.write(await file.read())
    
    # Generar nombre de base de datos
    db_name = f"database_{timestamp}.db"
    db_path = os.path.join(DB_DIR, db_name)
    
    # Llamar al script de terminal para procesar el PCAP
    script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../tests/data_processing/test_processor_db.py'))
    command = [sys.executable, script_path, file_path, '--db_file', db_path]
    print(f"Ejecutando: {' '.join(command)}")
    
    # Configurar el entorno para el subproceso
    process_env = os.environ.copy()
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
    process_env["PYTHONPATH"] = project_root
    
    # Ejecutar el script en un hilo aparte con el entorno configurado
    proc = await asyncio.get_event_loop().run_in_executor(None, lambda: subprocess.run(command, capture_output=True, text=True, env=process_env))
    print(proc.stdout)
    print(proc.stderr)
    
    # Verificar tamaño de la base de datos después de procesar
    db_size = os.path.getsize(db_path) if os.path.exists(db_path) else 0
    print(f"GENERATED DB SIZE: {db_size} bytes")
    
    return {"db_file": db_name, "db_path": db_path, "db_size": db_size}

@app.post("/api/nl_query")
async def nl_query(
    question: str = Body(...),
    db_file: str = Body(...)
):
    db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../databases', db_file))
    if not os.path.exists(db_path):
        return {"error": "Base de datos no encontrada"}
    # NOTA: Aquí podrías pedir la API key de Claude/OpenAI de forma segura
    engine = NaturalLanguageQueryEngine(db_path)
    response = engine.process_query(question)
    return {"response": response}
