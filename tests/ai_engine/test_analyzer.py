# test_analyzer.py
# Este script es un ejemplo de cómo utilizar el analizador de paquetes avanzado para analizar sesiones de red, detectar anomalías, escaneos de puertos y patrones de comunicación.  

import os
import sys
import argparse
import json
from datetime import datetime, timedelta
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.packet_capture.capture_manager import CaptureManager
from src.data_processing.packet_processor import PacketProcessor
from src.data_processing.storage_manager import StorageManager
from src.ai_engine.packet_analyzer import PacketAnalyzer

def parse_arguments():
    parser = argparse.ArgumentParser(description='Prueba del analizador de paquetes avanzado')
    parser.add_argument('--db_path', type=str, default='captures/network_data.db',
                        help='Ruta a la base de datos SQLite')
    parser.add_argument('--session_id', type=str, 
                        help='ID de sesión específica a analizar (opcional)')
    parser.add_argument('--analyze_all', action='store_true',
                        help='Analizar todas las sesiones disponibles')
    parser.add_argument('--detect_anomalies', action='store_true',
                        help='Buscar anomalías en todo el tráfico')
    parser.add_argument('--detect_scans', action='store_true',
                        help='Detectar escaneos de puertos')
    parser.add_argument('--top_talkers', action='store_true',
                        help='Identificar los hosts más activos')
    parser.add_argument('--focus_ip', type=str,
                        help='IP específica para analizar en detalle')
    parser.add_argument('--output', type=str,
                        help='Ruta para guardar los resultados en formato JSON')
    
    return parser.parse_args()

def print_analysis_results(results, title):
    """Imprime los resultados del análisis de forma legible"""
    print(f"\n{'=' * 80}")
    print(f"{title}")
    print(f"{'=' * 80}")
    
    # Convertir a JSON formateado para mejor visualización
    formatted_json = json.dumps(results, indent=2, ensure_ascii=False)
    print(formatted_json)

def main():
    args = parse_arguments()
    
    # Si la ruta es relativa, intentar resolverla respecto a diferentes ubicaciones
    if args.db_path and not os.path.isabs(args.db_path):
        potential_paths = [
            args.db_path,  # Directamente como se proporcionó
            os.path.join(os.getcwd(), args.db_path),  # Relativo al directorio de trabajo actual
            os.path.join(os.path.dirname(__file__), '..', args.db_path),  # Relativo a la raíz del proyecto
            os.path.join(os.path.dirname(__file__), '..', 'databases', os.path.basename(args.db_path))  # En el directorio databases
        ]
        
        for path in potential_paths:
            if os.path.exists(path):
                args.db_path = path
                break
    
    # Verificar que la base de datos existe
    if not os.path.exists(args.db_path):
        print(f"Error: La base de datos {args.db_path} no existe.")
        return
    
    # Generar nombre de archivo de resultados si se especificó una carpeta
    if args.output:
        # Verificar si se especificó un archivo de salida o solo un directorio
        output_is_dir = args.output.endswith('/') or args.output.endswith('\\') or os.path.isdir(args.output)
        
        if output_is_dir:
            # Es un directorio, generamos un nombre basado en la base de datos
            os.makedirs(args.output, exist_ok=True)
            
            # Extraer patrón de fecha/hora del nombre de la base de datos
            db_basename = os.path.basename(args.db_path)
            
            # Verificar si el nombre sigue el patrón database_YYYYMMDD_HHMMSS.db
            if db_basename.startswith("database_") and db_basename.endswith(".db"):
                timestamp_part = db_basename[9:-3]  # Extraer YYYYMMDD_HHMMSS
                
                # Generar nombre para el archivo JSON
                if args.analyze_all:
                    json_file = os.path.join(args.output, f"analysis_{timestamp_part}.json")
                elif args.detect_anomalies:
                    json_file = os.path.join(args.output, f"anomalies_{timestamp_part}.json")
                elif args.detect_scans:
                    json_file = os.path.join(args.output, f"scans_{timestamp_part}.json")
                elif args.top_talkers:
                    json_file = os.path.join(args.output, f"talkers_{timestamp_part}.json")
                elif args.focus_ip:
                    ip_part = args.focus_ip.replace('.', '_')
                    json_file = os.path.join(args.output, f"ip_{ip_part}_{timestamp_part}.json")
                elif args.session_id:
                    json_file = os.path.join(args.output, f"session_{args.session_id}_{timestamp_part}.json")
                else:
                    # Si ninguna opción específica, usar un nombre genérico
                    json_file = os.path.join(args.output, f"results_{timestamp_part}.json")
            else:
                # Si no sigue el patrón, usar timestamp actual
                now = datetime.datetime.now()
                timestamp = now.strftime("%Y%m%d_%H%M%S")
                json_file = os.path.join(args.output, f"analysis_{timestamp}.json")
            
            # Actualizar args.output con el nombre de archivo generado
            args.output = json_file
    
    # Inicializar el analizador
    analyzer = PacketAnalyzer(args.db_path)
    print(f"Analizador inicializado con base de datos: {args.db_path}")
    
    # Variable para almacenar todos los resultados
    all_results = {}
    
    # Analizar una sesión específica
    if args.session_id:
        print(f"Analizando sesión: {args.session_id}")
        results = analyzer.analyze_session(args.session_id)
        print_analysis_results(results, f"Análisis de sesión: {args.session_id}")
        all_results["session_analysis"] = results
    
    # Analizar todas las sesiones
    if args.analyze_all:
        storage = StorageManager(args.db_path)
        sessions = storage.get_all_sessions()
        
        all_sessions_results = {}
        
        for session in sessions:
            session_id = session["id"]
            print(f"Analizando sesión: {session_id}")
            results = analyzer.analyze_session(session_id)
            all_sessions_results[session_id] = results
        
        print(f"Análisis completado para {len(sessions)} sesiones.")
        all_results["all_sessions"] = all_sessions_results
    
    # Buscar anomalías
    if args.detect_anomalies:
        # Establecer ventana de tiempo (últimas 24 horas por defecto)
        end_time = datetime.now()
        start_time = end_time - timedelta(days=1)
        
        print(f"Buscando anomalías desde {start_time} hasta {end_time}")
        anomalies = analyzer.search_anomalies(start_time=start_time.timestamp(), end_time=end_time.timestamp())
        
        print(f"Se encontraron {len(anomalies)} anomalías.")
        print_analysis_results(anomalies, "Anomalías Detectadas")
        all_results["anomalies"] = anomalies
    
    # Detectar escaneos de puertos
    if args.detect_scans:
        # Establecer ventana de tiempo (últimas 24 horas por defecto)
        end_time = datetime.now()
        start_time = end_time - timedelta(days=1)
        
        print(f"Detectando escaneos de puertos desde {start_time} hasta {end_time}")
        scans = analyzer.detect_port_scans(timeframe=(start_time.timestamp(), end_time.timestamp()))
        
        print(f"Se detectaron {len(scans)} posibles escaneos de puertos.")
        print_analysis_results(scans, "Escaneos de Puertos Detectados")
        all_results["port_scans"] = scans
    
    # Identificar los hosts más activos
    if args.top_talkers:
        print("Identificando hosts más activos...")
        top_talkers = analyzer.get_top_talkers(n=10)
        
        print_analysis_results(top_talkers, "Hosts Más Activos")
        all_results["top_talkers"] = top_talkers
    
    # Analizar una IP específica
    if args.focus_ip:
        print(f"Analizando patrones de comunicación para IP: {args.focus_ip}")
        ip_patterns = analyzer.analyze_communication_patterns(ip_address=args.focus_ip)
        
        print_analysis_results(ip_patterns, f"Análisis de IP: {args.focus_ip}")
        all_results["ip_analysis"] = ip_patterns
    
    # Guardar resultados si se especifica una ruta de salida
    if args.output:
        # Asegurarse de que el directorio existe
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(all_results, f, ensure_ascii=False, indent=2)
        print(f"Resultados guardados en: {args.output}")

if __name__ == "__main__":
    main()