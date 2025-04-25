# tests/test_processor_db.py
import sys
import os
import argparse
import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.data_processing.packet_processor import PacketProcessor
from src.data_processing.storage_manager import StorageManager

def main():
    parser = argparse.ArgumentParser(description='Procesa un archivo PCAP y lo guarda en una base de datos')
    parser.add_argument('pcap_file', help='Ruta al archivo PCAP a procesar')
    parser.add_argument('--db_file', default=None, 
                        help='Ruta a la base de datos SQLite (default: generada automáticamente)')
    parser.add_argument('--description', default=None, 
                        help='Descripción opcional para la sesión de captura')
    
    args = parser.parse_args()
    
    pcap_file = args.pcap_file
    
    # Asegurarse de que la carpeta databases existe
    database_dir = "databases"
    os.makedirs(database_dir, exist_ok=True)
    
    # Generar nombre de base de datos si no se especifica
    if args.db_file is None:
        # Extraer el patrón de fecha/hora del nombre del archivo PCAP 
        pcap_basename = os.path.basename(pcap_file)
        
        # Verificar si el nombre sigue el patrón capture_YYYYMMDD_HHMMSS.pcap
        if pcap_basename.startswith("capture_") and pcap_basename.endswith(".pcap"):
            timestamp_part = pcap_basename[8:-5]  # Extraer YYYYMMDD_HHMMSS
            db_file = os.path.join(database_dir, f"database_{timestamp_part}.db")
        else:
            # Crear un nuevo timestamp
            now = datetime.datetime.now()
            timestamp = now.strftime("%Y%m%d_%H%M%S")
            db_file = os.path.join(database_dir, f"database_{timestamp}.db")
    else:
        db_file = args.db_file
    
    print(f"Verificando que el directorio existe: {os.path.dirname(os.path.abspath(db_file))}")
    
    # Verificar que el archivo PCAP existe
    if not os.path.exists(pcap_file):
        print(f"Error: El archivo PCAP no existe en la ruta: {pcap_file}")
        return
    
    processor = PacketProcessor()
    
    # Process the PCAP file
    print(f"Processing PCAP file: {pcap_file}")
    print(f"Database will be saved as: {db_file}")
    processed_packets = processor.process_pcap_file(pcap_file)
    
    if processed_packets:
        print(f"\nProcessed {len(processed_packets)} packets")
        
        # Inicializar el StorageManager después de procesar
        try:
            # Crear StorageManager
            storage = StorageManager(db_file)

            # Obtener el nombre base del archivo PCAP para la descripción
            pcap_basename = os.path.basename(args.pcap_file) # Definir pcap_basename aquí

            # Iniciar sesión de captura
            description = args.description or f"Procesado de {pcap_basename}"
            capture_id = storage.start_capture_session(
                capture_file=pcap_file,
                description=description
            )
            
            if capture_id:
                print(f"\nCreated capture session with ID: {capture_id}")
                
                # Almacenar paquetes procesados en la base de datos
                stored_count = storage.store_processed_packets(capture_id, processed_packets)
                
                # Finalizar la sesión de captura
                storage.end_capture_session(capture_id, stored_count)
                
                print(f"Stored {stored_count} packets in database: {db_file}")
                
                # Count layer 4 protocols
                l4_protocols = {}
                for packet in processed_packets:
                    proto = packet.get('layer4', {}).get('protocol', 'unknown')
                    l4_protocols[proto] = l4_protocols.get(proto, 0) + 1
                
                print("\nLayer 4 Protocol Distribution:")
                for proto, count in l4_protocols.items():
                    print(f"  {proto.upper()}: {count} packets ({count/len(processed_packets)*100:.1f}%)")
            else:
                print("Failed to create capture session in database")
        except Exception as e:
            print(f"Error initializing database: {e}")
            import traceback
            traceback.print_exc()
    else:
        print("No packets were processed.")

if __name__ == "__main__":
    main()