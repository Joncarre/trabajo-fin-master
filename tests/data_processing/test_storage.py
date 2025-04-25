# Este script es una prueba para la clase StorageManager, que maneja la base de datos SQLite
# y la interacción con los paquetes procesados. Se utiliza para verificar que la clase funcione correctamente

import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.data_processing.packet_processor import PacketProcessor
from src.data_processing.storage_manager import StorageManager

def main():
    if len(sys.argv) < 2:
        print("Uso: python test_storage.py <ruta_archivo_pcap>")
        return
    
    pcap_file = sys.argv[1]
    
    # Procesar el archivo PCAP
    print(f"Procesando archivo PCAP: {pcap_file}")
    processor = PacketProcessor()
    processed_packets = processor.process_pcap_file(pcap_file)
    
    if not processed_packets:
        print("No se encontraron paquetes para procesar.")
        return
    
    print(f"Se procesaron {len(processed_packets)} paquetes")
    
    # Crear base de datos de prueba
    db_file = "network_data.db"
    # Si la base de datos ya existe, la eliminamos para empezar desde cero
    if os.path.exists(db_file):
        os.remove(db_file)
        print(f"Base de datos anterior eliminada: {db_file}")
    
    storage = StorageManager(db_file)
    
    # Iniciar una sesión de captura
    description = f"Captura de prueba: {os.path.basename(pcap_file)}"
    capture_id = storage.start_capture_session(pcap_file, description)
    
    # Almacenar los paquetes procesados
    stored_count = storage.store_processed_packets(capture_id, processed_packets)
    print(f"Se almacenaron {stored_count} paquetes en la base de datos")
    
    # Finalizar la sesión de captura
    storage.end_capture_session(capture_id, stored_count)
    
    # Realizar algunas consultas para demostrar las capacidades
    print("\n--- Estadísticas de Protocolos ---")
    protocol_stats = storage.get_protocol_statistics()
    for protocol, count in protocol_stats.items():
        print(f"  {protocol.upper()}: {count} paquetes")
    
    print("\n--- IPs Más Activas ---")
    top_talkers = storage.get_top_talkers(limit=5)
    print("Origen:")
    for ip, count in top_talkers['source']:
        print(f"  {ip}: {count} paquetes enviados")
    
    print("Destino:")
    for ip, count in top_talkers['destination']:
        print(f"  {ip}: {count} paquetes recibidos")
    
    # Obtener estadísticas de puertos para TCP
    if 'tcp' in protocol_stats and protocol_stats['tcp'] > 0:
        print("\n--- Puertos TCP Más Comunes ---")
        top_tcp_ports = storage.get_top_ports(protocol='tcp', limit=5)
        for port, count in top_tcp_ports:
            print(f"  Puerto {port}: {count} conexiones")
    
    # Obtener estadísticas de anomalías
    anomaly_stats = storage.get_anomaly_statistics()
    if anomaly_stats:
        print("\n--- Anomalías Detectadas ---")
        for anomaly, count in anomaly_stats.items():
            print(f"  {anomaly}: {count} ocurrencias")
    else:
        print("\nNo se detectaron anomalías")
    
    # Realizar una consulta de paquetes con filtrado
    print("\n--- Muestra de Paquetes Consultados ---")
    packets = storage.query_packets(limit=3)
    for packet in packets:
        print(f"  Paquete {packet['id']}: {packet['src_ip']} -> {packet['dst_ip']}")
    
    print(f"\nPrueba completada exitosamente. Base de datos almacenada en: {db_file}")

if __name__ == "__main__":
    main()