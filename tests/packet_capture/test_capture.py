#!/usr/bin/env python3
"""
Script para probar las funcionalidades básicas de captura de paquetes.
"""

import os
import time
import argparse
import sys
import platform

# Añadir directorio raíz al path para importar módulos
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.packet_capture.capture_manager import CaptureManager, CaptureMethod
from src.packet_capture.utils import logger

def main():
    """Función principal del script de prueba."""
    # Configurar parser de argumentos
    parser = argparse.ArgumentParser(description="Herramienta de prueba para captura de paquetes")
    
    parser.add_argument("--list-interfaces", action="store_true", 
                        help="Listar interfaces de red disponibles")
    
    parser.add_argument("--capture", action="store_true",
                        help="Iniciar una captura de paquetes")
    
    parser.add_argument("--interface", type=str,
                        help="Interfaz de red a utilizar")
    
    parser.add_argument("--output", type=str,
                        help="Archivo de salida para la captura")
    
    parser.add_argument("--count", type=int,
                        help="Número de paquetes a capturar")
    
    parser.add_argument("--duration", type=int,
                        help="Duración de la captura en segundos")
    
    parser.add_argument("--filter", type=str,
                        help="Filtro BPF (ej: 'port 80' o 'host 192.168.1.1')")
    
    parser.add_argument("--list-captures", action="store_true",
                        help="Listar archivos de captura disponibles")
    
    parser.add_argument("--open", type=str,
                        help="Abrir archivo de captura en Wireshark")
    
    parser.add_argument("--select-interface", action="store_true",
                        help="Seleccionar interfaz interactivamente")
    
    args = parser.parse_args()
    
    # Crear administrador de captura
    capture_manager = CaptureManager(method=CaptureMethod.TSHARK)
    
    # Selección interactiva de interfaz
    if args.select_interface:
        interfaces = capture_manager.list_interfaces()
        print("Interfaces disponibles:")
        for i, interface in enumerate(interfaces, 1):
            if isinstance(interface, dict):
                print(f"  {i}. {interface['name']} (ID: {interface['id']})")
            else:
                print(f"  {i}. {interface}")
        
        try:
            selection = int(input("\nSeleccione el número de interfaz: "))
            if 1 <= selection <= len(interfaces):
                selected = interfaces[selection-1]
                if isinstance(selected, dict):
                    interface_id = selected['id']
                else:
                    interface_id = selected
                    
                print(f"\nInterfaz seleccionada: {interface_id}")
                print("Puede copiar este ID para usarlo con --interface")
            else:
                print("Selección fuera de rango")
        except ValueError:
            print("Por favor ingrese un número válido")
        return
    
    # Listar interfaces
    if args.list_interfaces:
        interfaces = capture_manager.list_interfaces()
        print("Interfaces disponibles:")
        for i, interface in enumerate(interfaces, 1):
            if isinstance(interface, dict):
                print(f"  {i}. {interface['name']} (ID: {interface['id']})")
            else:
                print(f"  {i}. {interface}")
        
        # Mensaje especial para Windows
        if platform.system() == "Windows":
            print("\nNota: En Windows, use el ID completo para la captura.")
            print("Para seleccionar una interfaz interactivamente, use --select-interface")
        return
    
    # Listar capturas
    if args.list_captures:
        capture_files = capture_manager.list_capture_files()
        print("Archivos de captura disponibles:")
        for i, file in enumerate(capture_files, 1):
            print(f"  {i}. {file}")
        return
    
    # Abrir captura en Wireshark
    if args.open:
        print(f"Abriendo archivo {args.open} en Wireshark...")
        success = capture_manager.open_in_wireshark(args.open)
        if success:
            print("Wireshark iniciado correctamente")
        else:
            print("Error al abrir Wireshark")
        return
    
    # Iniciar captura
    if args.capture:
        if not args.interface:
            print("Error: Debe especificar una interfaz con --interface")
            print("Use --list-interfaces para ver las interfaces disponibles")
            print("O use --select-interface para elegir interactivamente")
            return
        
        print(f"Iniciando captura en interfaz {args.interface}...")
        capture_id = capture_manager.start_capture(
            interface=args.interface,
            output_file=args.output,
            packet_count=args.count,
            capture_filter=args.filter,
            duration=args.duration
        )
        
        if not capture_id:
            print("Error al iniciar la captura")
            return
        
        print(f"Captura iniciada con ID: {capture_id}")
        
        # Si hay duración o cuenta, esperar a que termine
        if args.duration:
            print(f"Capturando durante {args.duration} segundos...")
            time.sleep(args.duration + 2)  # Añadir 2 segundos para asegurar finalización
            output_file = capture_manager.stop_capture(capture_id)
            if output_file:
                print(f"Captura finalizada. Archivo guardado en: {output_file}")
            else:
                print("La captura terminó automáticamente")
        elif args.count:
            print(f"Capturando {args.count} paquetes...")
            time.sleep(10)  # Esperar tiempo razonable para capturar los paquetes
            output_file = capture_manager.stop_capture(capture_id)
            if output_file:
                print(f"Captura finalizada. Archivo guardado en: {output_file}")
            else:
                print("La captura terminó automáticamente")
        else:
            # Captura continua, esperar entrada del usuario
            try:
                input("Presione Enter para detener la captura...")
            except KeyboardInterrupt:
                print("\nDetención solicitada...")
        
            # Detener la captura
            output_file = capture_manager.stop_capture(capture_id)
            if output_file:
                print(f"Captura finalizada. Archivo guardado en: {output_file}")
            else:
                print("Error al detener la captura")
    
    # Si no se especificó ninguna acción, mostrar ayuda
    if not (args.list_interfaces or args.capture or args.list_captures or args.open or args.select_interface):
        parser.print_help()

if __name__ == "__main__":
    main()