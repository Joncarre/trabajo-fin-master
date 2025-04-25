# tests/visualize_analysis.py

import json
import os
import sys
import argparse
import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd

def main():
    # Configurar argumentos de línea de comandos
    parser = argparse.ArgumentParser(description='Visualiza los resultados del análisis de paquetes')
    parser.add_argument('json_file', help='Ruta al archivo JSON de análisis')
    parser.add_argument('--output_dir', default='analysis_visualizations', 
                      help='Directorio para guardar las visualizaciones (default: analysis_visualizations)')
    
    args = parser.parse_args()
    
    # Verificar que el archivo existe
    if not os.path.exists(args.json_file):
        print(f"Error: El archivo {args.json_file} no existe.")
        return
    
    # Crear directorio de salida si no existe
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Cargar los datos JSON
    print(f"Leyendo archivo: {args.json_file}")
    with open(args.json_file, 'r', encoding='utf-8') as f:
        analysis = json.load(f)
    
    # Extraer datos de la primera sesión
    if 'all_sessions' in analysis:
        session_data = list(analysis['all_sessions'].values())[0]
    else:
        # Si no hay estructura all_sessions, usar el análisis directamente
        session_data = analysis
    
    # Verificar que tenemos datos para visualizar
    if not session_data:
        print("No se encontraron datos para visualizar en el archivo JSON.")
        return
    
    print("Generando visualizaciones...")
    
    # 1. Visualizar distribución de protocolos
    if 'visualizations' in session_data and 'protocol_distribution' in session_data['visualizations']:
        protocol_data = session_data['visualizations']['protocol_distribution']
        
        if 'data' in protocol_data and protocol_data['data']:
            visualize_protocol_distribution(protocol_data, args.output_dir)
    
    # 2. Visualizar comunicaciones entre IPs
    if 'visualizations' in session_data and 'ip_communications' in session_data['visualizations']:
        ip_data = session_data['visualizations']['ip_communications']
        
        if 'nodes' in ip_data and 'links' in ip_data:
            visualize_ip_communications(ip_data, args.output_dir)
    
    # 3. Visualizar resumen del tráfico
    if 'summary' in session_data:
        visualize_traffic_summary(session_data['summary'], args.output_dir)
    
    print(f"Visualizaciones guardadas en: {os.path.abspath(args.output_dir)}")

def visualize_protocol_distribution(protocol_data, output_dir):
    """Genera gráfico de distribución de protocolos"""
    # Mapeo de números de protocolo a nombres
    protocol_names = {
        0: "Desconocido",
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    
    # Extraer datos
    protocols = protocol_data['data']
    
    # Preparar etiquetas y valores
    labels = []
    sizes = []
    for p in protocols:
        protocol_num = p['protocol']
        protocol_name = protocol_names.get(protocol_num, f"Protocolo {protocol_num}")
        labels.append(f"{protocol_name} ({p['percentage']:.1f}%)")
        sizes.append(p['count'])
    
    # Crear figura
    plt.figure(figsize=(10, 6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90)
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    plt.title('Distribución de Protocolos')
    
    # Guardar figura
    output_file = os.path.join(output_dir, 'protocol_distribution.png')
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Generado: {output_file}")

def visualize_ip_communications(ip_data, output_dir):
    """Genera gráfico de red de comunicaciones entre IPs"""
    G = nx.DiGraph()
    
    # Añadir nodos con atributos
    for node in ip_data['nodes']:
        G.add_node(node['id'], 
                   packets_sent=node.get('packets_sent', 0),
                   packets_received=node.get('packets_received', 0),
                   total_activity=node.get('total_activity', 0))
    
    # Añadir enlaces con pesos
    for link in ip_data['links']:
        G.add_edge(link['source'], link['target'], weight=link['value'])
    
    # Calcular tamaños de nodos basados en actividad total
    node_sizes = []
    for node_id in G.nodes():
        total_activity = G.nodes[node_id].get('total_activity', 0)
        # Escalar el tamaño para mejor visualización
        node_sizes.append(100 + (total_activity / 1000) * 100)
    
    # Calcular anchos de enlaces basados en el valor
    edge_widths = []
    for u, v, data in G.edges(data=True):
        weight = data.get('weight', 1)
        # Escalar el ancho para mejor visualización
        edge_widths.append(0.5 + (weight / 1000) * 2)
    
    # Crear figura
    plt.figure(figsize=(12, 10))
    
    # Calcular layout (posicionamiento de nodos)
    pos = nx.spring_layout(G, seed=42, k=0.6)
    
    # Dibujar nodos
    nx.draw_networkx_nodes(G, pos, node_size=node_sizes, alpha=0.7)
    
    # Dibujar enlaces
    nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, 
                          edge_color='gray', arrows=True, 
                          connectionstyle='arc3,rad=0.1')
    
    # Dibujar etiquetas
    # Limitar la longitud de las etiquetas IP para mejor visualización
    labels = {}
    for node in G.nodes():
        if ":" in node:  # IPv6
            labels[node] = node.split(":")[0] + ":.."
        else:  # IPv4
            labels[node] = node
    
    nx.draw_networkx_labels(G, pos, labels=labels, font_size=8)
    
    plt.title('Comunicaciones entre IPs')
    plt.axis('off')  # Ocultar ejes
    
    # Guardar figura
    output_file = os.path.join(output_dir, 'ip_communications.png')
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Generado: {output_file}")

def visualize_traffic_summary(summary, output_dir):
    """Genera gráficos de resumen del tráfico"""
    # 1. Crear gráfico de barras para IPs origen más activas
    if 'top_source_ips' in summary and summary['top_source_ips']:
        plt.figure(figsize=(12, 6))
        
        # Extraer datos
        ips = list(summary['top_source_ips'].keys())
        packets = list(summary['top_source_ips'].values())
        
        # Acortar nombres de IPs para mejor visualización
        short_ips = []
        for ip in ips:
            if ":" in ip:  # IPv6
                short_ips.append(ip.split(":")[0] + ":..")
            else:  # IPv4
                short_ips.append(ip)
        
        # Crear gráfico
        bars = plt.bar(short_ips, packets)
        
        # Añadir etiquetas
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.title('IPs Origen Más Activas')
        plt.xlabel('Dirección IP')
        plt.ylabel('Número de Paquetes')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Guardar figura
        output_file = os.path.join(output_dir, 'top_source_ips.png')
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Generado: {output_file}")
    
    # 2. Crear gráfico de barras para IPs destino más activas
    if 'top_destination_ips' in summary and summary['top_destination_ips']:
        plt.figure(figsize=(12, 6))
        
        # Extraer datos
        ips = list(summary['top_destination_ips'].keys())
        packets = list(summary['top_destination_ips'].values())
        
        # Acortar nombres de IPs para mejor visualización
        short_ips = []
        for ip in ips:
            if ":" in ip:  # IPv6
                short_ips.append(ip.split(":")[0] + ":..")
            else:  # IPv4
                short_ips.append(ip)
        
        # Crear gráfico
        bars = plt.bar(short_ips, packets)
        
        # Añadir etiquetas
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                    f'{int(height)}', ha='center', va='bottom')
        
        plt.title('IPs Destino Más Activas')
        plt.xlabel('Dirección IP')
        plt.ylabel('Número de Paquetes')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        # Guardar figura
        output_file = os.path.join(output_dir, 'top_destination_ips.png')
        plt.savefig(output_file, dpi=300, bbox_inches='tight')
        plt.close()
        print(f"Generado: {output_file}")

if __name__ == "__main__":
    main()