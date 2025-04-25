# Análisis de Tráfico de Red con Consultas en Lenguaje Natural

**Trabajo Fin de Máster - 2025**

Una herramienta avanzada para la captura, análisis y consulta de tráfico de red mediante lenguaje natural, con capacidades de detección de patrones y anomalías.

![versión](https://img.shields.io/badge/versión-1.0-blue)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.103-green)
![React](https://img.shields.io/badge/React-18-61DAFB)

## 📋 Índice

- [Descripción General](#-descripción-general)
- [Características](#-características)
- [Arquitectura](#-arquitectura)
- [Requisitos Previos](#-requisitos-previos)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Comandos Útiles](#-comandos-útiles)
- [Capturas de Pantalla](#-capturas-de-pantalla)
- [Estructura del Proyecto](#-estructura-del-proyecto)
- [Licencia](#-licencia)

## 🔍 Descripción General

Esta herramienta permite el análisis avanzado de tráfico de red mediante una interfaz web intuitiva. Combina la potencia de la captura de paquetes, el almacenamiento eficiente en bases de datos SQLite y algoritmos de análisis avanzados para detectar patrones y anomalías en el tráfico de red. Lo más destacable es su capacidad para procesar consultas en lenguaje natural, permitiendo a usuarios no técnicos obtener información valiosa de los datos capturados.

## ✨ Características

- **Captura de Paquetes**: Utiliza TShark (CLI de Wireshark) para capturar tráfico de red.
- **Procesamiento y Almacenamiento**: Extrae información relevante y la almacena en bases de datos SQLite optimizadas.
- **Análisis Inteligente**:
  - Detección de patrones temporales (horas pico, periodicidad)
  - Análisis de comunicaciones entre hosts
  - Detección de anomalías de red
  - Evaluación de riesgos potenciales
- **Consultas en Lenguaje Natural**:
  - "¿Cuáles son las IPs más activas?"
  - "¿Ha habido intentos de escaneo de puertos?"
  - "Muestra la distribución de tráfico por protocolo"
- **Visualización**: Generación de gráficos para análisis visual de datos.
- **Interfaz Web**: Moderna interfaz basada en React con Tailwind CSS.

## 🏛 Arquitectura

El sistema se compone de cuatro módulos principales:

1. **Captura de Paquetes** (`packet_capture/`): Maneja la interfaz con TShark para la captura.
2. **Procesamiento de Datos** (`data_processing/`): Procesa los paquetes y gestiona el almacenamiento.
3. **Motor de Análisis** (`ai_engine/`): Realiza análisis avanzados, detecta patrones y anomalías.
4. **Motor de Consultas** (`query_engine/`): Interpreta y ejecuta consultas en lenguaje natural.

La arquitectura sigue un diseño modular donde cada componente puede evolucionar independientemente.

## 📋 Requisitos Previos

- **Python 3.9+**
- **Node.js 16+**
- **Wireshark/TShark**: Necesario para la captura de paquetes. [Descargar aquí](https://www.wireshark.org/download.html)
- **SQLite3**: Para la gestión de las bases de datos

## 🚀 Instalación

### Backend (Python)

```bash
# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
# En Windows
.\venv\Scripts\Activate.ps1
# En Linux/macOS
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt
```

### Frontend (React)

```bash
# Instalar dependencias
npm install

# Ejecutar en modo desarrollo
npm run dev
```

### Configuración

Crea un archivo `.env` en la raíz del proyecto (puedes usar `.env.example` como plantilla):

```
# Ruta a TShark (necesario para captura de paquetes)
TSHARK_PATH=C:\Program Files\Wireshark\tshark.exe

# Directorio para guardar capturas
CAPTURE_OUTPUT_DIR=./captures
```

## 💻 Uso

### Iniciar el Servidor Backend

```bash
# Activar entorno virtual si no está activo
.\venv\Scripts\Activate.ps1

# Iniciar servidor FastAPI
uvicorn src.web_interface.api:app --reload
```

### Iniciar el Frontend

```bash
npm run dev
```

Accede a la aplicación en `http://localhost:5173` (o el puerto indicado por Vite).

## 🛠 Comandos Útiles

### Procesamiento de Archivos PCAP

```bash
# Procesar un archivo PCAP y guardar en una base de datos
python tests/data_processing/test_processor_db.py captures/mi_captura.pcap

# Especificar archivo de salida para la base de datos
python tests/data_processing/test_processor_db.py captures/mi_captura.pcap --db_file databases/mi_base.db

# Añadir una descripción
python tests/data_processing/test_processor_db.py captures/mi_captura.pcap --description "Captura de red corporativa"
```

### Análisis de Tráfico

```bash
# Visualizar análisis de una base de datos
python tests/ai_engine/visualize_analysis.py databases/mi_base.db

# Pruebas de análisis completo
python tests/ai_engine/test_analyzer.py databases/mi_base.db
```

### Pruebas de Consultas

```bash
# Probar consultas en lenguaje natural
python tests/query_engine/query_test.py "¿Cuáles son los hosts más activos?" databases/mi_base.db

# Ejecutar pruebas por lotes
python tests/query_engine/batch_query_test.py databases/mi_base.db
```

### Evaluación del Sistema de Consultas

```bash
# Benchmark del motor de consultas
python tests/query_engine/benchmark_query_engine.py databases/mi_base.db
```

## 📊 Capturas de Pantalla

Las visualizaciones generadas se guardan en el directorio `analysis_visualizations/`, incluyendo:

- Gráficos de comunicación entre IPs
- Distribución de protocolos
- Top IPs origen/destino
- Análisis de anomalías

## 📁 Estructura del Proyecto

```
├── src/                    # Código fuente principal
│   ├── packet_capture/     # Captura de paquetes
│   ├── data_processing/    # Procesamiento y almacenamiento
│   ├── ai_engine/          # Análisis, patrones y anomalías
│   ├── query_engine/       # Consultas en lenguaje natural
│   ├── components/         # Componentes React de la interfaz
│   └── web_interface/      # API FastAPI
├── tests/                  # Scripts de prueba
├── analysis_results/       # Resultados de análisis (JSON)
├── analysis_visualizations/# Gráficos generados
├── captures/               # Archivos de captura
├── databases/              # Bases de datos SQLite
└── query_logs/             # Logs de consultas
```

## 📄 Licencia

© 2025 - Todos los derechos reservados - Trabajo Fin de Máster
