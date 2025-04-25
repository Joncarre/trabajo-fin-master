import { useState, useEffect } from 'react';
import NetworkSelector from './components/NetworkSelector';
import CaptureControls from './components/CaptureControls';
import PcapUploader from './components/PcapUploader';
import ChatPrompt from './components/ChatPrompt';
import './App.css';

function App() {
  const [selectedInterface, setSelectedInterface] = useState<string | null>(null);
  const [isCapturing, setIsCapturing] = useState(false);
  const [notification, setNotification] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dbFiles, setDbFiles] = useState<string[]>([]);

  // Cargar la lista de bases de datos disponibles al iniciar
  useEffect(() => {
    const loadDatabases = async () => {
      try {
        const response = await fetch('/api/databases');
        const data = await response.json();
        if (data.databases && Array.isArray(data.databases)) {
          setDbFiles(data.databases);
        }
      } catch (e) {
        console.error('Error cargando bases de datos:', e);
        // Usar bases de datos por defecto si falla la carga
        setDbFiles(["database_20250415_120812.db", "database_20250418_141938.db"]);
      }
    };

    loadDatabases();
  }, []);

  const handleStartCapture = async (duration: number) => {
    setError(null);
    setNotification(null);
    if (!selectedInterface) {
      setError('Selecciona una interfaz de red.');
      return;
    }
    setIsCapturing(true);
    setNotification('Capturando...'); // Mostramos el mensaje inmediatamente al pulsar el botón
    try {
      const res = await fetch('/api/capture/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ interface: selectedInterface, duration }),
      });
      const data = await res.json();
      if (data.capture_id) {
        // Ya no necesitamos establecer la notificación aquí porque ya se ha mostrado

        setTimeout(() => {
          setIsCapturing(false);
          setNotification(`Captura de ${duration} segundos finalizada.`); // Mensaje al finalizar
        }, duration * 1000);

      } else {
        setError('No se pudo iniciar la captura.');
        setIsCapturing(false);
      }
    } catch (e) {
      console.error('Error starting capture:', e);
      setError('Error al iniciar la captura.');
      setIsCapturing(false);
    }
  };

  // Función para añadir una nueva base de datos a la lista
  const handleNewDatabase = (dbFile: string) => {
    setDbFiles(prev => {
      // Evitar duplicados
      if (!prev.includes(dbFile)) {
        return [...prev, dbFile];
      }
      return prev;
    });
  };

  return (
    <div className="min-h-screen bg-gray-50 bg-opacity-80 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-xl rounded-2xl shadow-lg bg-white bg-opacity-80 p-6 flex flex-col gap-6">
        <NetworkSelector selected={selectedInterface} onSelect={setSelectedInterface} disabled={isCapturing} />
        <CaptureControls
          disabled={!selectedInterface}
          onStart={handleStartCapture}
          isCapturing={isCapturing}
          statusMessage={notification || undefined}
        />
        <PcapUploader onDbReady={handleNewDatabase} />
        <ChatPrompt dbFiles={dbFiles} />
        {/* Notificaciones - Solo para errores y otras notificaciones, pero no para mensajes de captura */}
        <div className="h-10 text-center text-sm">
          {error && <span className="text-red-500">{error}</span>}
        </div>
      </div>
      <footer className="mt-8 text-xs text-gray-400">TFM &copy; 2025</footer>
    </div>
  );
}

export default App;
