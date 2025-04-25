import React, { useRef, useState } from "react";

interface Props {
  onDbReady: (dbFile: string) => void;
}

const PcapUploader: React.FC<Props> = ({ onDbReady }) => {
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const handleUpload = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    const files = fileInput.current?.files;
    if (!files || files.length === 0) {
      setError("Selecciona un archivo .pcap");
      return;
    }

    // Add file extension validation
    const selectedFile = files[0];
    if (!selectedFile.name.toLowerCase().endsWith('.pcap')) {
      setError("El archivo seleccionado debe tener la extensión .pcap");
      // Reset the file input if the extension is wrong
      if (fileInput.current) {
        fileInput.current.value = '';
      }
      return;
    }

    const formData = new FormData();
    formData.append("file", selectedFile); // Use selectedFile here
    setUploading(true);
    try {
      const res = await fetch("/api/upload_pcap", {
        method: "POST",
        body: formData,
      });
      const data = await res.json();
      if (data.db_file) {
        setSuccess("Base de datos generada: " + data.db_file);
        onDbReady(data.db_file);
        // Reset the file input after successful processing
        if (fileInput.current) {
          fileInput.current.value = '';
        }
      } else {
        setError("No se pudo procesar el archivo");
      }
    } catch {
      setError("Error al subir el archivo");
    }
    setUploading(false);
  };
  return (
    <form onSubmit={handleUpload} className="flex flex-col gap-2 items-start">
      <label className="font-semibold text-sm">Generar base de datos desde archivo pcap</label>
      <input
        type="file"
        accept=".pcap"
        ref={fileInput}
        className="block text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
        disabled={uploading}
      />
      <button
        type="submit"
        className="bg-blue-500 hover:bg-blue-600 text-white rounded-lg px-4 py-2 disabled:opacity-50 mt-2"
        disabled={uploading}
      >
        {uploading ? "Procesando..." : "Subir y procesar"}
      </button>
      {uploading && (
        <div className="text-xs text-blue-600">Generando base de datos... Esto podría tardar unos minutos</div>
      )}
      {error && <div className="text-xs text-red-500">{error}</div>}
      {success && <div className="text-xs text-green-600">{success}</div>}
    </form>
  );
};

export default PcapUploader;
