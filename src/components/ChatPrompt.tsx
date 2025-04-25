import React, { useState, useRef } from "react";

interface ChatMessage {
  question: string;
  answer: string;
}

interface Props {
  selectedDb: string | null; // Prop for the currently selected DB file name
  onDbSelect: (dbFile: string | null) => void; // Callback to update the selected DB in App.tsx
}

// Ensure the component only receives selectedDb and onDbSelect props
const ChatPrompt: React.FC<Props> = ({ selectedDb, onDbSelect }) => {
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [dbSelectionError, setDbSelectionError] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const dbFileInput = useRef<HTMLInputElement>(null);

  const handleDbFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setDbSelectionError(null);
    const file = e.target.files?.[0];

    if (!file) {
      onDbSelect(null);
      // Ensure the input is cleared if the user cancels selection
      if (dbFileInput.current) {
          dbFileInput.current.value = '';
      }
      return;
    }

    if (!file.name.toLowerCase().endsWith('.db')) {
      setDbSelectionError("El archivo seleccionado debe tener la extensión .db");
      onDbSelect(null);
      if (dbFileInput.current) {
        dbFileInput.current.value = '';
      }
      return;
    }
    // Pass the file *name* to the parent
    onDbSelect(file.name);
  };

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    // Use the selectedDb prop passed from App.tsx
    if (!input.trim() || !selectedDb) {
        if (!selectedDb) {
            setError("Por favor, selecciona un archivo de base de datos (.db) primero.");
        }
        return;
    }
    setLoading(true);
    try {
      const res = await fetch("/api/nl_query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: input, db_file: selectedDb }), // Use selectedDb prop
      });
      const data = await res.json();
      if (data.response) {
        setMessages((msgs) => [...msgs, { question: input, answer: data.response }]);
        setInput("");
      } else {
        setError(data.error || "Error en la consulta");
      }
    } catch {
      setError("Error de red o del servidor");
    }
    setLoading(false);
  };

  return (
    <div className="flex flex-col gap-4 h-96">
      {/* Database Selection Section */}
      <div className="flex flex-col gap-1">
        <label className="text-sm font-semibold">Seleccionar base de datos (.db)</label>
        <input
          type="file"
          accept=".db"
          ref={dbFileInput}
          onChange={handleDbFileChange}
          className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100"
        />
        {dbSelectionError && <div className="text-xs text-red-500 mt-1">{dbSelectionError}</div>}
      </div>

      {/* Chat History Section */}
      <div className="flex-1 overflow-y-auto bg-gray-50 rounded-lg p-2 border text-xs">
        {messages.length === 0 && <div className="text-gray-400">No hay consultas aún.</div>}
        {messages.map((msg, i) => (
          <div key={i} className="mb-2">
            <div className="font-semibold text-blue-700">Tú: {msg.question}</div>
            <div className="text-gray-800 whitespace-pre-line">{msg.answer}</div>
          </div>
        ))}
      </div>

      {/* Input Form Section - Ensure disabled logic uses selectedDb prop */}
      <form onSubmit={handleSend} className="flex gap-2 mt-auto">
        <input
          type="text"
          className="flex-1 rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          placeholder={selectedDb ? "Haz una pregunta sobre la base de datos..." : "Selecciona una base de datos primero..."}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={loading || !selectedDb} // Use selectedDb prop
        />
        <button
          type="submit"
          className="bg-blue-500 hover:bg-blue-600 text-white rounded-lg px-4 py-2 disabled:opacity-50"
          disabled={loading || !input.trim() || !selectedDb} // Use selectedDb prop
        >
          {loading ? "Enviando..." : "Enviar"}
        </button>
      </form>
      {error && <div className="text-xs text-red-500">{error}</div>}
    </div>
  );
};

export default ChatPrompt;
