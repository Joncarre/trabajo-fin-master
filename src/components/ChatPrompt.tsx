import React, { useState } from "react";

interface ChatMessage {
  question: string;
  answer: string;
}

interface Props {
  dbFiles: string[];
  defaultDb?: string;
}

const ChatPrompt: React.FC<Props> = ({ dbFiles, defaultDb }) => {
  const [selectedDb, setSelectedDb] = useState(defaultDb || (dbFiles[0] || ""));
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!input.trim() || !selectedDb) return;
    setLoading(true);
    try {
      const res = await fetch("/api/nl_query", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: input, db_file: selectedDb }),
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
    <div className="flex flex-col gap-2 h-80">      <div className="flex gap-2 items-center">
        <label className="text-sm font-semibold">Seleccionar base de datos existente</label>
        <select
          className="rounded-lg border px-2 py-1 text-sm"
          value={selectedDb}
          onChange={(e) => setSelectedDb(e.target.value)}
        >
          {dbFiles.map((db) => (
            <option key={db} value={db}>{db}</option>
          ))}
        </select>
      </div>
      <div className="flex-1 overflow-y-auto bg-gray-50 rounded-lg p-2 border text-xs">
        {messages.length === 0 && <div className="text-gray-400">No hay consultas aún.</div>}
        {messages.map((msg, i) => (
          <div key={i} className="mb-2">
            <div className="font-semibold text-blue-700">Tú: {msg.question}</div>
            <div className="text-gray-800 whitespace-pre-line">{msg.answer}</div>
          </div>
        ))}
      </div>
      <form onSubmit={handleSend} className="flex gap-2 mt-2">
        <input
          type="text"
          className="flex-1 rounded-lg border px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-400"
          placeholder="Haz una pregunta sobre el tráfico capturado..."
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={loading || !selectedDb}
        />
        <button
          type="submit"
          className="bg-blue-500 hover:bg-blue-600 text-white rounded-lg px-4 py-2 disabled:opacity-50"
          disabled={loading || !input.trim() || !selectedDb}
        >
          {loading ? "Enviando..." : "Enviar"}
        </button>
      </form>
      {error && <div className="text-xs text-red-500">{error}</div>}
    </div>
  );
};

export default ChatPrompt;
