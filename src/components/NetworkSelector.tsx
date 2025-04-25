import React, { useEffect, useState } from "react";

export interface NetworkInterface {
  id: string;
  name: string;
}

interface Props {
  selected: string | null;
  onSelect: (id: string) => void;
  disabled: boolean; // Add disabled prop
}

const NetworkSelector: React.FC<Props> = ({ selected, onSelect, disabled }) => { // Receive disabled prop
  const [interfaces, setInterfaces] = useState<NetworkInterface[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    fetch("/api/interfaces")
      .then((res) => res.json())
      .then((data) => {
        setInterfaces(data.interfaces || []);
        setLoading(false);
      })
      .catch(() => {
        setError("No se pudieron cargar las interfaces de red");
        setLoading(false);
      });
  }, []);

  return (
    <div className="flex flex-col gap-2">
      <label className="font-semibold text-sm">Interfaz de red</label>
      {loading ? (
        <div className="text-xs text-gray-400">Cargando...</div>
      ) : error ? (
        <div className="text-xs text-red-500">{error}</div>
      ) : (
        <select
          className="rounded-lg border px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 disabled:opacity-50 disabled:bg-gray-100" // Add disabled styles
          value={selected || ""}
          onChange={(e) => onSelect(e.target.value)}
          disabled={disabled} // Use the disabled prop here
        >
          <option value="" disabled>
            Selecciona una interfaz
          </option>
          {interfaces.map((iface) => (
            <option key={iface.id} value={iface.id}>
              {iface.name}
            </option>
          ))}
        </select>
      )}
    </div>
  );
};

export default NetworkSelector;
