import React, { useState } from "react";

interface Props {
  disabled: boolean;
  onStart: (duration: number) => void;
  isCapturing: boolean;
  statusMessage?: string; // Mensaje de estado opcional
}

const CaptureControls: React.FC<Props> = ({ disabled, onStart, isCapturing, statusMessage }) => {
  const [duration, setDuration] = useState(30);
  const [inputError, setInputError] = useState<string | null>(null);

  const handleDurationChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value;
    setDuration(Number(value));
    
    // Validar que el valor sea un número mayor que 0
    if (value === "" || isNaN(Number(value)) || Number(value) <= 0) {
      setInputError("Debe ser un número mayor que 0");
    } else {
      setInputError(null);
    }
  };

  return (
    <div className="flex flex-col gap-2">
      <label className="font-semibold text-sm">Duración (segundos)</label>
      <div>
        <input
          type="text" 
          value={duration}
          onChange={handleDurationChange}
          className="rounded-lg border px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400 w-32"
          disabled={disabled || isCapturing}
          placeholder="Ej: 30"
        />
        {inputError && <div className="text-xs text-red-500 mt-1">{inputError}</div>}      </div>      <div className="flex flex-col gap-2 mt-2">
        <button
          className="bg-blue-500 hover:bg-blue-600 text-white rounded-lg px-4 py-2 disabled:opacity-50"
          onClick={() => onStart(duration)}
          disabled={disabled || isCapturing || inputError !== null || duration <= 0}
        >
          Iniciar captura
        </button>
        {statusMessage && (
          <div className="text-blue-500 text-sm mt-1 font-medium">
            {statusMessage}
          </div>
        )}
      </div>
    </div>
  );
};

export default CaptureControls;
