import type { ReactNode } from "react";

export interface PickOption {
  id: string;
  label?: ReactNode;
  count?: number;
}

/** Выбор нескольких значений чипами. Выбранные значения, которых больше нет среди вариантов
 * (группу удалили в «Сканере»), остаются видны — их можно снять. */
export function ChipPicker({
  label,
  options,
  value,
  onChange,
  hint,
  empty = "Вариантов нет",
}: {
  label: string;
  options: PickOption[];
  value: string[];
  onChange: (v: string[]) => void;
  hint?: ReactNode;
  empty?: ReactNode;
}) {
  const known = new Set(options.map((o) => o.id));
  const all: PickOption[] = [...options, ...value.filter((v) => !known.has(v)).map((id) => ({ id, label: `${id} (нет)` }))];
  const toggle = (id: string) => onChange(value.includes(id) ? value.filter((x) => x !== id) : [...value, id]);
  const labelId = `pick-${label.replace(/\s+/g, "-")}`;
  return (
    <div className="field">
      <span id={labelId}>{label}</span>
      {all.length ? (
        <div className="picker" role="group" aria-labelledby={labelId}>
          {all.map((o) => (
            <button key={o.id} type="button" className="chip" aria-pressed={value.includes(o.id)} onClick={() => toggle(o.id)}>
              {o.label ?? o.id}
              {o.count !== undefined && <span className="picker-count">{o.count}</span>}
            </button>
          ))}
        </div>
      ) : (
        <span className="faint" style={{ fontSize: 13 }}>
          {empty}
        </span>
      )}
      {hint && <small>{hint}</small>}
    </div>
  );
}
