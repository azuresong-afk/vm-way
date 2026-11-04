import { useState } from "react";
import type { SevCounts, Severity } from "../../api/types";
import { fmtDay, fmtDayShort, fmtNumber } from "../../lib/format";
import { SEVERITIES, SEVERITY_LABEL } from "../../lib/labels";
import { niceMax } from "./scale";

export interface Week {
  start: string;
  opened: SevCounts;
  closed: SevCounts;
}

const W = 760;
const H = 300;
const PAD = { l: 40, r: 12, t: 14, b: 28 };
const SEV_VAR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

const sum = (c: SevCounts) => SEVERITIES.reduce((a, s) => a + c[s], 0);

/**
 * «Появилось / закрыто» по неделям: столбцы вверх от оси — новые уязвимости, вниз — закрытые
 * (подтверждённые сканером). Внутри столбца уровни складываются от оси наружу, начиная с критических.
 */
export function WeekChart({ weeks }: { weeks: Week[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const upRaw = Math.max(0, ...weeks.map((w) => sum(w.opened)));
  const downRaw = Math.max(0, ...weeks.map((w) => sum(w.closed)));
  // Одна шкала для обоих направлений: единица — одной длины вверх и вниз.
  const unit = niceMax(Math.max(1, upRaw, downRaw));
  const upMax = upRaw ? niceMax(upRaw) : unit / 5;
  const downMax = downRaw ? niceMax(downRaw) : unit / 5;
  const ih = H - PAD.t - PAD.b;
  const scale = ih / (upMax + downMax);
  const zero = PAD.t + upMax * scale;
  const iw = W - PAD.l - PAD.r;
  const band = iw / Math.max(1, weeks.length);
  const bw = Math.min(28, band * 0.62);
  const x = (i: number) => PAD.l + band * i + band / 2;
  const labelEvery = Math.max(1, Math.ceil(weeks.length / 13));
  // Подписи шкалы — только там, где им хватает места (не ближе 18 px друг к другу).
  const upTicks = [0, 0.5, 1].map((k) => upMax * k).filter((t, i) => i === 0 || t * scale >= 18);
  const downTicks = [0.5, 1].map((k) => downMax * k).filter((t) => t * scale >= 18);
  const totalOpened = weeks.reduce((a, w) => a + sum(w.opened), 0);
  const totalClosed = weeks.reduce((a, w) => a + sum(w.closed), 0);

  const stack = (c: SevCounts, i: number, dir: 1 | -1) => {
    let acc = 0;
    return SEVERITIES.filter((s) => c[s] > 0).map((s) => {
      const h = c[s] * scale;
      const y = dir === 1 ? zero - acc - h : zero + acc;
      acc += h;
      return (
        <rect
          key={s}
          x={x(i) - bw / 2}
          y={y}
          width={bw}
          height={Math.max(h - 1, 1)}
          fill={SEV_VAR[s]}
          opacity={dir === -1 ? 0.55 : 1}
          rx={0}
        />
      );
    });
  };

  const hw = hover !== null ? weeks[hover] : null;
  return (
    <div className="chart" onMouseLeave={() => setHover(null)}>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label={`По неделям: появилось ${totalOpened}, закрыто ${totalClosed}. Подробности — в варианте «Таблица».`}
      >
        {upTicks.map((t) => (
          <g key={`u${t}`}>
            <line x1={PAD.l} x2={W - PAD.r} y1={zero - t * scale} y2={zero - t * scale} stroke="var(--grid)" />
            <text x={PAD.l - 8} y={zero - t * scale + 4} textAnchor="end" fontSize={11} fill="var(--text-3)">
              {fmtNumber(t)}
            </text>
          </g>
        ))}
        {downTicks.map((t) => (
          <g key={`d${t}`}>
            <line x1={PAD.l} x2={W - PAD.r} y1={zero + t * scale} y2={zero + t * scale} stroke="var(--grid)" />
            <text x={PAD.l - 8} y={zero + t * scale + 4} textAnchor="end" fontSize={11} fill="var(--text-3)">
              −{fmtNumber(t)}
            </text>
          </g>
        ))}
        {hover !== null && (
          <rect x={x(hover) - band / 2} y={PAD.t} width={band} height={ih} fill="var(--surface-2)" />
        )}
        {weeks.map((w, i) => (
          <g key={w.start}>
            {stack(w.opened, i, 1)}
            {stack(w.closed, i, -1)}
          </g>
        ))}
        <line x1={PAD.l} x2={W - PAD.r} y1={zero} y2={zero} stroke="var(--axis)" />
        {weeks.map((w, i) =>
          i % labelEvery === 0 || i === weeks.length - 1 ? (
            <text key={w.start} x={x(i)} y={H - 8} textAnchor="middle" fontSize={11} fill="var(--text-3)">
              {fmtDayShort(w.start)}
            </text>
          ) : null,
        )}
        {weeks.map((w, i) => (
          <rect
            key={`h${w.start}`}
            x={x(i) - band / 2}
            y={PAD.t}
            width={band}
            height={ih}
            fill="transparent"
            onMouseEnter={() => setHover(i)}
          />
        ))}
      </svg>
      {hw && hover !== null && (
        <div
          className="tooltip"
          style={{
            left: `${Math.min(85, Math.max(15, (x(hover) / W) * 100))}%`,
            top: `${((zero - sum(hw.opened) * scale) / H) * 100}%`,
          }}
        >
          <b>Неделя с {fmtDay(hw.start)}</b>
          <div>
            <span>Появилось</span>
            <span className="num">{fmtNumber(sum(hw.opened))}</span>
          </div>
          <div>
            <span>Закрыто</span>
            <span className="num">{fmtNumber(sum(hw.closed))}</span>
          </div>
          {SEVERITIES.filter((s) => hw.opened[s] || hw.closed[s]).map((s) => (
            <div key={s} className="faint">
              <span>{SEVERITY_LABEL[s]}</span>
              <span className="num">
                +{hw.opened[s]} / −{hw.closed[s]}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** Тот же график таблицей — для доступности и выгрузки глазами. */
export function WeekTable({ weeks }: { weeks: Week[] }) {
  const rows = weeks.filter((w) => sum(w.opened) || sum(w.closed));
  if (!rows.length) return <p className="muted" style={{ margin: 0 }}>За период изменений не было.</p>;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Неделя</th>
            <th className="right">Появилось</th>
            <th className="right">Закрыто</th>
            {SEVERITIES.slice(0, 4).map((s) => (
              <th key={s} className="right">
                {SEVERITY_LABEL[s]}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((w) => (
            <tr key={w.start}>
              <td className="nowrap">с {fmtDay(w.start)}</td>
              <td className="right num">{fmtNumber(sum(w.opened))}</td>
              <td className="right num">{fmtNumber(sum(w.closed))}</td>
              {SEVERITIES.slice(0, 4).map((s) => (
                <td key={s} className="right num">
                  +{w.opened[s]} / −{w.closed[s]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
