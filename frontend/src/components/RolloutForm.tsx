import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertTriangle } from "lucide-react";
import { api } from "../api/client";
import type { RolloutDraft, RolloutIn, RolloutMeta, RolloutTemplate, TicketDetail } from "../api/types";
import { useAsync } from "../lib/useAsync";
import { ChipPicker } from "./ChipPicker";
import { ErrorAlert, Loading, Modal } from "./ui";

// Та же регулярка, что на сервере (rollout_templates.NAME_RE): данные пришли со сканируемых хостов.
const NAME_RE = /^[A-Za-z0-9][A-Za-z0-9+.:~_-]*$/;
const SERVICE_RE = /^[A-Za-z0-9][A-Za-z0-9@._:-]*$/;

const TEMPLATE_HINT: Record<RolloutTemplate, string> = {
  package: "Обновить пакеты до последней версии из репозиториев хоста и проверить, что она не ниже исправленной.",
  kernel: "Обновить пакет ядра. Новое ядро заработает только после перезагрузки — её разрешает руководитель при утверждении.",
  service: "Перезапустить службу systemd и проверить, что она снова активна.",
  custom: "Одна команда списком аргументов, без shell. Нужно право «Произвольные команды» и отдельное подтверждение руководителя.",
};

/** «Подготовить раскатку» из карточки заявки: шаблон, хосты, канарейка, окно, партии и порог. */
export function PrepareRolloutModal({ t, onClose }: { t: TicketDetail; onClose: () => void }) {
  const navigate = useNavigate();
  const draft = useAsync<RolloutDraft>(() => api.rolloutDraft(t.id), [t.id]);
  const meta = useAsync<RolloutMeta>(() => api.rolloutMeta(), []);
  const [f, setF] = useState<RolloutIn | null>(null);
  const [command, setCommand] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const d = draft.data;
    if (d && !f) {
      setF({
        template: d.template,
        manager: d.manager,
        packages: d.packages,
        fixed_version: d.fixed_version,
        service: d.service,
        hosts: d.hosts,
        canary_host: d.canary_host,
        window_id: d.window_id,
        batch_percent: d.batch_percent,
        failure_threshold: d.failure_threshold,
        note: "",
      });
    }
  }, [draft.data, f]);

  if (draft.error) {
    return (
      <Modal title="Подготовить раскатку" onClose={onClose}>
        <ErrorAlert error={draft.error} onRetry={() => void draft.reload()} />
      </Modal>
    );
  }
  if (!draft.data || !f || !meta.data) {
    return (
      <Modal title="Подготовить раскатку" onClose={onClose}>
        <Loading />
      </Modal>
    );
  }
  const d = draft.data;
  const set = (patch: Partial<RolloutIn>) => setF({ ...f, ...patch });
  const pkgTemplate = f.template === "package" || f.template === "kernel";
  const badPkgs = (f.packages ?? []).filter((p) => !NAME_RE.test(p));
  const hosts = f.hosts ?? [];
  const batchSize = Math.max(1, Math.ceil((hosts.length * (f.batch_percent ?? 10)) / 100));
  const batches = hosts.length > 1 ? Math.ceil((hosts.length - 1) / batchSize) : 0;
  const invalid =
    !hosts.length ||
    (pkgTemplate && (!(f.packages ?? []).length || badPkgs.length > 0 || !f.manager)) ||
    (f.template === "service" && !SERVICE_RE.test(f.service ?? "")) ||
    (f.template === "custom" && !command.trim());

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const body: RolloutIn = { ...f, command: f.template === "custom" ? command : "" };
      if (!pkgTemplate) {
        body.packages = [];
        body.manager = "";
      }
      const r = await api.createRollout(t.id, body);
      navigate(`/rollouts/${r.id}`);
    } catch (e) {
      setError((e as Error).message);
      setBusy(false);
    }
  };

  if (d.active_rollout_id) {
    return (
      <Modal
        title="Подготовить раскатку"
        onClose={onClose}
        footer={
          <button type="button" className="btn btn-primary" onClick={() => navigate(`/rollouts/${d.active_rollout_id}`)}>
            Открыть раскатку №{d.active_rollout_id}
          </button>
        }
      >
        <span className="muted">
          По заявке уже есть незавершённая раскатка №{d.active_rollout_id}. Новую можно подготовить, когда она закончится или будет отменена.
        </span>
      </Modal>
    );
  }

  return (
    <Modal
      title={`Раскатка по заявке №${t.id}`}
      onClose={onClose}
      wide
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void submit()} disabled={busy || invalid}>
            {busy ? "Сохранение…" : "Подготовить"}
          </button>
        </>
      }
    >
      <span className="muted">
        После подготовки нужен пробный прогон: он покажет, что изменится на каждом хосте. Затем раскатку утверждает руководитель —
        другой человек, — и только после этого её можно запустить.
      </span>
      {d.problems.length > 0 && (
        <div className="alert alert-warn">
          <AlertTriangle size={16} aria-hidden="true" />
          <span>Данные «Сканера» не прошли проверку и в раскатку не попадут: {d.problems.join("; ")}</span>
        </div>
      )}
      <div className="form-grid-2">
        <label className="field">
          <span>Шаблон</span>
          <select className="select" value={f.template} onChange={(e) => set({ template: e.target.value as RolloutTemplate })}>
            {meta.data.templates
              .filter((x) => x.id !== "custom" || d.can_custom)
              .map((x) => (
                <option key={x.id} value={x.id}>
                  {x.label}
                </option>
              ))}
          </select>
          <small>{TEMPLATE_HINT[f.template]}</small>
        </label>
        {pkgTemplate && (
          <label className="field">
            <span>Менеджер пакетов</span>
            <select className="select" value={f.manager} onChange={(e) => set({ manager: e.target.value })}>
              <option value="">— выберите —</option>
              {meta.data.managers.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
            {t.os && <small>ОС заявки: {t.os}</small>}
          </label>
        )}
        {f.template === "service" && (
          <label className="field">
            <span>Служба systemd</span>
            <input className="input mono" value={f.service} onChange={(e) => set({ service: e.target.value.trim() })} placeholder="nginx" maxLength={128} />
            {f.service && !SERVICE_RE.test(f.service) && <small style={{ color: "var(--danger)" }}>Латиница, цифры и «@ . _ : -»</small>}
          </label>
        )}
      </div>
      {pkgTemplate && (
        <div className="form-grid-2">
          <label className="field">
            <span>Пакеты</span>
            <input
              className="input mono"
              value={(f.packages ?? []).join(" ")}
              onChange={(e) => set({ packages: e.target.value.split(/[\s,]+/).filter(Boolean) })}
              placeholder="openssh-server"
            />
            {badPkgs.length > 0 ? (
              <small style={{ color: "var(--danger)" }}>Недопустимые имена: {badPkgs.join(", ")}</small>
            ) : (
              <small>Через пробел. Обновляются только установленные на хосте.</small>
            )}
          </label>
          <label className="field">
            <span>Исправленная версия</span>
            <input className="input mono" value={f.fixed_version} onChange={(e) => set({ fixed_version: e.target.value.trim() })} />
            <small>Версия «после» должна быть не ниже — иначе хост считается неуспешным.</small>
          </label>
        </div>
      )}
      {f.template === "custom" && (
        <label className="field">
          <span>Команда</span>
          <input className="input mono" value={command} onChange={(e) => setCommand(e.target.value)} placeholder="systemctl reload nginx" maxLength={2000} />
          <small>Разбирается на аргументы как в shell, но выполняется без shell: «;», «|», «$()» не работают.</small>
        </label>
      )}
      <ChipPicker
        label={`Хосты (${hosts.length} из ${d.hosts.length})`}
        options={d.hosts.map((h) => ({ id: h, label: <span className="mono">{h}</span> }))}
        value={hosts}
        onChange={(v) => set({ hosts: v, canary_host: v.includes(f.canary_host ?? "") ? f.canary_host : (v[0] ?? "") })}
        hint="Неподтверждённые хосты заявки. Перед каждым этапом allowlist «Сканера» и окно проверяются заново."
        empty="Все хосты заявки подтверждены"
      />
      <div className="form-grid-2">
        <label className="field">
          <span>Канарейка</span>
          <select className="select mono" value={f.canary_host} onChange={(e) => set({ canary_host: e.target.value })}>
            {hosts.map((h) => (
              <option key={h} value={h}>
                {h}
              </option>
            ))}
          </select>
          <small>Первый хост; если на нём ошибка, партии не начнутся. По умолчанию — наименее критичный.</small>
        </label>
        <label className="field">
          <span>Окно обслуживания</span>
          <select className="select" value={f.window_id ?? ""} onChange={(e) => set({ window_id: e.target.value ? Number(e.target.value) : null })}>
            <option value="">— без окна (запуск вне окна решает руководитель) —</option>
            {d.windows.map((w) => (
              <option key={w.id} value={w.id}>
                {w.name}
              </option>
            ))}
          </select>
        </label>
        <label className="field">
          <span>Партия, % хостов</span>
          <input className="input" type="number" min={1} max={100} value={f.batch_percent} onChange={(e) => set({ batch_percent: Number(e.target.value) })} />
          <small>
            Канарейка и {batches} {batches === 1 ? "партия" : batches > 1 && batches < 5 ? "партии" : "партий"} по {batchSize} хост(а)
          </small>
        </label>
        <label className="field">
          <span>Порог ошибок, %</span>
          <input className="input" type="number" min={0} max={100} value={f.failure_threshold} onChange={(e) => set({ failure_threshold: Number(e.target.value) })} />
          <small>Больше этой доли хостов с ошибкой — раскатка останавливается.</small>
        </label>
      </div>
      <label className="field">
        <span>Комментарий (необязательно)</span>
        <textarea className="textarea" style={{ fontFamily: "var(--font)", minHeight: 60 }} value={f.note} onChange={(e) => set({ note: e.target.value })} maxLength={2000} />
      </label>
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}
