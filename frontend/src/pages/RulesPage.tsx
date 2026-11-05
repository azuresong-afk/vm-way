import { useState } from "react";
import { Link } from "react-router-dom";
import { ArrowDown, ArrowUp, Pencil, Play, Plus, Trash2, Users, Workflow } from "lucide-react";
import { api } from "../api/client";
import type { HostMatch, RuleIn, RuleOut, RulesApplyOut, TeamOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { projectLabel, useProject } from "../auth/ProjectContext";
import { ChipPicker } from "../components/ChipPicker";
import { ConfirmModal, Empty, ErrorAlert, Loading, Modal, SeverityBadge } from "../components/ui";
import { fmtNumber, plural } from "../lib/format";
import { KIND_LABEL } from "../lib/labels";
import { useAsync } from "../lib/useAsync";

const HOST_MATCH_LABEL: Record<HostMatch, string> = { all: "все хосты заявки", any: "хотя бы один хост" };

function Cond({ label, values }: { label: string; values: string[] }) {
  if (!values.length) return null;
  return (
    <span className="inline" style={{ gap: 4 }}>
      <span className="faint">{label}:</span>
      {values.map((v) => (
        <span key={v} className="tag tag-muted">
          {v}
        </span>
      ))}
    </span>
  );
}

function RuleConditions({ r }: { r: RuleOut }) {
  const hostConds = r.groups.length || r.tags.length || r.owners.length;
  const any = hostConds || r.os.length || r.kinds.length;
  return (
    <div className="rule-cond">
      {!any && <span className="faint">любая новая заявка</span>}
      <Cond label="группа" values={r.groups} />
      <Cond label="тег" values={r.tags} />
      <Cond label="владелец" values={r.owners} />
      <Cond label="ОС" values={r.os} />
      <Cond label="вид" values={r.kinds.map((k) => KIND_LABEL[k] ?? k)} />
      {hostConds ? <span className="faint">· {HOST_MATCH_LABEL[r.host_match]}</span> : null}
    </div>
  );
}

function Target({ r }: { r: RuleOut }) {
  if (r.team)
    return (
      <span>
        <Users size={14} aria-hidden="true" style={{ verticalAlign: -2 }} /> {r.team.name}
        <div className="faint" style={{ fontSize: 12.5 }}>
          {r.team.members
            ? `по загрузке, ${r.team.members} ${plural(r.team.members, ["участник", "участника", "участников"])}`
            : "в команде некому назначать"}
        </div>
      </span>
    );
  if (r.assignee)
    return (
      <span>
        {r.assignee.display_name}
        {!r.assignee.available && <div className="faint" style={{ fontSize: 12.5 }}>отключён — правило пропускается</div>}
      </span>
    );
  return <span className="faint">не задано</span>;
}

/** Создание и правка правила назначения. */
function RuleForm({
  projectId,
  initial,
  teams,
  onClose,
  onSaved,
}: {
  projectId: string;
  initial?: RuleOut;
  teams: TeamOut[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const assets = useAsync(() => api.assetFacets(projectId), [projectId]);
  const tickets = useAsync(() => api.ticketFacets(projectId), [projectId]);
  const people = useAsync(() => api.assignable(projectId), [projectId]);
  const [name, setName] = useState(initial?.name ?? "");
  const [groups, setGroups] = useState(initial?.groups ?? []);
  const [tags, setTags] = useState(initial?.tags ?? []);
  const [owners, setOwners] = useState(initial?.owners ?? []);
  const [os, setOs] = useState(initial?.os ?? []);
  const [kinds, setKinds] = useState(initial?.kinds ?? []);
  const [hostMatch, setHostMatch] = useState<HostMatch>(initial?.host_match ?? "all");
  const [mode, setMode] = useState<"team" | "user">(initial?.assignee ? "user" : teams.length ? "team" : "user");
  const [teamId, setTeamId] = useState<number | "">(initial?.team?.id ?? teams[0]?.id ?? "");
  const [userId, setUserId] = useState<number | "">(initial?.assignee?.id ?? "");
  const [active, setActive] = useState(initial?.is_active ?? true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const hostConds = groups.length + tags.length + owners.length > 0;
  const target = mode === "team" ? teamId : userId;

  const save = async () => {
    setBusy(true);
    setError(null);
    const data: RuleIn = {
      name: name.trim(),
      is_active: active,
      groups,
      tags,
      owners,
      os,
      kinds,
      host_match: hostMatch,
      assignee_id: mode === "user" && userId !== "" ? userId : null,
      team_id: mode === "team" && teamId !== "" ? teamId : null,
    };
    try {
      if (initial) await api.updateRule(initial.id, data);
      else await api.createRule(projectId, data);
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    setBusy(true);
    try {
      await api.deleteRule(initial!.id);
      onSaved();
    } catch (e) {
      setError((e as Error).message);
      setConfirmDelete(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <Modal
        title={initial ? `Правило «${initial.name}»` : "Новое правило назначения"}
        onClose={onClose}
        wide
        footer={
          <>
            {initial && (
              <button type="button" className="btn btn-ghost" style={{ marginRight: "auto" }} onClick={() => setConfirmDelete(true)}>
                <Trash2 size={15} aria-hidden="true" /> Удалить
              </button>
            )}
            <button type="button" className="btn" onClick={onClose}>
              Отмена
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void save()} disabled={busy || !name.trim() || target === ""}>
              {busy ? "Сохранение…" : initial ? "Сохранить" : "Создать"}
            </button>
          </>
        }
      >
        <label className="field">
          <span>Название</span>
          <input className="input" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} placeholder="Например, «DMZ — команде веб-сервисов»" />
        </label>
        <p className="muted" style={{ margin: 0, fontSize: 13 }}>
          Пустое условие — любое значение. Внутри условия достаточно одного из выбранных значений, условия между собой — все сразу.
        </p>
        <ChipPicker
          label="Группа активов"
          options={(assets.data?.groups ?? []).map((g) => ({ id: g.name, count: g.assets }))}
          value={groups}
          onChange={setGroups}
          empty={assets.loading ? "Загрузка…" : "Групп нет — они приходят из «Сканера»"}
        />
        <ChipPicker label="Тег актива" options={(assets.data?.tags ?? []).map((t) => ({ id: t.name, count: t.assets }))} value={tags} onChange={setTags} empty="Тегов нет" />
        <ChipPicker
          label="Владелец актива"
          options={(assets.data?.owners ?? []).map((o) => ({ id: o.name, count: o.assets }))}
          value={owners}
          onChange={setOwners}
          empty="Владельцы не заданы в «Сканере»"
        />
        {hostConds && (
          <div className="field">
            <span id="rf-match">Условия по активам должны выполняться</span>
            <div className="seg" role="radiogroup" aria-labelledby="rf-match">
              {(["all", "any"] as HostMatch[]).map((m) => (
                <button key={m} type="button" role="radio" aria-checked={hostMatch === m} onClick={() => setHostMatch(m)}>
                  {m === "all" ? "Для всех хостов заявки" : "Хотя бы для одного"}
                </button>
              ))}
            </div>
            <small>Подтверждённые хосты не учитываются. Хост, которого нет среди активов «Сканера», условиям не удовлетворяет.</small>
          </div>
        )}
        <ChipPicker label="ОС" options={(tickets.data?.os ?? []).map((o) => ({ id: o.id }))} value={os} onChange={setOs} empty="ОС появятся после импорта" />
        <ChipPicker label="Вид заявки" options={Object.entries(KIND_LABEL).map(([id, label]) => ({ id, label }))} value={kinds} onChange={setKinds} />
        <div className="field">
          <span id="rf-target">Кому назначать</span>
          <div className="seg" role="radiogroup" aria-labelledby="rf-target">
            <button type="button" role="radio" aria-checked={mode === "team"} onClick={() => setMode("team")}>
              Команде по загрузке
            </button>
            <button type="button" role="radio" aria-checked={mode === "user"} onClick={() => setMode("user")}>
              Исполнителю
            </button>
          </div>
          {mode === "team" ? (
            teams.length ? (
              <select className="select" aria-label="Команда" value={teamId} onChange={(e) => setTeamId(Number(e.target.value))}>
                {teams.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} · {t.members.length} {plural(t.members.length, ["участник", "участника", "участников"])}
                  </option>
                ))}
              </select>
            ) : (
              <small>Команд пока нет — создайте её в разделе «Команды» ниже.</small>
            )
          ) : (
            <select className="select" aria-label="Исполнитель" value={userId} onChange={(e) => setUserId(e.target.value ? Number(e.target.value) : "")}>
              <option value="">Выберите исполнителя</option>
              {initial?.assignee && !people.data?.some((u) => u.id === initial.assignee!.id) && (
                <option value={initial.assignee.id}>{initial.assignee.display_name} (отключён)</option>
              )}
              {(people.data ?? []).map((u) => (
                <option key={u.id} value={u.id}>
                  {u.display_name} · открытых заявок {u.open_tickets ?? 0}
                </option>
              ))}
            </select>
          )}
          {mode === "team" && <small>Заявка достаётся участнику с наименьшим числом открытых заявок проекта.</small>}
        </div>
        {initial && (
          <label className="inline" style={{ gap: 8 }}>
            <input type="checkbox" className="cb" checked={active} onChange={(e) => setActive(e.target.checked)} />
            Правило включено
          </label>
        )}
        {error && <ErrorAlert error={error} />}
      </Modal>
      {confirmDelete && (
        <ConfirmModal title="Удалить правило?" confirmLabel="Удалить" busy={busy} onConfirm={() => void remove()} onClose={() => setConfirmDelete(false)}>
          <p style={{ margin: 0 }}>Правило «{initial!.name}» будет удалено. Уже назначенные заявки останутся у исполнителей.</p>
        </ConfirmModal>
      )}
    </>
  );
}

/** Команда: название и участники (исполнители и руководители). */
function TeamForm({ projectId, initial, onClose, onSaved }: { projectId: string; initial?: TeamOut; onClose: () => void; onSaved: () => void }) {
  const people = useAsync(() => api.assignable(projectId), [projectId]);
  const [name, setName] = useState(initial?.name ?? "");
  const [members, setMembers] = useState<number[]>(initial?.members.map((m) => m.id) ?? []);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const toggle = (id: number) => setMembers((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]));
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      if (initial) await api.updateTeam(initial.id, { name: name.trim(), member_ids: members });
      else await api.createTeam({ name: name.trim(), member_ids: members });
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const remove = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.deleteTeam(initial!.id);
      onSaved();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const inactive = (initial?.members ?? []).filter((m) => !m.available);
  return (
    <Modal
      title={initial ? `Команда «${initial.name}»` : "Новая команда"}
      onClose={onClose}
      footer={
        <>
          {initial && (
            <button type="button" className="btn btn-ghost" style={{ marginRight: "auto" }} onClick={() => void remove()} disabled={busy}>
              <Trash2 size={15} aria-hidden="true" /> Удалить
            </button>
          )}
          <button type="button" className="btn" onClick={onClose}>
            Отмена
          </button>
          <button type="button" className="btn btn-primary" onClick={() => void save()} disabled={busy || !name.trim()}>
            {busy ? "Сохранение…" : initial ? "Сохранить" : "Создать"}
          </button>
        </>
      }
    >
      <label className="field">
        <span>Название</span>
        <input className="input" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} placeholder="Например, «Linux-администраторы»" />
      </label>
      <div className="field">
        <span id="tf-members">Участники</span>
        {people.loading && !people.data && <Loading />}
        <div className="picker" role="group" aria-labelledby="tf-members">
          {(people.data ?? []).map((u) => (
            <button key={u.id} type="button" className="chip" aria-pressed={members.includes(u.id)} onClick={() => toggle(u.id)}>
              {u.display_name}
              <span className="picker-count" title="Открытых заявок проекта">{u.open_tickets ?? 0}</span>
            </button>
          ))}
          {inactive.map((m) => (
            <button key={m.id} type="button" className="chip" aria-pressed={members.includes(m.id)} onClick={() => toggle(m.id)}>
              {m.display_name} (отключён)
            </button>
          ))}
        </div>
        <small>Команда общая для всех проектов. Число рядом с именем — открытые заявки в текущем проекте.</small>
      </div>
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

/** Предпросмотр и применение правил к новым заявкам без исполнителя. */
function ApplyModal({ projectId, onClose, onDone }: { projectId: string; onClose: () => void; onDone: (n: number) => void }) {
  const preview = useAsync(() => api.applyRules(projectId, true), [projectId]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<RulesApplyOut | null>(null);
  const apply = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api.applyRules(projectId, false);
      setResult(r);
      onDone(r.assigned);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const data = result ?? preview.data;
  const n = preview.data?.assigned ?? 0;
  return (
    <Modal
      title="Применить правила"
      onClose={onClose}
      wide
      footer={
        result ? (
          <button type="button" className="btn btn-primary" onClick={onClose}>
            Готово
          </button>
        ) : (
          <>
            <button type="button" className="btn" onClick={onClose}>
              Отмена
            </button>
            <button type="button" className="btn btn-primary" onClick={() => void apply()} disabled={busy || !n}>
              {busy ? "Назначение…" : `Назначить ${fmtNumber(n)}`}
            </button>
          </>
        )
      }
    >
      <p className="muted" style={{ margin: 0, fontSize: 13 }}>
        {result
          ? `Назначено ${fmtNumber(result.assigned)} из ${fmtNumber(result.tickets)}. Остальные остались без исполнителя.`
          : "Правила применяются к новым заявкам без исполнителя. Ниже — кому достанется каждая заявка; ничего ещё не изменено."}
      </p>
      {preview.error && <ErrorAlert error={preview.error} onRetry={() => void preview.reload()} />}
      {preview.loading && !preview.data && <Loading />}
      {data && data.items.length === 0 && <Empty title="Новых заявок без исполнителя нет" />}
      {data && data.items.length > 0 && (
        <div className="table-wrap" style={{ maxHeight: 380 }}>
          <table className="table">
            <thead>
              <tr>
                <th>Заявка</th>
                <th>Правило</th>
                <th>Кому</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((i) => (
                <tr key={i.ticket_id} className={i.rule ? "" : "rule-off"}>
                  <td style={{ minWidth: 220 }}>
                    <Link to={`/tickets/${i.ticket_id}`} className="ticket-title">
                      №{i.ticket_id} · {i.title}
                    </Link>
                    <div className="ticket-sub faint">
                      <SeverityBadge severity={i.severity} short /> {KIND_LABEL[i.kind] ?? i.kind}
                      {i.os && ` · ${i.os}`}
                    </div>
                  </td>
                  <td>{i.rule ? i.rule.name : <span className="faint">{i.note || "—"}</span>}</td>
                  <td className="nowrap">{i.assignee?.display_name ?? <span className="faint">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {error && <ErrorAlert error={error} />}
    </Modal>
  );
}

/** «Правила назначения»: правила проекта по порядку и команды. */
export function RulesPage() {
  const { current } = useProject();
  const { has } = useAuth();
  const projectId = current!.id;
  const canEdit = has("rules_manage");
  const rules = useAsync(() => api.rules(projectId), [projectId]);
  const teams = useAsync(() => api.teams(), []);
  const [ruleForm, setRuleForm] = useState<{ rule?: RuleOut } | null>(null);
  const [teamForm, setTeamForm] = useState<{ team?: TeamOut } | null>(null);
  const [applying, setApplying] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const move = async (idx: number, dir: -1 | 1) => {
    const list = rules.data ?? [];
    const ids = list.map((r) => r.id);
    const j = idx + dir;
    if (j < 0 || j >= ids.length) return;
    [ids[idx], ids[j]] = [ids[j], ids[idx]];
    setError(null);
    try {
      rules.setData(await api.reorderRules(projectId, ids));
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const toggle = async (r: RuleOut) => {
    setError(null);
    try {
      await api.updateRule(r.id, { is_active: !r.is_active });
      await rules.reload();
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const list = rules.data ?? [];

  return (
    <>
      <div className="page-head">
        <div>
          <span className="crumbs">{projectLabel(current!)}</span>
          <h1>Правила назначения</h1>
        </div>
        <div className="actions">
          {has("ticket_assign") && (
            <button type="button" className="btn" onClick={() => { setNote(null); setApplying(true); }} disabled={!list.some((r) => r.is_active)}>
              <Play size={15} aria-hidden="true" /> Применить к новым заявкам
            </button>
          )}
          {canEdit && (
            <button type="button" className="btn btn-primary" onClick={() => setRuleForm({})}>
              <Plus size={15} aria-hidden="true" /> Новое правило
            </button>
          )}
        </div>
      </div>
      {note && <div className="alert alert-ok" role="status">{note}</div>}
      {error && <ErrorAlert error={error} />}

      <section className="card" aria-labelledby="rules-head">
        <div className="card-head">
          <h2 id="rules-head">Правила</h2>
          <span className="faint" style={{ fontSize: 13 }}>
            сверху вниз, срабатывает первое подходящее · новые заявки из импорта назначаются автоматически
          </span>
        </div>
        {rules.error && <ErrorAlert error={rules.error} onRetry={() => void rules.reload()} />}
        {rules.loading && !rules.data && <Loading />}
        {rules.data && list.length === 0 && (
          <Empty title="Правил пока нет" icon={<Workflow size={28} />}>
            Правило назначает новую заявку исполнителю или команде по группе активов, тегу, владельцу, ОС или виду заявки.
          </Empty>
        )}
        {list.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 56 }}>№</th>
                  <th>Правило и условия</th>
                  <th>Кому</th>
                  <th>Состояние</th>
                  {canEdit && <th className="right">Действия</th>}
                </tr>
              </thead>
              <tbody>
                {list.map((r, i) => (
                  <tr key={r.id} className={r.is_active ? "" : "rule-off"}>
                    <td className="mono faint">{i + 1}</td>
                    <td style={{ minWidth: 260 }}>
                      <span style={{ fontWeight: 500 }}>{r.name}</span>
                      <RuleConditions r={r} />
                    </td>
                    <td style={{ minWidth: 160 }}>
                      <Target r={r} />
                    </td>
                    <td className="nowrap">
                      {canEdit ? (
                        <label className="inline" style={{ gap: 6 }}>
                          <input type="checkbox" className="cb" checked={r.is_active} onChange={() => void toggle(r)} aria-label={`Правило «${r.name}» включено`} />
                          {r.is_active ? "включено" : "выключено"}
                        </label>
                      ) : r.is_active ? (
                        "включено"
                      ) : (
                        "выключено"
                      )}
                    </td>
                    {canEdit && (
                      <td className="right nowrap">
                        <span className="inline" style={{ gap: 4, justifyContent: "flex-end" }}>
                          <button type="button" className="btn btn-sm btn-ghost" aria-label="Выше" disabled={i === 0} onClick={() => void move(i, -1)}>
                            <ArrowUp size={14} />
                          </button>
                          <button type="button" className="btn btn-sm btn-ghost" aria-label="Ниже" disabled={i === list.length - 1} onClick={() => void move(i, 1)}>
                            <ArrowDown size={14} />
                          </button>
                          <button type="button" className="btn btn-sm" onClick={() => setRuleForm({ rule: r })}>
                            <Pencil size={14} aria-hidden="true" /> Изменить
                          </button>
                        </span>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card" aria-labelledby="teams-head">
        <div className="card-head">
          <h2 id="teams-head">Команды</h2>
          {canEdit && (
            <button type="button" className="btn btn-sm" onClick={() => setTeamForm({})}>
              <Plus size={14} aria-hidden="true" /> Новая команда
            </button>
          )}
        </div>
        {teams.error && <ErrorAlert error={teams.error} onRetry={() => void teams.reload()} />}
        {teams.loading && !teams.data && <Loading />}
        {teams.data && teams.data.length === 0 && (
          <Empty title="Команд пока нет" icon={<Users size={28} />}>
            Команда делит заявки между участниками по загрузке: каждая новая заявка достаётся наименее занятому.
          </Empty>
        )}
        {(teams.data ?? []).map((t) => (
          <div key={t.id} className="team-row">
            <div style={{ minWidth: 0 }}>
              <span style={{ fontWeight: 500 }}>{t.name}</span>
              <span className="faint" style={{ fontSize: 12.5 }}>
                {" "}
                · {t.rules ? `в правилах: ${t.rules}` : "в правилах не используется"}
              </span>
              <div className="team-members">
                {t.members.length ? (
                  t.members.map((m) => (
                    <span key={m.id} className={`tag ${m.available ? "" : "tag-muted"}`} title={m.available ? undefined : "Отключён или без права работать с заявками — пропускается"}>
                      {m.display_name}
                      {!m.available && " (не назначается)"}
                    </span>
                  ))
                ) : (
                  <span className="faint">участников нет</span>
                )}
              </div>
            </div>
            {canEdit && (
              <button type="button" className="btn btn-sm" onClick={() => setTeamForm({ team: t })}>
                <Pencil size={14} aria-hidden="true" /> Изменить
              </button>
            )}
          </div>
        ))}
      </section>

      {ruleForm && (
        <RuleForm
          projectId={projectId}
          initial={ruleForm.rule}
          teams={teams.data ?? []}
          onClose={() => setRuleForm(null)}
          onSaved={() => {
            setRuleForm(null);
            void rules.reload();
            void teams.reload();
          }}
        />
      )}
      {teamForm && (
        <TeamForm
          projectId={projectId}
          initial={teamForm.team}
          onClose={() => setTeamForm(null)}
          onSaved={() => {
            setTeamForm(null);
            void teams.reload();
            void rules.reload();
          }}
        />
      )}
      {applying && (
        <ApplyModal
          projectId={projectId}
          onClose={() => setApplying(false)}
          onDone={(n) => setNote(`Назначено заявок: ${fmtNumber(n)}.`)}
        />
      )}
    </>
  );
}
