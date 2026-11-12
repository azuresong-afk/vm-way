import type { Criticality, ExceptionKind, ExceptionStatus, HostStatus, RolloutHostStatus, RolloutStatus, Severity, StageState, TicketStatus } from "../api/types";

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Критический",
  high: "Высокий",
  medium: "Средний",
  low: "Низкий",
  info: "Инфо",
};

export const SEVERITY_SHORT: Record<Severity, string> = {
  critical: "Крит.",
  high: "Выс.",
  medium: "Сред.",
  low: "Низк.",
  info: "Инфо",
};

export const STATUS_LABEL: Record<TicketStatus, string> = {
  new: "Новая",
  assigned: "Назначена",
  in_progress: "В работе",
  waiting_window: "Ожидает окна",
  fixed: "Исправлено, ждёт проверки",
  verified: "Подтверждено",
  not_verified: "Не подтверждено",
  risk_accepted: "Принят риск",
  false_positive: "Ложное срабатывание",
  no_vendor_fix: "Нет исправления у производителя",
  regression: "Регрессия",
};

/** Порядок статусов по ходу работы — для фильтра и сводки. */
export const STATUS_ORDER: TicketStatus[] = [
  "new",
  "assigned",
  "in_progress",
  "waiting_window",
  "fixed",
  "not_verified",
  "regression",
  "no_vendor_fix",
  "verified",
  "risk_accepted",
  "false_positive",
];

export const CLOSED_STATUSES: TicketStatus[] = ["verified", "risk_accepted", "false_positive"];
export const EXCEPTION_STATUSES: TicketStatus[] = ["risk_accepted", "false_positive"];

export const STATUS_PILL: Record<TicketStatus, string> = {
  new: "pill-info",
  assigned: "pill-info",
  in_progress: "pill-info pill-running",
  waiting_window: "pill-muted",
  fixed: "pill-warn",
  verified: "pill-ok",
  not_verified: "pill-danger",
  risk_accepted: "pill-muted",
  false_positive: "pill-muted",
  no_vendor_fix: "pill-muted",
  regression: "pill-danger",
};

/** Нужна ли причина для перехода (как в backend/app/services/workflow.py). Исключения — отдельной формой. */
export function reasonRequired(from: TicketStatus): boolean {
  return from === "fixed";
}

export const EXCEPTION_KIND_LABEL: Record<ExceptionKind, string> = {
  risk_accepted: "Принятие риска",
  false_positive: "Ложное срабатывание",
};

export const EXCEPTION_STATUS_PILL: Record<ExceptionStatus, string> = {
  pending: "pill-warn",
  active: "pill-info",
  rejected: "pill-danger",
  withdrawn: "pill-muted",
  revoked: "pill-muted",
  expired: "pill-muted",
};

export const HOST_STATUS_LABEL: Record<HostStatus, string> = {
  open: "Открыт",
  confirmed: "Подтверждено",
  not_confirmed: "Не подтверждено",
  unverified: "Не проверено",
};

export const HOST_STATUS_PILL: Record<HostStatus, string> = {
  open: "pill-muted",
  confirmed: "pill-ok",
  not_confirmed: "pill-danger",
  unverified: "pill-warn",
};

export const KIND_LABEL: Record<string, string> = {
  package: "Пакет",
  kernel: "Ядро",
  software: "ПО",
  config: "Конфигурация",
  account: "Учётная запись",
  other: "Прочее",
};

export const ROLE_LABEL: Record<string, string> = {
  manager: "Руководитель",
  engineer: "Исполнитель",
  viewer: "Наблюдатель",
  admin: "Администратор",
};

export const MODULE_LABEL: Record<string, string> = {
  discovery: "Обнаружение",
  vuln: "Уязвимости",
  auth_inventory: "Инвентаризация (SSH)",
  win_inventory: "Инвентаризация (WinRM)",
  config_audit: "Аудит конфигураций",
  cred_audit: "Аудит паролей",
};

export const OUTCOME_LABEL: Record<string, string> = {
  verified: "Подтверждено",
  not_verified: "Не подтверждено",
  partial: "Частично",
  unverified: "Не проверено",
};

export const OUTCOME_PILL: Record<string, string> = {
  verified: "pill-ok",
  not_verified: "pill-danger",
  partial: "pill-warn",
  unverified: "pill-warn",
};

export const AUDIT_ACTION_LABEL: Record<string, string> = {
  "auth.login": "Вход",
  "auth.logout": "Выход",
  "user.create": "Пользователь создан",
  "user.update": "Пользователь изменён",
  "user.password_reset": "Сброс пароля",
  "project.create": "Проект создан",
  "project.update": "Проект изменён",
  "source.create": "Источник добавлен",
  "source.update": "Источник изменён",
  "source.delete": "Источник удалён",
  "source.test": "Проверка связи",
  "link.create": "Привязка добавлена",
  "link.delete": "Привязка снята",
  "run.import_requested": "Импорт запрошен",
  "run.import": "Прогон импортирован",
  "ticket.take": "Заявка взята",
  "ticket.assign": "Назначение",
  "ticket.status": "Смена статуса",
  "ticket.override": "Переопределение",
  "ticket.comment": "Комментарий",
  "ticket.watch": "Наблюдение",
  "ticket.unwatch": "Наблюдение снято",
  "ticket.bulk": "Массовое действие",
  "ticket.verify": "Повторная проверка",
  "ticket.verify_result": "Итог проверки",
  "ticket.verify_cancel": "Проверка отменена",
  "ticket.window": "Заявка в окне",
  "window.create": "Окно создано",
  "window.update": "Окно изменено",
  "window.delete": "Окно удалено",
  "audit.export": "Выгрузка журнала",
  "rollout.create": "Раскатка подготовлена",
  "rollout.dry_run": "Пробный прогон",
  "rollout.dry_run_result": "Итог пробного прогона",
  "rollout.approve": "Раскатка утверждена",
  "rollout.reject": "Раскатка отклонена",
  "rollout.cancel": "Раскатка отменена",
  "rollout.start": "Раскатка запущена",
  "rollout.denied": "Хосты не допущены",
  "rollout.host": "Раскатка на хосте",
  "rollout.stop": "Аварийный стоп",
  "rollout.finish": "Раскатка завершена",
  "rollout.settings": "Параллельность раскаток",
  "demo.seed": "Демо-данные",
};

/** Права роли — человеческими словами (экран «Пользователи и роли»). */
export const PERM_LABEL: Record<string, string> = {
  view: "просмотр",
  import: "импорт прогонов",
  ticket_work: "работа с заявками",
  ticket_assign: "назначение",
  ticket_override: "переопределение уровня",
  verify: "повторная проверка",
  windows_manage: "окна обслуживания",
  rules_manage: "правила назначения",
  credentials_manage: "SSH-учётки",
  rollout_approve: "утверждение раскаток",
  projects_manage: "проекты",
  sources_manage: "источники",
  users_manage: "пользователи",
  audit_view: "журнал аудита",
};

export function isClosed(s: TicketStatus): boolean {
  return CLOSED_STATUSES.includes(s);
}

// Критичность актива — подписи как в «Сканере» (web/src/lib/labels.ts).
export const CRITICALITIES: Criticality[] = ["critical", "high", "medium", "low"];

export const CRITICALITY_LABEL: Record<Criticality, string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
};

// --- Раскатки (задача 2.4) ---

export const ROLLOUT_STATUS_PILL: Record<RolloutStatus, string> = {
  draft: "pill-muted",
  dry_run: "pill-info pill-running",
  pending_approval: "pill-warn",
  approved: "pill-info",
  running: "pill-info pill-running",
  done: "pill-ok",
  failed: "pill-danger",
  stopped: "pill-danger",
  rejected: "pill-muted",
  cancelled: "pill-muted",
};

export const ROLLOUT_HOST_PILL: Record<RolloutHostStatus, string> = {
  pending: "pill-muted",
  dry_ok: "pill-ok",
  dry_failed: "pill-danger",
  queued: "pill-muted",
  running: "pill-info pill-running",
  succeeded: "pill-ok",
  reboot_pending: "pill-warn",
  failed: "pill-danger",
  skipped: "pill-muted",
};

export const STAGE_LABEL: Record<StageState, string> = {
  pending: "впереди",
  running: "идёт",
  done: "готово",
  failed: "ошибка",
  skipped: "пропущено",
};
