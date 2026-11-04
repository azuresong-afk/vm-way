import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import type { ProjectOut } from "../api/types";
import { useAuth } from "./AuthContext";

/** Общий ключ продуктов (контракт платформы, п. 3); проект из ?project= важнее. */
export const PROJECT_KEY = "platform.project";

interface ProjectValue {
  projects: ProjectOut[];
  current: ProjectOut | null;
  select: (id: string) => void;
  reload: () => Promise<void>;
  loading: boolean;
  error: Error | null;
}

const Ctx = createContext<ProjectValue | null>(null);

function savedId(): string | null {
  try {
    return localStorage.getItem(PROJECT_KEY);
  } catch {
    return null;
  }
}

function remember(id: string): void {
  try {
    localStorage.setItem(PROJECT_KEY, id);
  } catch {
    /* ignore */
  }
}

/** Текущий проект — общий контекст всех экранов; ссылки между продуктами несут его в ?project=. */
export function ProjectProvider({ children }: { children: ReactNode }) {
  const { me, has } = useAuth();
  const [params, setParams] = useSearchParams();
  const [projects, setProjects] = useState<ProjectOut[]>([]);
  const [currentId, setCurrentId] = useState<string | null>(() => params.get("project") ?? savedId());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const canView = has("view");
  const fromUrl = params.get("project");

  const reload = useCallback(async () => {
    if (!canView) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      setProjects(await api.projects());
      setError(null);
    } catch (e) {
      setError(e as Error);
    } finally {
      setLoading(false);
    }
  }, [canView]);

  useEffect(() => {
    if (me) void reload();
  }, [me, reload]);

  // Переход по ссылке из другого продукта: ?project= выбирает проект и запоминается.
  useEffect(() => {
    if (fromUrl && fromUrl !== currentId) {
      setCurrentId(fromUrl);
      remember(fromUrl);
    }
  }, [fromUrl, currentId]);

  const select = useCallback(
    (id: string) => {
      setCurrentId(id);
      remember(id);
      if (params.has("project")) {
        const next = new URLSearchParams(params);
        next.set("project", id);
        setParams(next, { replace: true });
      }
    },
    [params, setParams],
  );

  const current = useMemo(() => {
    if (!projects.length) return null;
    return projects.find((p) => p.id === currentId) ?? projects[0];
  }, [projects, currentId]);

  const value = useMemo(
    () => ({ projects, current, select, reload, loading, error }),
    [projects, current, select, reload, loading, error],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useProject(): ProjectValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useProject outside ProjectProvider");
  return v;
}

export function projectLabel(p: ProjectOut): string {
  return p.client ? `${p.client} · ${p.name}` : p.name;
}
