import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

export type Theme = "dark" | "light";

/** Общий ключ продуктов на одном origin; у «Сканера» пока свой — читаем и его. */
export const THEME_KEY = "platform.theme";
const LEGACY_KEYS = ["scanner.theme"];

export function savedTheme(): Theme {
  try {
    for (const key of [THEME_KEY, ...LEGACY_KEYS]) {
      const v = localStorage.getItem(key);
      if (v === "dark" || v === "light") return v;
    }
  } catch {
    /* хранилище недоступно */
  }
  return "dark";
}

interface ThemeValue {
  theme: Theme;
  toggleTheme: () => void;
}

const Ctx = createContext<ThemeValue>({ theme: "dark", toggleTheme: () => {} });

/** Светлая или тёмная тема (по умолчанию тёмная), запоминается в браузере. */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>(savedTheme);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* тема продержится до перезагрузки */
    }
  }, [theme]);

  const toggleTheme = useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), []);
  const value = useMemo(() => ({ theme, toggleTheme }), [theme, toggleTheme]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export const useTheme = () => useContext(Ctx);
