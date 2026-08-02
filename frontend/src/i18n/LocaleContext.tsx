import { createContext, useCallback, useContext, useEffect, useMemo, useState, type PropsWithChildren } from "react";
import { en } from "@/i18n/en";
import { de } from "@/i18n/de";

export type Locale = "en" | "de";

const dictionaries = { en, de };

// Endonyms — each language's own name for itself, spelled the way its speakers spell it.
// Not translated: it should read "Deutsch" even when the UI is in English, and vice versa.
export const localeNames: Record<Locale, string> = {
  en: "English",
  de: "Deutsch"
};

interface LocaleContextValue {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: typeof en;
}

const LocaleContext = createContext<LocaleContextValue | null>(null);

function getInitialLocale(): Locale {
  const stored = window.localStorage.getItem("locale");
  if (stored === "en" || stored === "de") return stored;
  return navigator.language.toLowerCase().startsWith("de") ? "de" : "en";
}

export function LocaleProvider({ children }: PropsWithChildren) {
  const [locale, setLocaleState] = useState<Locale>(getInitialLocale);

  useEffect(() => {
    document.documentElement.lang = locale;
    window.localStorage.setItem("locale", locale);
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    setLocaleState(next);
  }, []);

  const value = useMemo<LocaleContextValue>(
    () => ({ locale, setLocale, t: dictionaries[locale] }),
    [locale, setLocale]
  );

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

export function useLocale() {
  const context = useContext(LocaleContext);
  if (!context) throw new Error("useLocale must be used within a LocaleProvider");
  return context;
}
