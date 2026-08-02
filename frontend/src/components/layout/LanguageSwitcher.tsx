import { useEffect, useRef, useState } from "react";
import { useLocale, localeNames, type Locale } from "@/i18n/LocaleContext";
import { cn } from "@/lib/utils";

const flags: Record<Locale, string> = {
  en: "🇺🇸",
  de: "🇩🇪"
};

export function LanguageSwitcher() {
  const { locale, setLocale, t } = useLocale();
  const [open, setOpen] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  return (
    <div className="relative" ref={containerRef}>
      <button
        type="button"
        aria-label={t.common.language}
        onClick={() => setOpen((current) => !current)}
        className="flex h-9 w-9 items-center justify-center rounded-md border border-input bg-background text-lg hover:bg-accent"
      >
        {flags[locale]}
      </button>

      {open && (
        <div className="absolute right-0 z-50 mt-1 w-40 rounded-md border bg-popover p-1 text-popover-foreground shadow-md">
          <button
            type="button"
            onClick={() => {
              setLocale("en");
              setOpen(false);
            }}
            className={cn(
              "flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground",
              locale === "en" && "bg-accent text-accent-foreground"
            )}
          >
            <span className="text-base">{flags.en}</span>
            {localeNames.en}
          </button>
          <button
            type="button"
            onClick={() => {
              setLocale("de");
              setOpen(false);
            }}
            className={cn(
              "flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-sm hover:bg-accent hover:text-accent-foreground",
              locale === "de" && "bg-accent text-accent-foreground"
            )}
          >
            <span className="text-base">{flags.de}</span>
            {localeNames.de}
          </button>
        </div>
      )}
    </div>
  );
}
