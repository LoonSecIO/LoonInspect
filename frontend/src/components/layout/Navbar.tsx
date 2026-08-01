import { ShieldCheck } from "lucide-react";
import { useTheme } from "@/hooks/useTheme";
import { Button } from "@/components/ui/button";

export function Navbar() {
  const { theme, toggleTheme } = useTheme();

  return (
    <header className="sticky top-0 z-40 border-b bg-background/95 backdrop-blur">
      <div className="flex h-14 items-center justify-between px-6">
        <div className="flex items-center gap-2 font-semibold">
          <ShieldCheck className="h-5 w-5 text-primary" />
          <span>LoonInspect</span>
        </div>

        <Button variant="outline" size="sm" onClick={toggleTheme}>
          {theme === "dark" ? "Light" : "Dark"} mode
        </Button>
      </div>
    </header>
  );
}