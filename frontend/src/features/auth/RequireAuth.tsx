import { useEffect } from "react";
import { Navigate, Outlet, useLocation } from "react-router";
import { enrolmentRedirect, useAuthStore } from "@/features/auth/store";
import { useLocale } from "@/i18n/LocaleContext";

export function RequireAuth() {
  const { t } = useLocale();
  const location = useLocation();
  const status = useAuthStore((state) => state.status);
  const user = useAuthStore((state) => state.user);
  const bootstrap = useAuthStore((state) => state.bootstrap);

  useEffect(() => {
    if (status === "unknown") void bootstrap();
  }, [status, bootstrap]);

  if (status === "unknown") {
    // Deliberately blank rather than a login redirect: on a refresh the session is
    // valid but not yet confirmed, and bouncing to /login would log people out visually
    // every time they hit reload.
    return (
      <div className="flex min-h-screen items-center justify-center text-sm text-muted-foreground">
        {t.auth.loading}
      </div>
    );
  }

  if (status === "setup-required") {
    return <Navigate to="/setup" replace />;
  }

  if (status === "unauthenticated") {
    // Carry the attempted path so login can return them where they were headed.
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }

  const held = enrolmentRedirect(user, location.pathname);
  if (held) return <Navigate to={held} replace />;

  return <Outlet />;
}
