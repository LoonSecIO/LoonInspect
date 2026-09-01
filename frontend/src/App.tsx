import { Outlet, useLocation } from "react-router";
import { MainContainer } from "@/components/layout/MainContainer";
import { Navbar } from "@/components/layout/Navbar";
import { Sidebar } from "@/components/layout/Sidebar";
import { ErrorBoundary } from "@/features/errors/ErrorBoundary";
import { UpdateBanner } from "@/features/system/UpdateBanner";

export function App() {
  const location = useLocation();

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      <UpdateBanner />

      <div className="flex">
        <Sidebar />

        <MainContainer>
          {/* Inside the chrome, so a page that throws leaves the nav and sidebar
              standing and the user can click somewhere else — the outer boundary in
              main.tsx would replace those too. Resetting on the path is what makes
              clicking somewhere else actually work. */}
          <ErrorBoundary resetKey={location.pathname}>
            <Outlet />
          </ErrorBoundary>
        </MainContainer>
      </div>
    </div>
  );
}
