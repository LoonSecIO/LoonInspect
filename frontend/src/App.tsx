import { MainContainer } from "@/components/layout/MainContainer";
import { Navbar } from "@/components/layout/Navbar";
import { Sidebar } from "@/components/layout/Sidebar";
import { Button } from "@/components/ui/button";

export function App() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />

      <div className="flex">
        <Sidebar />

        <MainContainer>
          <section className="space-y-6">
            <div>
              <p className="text-sm font-medium text-muted-foreground">
                LoonInspect
              </p>
              <h1 className="text-3xl font-bold tracking-tight">
                Backend Security Dashboard
              </h1>
              <p className="mt-2 max-w-2xl text-muted-foreground">
                Monitor MDM sync status, vulnerability manifests, and endpoint
                application inventory.
              </p>
            </div>

            <div className="rounded-lg border bg-card p-6 text-card-foreground shadow-sm">
              <h2 className="text-xl font-semibold">API Connection</h2>
              <p className="mt-2 text-sm text-muted-foreground">
                The Vite dev server proxies frontend requests from{" "}
                <code className="rounded bg-muted px-1 py-0.5">/api</code> to
                FastAPI.
              </p>

              <div className="mt-4">
                <Button>Check API Status</Button>
              </div>
            </div>
          </section>
        </MainContainer>
      </div>
    </div>
  );
}