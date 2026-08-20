import { Outlet } from "react-router";
import { MainContainer } from "@/components/layout/MainContainer";
import { Navbar } from "@/components/layout/Navbar";
import { Sidebar } from "@/components/layout/Sidebar";
import { UpdateBanner } from "@/features/system/UpdateBanner";

export function App() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      <UpdateBanner />

      <div className="flex">
        <Sidebar />

        <MainContainer>
          <Outlet />
        </MainContainer>
      </div>
    </div>
  );
}
