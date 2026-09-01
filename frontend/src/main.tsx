import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router";
import { AppRoutes } from "@/routes";
import { AppProviders } from "@/providers/AppProviders";
import { ErrorBoundary } from "@/features/errors/ErrorBoundary";
import "@fontsource/geist-sans/400.css";
import "@fontsource/geist-sans/500.css";
import "@fontsource/geist-sans/600.css";
import "@fontsource/geist-sans/700.css";
import "@/index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      {/* Under AppProviders, not over it: the fallback needs the locale dictionary.
          That leaves a provider's own throw uncaught, which is the honest trade — a
          boundary above the providers could only ever render untranslated English,
          and this is the mount that catches the sign-in and setup pages, the navbar
          and the sidebar, none of which the in-shell boundary in App.tsx wraps. */}
      <AppProviders>
        <ErrorBoundary>
          <AppRoutes />
        </ErrorBoundary>
      </AppProviders>
    </BrowserRouter>
  </React.StrictMode>
);
