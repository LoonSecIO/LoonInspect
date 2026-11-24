// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation, useNavigate } from "react-router";
import { afterEach, expect, it, vi } from "vitest";
import { PatchPlansPage } from "./PatchPlansPage";
import { ApplicationsOverviewPage } from "@/features/devices/ApplicationsOverviewPage";
import { CatalogPage } from "./CatalogPage";

vi.mock("./PatchPlanWorkspace", () => ({ PatchPlanWorkspace: (props: { planId: string | null; selected: string[]; onOpen: (id: string) => void }) =>
  <div><output aria-label="Selected plan">{props.planId}</output><output aria-label="Selected apps">{props.selected.join(",")}</output>
    <button onClick={() => props.onOpen("second")}>Open second plan</button></div> }));
function History() {
  const nav = useNavigate(); const location = useLocation();
  return <><output aria-label="Location">{location.pathname}{location.search}</output><button onClick={() => nav(-1)}>Back</button><button onClick={() => nav(1)}>Forward</button></>;
}
function page(url: string) {
  return render(<MemoryRouter initialEntries={[url]}><Routes>
    <Route path="/patch-plans" element={<PatchPlansPage />} />
    <Route path="/devices/applications" element={<ApplicationsOverviewPage />} />
    <Route path="/devices/applications/catalog" element={<CatalogPage />} />
  </Routes><History /></MemoryRouter>);
}
afterEach(cleanup);
it.each(["/devices/applications", "/devices/applications/catalog"])("preserves legacy saved-plan links from %s", async path => {
  page(`${path}?plan=first&severity=high&severity=critical&hasKev=true`);
  expect(await screen.findByRole("heading", { name: "Patch Plans" })).toBeTruthy();
  expect(screen.getByLabelText("Selected plan").textContent).toBe("first");
  const url = new URL(screen.getByLabelText("Location").textContent!, "https://example.invalid");
  expect(url.pathname).toBe("/patch-plans"); expect(url.searchParams.getAll("severity")).toEqual(["high", "critical"]);
});
it("keeps saved-plan selection in browser history and on a fresh page load", async () => {
  const view = page("/patch-plans?plan=first&appHash=a&appHash=a");
  expect(screen.getByLabelText("Selected apps").textContent).toBe("a");
  fireEvent.click(screen.getByRole("button", { name: "Open second plan" }));
  expect(screen.getByLabelText("Selected plan").textContent).toBe("second");
  expect(screen.getByLabelText("Selected apps").textContent).toBe("");
  fireEvent.click(screen.getByRole("button", { name: "Back" }));
  expect(screen.getByLabelText("Selected plan").textContent).toBe("first");
  fireEvent.click(screen.getByRole("button", { name: "Forward" }));
  expect(screen.getByLabelText("Selected plan").textContent).toBe("second");
  const url = screen.getByLabelText("Location").textContent!;
  view.unmount(); page(url);
  expect(screen.getByLabelText("Selected plan").textContent).toBe("second");
});
