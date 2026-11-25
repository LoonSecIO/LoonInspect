// @vitest-environment jsdom
/** The migration briefing panel (#911): sent only on a press, for the scope and the provider on screen, each line worded by the page.
 *  `apiRequest` answers by method: a GET is the status, a POST the briefing. */
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { ApiError, apiRequest } from "@/config/api";
import { FleetBriefing } from "@/features/fleetCatalog/FleetBriefing";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const locale = vi.hoisted(() => ({ current: "en" as "en" | "de" }));
vi.mock("@/i18n/LocaleContext", async () => ({ useLocale: () => ({ locale: locale.current, t: locale.current === "de" ? de : en }) }));
vi.mock("@/config/api", async original => ({ ...await original<typeof import("@/config/api")>(), apiRequest: vi.fn() }));

const request = vi.mocked(apiRequest);
const words = en.fleetPlanning.briefing;
const scope = new URLSearchParams({ deviceScope: JSON.stringify({ match: "all", connectionId: 7, rules: [] }) }).toString();
const saved = { available: true, reason: null, providers: [{ provider: "apple_fm", model: "system" }, { provider: "openai_compatible", model: "qwen" }] };
const serve = (briefing: (provider: unknown) => unknown, status: () => unknown = () => saved) =>
  request.mockImplementation(async (_path, init) => init?.method === "POST" ? briefing((init.json as { provider: unknown }).provider) : status());
const posts = () => request.mock.calls.filter(([, init]) => init?.method === "POST");
const answer = (overrides: object = {}) => ({ outcome: "selected", reason: null, highlights: [{ code: "apps_with_kev", count: 1234 }],
  provider: "openai_compatible", model: "qwen", error: null, ...overrides });
const press = async (name = words.generate) => fireEvent.click(await screen.findByRole("button", { name }));
const unauthorized = "HTTP 401: The endpoint rejected authentication. Check the saved key and its expiry. Response body withheld.";
afterEach(() => { cleanup(); vi.clearAllMocks(); locale.current = "en"; });

it("sends only on a press, pins the provider on screen, and words each lead and count itself", async () => { // #857's, on #910's codes
  let release!: (body: unknown) => void;
  serve(provider => provider === "apple_fm" ? new Promise(done => { release = done; }) : answer());
  render(<FleetBriefing scope={scope} />);
  await screen.findByRole("button", { name: words.generate });
  expect(posts()).toHaveLength(0);
  await press();
  expect(posts().map(([path, init]) => [path, init?.json])).toEqual([[`/fleet-catalog/briefing?${scope}`, { provider: "apple_fm" }]]);
  expect(screen.getByRole("button", { name: words.pending }).hasAttribute("disabled")).toBe(true);
  await act(async () => release(answer({ outcome: "fallback", reason: "unusable", provider: "apple_fm", model: "system",
    highlights: [{ code: "ambiguous_apps", count: 1 }, { code: "scoped_macs", count: 1 }] })));
  expect(screen.getByText(words.unusable("Apple Foundation Models via Docker Desktop · system"))).toBeTruthy();
  expect(screen.getByText("1 app with a Fleet identity that needs review.")).toBeTruthy();
  expect(screen.getByText("1 Mac in the device filter.")).toBeTruthy();
  fireEvent.change(screen.getByLabelText(words.provider), { target: { value: "openai_compatible" } });
  expect(screen.queryByText("1 Mac in the device filter.")).toBeNull();
  await press();
  expect(await screen.findByText(words.selected("OpenAI-compatible · qwen"))).toBeTruthy();
  expect(screen.getByText("1,234 apps with an older installed build carrying a KEV-listed finding.")).toBeTruthy();
  expect(posts().map(([, init]) => init?.json)).toEqual([{ provider: "apple_fm" }, { provider: "openai_compatible" }]);
});

it("renders nothing and sends nothing while a switch is off, and main's sentence when its settings could not be read", async () => {
  serve(() => answer(), () => ({ ...saved, available: false, reason: "consent_off" })); // the cards are listed while consent is off
  const { container } = render(<FleetBriefing scope={scope} />);
  await act(async () => {});
  expect([container.innerHTML, request.mock.calls.length, posts().length]).toEqual(["", 1, 0]);
  cleanup();
  serve(() => answer(), () => { throw new ApiError(500, null); });
  render(<FleetBriefing scope={scope} />);
  expect(await screen.findByText(
    "The migration briefing could not check its settings: the server answered 500 without a reason. Check docker compose logs app.")).toBeTruthy();
});

it("shows a refusal as sent, words every other failure itself, and never names an error kind", async () => {
  const refusal = "AI-inference consent is off; fleet_catalog_briefing may not send bytes to http://127.0.0.1:11434.";
  const failed = (reason: string) => `The migration briefing could not be prepared: ${reason}. Check docker compose logs app.`;
  const cases: [() => unknown, string][] = [[() => { throw new ApiError(409, refusal); }, refusal],
    [() => { throw new ApiError(500, null); }, failed("the server answered 500 without a reason")],
    [() => answer({ outcome: "fallback", reason: "error", error: { kind: "http_status", message: unauthorized, status: 401 } }), words.error(unauthorized)],
    // An unknown code, a count that is not whole, a fallback with no reason, an error with no sentence: answers the page cannot read.
    ...[{ highlights: [{ code: "apps_unknown", count: 1 }] }, { highlights: [{ code: "apps_overdue", count: 1.5 }] }, { outcome: "fallback" },
      { outcome: "fallback", reason: "error" }].map((bad): [() => unknown, string] => [() => answer(bad), failed("the server's answer could not be read")])];
  for (const [reply, text] of cases) {
    serve(reply);
    render(<FleetBriefing scope={scope} />);
    await press();
    expect(await screen.findByText(text)).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/http_status|Check AI settings/);
    cleanup();
  }
});

it("reads in German, and asks for every Mac with no query when no device filter is applied", async () => {
  locale.current = "de";
  const replies = [answer({ highlights: [{ code: "apps_overdue", count: 1 }, { code: "scoped_macs", count: 1234 }] }),
    answer({ outcome: "fallback", reason: "nothing_to_rank", provider: null, model: null, highlights: [{ code: "scoped_macs", count: 1 }] })];
  serve(() => replies.shift());
  render(<FleetBriefing scope="" />);
  await press("Übersicht erstellen");
  expect(await screen.findByText("1.234 Macs im Gerätefilter.")).toBeTruthy();
  expect(screen.getByText(/^1 App /)).toBeTruthy();
  await press("Übersicht erstellen");
  expect(await screen.findByText(de.fleetPlanning.briefing.nothingToRank)).toBeTruthy();
  expect(screen.getByText("1 Mac im Gerätefilter.")).toBeTruthy();
  expect(posts().map(([path]) => path)).toEqual(["/fleet-catalog/briefing", "/fleet-catalog/briefing"]);
});
