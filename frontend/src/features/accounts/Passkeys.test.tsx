/** My Account › Passkeys (#955): the list, the enrolment form and its walk, removal, and the address and browser
 *  explanations that stand where no passkey can be offered. Node lane: the view server-rendered, the browser's WebAuthn
 *  surface and the shared client stubbed. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ApiError, apiRequest } from "@/config/api";
import { listPasskeys, passkeyRegistrationOptions, removeAccountPasskeys, removePasskey, savePasskey } from "@/features/accounts/api";
import { addPasskey, dropPasskey, PANEL_CLOSED, type PasskeyPanel, type PasskeyRead } from "@/features/accounts/passkeyPanel";
import { PasskeysView } from "@/features/accounts/Passkeys";
import type { Passkey } from "@/features/accounts/types";
import { addressRule, passkeySupport, type PasskeySupport } from "@/features/auth/passkeys";
import { useAuthStore } from "@/features/auth/store";
import type { AuthUser } from "@/features/auth/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

vi.mock("@/config/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/config/api")>()),
  apiRequest: vi.fn()
}));

const copy = en.myAccount.passkeys;
const ORIGIN = "https://inspect.example.com";
const MAC: Passkey = { id: "p1", name: "MacBook Pro", host: "inspect.example.com", createdAt: "2026-11-20T09:00:00Z", lastUsedAt: "2026-11-27T16:30:00Z" };
const KEY: Passkey = { id: "p2", name: "YubiKey", host: "old-name.example.com", createdAt: "2026-10-01T09:00:00Z", lastUsedAt: null };
const AVAILABLE: PasskeySupport = { state: "available", conditional: true };
const OPTIONS = { publicKey: { challenge: "Y2hhbGxlbmdl", rp: { name: "LoonInspect", id: "inspect.example.com" } } };
const ANSWER = { id: "Y3JlZA", rawId: "Y3JlZA", type: "public-key", response: {} };

const ready = (passkeys: Passkey[]): PasskeyRead => ({ state: "ready", passkeys });
const render = (read: PasskeyRead, support: PasskeySupport | null, panel: PasskeyPanel = PANEL_CLOSED, extra: { held?: boolean } = {}, locale: "en" | "de" = "en") =>
  renderToStaticMarkup(
    <PasskeysView read={read} support={support} panel={panel} copy={locale === "en" ? copy : de.myAccount.passkeys} locale={locale} hostname="inspect.example.com" {...extra} />
  );

const create = vi.fn();
beforeEach(() => {
  class FakeCredential {
    toJSON() {
      return ANSWER;
    }
    static parseCreationOptionsFromJSON = vi.fn((options: unknown) => ({ parsed: options }));
    static parseRequestOptionsFromJSON = vi.fn((options: unknown) => ({ parsed: options }));
  }
  vi.stubGlobal("PublicKeyCredential", FakeCredential);
  vi.stubGlobal("navigator", { credentials: { create, get: vi.fn() } });
  create.mockResolvedValue(new FakeCredential());
});
afterEach(() => {
  vi.clearAllMocks();
  vi.unstubAllGlobals();
});

describe("My Account's passkeys (#955)", () => {
  it("reads and writes through the shared client's passkey paths", async () => {
    await listPasskeys();
    await passkeyRegistrationOptions("current password");
    await savePasskey("MacBook Pro", ANSWER as unknown as RegistrationResponseJSON);
    await removePasskey("p 1");
    await removeAccountPasskeys("a1");
    expect(vi.mocked(apiRequest).mock.calls).toEqual([
      ["/auth/passkeys"],
      ["/auth/passkeys/options", { method: "POST", json: { currentPassword: "current password" } }],
      ["/auth/passkeys", { method: "POST", json: { name: "MacBook Pro", credential: ANSWER } }],
      ["/auth/passkeys/p%201", { method: "DELETE" }],
      ["/accounts/a1/passkeys", { method: "DELETE" }]
    ]);
  });

  it("lists each passkey with its name, the host it works at, when it was made and when it last signed in", () => {
    const html = render(ready([MAC, KEY]), AVAILABLE);
    const day = (value: string) => new Date(value).toLocaleDateString("en", { dateStyle: "medium" });
    for (const shape of ["MacBook Pro", copy.worksAt("inspect.example.com"), copy.added(day(MAC.createdAt)), copy.lastUsed(day("2026-11-27T16:30:00Z"))]) {
      expect(html).toContain(shape);
    }
    // A passkey made at another host is listed, and says it is not offered at this one.
    expect(html).toContain(copy.notHere("old-name.example.com"));
    expect(html).not.toContain(copy.notHere("inspect.example.com"));
    expect(html).toContain(copy.neverUsed);
    expect(html.match(/>Remove<\/button>/g)).toHaveLength(2);
    expect(html).toContain(`${copy.add}</button>`);
    expect(render(ready([]), AVAILABLE)).toContain(copy.none);
    // An unreadable list is not an empty one.
    const unread = render({ state: "failed" }, AVAILABLE);
    expect(unread).toContain(copy.unreadable);
    expect(unread).not.toContain(copy.none);
    expect(render(ready([MAC]), AVAILABLE, PANEL_CLOSED, {}, "de")).toContain("Funktioniert unter inspect.example.com");
  });

  it("draws the enrolment form: a name, and the current password the server asks for before any passkey is made", () => {
    const html = render(ready([]), AVAILABLE, { step: "form", error: null });
    expect(html).toMatch(/<input[^>]*id="passkeyName"[^>]*required=""[^>]*maxLength="64"[^>]*autoComplete="off"/);
    expect(html).toMatch(/<input type="password"[^>]*id="passkeyPassword"[^>]*required=""[^>]*autoComplete="current-password"/);
    expect(html).toContain(copy.nameHelp);
    expect(html).toMatch(new RegExp(`<button type="submit"[^>]*>${copy.add}</button>`));
    // The form asks; the browser is not asked for a passkey until it is sent.
    expect(create).not.toHaveBeenCalled();
  });

  it("walks the form: the password earns a challenge, the browser makes the passkey, the server adds it, once", async () => {
    vi.mocked(apiRequest).mockResolvedValueOnce(OPTIONS).mockResolvedValueOnce({ ...MAC });
    const move = await addPasskey("MacBook Pro", "current password", en, ORIGIN);
    expect(move).toEqual({ panel: { step: "closed", error: null, notice: copy.addedNotice("MacBook Pro") }, refresh: true });
    expect(vi.mocked(apiRequest).mock.calls).toEqual([
      ["/auth/passkeys/options", { method: "POST", json: { currentPassword: "current password" } }],
      ["/auth/passkeys", { method: "POST", json: { name: "MacBook Pro", credential: ANSWER } }]
    ]);
    expect(create).toHaveBeenCalledWith({ publicKey: { parsed: OPTIONS.publicKey } });
    expect(render(ready([MAC]), AVAILABLE, move.panel)).toContain(copy.addedNotice("MacBook Pro"));
  });

  it("keeps the form up with the server's sentence for a wrong password, and asks the browser for nothing", async () => {
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(401, "Current password is incorrect"));
    const move = await addPasskey("MacBook Pro", "wrong", en, ORIGIN);
    expect(move).toEqual({ panel: { step: "form", error: "Current password is incorrect" }, refresh: false });
    expect(create).not.toHaveBeenCalled();
    expect(render(ready([]), AVAILABLE, move.panel)).toContain('<p role="alert" class="text-sm text-destructive">Current password is incorrect</p>');
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(429, "Too many failed attempts. Try again later."));
    expect((await addPasskey("MacBook Pro", "wrong", en, ORIGIN)).panel).toEqual({ step: "form", error: en.auth.passkeys.lockedOut });
  });

  it("says the browser's own sentence when it ends the ceremony, and the server's when it refuses the answer", async () => {
    const endings: Array<[string, string]> = [
      ["NotAllowedError", en.auth.passkeys.cancelledAdd],
      ["InvalidStateError", en.auth.passkeys.alreadyOnDevice],
      ["SecurityError", en.auth.passkeys.refusedHere(ORIGIN)],
      ["NotSupportedError", en.auth.passkeys.unsupported],
      ["UnknownError", en.auth.passkeys.browserFailed]
    ];
    for (const [name, sentence] of endings) {
      vi.mocked(apiRequest).mockResolvedValueOnce(OPTIONS);
      create.mockRejectedValueOnce(new DOMException("ended", name));
      expect((await addPasskey("MacBook Pro", "pw", en, ORIGIN)).panel).toEqual({ step: "form", error: sentence });
    }
    const spent = "That passkey request was already answered or has expired. Choose Add a passkey to start again.";
    vi.mocked(apiRequest).mockResolvedValueOnce(OPTIONS).mockRejectedValueOnce(new ApiError(409, spent));
    expect((await addPasskey("MacBook Pro", "pw", en, ORIGIN)).panel).toEqual({ step: "form", error: spent });
    vi.mocked(apiRequest).mockRejectedValueOnce(new TypeError("Failed to fetch"));
    expect((await addPasskey("MacBook Pro", "pw", de, ORIGIN)).panel).toEqual({ step: "form", error: de.auth.passkeys.unreachable });
  });

  it("lets a session the policy holds go once its passkey is added, with no sign-out", async () => {
    const held = { id: "a1", mfaEnrolmentRequired: true } as unknown as AuthUser;
    useAuthStore.setState({ status: "authenticated", user: held });
    vi.mocked(apiRequest).mockResolvedValueOnce(OPTIONS).mockResolvedValueOnce(MAC).mockResolvedValueOnce({ ...held, mfaEnrolmentRequired: false });
    await addPasskey("MacBook Pro", "pw", en, ORIGIN);
    expect(apiRequest).toHaveBeenLastCalledWith("/auth/me");
    expect(useAuthStore.getState().user?.mfaEnrolmentRequired).toBe(false);
    expect(render(ready([]), AVAILABLE, PANEL_CLOSED, { held: true })).toContain(copy.held);
    // While held, removal waits: the server would answer only enrolment.
    expect(render(ready([MAC]), AVAILABLE, PANEL_CLOSED, { held: true })).not.toContain(">Remove</button>");
  });

  it("removes a passkey after a confirmation, then asks whether this browser is still signed in", async () => {
    const confirming = render(ready([MAC]), AVAILABLE, { step: "remove", passkey: MAC, error: null });
    expect(confirming).toContain(copy.removeConfirm("MacBook Pro"));
    vi.mocked(apiRequest).mockResolvedValueOnce(undefined).mockResolvedValueOnce({ setupRequired: false, authenticated: false, version: null });
    expect(await dropPasskey(MAC, en)).toEqual({ panel: PANEL_CLOSED, refresh: true });
    expect(vi.mocked(apiRequest).mock.calls.map((call) => call[0])).toEqual(["/auth/passkeys/p1", "/auth/status"]);
    // It signed this session in, so this session ended with it: the store says so, and the sign-in page follows.
    expect(useAuthStore.getState().status).toBe("unauthenticated");
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(404, "Passkey not found"));
    expect((await dropPasskey(MAC, en)).panel).toEqual({ step: "remove", passkey: MAC, error: "Passkey not found" });
  });

  it("says why no passkey is offered at an IP address or over plain HTTP, with the address and what to open instead", () => {
    const ip = addressRule({ hostname: "127.0.0.1", port: "8001", origin: "http://127.0.0.1:8001", secure: true });
    const plain = addressRule({ hostname: "inspect.corp.example", port: "8001", origin: "http://inspect.corp.example:8001", secure: false });
    expect(ip).toEqual({ state: "address", reason: "ip", origin: "http://127.0.0.1:8001", localhost: "http://localhost:8001" });
    expect(plain).toEqual({ state: "address", reason: "plain-http", origin: "http://inspect.corp.example:8001", localhost: "http://localhost:8001" });
    expect(addressRule({ hostname: "[::1]", port: "", origin: "http://[::1]", secure: true })).toMatchObject({ reason: "ip", localhost: "http://localhost" });
    expect(addressRule({ hostname: "localhost", port: "8001", origin: "http://localhost:8001", secure: true })).toBeNull();
    for (const [support, sentence] of [
      [ip, copy.ipAddress("http://127.0.0.1:8001", "http://localhost:8001")],
      [plain, copy.plainHttp("http://inspect.corp.example:8001", "http://localhost:8001")]
    ] as const) {
      const html = render(ready([MAC]), support);
      expect(html).toContain(sentence);
      // No way to add one, while what is held stays listed and removable.
      expect(html).not.toContain(`${copy.add}</button>`);
      expect(html).toContain(">Remove</button>");
    }
    expect(render(ready([]), ip, PANEL_CLOSED, {}, "de")).toContain("ist eine IP-Adresse");
  });

  it("shows no control where the browser answers false to both availability calls or lacks the JSON methods", async () => {
    const secure = { hostname: "inspect.example.com", port: "", origin: ORIGIN, secure: true };
    const answering = (platform: boolean, conditional: boolean) => ({
      parseRequestOptionsFromJSON: () => ({}) as PublicKeyCredentialRequestOptions,
      parseCreationOptionsFromJSON: () => ({}) as PublicKeyCredentialCreationOptions,
      isUserVerifyingPlatformAuthenticatorAvailable: async () => platform,
      isConditionalMediationAvailable: async () => conditional,
      prototype: { toJSON: () => ({}) }
    });
    expect(await passkeySupport(secure, answering(false, false))).toEqual({ state: "browser" });
    expect(await passkeySupport(secure, answering(true, false))).toEqual({ state: "available", conditional: false });
    expect(await passkeySupport(secure, answering(false, true))).toEqual({ state: "available", conditional: true });
    expect(await passkeySupport(secure, { ...answering(true, true), parseRequestOptionsFromJSON: undefined })).toEqual({ state: "browser" });
    expect(await passkeySupport(secure, undefined)).toEqual({ state: "browser" });
    const html = render(ready([]), { state: "browser" });
    expect(html).toContain(copy.browser);
    expect(html).not.toContain(`${copy.add}</button>`);
    // Still asking: nothing said yet, and no button.
    expect(render({ state: "loading" }, null)).not.toContain(`${copy.add}</button>`);
  });
});
