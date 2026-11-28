// @vitest-environment jsdom
/** The sign-in page's passkey (#955), with and without the conditional form: the email field offers a passkey beside
 *  the password, a conditional request is open only where the browser has that form, it ends when the person signs in
 *  another way or leaves, and Sign in with a passkey covers the rest. jsdom, with the browser's WebAuthn surface and
 *  LoonInspect's answers stubbed; the real ceremony is the browser lane's (tests/browser/passkey.spec.js). */

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LoginPage } from "@/features/auth/LoginPage";
import { useAuthStore } from "@/features/auth/store";
import type { AuthUser } from "@/features/auth/types";
import { en } from "@/i18n/en";

vi.mock("@/i18n/LocaleContext", async () => {
  const { en: english } = await import("@/i18n/en");
  return { useLocale: () => ({ t: english, locale: "en" }) };
});

const USER = { id: "a1", email: "ada@example.com", displayName: "Ada", roles: ["admin"], permissions: [], isBreakGlass: false, tenant: null, tenants: [], mfaEnrolmentRequired: false } satisfies AuthUser;
const OPTIONS = { publicKey: { challenge: "Y2hhbGxlbmdl", rpId: "localhost", userVerification: "required", timeout: 300000 } };
const ANSWER = { id: "Y3JlZA", rawId: "Y3JlZA", type: "public-key", response: { clientDataJSON: "e30" }, clientExtensionResults: {} };

type Requested = CredentialRequestOptions & { signal: AbortSignal };
let requests: Requested[];
let settle: Array<(credential: unknown) => void>;
const sent: Array<{ path: string; body: unknown }> = [];

function browser({ conditional, platform }: { conditional: boolean; platform: boolean }) {
  class FakeCredential {
    toJSON() {
      return ANSWER;
    }
    static parseRequestOptionsFromJSON = vi.fn((options: unknown) => ({ parsed: options }));
    static parseCreationOptionsFromJSON = vi.fn((options: unknown) => ({ parsed: options }));
    static isConditionalMediationAvailable = vi.fn(async () => conditional);
    static isUserVerifyingPlatformAuthenticatorAvailable = vi.fn(async () => platform);
  }
  vi.stubGlobal("PublicKeyCredential", FakeCredential);
  const get = vi.fn((request: Requested) => {
    requests.push(request);
    return new Promise((resolve, reject) => {
      settle.push(resolve);
      request.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    });
  });
  Object.defineProperty(navigator, "credentials", { configurable: true, value: { get, create: vi.fn() } });
  return { get, credential: new FakeCredential() };
}

function answer(path: string): Response {
  const body = path === "/api/auth/login/passkey/options" ? OPTIONS : path === "/api/auth/login/passkey" ? USER : { detail: "Invalid email or password" };
  return new Response(JSON.stringify(body), { status: path === "/api/auth/login" ? 401 : 200, headers: { "Content-Type": "application/json" } });
}

beforeEach(() => {
  requests = [];
  settle = [];
  sent.length = 0;
  Object.defineProperty(window, "isSecureContext", { configurable: true, value: true });
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    const path = new URL(url, "http://localhost").pathname;
    sent.push({ path, body: init?.body ? JSON.parse(String(init.body)) : null });
    return answer(path);
  }));
  useAuthStore.setState({ status: "unauthenticated", user: null });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

const page = () => render(<MemoryRouter><LoginPage /></MemoryRouter>);
const passkeyButton = () => screen.queryByRole("button", { name: en.auth.passkeys.signIn });

describe("the sign-in page's passkey (#955)", () => {
  it("offers a passkey in the email field's autofill and keeps a conditional request open where the browser has that form", async () => {
    const { get } = browser({ conditional: true, platform: true });
    page();
    expect(screen.getByLabelText(en.auth.email).getAttribute("autocomplete")).toBe("username webauthn");
    await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
    expect(requests[0].mediation).toBe("conditional");
    expect(requests[0].publicKey).toEqual({ parsed: OPTIONS.publicKey });
    expect(requests[0].signal.aborted).toBe(false);
    expect(passkeyButton()).not.toBeNull();
    expect(sent.map((request) => request.path)).toEqual(["/api/auth/login/passkey/options"]);
  });

  it("signs in when the person picks the passkey from the autofill menu", async () => {
    const { credential } = browser({ conditional: true, platform: false });
    page();
    await waitFor(() => expect(settle).toHaveLength(1));
    await act(async () => settle[0](credential));
    await waitFor(() => expect(useAuthStore.getState().status).toBe("authenticated"));
    expect(sent.at(-1)).toEqual({ path: "/api/auth/login/passkey", body: { credential: ANSWER } });
    expect(useAuthStore.getState().user).toEqual(USER);
  });

  it("ends the conditional request when the person signs in with the password, and opens it again when that fails", async () => {
    browser({ conditional: true, platform: true });
    page();
    await waitFor(() => expect(requests).toHaveLength(1));
    fireEvent.change(screen.getByLabelText(en.auth.email), { target: { value: "ada@example.com" } });
    fireEvent.change(screen.getByLabelText(en.auth.password), { target: { value: "wrong password" } });
    fireEvent.click(screen.getByRole("button", { name: en.auth.signIn }));
    expect(requests[0].signal.aborted).toBe(true);
    await screen.findByText(en.auth.invalidCredentials);
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[1].signal.aborted).toBe(false);
  });

  it("ends the conditional request when the person leaves the page", async () => {
    browser({ conditional: true, platform: true });
    const { unmount } = page();
    await waitFor(() => expect(requests).toHaveLength(1));
    unmount();
    expect(requests[0].signal.aborted).toBe(true);
  });

  it("opens no conditional request without that form, and the button asks for a passkey there instead", async () => {
    const { get, credential } = browser({ conditional: false, platform: true });
    page();
    const button = await screen.findByRole("button", { name: en.auth.passkeys.signIn });
    expect(get).not.toHaveBeenCalled();
    fireEvent.click(button);
    await waitFor(() => expect(requests).toHaveLength(1));
    expect(requests[0].mediation).toBeUndefined();
    await act(async () => settle[0](credential));
    await waitFor(() => expect(useAuthStore.getState().status).toBe("authenticated"));
  });

  it("ends the open conditional request before the button asks, so only one request is ever pending", async () => {
    browser({ conditional: true, platform: true });
    page();
    await waitFor(() => expect(requests).toHaveLength(1));
    fireEvent.click(screen.getByRole("button", { name: en.auth.passkeys.signIn }));
    expect(requests[0].signal.aborted).toBe(true);
    await waitFor(() => expect(requests).toHaveLength(2));
    expect(requests[1].mediation).toBeUndefined();
  });

  it("says the browser's own sentence when the button's request is cancelled", async () => {
    browser({ conditional: false, platform: true });
    vi.mocked(navigator.credentials.get).mockRejectedValueOnce(new DOMException("cancelled", "NotAllowedError"));
    page();
    fireEvent.click(await screen.findByRole("button", { name: en.auth.passkeys.signIn }));
    expect((await screen.findByRole("alert")).textContent).toBe(en.auth.passkeys.cancelledSignIn);
  });

  it("shows no passkey control where the browser answers false to both availability calls, as the Mac app's window does", async () => {
    const { get } = browser({ conditional: false, platform: false });
    page();
    await waitFor(() => expect(PublicKeyCredential.isConditionalMediationAvailable).toHaveBeenCalled());
    await act(async () => undefined);
    expect(passkeyButton()).toBeNull();
    expect(get).not.toHaveBeenCalled();
  });

  it("shows no passkey control on a page that is not a secure context: plain HTTP off localhost", async () => {
    const { get } = browser({ conditional: true, platform: true });
    Object.defineProperty(window, "isSecureContext", { configurable: true, value: false });
    page();
    await act(async () => undefined);
    expect(passkeyButton()).toBeNull();
    expect(get).not.toHaveBeenCalled();
    expect(sent).toEqual([]);
  });
});
