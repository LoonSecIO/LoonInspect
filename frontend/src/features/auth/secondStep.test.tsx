/** The sign-in page's second step (#653): the password earns a challenge, never a session; a code
 *  redeems it into the session a password alone gives; a refusal is the server's sentence as it came.
 *  Frontend lane (#285), node only: moves run through the reducer, requests through a stubbed fetch. */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ApiError } from "@/config/api";
import { SecondStepForm } from "@/features/auth/SecondStepForm";
import { secondStep, secondStepError, type SecondStep, type SecondStepAction } from "@/features/auth/secondStep";
import { useAuthStore } from "@/features/auth/store";
import type { AuthUser, MfaChallenge } from "@/features/auth/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

const USER: AuthUser = {
  id: "a1", email: "mfa@example.com", displayName: "MFA", roles: ["admin"], permissions: [], isBreakGlass: false, tenant: null, tenants: [], mfaEnrolmentRequired: false
};
const CHALLENGE: MfaChallenge = { challenge: "a1.1790000000.9f86d0", methods: ["totp", "recovery"] };
const CHALLENGED: SecondStepAction = { type: "challenged", challenge: CHALLENGE };
// The server's sentences as backend/app/api/auth.py words them; the page adds none of its own.
const WRONG = "That code was not accepted: six digits, a new one every 30 seconds, each good once; a recovery code works too.";
const EXPIRED = "The sign-in challenge has expired or is not valid. Start again from the password step.";

const answers: Response[] = [];
const fetchStub = vi.fn<typeof fetch>(async () => answers.shift() ?? Promise.reject(new Error("no answer queued")));
const reply = (status: number, body: unknown) => new Response(JSON.stringify(body), { status });
const sent = (call: number) => ({ url: fetchStub.mock.calls[call][0], body: JSON.parse(String(fetchStub.mock.calls[call][1]?.body)) });
const session = () => ({ status: useAuthStore.getState().status, user: useAuthStore.getState().user });
const signedOut = { status: "unauthenticated", user: null } as const;
const run = (...actions: SecondStepAction[]) => actions.reduce<SecondStep | null>(secondStep, null);
const form = (step: SecondStep | null) =>
  renderToStaticMarkup(<SecondStepForm step={step!} copy={en.auth} submitting={false} dispatch={() => {}} onSubmit={() => {}} />);
const refusal = (code: string) => useAuthStore.getState().loginMfa(CHALLENGE.challenge, code).catch((caught: unknown) => caught);

beforeEach(() => {
  // apiRequest reads the CSRF cookie before a POST, and this lane has no DOM to hold one.
  vi.stubGlobal("document", { cookie: "" });
  vi.stubGlobal("fetch", fetchStub);
  useAuthStore.setState(signedOut);
});
afterEach(() => {
  vi.unstubAllGlobals();
  fetchStub.mockClear();
  answers.length = 0;
});

describe("202, then the code step, then signed in", () => {
  it("the password earns a challenge and no session; the code then signs in as a password alone does", async () => {
    answers.push(reply(200, USER), reply(202, CHALLENGE), reply(200, USER));
    expect(await useAuthStore.getState().login("plain@example.com", "pw")).toBeNull();
    const passwordOnly = session();
    useAuthStore.setState(signedOut);

    expect(await useAuthStore.getState().login("mfa@example.com", "pw")).toEqual(CHALLENGE);
    expect(sent(1)).toEqual({ url: "/api/auth/login", body: { email: "mfa@example.com", password: "pw" } });
    expect(session()).toEqual(signedOut);
    const html = form(run(CHALLENGED));
    for (const shape of ['inputMode="numeric"', 'autoComplete="one-time-code"', 'autofocus=""', en.auth.codeLabel]) expect(html).toContain(shape);

    await useAuthStore.getState().loginMfa(CHALLENGE.challenge, "123 456");
    expect(sent(2)).toEqual({ url: "/api/auth/login/mfa", body: { challenge: CHALLENGE.challenge, code: "123 456" } });
    expect(session()).toEqual(passwordOnly);
  });
});

describe("a wrong code", () => {
  it("shows the server's sentence as it came, in either language, and the field starts empty", async () => {
    answers.push(reply(401, { detail: WRONG }));
    const refused = await refusal("000000");
    expect(session()).toEqual(signedOut);
    expect([secondStepError(refused, en.auth), secondStepError(refused, de.auth)]).toEqual([WRONG, WRONG]);
    const step = run(CHALLENGED, { type: "typed", code: "000000" }, { type: "sent" }, { type: "refused", error: WRONG });
    expect(step).toMatchObject({ code: "", error: WRONG });
    expect(form(step)).toContain(`<p role="alert" class="text-sm text-destructive">${WRONG}</p>`);
    // Sending again clears the line, so a second refusal is announced afresh.
    expect(secondStep(step, { type: "sent" })?.error).toBeNull();
  });

  it("an expired challenge is the server's sentence too; a lockout or a silent failure gets none invented", async () => {
    answers.push(reply(401, { detail: EXPIRED }));
    expect(secondStepError(await refusal("123456"), en.auth)).toBe(EXPIRED);
    expect(secondStepError(new ApiError(429, "Too many failed attempts. Try again later."), de.auth)).toBe(de.auth.lockedOut);
    expect(secondStepError(new ApiError(401, null), en.auth)).toBe(en.auth.genericError);
    expect(secondStepError(new TypeError("Failed to fetch"), en.auth)).toBe(en.auth.genericError);
  });
});

describe("the recovery-code path", () => {
  it("switches the input to the xxxxx-xxxxx shape and back, dropping what was typed", () => {
    const recovery = run(CHALLENGED, { type: "typed", code: "123" }, { type: "switched" });
    expect(recovery).toMatchObject({ recovery: true, code: "" });
    const html = form(recovery);
    for (const shape of ['placeholder="xxxxx-xxxxx"', 'inputMode="text"', 'autoComplete="off"', en.auth.recoveryCodeLabel, en.auth.useAuthenticatorCode]) {
      expect(html).toContain(shape);
    }
    expect(html).not.toContain("one-time-code");
    expect(secondStep(recovery, { type: "switched" })).toMatchObject({ recovery: false, code: "" });
  });

  it("posts the recovery code as typed and signs in; a refused one stays, so a typo can be seen", async () => {
    answers.push(reply(200, USER));
    await useAuthStore.getState().loginMfa(CHALLENGE.challenge, "abcde-fghjk");
    expect(sent(0).body).toEqual({ challenge: CHALLENGE.challenge, code: "abcde-fghjk" });
    expect(session()).toEqual({ status: "authenticated", user: USER });
    const typo = run(CHALLENGED, { type: "switched" }, { type: "typed", code: "abcde-fghjx" }, { type: "refused", error: WRONG });
    expect(typo).toMatchObject({ code: "abcde-fghjx", error: WRONG });
  });

  it("is offered only when the challenge names it", () => {
    expect(form(run({ type: "challenged", challenge: { ...CHALLENGE, methods: ["totp"] } }))).not.toContain(en.auth.useRecoveryCode);
  });
});

describe("Start over", () => {
  it("returns to the password step and keeps nothing of the challenge", () => {
    const step = run(CHALLENGED, { type: "switched" }, { type: "typed", code: "abcde" }, { type: "refused", error: EXPIRED });
    expect(secondStep(step, { type: "start-over" })).toBeNull();
    // An answer that lands after starting over has no step left to move.
    expect(secondStep(null, { type: "refused", error: WRONG })).toBeNull();
  });

  it("is a button that moves the step, as the switch is, never one that submits the code", () => {
    const html = form(run(CHALLENGED));
    for (const label of [en.auth.startOver, en.auth.useRecoveryCode]) expect(html).toMatch(new RegExp(`<button type="button"[^>]*>${label}</button>`));
  });
});
