/** My Account › Two-step sign-in (#653): the status both ways, the set-up walk, and its refusals. */

import { afterEach, describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { ApiError, apiRequest } from "@/config/api";
import { confirmMfa, enrolMfa, getMfaStatus } from "@/features/accounts/api";
import { TwoStepSignInView, type StatusRead } from "@/features/accounts/TwoStepSignIn";
import { CLOSED, confirmCode, renewCodes, startSetUp, type Panel } from "@/features/accounts/twoStep";
import type { MfaStatus } from "@/features/accounts/types";
import { enrolmentRedirect, MY_ACCOUNT, useAuthStore } from "@/features/auth/store";
import type { AuthUser } from "@/features/auth/types";
import { de } from "@/i18n/de";
import { en } from "@/i18n/en";

vi.mock("@/config/api", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/config/api")>()),
  apiRequest: vi.fn()
}));
afterEach(() => vi.clearAllMocks());

const copy = en.myAccount.twoStep;
const ready = (status: MfaStatus): StatusRead => ({ state: "ready", status });
const offStatus: MfaStatus = { enrolled: false, pending: false, confirmedAt: null, recoveryCodesRemaining: 0 };
const confirmedAt = "2026-09-26T12:00:00Z";
const on = ready({ enrolled: true, pending: false, confirmedAt, recoveryCodesRemaining: 10 });
const secret = "JBSWY3DPEHPK3PXP";
const enrolment = { secret, otpauthUrl: `otpauth://totp/LoonInspect:ada%40example.com?secret=${secret}&issuer=LoonInspect` };
const codes = Array.from({ length: 10 }, (_, index) => `abcde-fghj${"kmnpqrstuv"[index]}`);
const render = (read: StatusRead, panel: Panel, locale: "en" | "de" = "en") =>
  renderToStaticMarkup(
    <TwoStepSignInView read={read} panel={panel} copy={locale === "en" ? copy : de.myAccount.twoStep} locale={locale} />
  );

describe("two-step sign-in on My Account (#653)", () => {
  it("reads and writes through the shared client's /auth/mfa paths", async () => {
    await getMfaStatus();
    await enrolMfa();
    await confirmMfa("123456");
    expect(apiRequest).toHaveBeenNthCalledWith(1, "/auth/mfa");
    expect(apiRequest).toHaveBeenNthCalledWith(2, "/auth/mfa/enrol", { method: "POST" });
    expect(apiRequest).toHaveBeenNthCalledWith(3, "/auth/mfa/confirm", { method: "POST", json: { code: "123456" } });
  });

  it("says off with a Set up button, or on since a date with the recovery codes remaining", () => {
    const off = render(ready(offStatus), CLOSED);
    expect(off).toContain(copy.off);
    expect(off).toContain(">Set up</button>");
    expect(off).not.toContain("On since");
    const enrolled = render(on, CLOSED);
    const day = new Date(confirmedAt).toLocaleDateString("en", { dateStyle: "medium" });
    expect(enrolled).toContain(`On since ${day}.`);
    expect(enrolled).toContain("10 recovery codes remaining.");
    expect(enrolled).not.toContain("Set up");
    expect(render(on, CLOSED, "de")).toContain("Aktiv seit");
    // A set-up left unfinished is still off, and says so; an unreadable status is not "off".
    expect(render(ready({ ...offStatus, pending: true }), CLOSED)).toContain(copy.pending);
    const unknown = render({ state: "failed" }, CLOSED);
    expect(unknown).toContain(copy.unreadable);
    expect(unknown).not.toContain("Set up");
  });

  it("walks Set up → QR code and key → a good code → the ten codes, once → closed", async () => {
    vi.mocked(apiRequest).mockResolvedValueOnce(enrolment);
    const scan = await startSetUp("fallback");
    expect(scan.refresh).toBe(false);
    const scanning = render(ready(offStatus), scan.panel);
    expect(scanning).toContain(`<title>${copy.qrTitle}</title>`);
    expect(scanning).toContain(secret);
    expect(scanning).not.toContain(">Set up</button>");
    vi.mocked(apiRequest).mockResolvedValueOnce({ recoveryCodes: codes, confirmedAt });
    const shown = await confirmCode(enrolment, "123 456", "fallback");
    expect(apiRequest).toHaveBeenLastCalledWith("/auth/mfa/confirm", { method: "POST", json: { code: "123 456" } });
    expect(shown.refresh).toBe(true); // the status is read again, and now says on
    const saving = render(on, shown.panel);
    codes.forEach((code) => expect(saving).toContain(code));
    expect(saving).toContain("never again");
    expect(saving).toContain(">I have saved these</button>");
    expect(render(on, shown.panel, "de")).toContain("nie wieder");
    // "I have saved these" closes the panel, and the codes go with it.
    const closed = render(on, CLOSED);
    expect(closed).toContain("On since");
    codes.forEach((code) => expect(closed).not.toContain(code));
  });

  it("keeps the QR code up and shows the server's sentence when a code is refused", async () => {
    const refused = "That code was not accepted. Scan the QR code again, check the phone's clock, and type the current code.";
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(401, refused));
    const move = await confirmCode(enrolment, "000000", "fallback");
    expect(move).toEqual({ panel: { step: "scan", enrolment, error: refused }, refresh: false });
    const html = render(ready(offStatus), move.panel);
    expect(html).toContain('<p role="alert" class="text-sm text-destructive">That code was not accepted.');
    expect(html).toContain(`<title>${copy.qrTitle}</title>`);
  });

  it("answers a 409 with the server's sentence, a closed panel and a fresh status read", async () => {
    const enrolled = "A second factor is already enrolled on this account. Remove it before enrolling another.";
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(409, enrolled));
    const started = await startSetUp("fallback");
    expect(started).toEqual({ panel: { step: "closed", error: enrolled }, refresh: true });
    expect(render(on, started.panel)).toContain(enrolled);
    const waiting = "There is no enrolment waiting for a code. Start one first.";
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(409, waiting));
    expect(await confirmCode(enrolment, "123456", "fallback")).toEqual({ panel: { step: "closed", error: waiting }, refresh: true });
    // No answer at all: the page's own sentence, and no re-read to prompt.
    vi.mocked(apiRequest).mockRejectedValueOnce(new TypeError("Failed to fetch"));
    expect(await startSetUp("fallback")).toEqual({ panel: { step: "closed", error: "fallback" }, refresh: false });
  });

  it("holds an account the policy asks on My Account until a confirmed code lets it go, codes still shown", async () => {
    const held = { id: "a1", roles: ["viewer"], permissions: [], tenants: [], mfaEnrolmentRequired: true } as unknown as AuthUser;
    useAuthStore.setState({ status: "authenticated", user: held });
    expect(["/", "/devices", MY_ACCOUNT].map((path) => enrolmentRedirect(held, path))).toEqual([MY_ACCOUNT, MY_ACCOUNT, null]);
    expect(en.myAccount.held).toBe("Your administrator requires two-step sign-in for this account. Set it up on My Account; nothing else opens until then.");
    vi.mocked(apiRequest).mockResolvedValueOnce({ recoveryCodes: codes, confirmedAt }).mockResolvedValueOnce({ ...held, mfaEnrolmentRequired: false });
    expect((await confirmCode(enrolment, "123456", "fallback")).panel).toEqual({ step: "codes", codes });
    expect(apiRequest).toHaveBeenLastCalledWith("/auth/me"); // no sign-out: the same session, read again
    expect(enrolmentRedirect(useAuthStore.getState().user, "/devices")).toBeNull();
  });

  it("replaces the recovery codes for a fresh code, shown once, and shows a refused code in the server's words", async () => {
    expect(render(on, CLOSED)).toContain(`>${copy.renew}</button>`);
    vi.mocked(apiRequest).mockResolvedValueOnce({ recoveryCodes: codes, confirmedAt });
    expect(await renewCodes("123456", "fallback")).toEqual({ panel: { step: "codes", codes }, refresh: true }); // count re-read
    expect(apiRequest).toHaveBeenLastCalledWith("/auth/mfa/recovery-codes", { method: "POST", json: { code: "123456" } });
    const wrong = "That code was not accepted: the current six digits from the authenticator app, each good once.";
    vi.mocked(apiRequest).mockRejectedValueOnce(new ApiError(401, wrong));
    const refused = await renewCodes("000000", "fallback");
    expect(refused).toEqual({ panel: { step: "renew", error: wrong }, refresh: false });
    expect(render(on, refused.panel)).toContain(`<p role="alert" class="text-sm text-destructive">${wrong}</p>`);
  });
});
