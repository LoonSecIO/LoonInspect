import { ApiError } from "@/config/api";
import { passkeySignIn, passkeySignInOptions } from "@/features/auth/api";
import type { AuthUser } from "@/features/auth/types";
import type { Translations } from "@/i18n/en";

/**
 * Passkeys in the browser (#955): whether this page can offer one, the two ceremonies, and the sentence for each
 * way they end short of a session. A passkey is bound to a host name, over HTTPS or at localhost, so a page reached
 * at an IP address, or over plain HTTP anywhere else, offers none (trap 1) and My Account says why, with the
 * address and what to open instead. A browser that answers false to both availability calls, or that lacks the
 * WebAuthn JSON methods (Safari before 18.4, Chrome and Edge before 129, Firefox before 119), offers none either:
 * no control rather than one that fails (trap 6; the Mac app's window is one, and is at 127.0.0.1 besides). The
 * server holds the same address rules (backend/app/core/passkeys.py) and says the refusals it adds in its own words.
 */

export type PasskeyCopy = Translations["auth"]["passkeys"];

/** Where this page is, as the browser sees it: what a passkey made here would be bound to. */
export interface PageAddress {
  hostname: string;
  port: string;
  origin: string;
  /** `window.isSecureContext`: HTTPS without certificate errors, or a loopback host such as localhost. */
  secure: boolean;
}

export type PasskeySupport =
  | { state: "available"; conditional: boolean }
  /** No passkey can work at this address. `localhost` is what to open instead on the machine LoonInspect runs on. */
  | { state: "address"; reason: "ip" | "plain-http"; origin: string; localhost: string }
  /** This browser offers no passkeys here. */
  | { state: "browser" };

type PasskeyApi = {
  parseRequestOptionsFromJSON?: (options: PublicKeyCredentialRequestOptionsJSON) => PublicKeyCredentialRequestOptions;
  parseCreationOptionsFromJSON?: (options: PublicKeyCredentialCreationOptionsJSON) => PublicKeyCredentialCreationOptions;
  isConditionalMediationAvailable?: () => Promise<boolean>;
  isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>;
  prototype?: { toJSON?: unknown };
};

export function pageAddress(): PageAddress {
  return {
    hostname: window.location.hostname,
    port: window.location.port,
    origin: window.location.origin,
    secure: window.isSecureContext === true
  };
}

/** A host that is an IP literal, which can never be a relying-party id: dotted IPv4, or IPv6 in its brackets. */
export function isIpAddress(hostname: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.startsWith("[") || hostname.includes(":");
}

/** The address rule alone (trap 1): null where a passkey can work, or which reason it cannot. */
export function addressRule(address: PageAddress): PasskeySupport | null {
  const localhost = `http://localhost${address.port ? `:${address.port}` : ""}`;
  if (isIpAddress(address.hostname)) return { state: "address", reason: "ip", origin: address.origin, localhost };
  if (!address.secure) return { state: "address", reason: "plain-http", origin: address.origin, localhost };
  return null;
}

async function answersTrue(call: (() => Promise<boolean>) | undefined): Promise<boolean> {
  if (typeof call !== "function") return false;
  try {
    return (await call()) === true;
  } catch {
    return false;
  }
}

function passkeyApi(): PasskeyApi | undefined {
  return (globalThis as { PublicKeyCredential?: PasskeyApi }).PublicKeyCredential;
}

/** What this page can offer: the address first, then the browser's own JSON methods, then its two availability calls. */
export async function passkeySupport(address: PageAddress = pageAddress(), api: PasskeyApi | undefined = passkeyApi()): Promise<PasskeySupport> {
  const rule = addressRule(address);
  if (rule) return rule;
  const credentials = typeof navigator === "undefined" ? undefined : navigator.credentials;
  if (
    !api ||
    typeof api.parseRequestOptionsFromJSON !== "function" ||
    typeof api.parseCreationOptionsFromJSON !== "function" ||
    typeof api.prototype?.toJSON !== "function" ||
    typeof credentials?.get !== "function" ||
    typeof credentials?.create !== "function"
  ) {
    return { state: "browser" };
  }
  const [platform, conditional] = await Promise.all([
    answersTrue(api.isUserVerifyingPlatformAuthenticatorAvailable?.bind(api)),
    answersTrue(api.isConditionalMediationAvailable?.bind(api))
  ]);
  return platform || conditional ? { state: "available", conditional } : { state: "browser" };
}

const isAbort = (caught: unknown): boolean => caught instanceof DOMException && caught.name === "AbortError";

/** The sentence for a ceremony the browser ended, or null when this page ended it (an abort says nothing). */
export function ceremonyError(caught: unknown, copy: PasskeyCopy, kind: "signIn" | "add", origin: string): string | null {
  if (isAbort(caught)) return null;
  const name = caught instanceof DOMException || caught instanceof Error ? caught.name : "";
  if (name === "NotAllowedError") return kind === "signIn" ? copy.cancelledSignIn : copy.cancelledAdd;
  if (name === "InvalidStateError" && kind === "add") return copy.alreadyOnDevice;
  if (name === "SecurityError") return copy.refusedHere(origin);
  if (name === "NotSupportedError") return copy.unsupported;
  return copy.browserFailed;
}

/** The server's sentence when it gave one, which says what to check; the page's own when no answer could be read. */
export function answerError(caught: unknown, copy: PasskeyCopy): string {
  if (caught instanceof ApiError && caught.status === 429) return copy.lockedOut;
  return caught instanceof ApiError && caught.detail ? caught.detail : copy.unreachable;
}

export type SignInOutcome =
  | { kind: "signed-in"; user: AuthUser }
  /** This page ended the request: another way to sign in was chosen, or the page was left. */
  | { kind: "aborted" }
  /** A passkey was chosen and its answer refused, or the browser ended the ceremony: the sentence says which. */
  | { kind: "refused"; error: string }
  /** No challenge came: the server refused this address, or did not answer. */
  | { kind: "unavailable"; error: string };

/**
 * One passkey sign-in: a challenge, the browser's ceremony, the server's verdict. `conditional` is the request the
 * sign-in page keeps open so a password manager offers the passkey in the email field's autofill menu; it says
 * nothing until someone picks a passkey, because a page that greets everyone with an error is broken. `modal` is
 * the Sign in with a passkey button, which covers a security key and a browser without the conditional form.
 */
export async function passkeySignInFlow(mode: "conditional" | "modal", signal: AbortSignal, copy: PasskeyCopy): Promise<SignInOutcome> {
  const api = passkeyApi();
  let options: PublicKeyCredentialRequestOptionsJSON;
  try {
    options = (await passkeySignInOptions()).publicKey;
  } catch (caught) {
    return { kind: "unavailable", error: answerError(caught, copy) };
  }
  if (signal.aborted || !api?.parseRequestOptionsFromJSON) return { kind: "aborted" };
  let answer: AuthenticationResponseJSON;
  try {
    const publicKey = api.parseRequestOptionsFromJSON(options);
    const request: CredentialRequestOptions = mode === "conditional" ? { publicKey, signal, mediation: "conditional" } : { publicKey, signal };
    const credential = (await navigator.credentials.get(request)) as PublicKeyCredential | null;
    if (!credential) return { kind: "aborted" };
    answer = credential.toJSON() as AuthenticationResponseJSON;
  } catch (caught) {
    const error = ceremonyError(caught, copy, "signIn", window.location.origin);
    // The conditional request ends quietly however the browser ends it: nobody asked for it.
    return error === null || mode === "conditional" ? { kind: "aborted" } : { kind: "refused", error };
  }
  try {
    return { kind: "signed-in", user: await passkeySignIn(answer) };
  } catch (caught) {
    return { kind: "refused", error: answerError(caught, copy) };
  }
}

/** The browser's ceremony for a new passkey, from the options a registration challenge answered with. */
export async function createPasskey(options: PublicKeyCredentialCreationOptionsJSON): Promise<RegistrationResponseJSON> {
  const api = passkeyApi();
  if (!api?.parseCreationOptionsFromJSON) throw new DOMException("No WebAuthn JSON methods here", "NotSupportedError");
  const credential = (await navigator.credentials.create({ publicKey: api.parseCreationOptionsFromJSON(options) })) as PublicKeyCredential | null;
  if (!credential) throw new DOMException("The browser made no passkey", "NotAllowedError");
  return credential.toJSON() as RegistrationResponseJSON;
}
