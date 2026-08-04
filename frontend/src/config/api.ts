import { env } from "@/config/env";

/** Carries the HTTP status so callers can tell 401 from 403 from 429 — the previous
 *  generic throw made every failure look the same to the UI. */
export class ApiError extends Error {
  readonly status: number;
  readonly detail: string | null;

  constructor(status: number, detail: string | null) {
    super(detail ?? `API request failed: ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

type ApiRequestOptions = RequestInit & {
  json?: unknown;
};

const CSRF_COOKIE = "loon_csrf";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

let onUnauthorized: (() => void) | null = null;

/** Registered by the auth store so a 401 anywhere in the app drops the session state,
 *  without this module having to import the store and create a cycle. */
export function setUnauthorizedHandler(handler: (() => void) | null): void {
  onUnauthorized = handler;
}

function readCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

export async function apiRequest<TResponse>(
  path: string,
  options: ApiRequestOptions = {}
): Promise<TResponse> {
  const { json, headers, method = "GET", ...requestOptions } = options;

  const requestHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    ...(headers as Record<string, string> | undefined)
  };

  // The server only enforces CSRF on cookie-authenticated mutations. Sending the
  // header on every unsafe method is simpler than tracking which routes are public,
  // and harmless where it isn't checked.
  if (!SAFE_METHODS.has(method.toUpperCase())) {
    const csrfToken = readCookie(CSRF_COOKIE);
    if (csrfToken) requestHeaders["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(`${env.apiBaseUrl}${path}`, {
    ...requestOptions,
    method,
    headers: requestHeaders,
    body: json === undefined ? requestOptions.body : JSON.stringify(json),
    credentials: "include"
  });

  if (!response.ok) {
    let detail: string | null = null;
    try {
      const body = await response.json();
      if (body && typeof body.detail === "string") detail = body.detail;
    } catch {
      // Non-JSON error body; the status alone is enough to act on.
    }

    // A rejected login is a 401 too, but it means "those credentials are wrong", not
    // "your session ended" — routing it through the global handler would be wrong.
    if (response.status === 401 && onUnauthorized && !path.startsWith("/auth/")) {
      onUnauthorized();
    }

    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) {
    return undefined as TResponse;
  }

  return response.json() as Promise<TResponse>;
}
