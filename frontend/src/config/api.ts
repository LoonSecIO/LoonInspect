import { env } from "@/config/env";

type ApiRequestOptions = RequestInit & {
  json?: unknown;
};

export async function apiRequest<TResponse>(
  path: string,
  options: ApiRequestOptions = {}
): Promise<TResponse> {
  const { json, headers, ...requestOptions } = options;

  const response = await fetch(`${env.apiBaseUrl}${path}`, {
    ...requestOptions,
    headers: {
      "Content-Type": "application/json",
      ...headers
    },
    body: json === undefined ? requestOptions.body : JSON.stringify(json),
    credentials: "include"
  });

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }

  return response.json() as Promise<TResponse>;
}