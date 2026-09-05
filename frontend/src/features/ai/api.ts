import { apiRequest } from "@/config/api";

export type Provider = "apple_fm" | "openai_compatible" | "anthropic";
export type HostReach = "docker_desktop" | "orbstack" | "colima" | "podman" | "remote_mac" | "custom";
export type KeyRule = "none" | "optional" | "required";
export type Outcome = "answered" | "empty" | "budget_exhausted_thinking" | "error";

export interface ProviderEntry {
  provider: Provider;
  wire: "openai_chat" | "anthropic_messages";
  baseUrl: string;
  model: string;
  key: KeyRule;
  reasoningEffort: string | null;
  usesHostReach: boolean;
  models: string[];
}

export interface HostReachEntry {
  reach: HostReach;
  hostname: string | null;
  implemented: boolean;
}

export interface ProvidersResponse {
  entries: ProviderEntry[];
  reaches: HostReachEntry[];
  reasoningEfforts: string[];
}

export interface HostDetection {
  runtime: string;
  hostOs: string;
  appleSilicon: boolean;
  alias: string;
  aliasResolves: boolean;
  dockerDesktopOnMacos: boolean;
  evidence: Record<string, string>;
}

export interface TestRequest {
  provider: Provider;
  hostReach?: HostReach;
  baseUrl: string;
  model: string;
  apiKey?: string;
  prompt: string;
  reasoningEffort?: string | null;
  maxTokens?: number;
}

export interface TestError {
  kind: string;
  message: string;
  status: number | null;
}

export interface TestResponse {
  provider: Provider;
  wire: string;
  destination: string;
  model: string | null;
  outcome: Outcome;
  content: string;
  reasoning: string | null;
  finishReason: string | null;
  completionTokens: number | null;
  latencyMs: number;
  error: TestError | null;
}

export interface ModelsRequest {
  provider: Provider;
  hostReach?: HostReach;
  baseUrl: string;
  apiKey?: string;
}

export interface ModelEntry {
  id: string;
  label: string | null;
}

export interface ModelsResponse {
  provider: Provider;
  wire: string;
  destination: string;
  models: ModelEntry[];
  latencyMs: number;
  error: TestError | null;
}

/** Ask the endpoint what it serves, through the backend (#322). Nothing of the
 *  fleet leaves; the gate still applies and the share log still gets its row. */
export function listModels(body: ModelsRequest): Promise<ModelsResponse> {
  return apiRequest<ModelsResponse>("/system/ai/models", { method: "POST", json: body });
}

export function getProviders(): Promise<ProvidersResponse> {
  return apiRequest<ProvidersResponse>("/system/ai/providers");
}

export function getHostDetection(): Promise<HostDetection> {
  return apiRequest<HostDetection>("/system/ai/host");
}

/** The one call that dials a model endpoint. Made by the backend, never by the
 *  browser: the key in `body` travels to this product's own API and stops there. */
export function sendTest(body: TestRequest): Promise<TestResponse> {
  return apiRequest<TestResponse>("/system/ai/test", { method: "POST", json: body });
}
