# The AI layer: the test box (built 2026-09-05, #319) and the plan behind it

Drafted and built 2026-09-05 on `claude/claude-rc-9d0536` (issue #319). The "Built" section is the
record of what ships; the plan below it is the road it sits on. Grounded in
#28 (body + the 2026-08-18 design comment that supersedes it + the 2026-08-31 v1 ruling),
`backend/app/core/ai.py` (the gate, INSPECT-0112), and the AI doctrine ruled 2026-08-29.
Run this session: one metadata probe, two Ollama chat completions, three Apple FM generations
(one through a throwaway shim). No docker, no Splunk, no container.

## Built (2026-09-05, #319)

What ships, where it lives, and what was proven against it.

- **Backend** `backend/app/ai/`: `providers.py` (the three entries, their defaults, the reach
  table), `adapters.py` (`openai_chat`, `anthropic_messages`, one normalised result, four
  failure kinds), `host_detect.py` (the pure detection over `/proc/version`, `/proc/cpuinfo`
  and an alias resolution, with its evidence). `backend/app/api/ai.py` serves
  `GET /api/system/ai/providers`, `GET /api/system/ai/host` (SYSTEM_READ) and
  `POST /api/system/ai/test` (SYSTEM_WRITE). `backend/app/core/egress.py` gained
  `validate_inference_base_url`, `inference_blocked_reason` and `destination_for_log`;
  `refuse_blocked_resolution` takes the reason function as a parameter. The audit log gained
  `ai.test.sent` (provider, destination, outcome, latency; never the prompt, never the key).
- **Frontend** `frontend/src/features/ai/`: Settings > AI, listed in the sidebar only while
  `ai_features` is on; three cards from the providers endpoint, the detection banner, the
  consent toggle (its first UI), the form, the reply with reasoning collapsed and error text
  verbatim. English and German.
- **Model listing (#322, same day).** "Load models" beside the Model field asks the endpoint
  what it serves — `GET {base}/models` on the OpenAI wire, `GET {base}/v1/models?limit=500` on
  Anthropic's — through `POST /api/system/ai/models`, and fills the suggestions from the reply.
  The gate learned one word for it: `require_ai(..., carries_no_fleet_data=True)` declares a
  control-plane call that leaves the pod carrying nothing of the fleet; the flag, the consent
  and the share-log row are all still required, and the row records `fields: []`, which is
  the honest disclosure. Naming fields while declaring none is refused.
- **One bounded door (#322).** Every call to an endpoint goes through `adapters._request`:
  a wall-clock bound on the whole exchange (`asyncio.timeout`; httpx's read timeout is per
  chunk), a 1 MiB reply cap read while streaming, redirects never followed, and at most two
  calls in flight per process. These close findings F1–F5 of `docs/ai-threat-model.md`.
- **Compose**: `extra_hosts: ["host.docker.internal:host-gateway"]` on `app`.
- **Tests**: `test_ai_adapters.py` (request shapes, parsing, the four failures, the URL rule,
  the provider table), `test_ai_host_detect.py` (table-driven), `test_ai_test_box_db.py`
  (the endpoint through the ASGI client: flag off, consent off, the disclosure row committed
  before the wire is dialled, the key on the wire and nowhere else, Anthropic's wire, reserved
  reach refused by name, blocked URL refused before the gate, an upstream failure reported not
  raised, auditor refused). 75 tests; the full backend suite passes with them.

**The request, in order.** URL rule → gate (`require_ai`, destination = the origin, fields =
`["prompt_text"]`, row committed first) → adapter with a 120 s timeout → reply
`{outcome, content, reasoning?, model, finishReason, completionTokens, latencyMs, error?}`.
`outcome` is `answered` | `empty` | `budget_exhausted_thinking` | `error`. Refusals are HTTP
errors with the gate's own sentence (409), the URL rule's reason (422), or the reach table's
"not yet" (400); an upstream failure is a 200 with `outcome: "error"` and a bounded message,
because the attempt is on record either way.

**Proven from inside the container on this Mac (Docker Desktop 4.82.0):**

| Send | Result |
| --- | --- |
| `GET /host` | `docker_desktop`, `macos`, Apple Silicon; evidence `6.12.76-linuxkit`, `0x61`, alias resolves |
| OpenAI-compatible → Ollama `qwen3.5:2b-mlx`, `reasoning_effort: none` | `answered` in 704 ms, 22 tokens, a joke |
| Apple FM via the shim | `answered` in 1081 ms |
| a model that does not exist | `outcome: error`, `HTTP 404: no such route or model at this URL — model 'no-such-model' not found` |
| `max_tokens: 64` without `reasoning_effort` | `budget_exhausted_thinking`, reasoning attached, `finish_reason: length` |
| the share log | one row per send: tier `ai`, endpoint origin, `{"feature": "ai_test_box", "fields": ["prompt_text"]}` |

**Two findings that changed the adapter.** Ollama's OpenAI endpoint honours the standard
`reasoning_effort` parameter (`"none"` gives a real answer in 57 tokens) and ignores
`think: false`; and a small thinking model spends even 1024 tokens thinking, so the card's
default is `reasoning_effort: none` and the empty-content case is its own outcome, never
"the model said nothing". OpenAI itself refuses unknown parameters, so the field is sent
only when set.

**Not in this PR.** The Apple shim (throwaway, session scratchpad; R1 on #28 open); a live
Anthropic run (needs a key entered by Kyle; the wire is unit-tested); settings persistence;
any caller outside Settings > AI; the runtime-portability issue (still owed).

## First cut, decided 2026-09-05 — the flag-gated test box

Executes today. Scope: prove the round trip behind the flag against three providers and
build the input/output shape.
No persistence, no feature surface, no interaction with any other area of the product.

**Verified this session.** Both backends answered "Tell me a joke." from an identical request
body; only `model` differs.

| Backend | URL from the host | Model id | Latency | Notes |
| --- | --- | --- | --- | --- |
| Ollama 0.33.3 | `http://127.0.0.1:11434` | `qwen3.8:27b-mlx` (build default is the smaller `qwen3.5:2b-mlx`) | 8.1 s cold (model load), 3.7 s warm | reply carries `message.reasoning` (thinking) beside `content`; 190–232 completion tokens for a two-line joke, so `max_tokens` must budget the thinking; 17.7 GiB resident while loaded, unloads after 5 min idle; listens on `*:11434` |
| Apple FM via throwaway shim | `http://127.0.0.1:11535` | `apple-foundation-model` | 1.0 s | shim = `afm_shim.py` (Python stdlib, loopback only, one request at a time) over `afm_say` (Swift CLI around `LanguageModelSession.respond`); `usage` is zeros; no `reasoning` field |
| Anthropic Messages API | `https://api.anthropic.com` | `claude-fable-5-1` | not run | needs Kyle's key; the executor runs it live and records the number |

Shim files live in this session's scratchpad: `/private/tmp/claude-501/-Users-kylepazandak-PycharmProjects-LoonInspect--claude-worktrees-api-migration-strategy-e39d80/026e9c52-bd92-4e70-ac37-8ef982987c9e/scratchpad/afm_shim.py`, `/private/tmp/claude-501/-Users-kylepazandak-PycharmProjects-LoonInspect--claude-worktrees-api-migration-strategy-e39d80/026e9c52-bd92-4e70-ac37-8ef982987c9e/scratchpad/afm_say`. It is running
(started 2026-09-05, loopback only). Restart with
`python3 /private/tmp/claude-501/-Users-kylepazandak-PycharmProjects-LoonInspect--claude-worktrees-api-migration-strategy-e39d80/026e9c52-bd92-4e70-ac37-8ef982987c9e/scratchpad/afm_shim.py /private/tmp/claude-501/-Users-kylepazandak-PycharmProjects-LoonInspect--claude-worktrees-api-migration-strategy-e39d80/026e9c52-bd92-4e70-ac37-8ef982987c9e/scratchpad/afm_say 11535`. Not in the repo; R1 stays open.

**Bonus, verified 2026-09-05: detect Docker Desktop on macOS from inside the container.** A
probe container on this Mac read these signals; the executor builds a pure function over them.

| Signal | Value seen here | Meaning |
| --- | --- | --- |
| `/proc/version` (also `uname -r`) | `Linux version 6.12.76-linuxkit (root@buildkitsandbox) …` | `linuxkit` = Docker Desktop's VM (macOS, or Windows on the Hyper-V backend); `microsoft-standard-WSL2` = Windows WSL2; `orbstack` = OrbStack; a plain distro kernel = Colima, Podman or Engine |
| `/proc/cpuinfo` | `CPU implementer : 0x61`, `CPU part : 0x000` | `0x61` is Apple's implementer id: Apple Silicon host. Intel Macs lack this signal; `x86_64` + `linuxkit` is then ambiguous with Windows Hyper-V |
| `/proc/cmdline` | `… linuxkit.unified_cgroup_hierarchy=1 console=hvc0 root=/dev/vdb rootfstype=erofs …` | second `linuxkit` witness |
| `/sys/class/dmi/id/*`, `/proc/device-tree/*` | absent | not exposed to containers here; never rely on them |
| `/.dockerenv`, `/etc/resolv.conf` "Generated by Docker Engine" | present | Docker generally, not Desktop |
| `getaddrinfo("host.docker.internal")` | `fdc4:f303:9324::254` | the alias resolves; then an HTTP probe of the shim proves reach |

Logic, in `app/core/host_detect.py`: `runtime` = `docker_desktop` if `linuxkit` in `/proc/version`,
`orbstack` if `orbstack`, `wsl2` if `microsoft`, else `unknown`; `apple_silicon` = regex
`CPU implementer\s*:\s*0x61` on `/proc/cpuinfo`; `host_os` = `macos` only when both a VM
runtime and `apple_silicon` hold, else `unknown`; `alias_resolves` from `getaddrinfo`. Returns
the verdict **with the evidence strings**, exposed at `GET /api/system/ai/host`. The Settings ›
AI page pre-selects the "via Docker Desktop" card when `runtime == docker_desktop and host_os
== macos` and shows the evidence under it ("kernel 6.12.76-linuxkit, Apple Silicon"); every
other outcome says what was seen and leaves the choice to the admin. It is a hint, never a
gate: the card stays clickable whatever was detected. Tests: table-driven over fixture strings
(linuxkit + 0x61 → macOS Docker Desktop; WSL2; orbstack; Ubuntu kernel + 0x41 → unknown), plus
the alias probe against a stub resolver.

**Build (one agent turn, one PR).**

- **The AI section: three entries, two wire adapters, one host-reach seam (Kyle, 2026-09-05).**
  Correction accepted the same hour: Ollama is not a provider, it is an OpenAI-compatible
  endpoint, so it is the documented local default of that entry, as #28 already said.
  `provider` is an enum on the request; each entry has its own defaults; the key is
  bring-your-own everywhere ("reward Anthropic and Claude too"). Base URLs follow the SDK
  conventions: OpenAI-style bases end in `/v1`, the Anthropic base does not.

  | `provider` | Wire adapter | Where it runs | Default base URL | Default model | Key |
  | --- | --- | --- | --- | --- | --- |
  | `apple_fm` | `openai_chat` via the shim | the Mac host | `http://{host}:11535/v1` | `apple-foundation-model` | none |
  | `openai_compatible` | `openai_chat` | the Mac host by default (Ollama); or anywhere: OpenAI itself, a gateway, LM Studio, vLLM | `http://{host}:11434/v1` (Ollama); `https://api.openai.com/v1` for OpenAI | `qwen3.5:2b-mlx` (2.9 GiB pull, chosen 2026-09-05 so repeated test sends stop loading the 17.7 GiB `qwen3.8:27b-mlx`; always the `-mlx` tag on Apple Silicon) | optional, bearer |
  | `anthropic` | `anthropic_messages` | Anthropic | `https://api.anthropic.com` | `claude-fable-5-1` (also `claude-opus-5`, `claude-sonnet-5`, `claude-haiku-4-5-20251001`) | required, `x-api-key` |

  "Any others" is the `openai_compatible` entry. A new entry is added only for a different
  wire, as Anthropic has; a different default URL is not a new entry.

- **Host reach: the seam for "a few versions of reaching Apple's FM" (decided 2026-09-05).**
  `{host}` above is neither typed by the admin nor part of the provider. It comes from a
  `host_reach` enum that answers one question: how does this container find the Mac that runs
  the shim, or the Ollama default? The initial design implements exactly one value, Docker Desktop, and
  refuses the others by name, so a future runtime is one table row, one test case and one
  verification run, never a redesign. **In the UI the pair is one card**: "Apple Foundation
  Models via Docker Desktop", read as "click here if you run LoonInspect under Docker Desktop"
  (Kyle, 2026-09-05: the label names the pattern the user is on, not what powers the model).
  The card submits `provider=apple_fm, hostReach=docker_desktop`; there is no separate reach
  control. Each future runtime arrives as its own card, and until it is built it has no pixels
  (no unbuilt pixels, ruled 2026-08-29): one line of copy names OrbStack, Colima and Podman as
  not yet supported and points at the editable URL.

  | `host_reach` | Host name inside the container | Status | Notes |
  | --- | --- | --- | --- |
  | `docker_desktop` | `host.docker.internal` | **implemented in this cut** | verified 2026-09-05 on Docker Desktop 4.82.0 / engine 29.6.1 from inside an `alpine:3` container: the alias resolves (to an IPv6 ULA here) and both the 127.0.0.1-bound shim and Ollama answered through it, so the loopback caveat is closed for Docker Desktop on macOS |
  | `orbstack` | `host.docker.internal` (also `host.internal`) | reserved; refused with "not yet" | commercial licence per #28; alias names to verify on a real install |
  | `colima` | `host.docker.internal` (Lima also `host.lima.internal`) | reserved | MIT; alias and loopback reach to verify |
  | `podman` | `host.containers.internal` | reserved | Apache 2.0 desktop; loopback reach to verify |
  | `remote_mac` | admin-typed host name or IP | reserved | a Mac mini on the network serving the shim to a Linux/NAS-hosted pod; needs a token and TLS on the shim, which bears on R1 |
  | `custom` | the editable URL field, as today | implemented | escape hatch; the share log records whatever was typed |

  `anthropic` ignores `host_reach`; `openai_compatible` uses it only while its URL is the
  host-local default. Only alias names differ across the Docker-family
  runtimes; whether each reaches 127.0.0.1-bound host services is a fact to measure per
  runtime, never assumed. That measurement is the runtime-portability issue still owed.

  `openai_chat`: POST `{base}/chat/completions`, body `{"model", "messages": [{"role": "user",
  "content": prompt}], "temperature": 0.7, "max_tokens": 1024}`, `Authorization: Bearer` only
  when a key is given; read `choices[0].message.content` and, when present, `.reasoning`.
  `anthropic_messages`: POST `{base}/v1/messages`, headers `x-api-key`, `anthropic-version:
  2023-06-01`, body `{"model", "max_tokens": 1024, "messages": [{"role": "user", "content":
  prompt}]}`; join the `text` blocks of `content`, read `usage.output_tokens` and `stop_reason`;
  map 401 (bad key), 429 (rate limit) and 529 (overloaded) to their own messages. Verify the
  Messages API shape and the model ids against the `claude-api` skill at build time; this
  session did not call Anthropic (no key was to be entered).
- Backend `POST /api/system/ai/test`, admin-only, body `{provider, hostReach?, baseUrl, model,
  apiKey?, prompt}`. `hostReach` is resolved to a host name by a pure function (table-tested);
  any value other than `docker_desktop` or `custom` is refused by name with 400 in this cut. In order: validate `baseUrl` (http/https, no userinfo; loopback and private hosts
  allowed, so this is a new rule, not `validate_mdm_base_url`) → `require_ai(db,
  "ai_test_box", destination=baseUrl, fields=["prompt_text"])` → the adapter call with a 120 s
  timeout → reply `{provider, content, reasoning?, model, latencyMs, completionTokens?}`. Typed
  errors, each with its own message: flag off, consent off, bad URL, unreachable, timeout,
  non-200 (status + first 300 chars of body), malformed JSON, empty content. Nothing stored
  beyond the share-log row the gate writes; the key is request-scoped, never logged, never
  echoed back.
- Frontend: a **Settings › AI** section, listed in Settings only while `ai_features` is on (no
  top-level nav item; `routes.tsx:63` stands). Content in this cut: three choice cards, "Apple
  Foundation Models via Docker Desktop", "OpenAI-compatible (Ollama on this Mac by default)",
  and "Anthropic"; picking a card fills the defaults and, for the Apple card, the host reach.
  Then base URL (editable), model, key (password field, required for Anthropic), prompt
  (default "Tell me a joke."), Send. Shows content, reasoning collapsed when present, model, latency, and error
  text verbatim. Copy: needs the AI flag and the AI-inference consent; every send writes a
  share-log row naming the destination and the one field that left (`prompt_text`).
- Compose: `extra_hosts: ["host.docker.internal:host-gateway"]` on `app`.
- Tests: httpx `MockTransport` per adapter — request shaping and headers (key present on the
  wire, absent from every log line), `reasoning` passthrough, Anthropic text-block join,
  timeout, 401/429/500/529, malformed body, empty content; gate refusals reuse the fixtures in `test_ai_gate_db.py`;
  assert the disclosure row is committed before the transport is called. The two live runs
  are manual, recorded in the PR against the numbers above.

**Caveats for the executor.**

- Container runtime: this Mac has Docker Desktop only (context `desktop-linux`; no OrbStack,
  Colima or Podman installed, checked 2026-09-05), so `host.docker.internal` resolves without
  compose changes here. First step for the executor, from inside any container:
  `curl -s http://host.docker.internal:11535/v1/models` — that proves the loopback-bound shim
  is reachable before any code is written. The record (#28 design comment, 2026-08-18) on other
  runtimes: OrbStack carries its own commercial licensing and is not the open-source escape
  hatch; the free ones are Colima (MIT), Rancher Desktop and Podman Desktop (Apache 2.0);
  Podman's alias is `host.containers.internal`; Docker Engine on Linux needs the
  `host-gateway` add-host and its gateway lands on the bridge IP, where 127.0.0.1-bound host
  services are not reachable. If the shim is ever unreachable, bind it to the bridge address or
  `0.0.0.0` behind a token, never silently to the LAN. Ollama already listens on `*:11434`.
  The runtime-portability verification issue that comment asked for was never filed; it is
  still owed.
- Consent: the box is off-pod by the gate's definition, so both switches must be on. This
  decides R2 for the box: any HTTP hop is off-pod.
- Out of scope for this cut: settings persistence or migration, sentence-to-filter, any nav
  item, streaming, tool calling, JSON-schema output, any caller outside the Settings page.

## What is already decided (and this plan does not reopen)

- **Client, not server.** The container speaks OpenAI-compatible `POST /v1/chat/completions`
  to an admin-configured URL. No host agent in this repo. Ollama is the documented default;
  Apple Foundation Models (AFM) is *one backend*, reached through a shim on the Mac host.
- **Nothing hardcodes a host name.** `host.docker.internal` (Docker Desktop/Engine),
  `host.containers.internal` (Podman) — the admin types the URL, the docs list the names.
- **The gate exists and nothing calls it.** `require_ai(db, feature, destination, fields)`:
  flag `ai_features` (default off) + consent `ai_inference` (default off) + one share-log
  disclosure row per off-pod call, committed before the first byte moves, 90-day retention.
- **Doctrine** (`ai.py` docstring, `docs/v-never.md`): no model-sourced numbers; fleet data
  (including typed search strings) runs BYO-key or on-device only; everything defaults off;
  no silent egress. Ruled feature #1: **sentence-to-filter, chips before execution**.
- **Pod is GPU-less and never pretends to infer.** The AI layer is interactive-only; it is
  never on the sweep path and never runs per device.

## What "pigeon-holed" means in code

The model gets exactly one job at a time, and each job is a *slot* with a typed contract:
free text in, a JSON document matching a schema out, and code (never the model) turns that
document into the thing the user sees. The model's output never reaches a data path, a
wire event, or a number. Slot 1 is sentence → `/api/changes` query params.

## What this Mac can do (verified today)

| Fact | Value |
| --- | --- |
| Host | macOS 27.0 beta (26A5406e), Apple M4 Max, Xcode 26.6 (macOS 26.5 SDK) + Swift 6.3.3 |
| AFM availability | `available`; `contextSize` = 8,192 (queried 2026-09-05, metadata only) |
| PyObjC bridge | not installed in the system Python; irrelevant if a shim serves HTTP |
| Container → host | compose has no `extra_hosts` yet; only Docker Desktop resolves the name |

AFM facts, verified on this Mac 2026-09-05 unless marked: the context window is a **runtime
value**, `SystemLanguageModel.contextSize` (SDK: available since 26.0, throws when the model is
unavailable), and it returned **8,192 tokens** here, shared by instructions, prompt and output.
The SDK's `exceededContextWindowSize` doc string still says 4,096: stale text, not the limit.
Whether older Apple silicon reports less is **unverified** (Kyle: M2 or later gets 8k), so the
shim's health endpoint must surface `contextSize` rather than hardcode either number.
`tokenCount(for:)` exists since 26.4, so a shim can budget prompts exactly;
`GenerationOptions.maximumResponseTokens` is the `max_tokens` mapping. A `rateLimited` error
case exists in the SDK with no documented trigger in the interface, so the spike must provoke
it. Guided generation is native (`@Generable`); whether a given shim maps OpenAI
`response_format: json_schema` onto it is unknown. Availability is a runtime answer too
(`SystemLanguageModel.default.availability`, `available` here), and the probe must surface it.

## The work, as agent turns (one issue each, in order)

1. **Spike on the host Mac (Kyle, ~half a day, no repo change).** Run one OpenAI-compatible
   AFM shim and Ollama side by side. Record for each: `GET /v1/models` shape, a chat
   completion with `temperature: 0` + `response_format` json_schema, p50 latency for a
   ~300-token prompt, behaviour at the `contextSize` ceiling (8,192 here), availability/rate-limit errors, auth
   (does the shim accept a bearer token at all). Output: a comment on #28 with the table.
   Decides R1 below. Runs in parallel with 2; blocks the docs wording only.
2. **Endpoint settings + probe.** Columns on the data-sharing settings row (the same row
   the consent lives on): `ai_endpoint_url`, `ai_model`, `ai_api_key` (encrypted with the
   existing `encryption_key`, as Jamf credentials are). URL validation is a *new* rule beside
   `core/egress.py:validate_mdm_base_url`: loopback/private hosts are **allowed** here because
   the operator typed them and every call is disclosed — the MDM guard's SSRF posture would
   refuse the only URLs this feature will ever see. `GET /api/system/ai/probe` calls
   `/v1/models` with a 5 s timeout and reports reachable / model present / error text.
   Settings › Data Sharing gains the three fields and the probe result; copy states the
   runtime host names. Env kill-switch mirroring `COMMUNITY_SHARING=false`. Tests: DB
   round-trip, key never returned by the API, probe against an httpx `MockTransport`.
3. **The client (`backend/app/ai/client.py`).** One function: `complete(db, feature, *,
   schema, messages, fields) -> dict`. It calls `require_ai` first, then `httpx` with a hard
   timeout (20 s), `max_tokens` ≤ 512, no retries on 5xx for interactive use, a process-wide
   semaphore of 2, strict JSON parse, unknown keys dropped, and a typed error for every
   failure path (flag off, consent off, unreachable, timeout, 401, malformed, empty). No
   caller yet. Tests against `MockTransport` for every failure path; one live test marked
   `@pytest.mark.hostbridge`, deselected by default (add the marker to `pyproject.toml`;
   there is no markers section today). CI never sees a real model: GitHub macOS runners
   have no Apple Intelligence.
4. **Slot 1 — sentence-to-filter on the changes feed.** Prompt + schema whose fields are
   exactly the existing `/api/changes` params (`connectionId`, `subjectId`, `subjectKind`,
   `minLevel`, page size) plus an *enum* time window (`24h|7d|30d`) — the model never emits
   a date; code resolves the enum to absolute timestamps. Disclosure `fields=["query_text"]`
   (typed text is fleet data → consent required, see R2). UI: text box on the changes
   filter bar, result rendered as chips, nothing executes until the user clicks Apply, chips
   are editable. Reserved-ID and wire vocabulary untouched. Tests: schema round-trip,
   unknown key dropped, relative window resolved by code, a malformed reply yields "could not
   parse" and no chips.
5. **Docs + copy, written last.** This file becomes the contract: endpoint, what leaves the
   pod, the three host names, Ollama default, AFM-via-shim, doctrine restated. README gets
   one sentence. `routes.tsx:63` keeps "No /ai" until 4 ships; no nav item ever, the feature
   lives inside the surfaces it filters. Also file the runtime-portability verification issue
   the design comment asked for, if none exists.

Compose change (with 2): `extra_hosts: ["host.docker.internal:host-gateway"]` on `app`, so
Docker Engine on Linux behaves like Desktop; harmless where it already resolves.

## Not in scope

No host agent in this repo. No per-device or sweep-time inference. No macOS-only code path.
No chat surface. No embeddings/RAG. No second slot until slot 1 has user evidence. No AI
sentence in the 2026-09-17 announcement (ruled 2026-08-31).

## Rulings needed from Kyle

- **R1 — shim.** Third-party OpenAI-compatible AFM shim (as ruled 2026-08-18) vs. a ~200-line
  Swift shim of our own in a sibling LoonSecIO repo. Recommend: third-party for the spike;
  write our own only if the spike finds a gap in structured output, auth, or availability.
- **R2 (decided for the test box, confirm as the general rule) — is the host Mac "on-device"?** The gate treats `destination=None` as on-pod. Any HTTP
  hop leaves the container's trust boundary. Recommend: every endpoint call is off-pod (flag
  + consent + disclosure), including AFM on the same Mac. Conservative, and it makes the
  disclosure row the single audit trail.
- **R3 (deferred; the test box persists nothing) — where the config lives.** Settings row + admin UI (recommended, matches "admin-
  configured URL") vs. env only. Env keeps a kill-switch either way.
- **R4 (deferred) — first surface.** Changes feed (recommended; doctrine's #1) vs. the devices list.
