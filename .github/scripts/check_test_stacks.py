#!/usr/bin/env python3
"""Nothing this repository starts for a test may be counted by LoonSec's production service as an install (#821).

It reads every tracked workflow's run steps, shell script and compose file (any YAML file with a top-level `services:`, whatever
its name). It fails a container a step or script starts, and a service a compose file other than SHIPPED defines, that could be
LoonInspect with neither UPDATE_CHECK=false nor an UPDATE_CHECK_URL off PRODUCTION_HOSTS. Without the setting, a container passes
only on an image NOT_THE_APP names or, one it cannot read, on a `# not the app image` comment directly above; an option it does
not know fails, as it then cannot tell the image. A compose start passes on the step's env or an earlier unindented `export`, and
only if each file it may start (-f, --file, the env's COMPOSE_FILE, any COMPOSE_FILE= in the step or script; from the checkout's
root) is a tracked compose file, held to its own rule. Unseen: what an action, a job's `services:`, swarm or a program other than
sh starts (make, python, podman); a command built at run time; a compose file written at run time and found by its default name;
env from $GITHUB_ENV; --env-file, env_file; an UPDATE_CHECK the step sets over its env; LoonInspect.app (#820); docs/.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
from dataclasses import dataclass, field
from itertools import takewhile
from pathlib import Path
from urllib.parse import urlsplit

try:
    import yaml
except ImportError:  # GitHub's runner images ship PyYAML; main() says so rather than install anything unpinned
    yaml = None

ROOT = Path(__file__).resolve().parents[2]
PRODUCTION_HOSTS = {"api.next.loonsec.io", "api.loonsec.io"}  # the name v1.2.0 asks by default, and the one to come
FALSE = {"0", "off", "f", "false", "n", "no"}  # what the app's settings read as false
SHIPPED = {"docker-compose.yml", "docker-compose.external.yml", "docker-compose.pull.yml"}  # an operator's: the default
NOT_THE_APP = {  # images that may start without the setting, by repository name, and what each is
    "postgres": "PostgreSQL, the server the smoke checks and the database lane stand up",
    "looninspect-db": "the database sidecar ops/postgres builds: Postgres and looninspect-db-init, never the app",
    "trufflehog": "the secret scanner .githooks/pre-commit runs",
}
MARKER = "not the app image"
NEITHER = "with neither UPDATE_CHECK=false nor an UPDATE_CHECK_URL off LoonSec's production hosts"
DOCKER = re.compile(r"(?:^|(?<=[\s;&|()`'\"{]))(?:[\w.-]*/)*docker(?:-compose)?(?=[ \t]|\\\n)", re.M)
OPERATORS = ";&|()<>\n"
STARTS = {"up", "run", "create", "start", "restart", "watch", "scale"}  # the compose commands that start a container
GLOBAL_VALUES = {"-c", "--context", "-H", "--host", "--config", "-l", "--log-level", "--tlscacert", "--tlscert", "--tlskey"}
RUN_FLAGS = {"-d", "--detach", "--rm", "-i", "--interactive", "-t", "--tty", "--init", "--privileged", "-P", "--publish-all",
             "--read-only", "-q"}  # `docker run --help`: the image is the first word neither an option nor an option's value
RUN_VALUES = set(" ".join(("-e --env --env-file -p --publish -v --volume --mount -u --user -w --workdir --name --network",
                           "--entrypoint --platform -h --hostname --add-host -l --label -m --memory --restart --pull")).split())
Text = type("Text", (str,), {"line": 1})  # a YAML string, and the line its text starts on, below a block's indicator


@dataclass
class Seen:
    path: str
    line: int
    image: str
    env: dict = field(default_factory=dict)
    where: str = ""
    passed: str | None = None  # "the setting", "not the app" or "the comment"
    why: str | None = None  # why it would be counted


def _load(text: str) -> dict:
    def string(loader, node):
        found = Text(loader.construct_scalar(node))
        found.line = node.start_mark.line + 1 + (node.style in ("|", ">"))
        return found

    def tagged(loader, suffix, node):  # compose's !reset and !override
        build = {yaml.MappingNode: loader.construct_mapping, yaml.SequenceNode: loader.construct_sequence}
        return None if suffix == "reset" else build.get(type(node), loader.construct_scalar)(node)

    loader = type("Loader", (yaml.SafeLoader,), {})
    loader.add_constructor("tag:yaml.org,2002:str", string)
    loader.add_multi_constructor("!", tagged)
    return data if isinstance(data := yaml.load(text, Loader=loader), dict) else {}


def _assignments(words) -> dict[str, str]:
    return {k: v.strip("\"'") for k, eq, v in (str(w).partition("=") for w in words) if eq and re.fullmatch(r"[A-Za-z_]\w*", k)}


def _env(node) -> dict[str, str]:
    env = (node.get("env") or node.get("environment")) if isinstance(node, dict) else None
    return {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else _assignments(env or [])


def keeps_out(env: dict) -> bool:
    """Whether an environment keeps an instance out of the count: the check off, or asked of a host that is not production."""
    if str(env.get("UPDATE_CHECK", "")).strip().lower() in FALSE:
        return True
    url = str(env.get("UPDATE_CHECK_URL", "")).strip()
    host = (urlsplit(url).hostname or "").rstrip(".") if "://" in url and "$" not in url else ""
    return bool(host) and host not in PRODUCTION_HOSTS


def repository(image: str) -> str:
    """An image's repository name: ghcr.io/loonsecio/looninspect-db:v1.2.0 is looninspect-db."""
    return image.split("@")[0].rsplit("/", 1)[-1].split(":")[0]


def _start(text: str, i: int, end: int = -1) -> tuple[str, list[str], bool] | None:
    """The command at text[i], its arguments split as sh splits them, and whether its quotes close, when it starts a
    container or a compose stack. It ends at an operator, a newline, a comment or `end`, the quote closing sh -c '…'."""
    lexer = shlex.shlex(re.sub(r"\\\n", " ", text[i : end if end > i else None]), posix=True, punctuation_chars=OPERATORS)
    lexer.whitespace, lexer.whitespace_split, lexer.commenters = " \t\r", True, ""
    words, closed = [], True
    try:
        words += takewhile(lambda word: not word or word[0] not in OPERATORS + "#", lexer)
    except ValueError:  # quotes that do not close: a start this cannot read, if it is a start at all
        closed = False
    rest = words[1:]
    if words[0].endswith("docker-compose"):
        return ("docker-compose", rest, closed) if STARTS & set(rest) else None
    while rest and rest[0].startswith("-"):
        rest = rest[2:] if rest[0] in GLOBAL_VALUES else rest[1:]
    rest = rest[1:] if rest[:1] == ["container"] else rest
    if rest[:1] in (["run"], ["create"]):
        return "docker " + rest[0], rest[1:], closed
    return ("docker compose", rest[1:], closed) if rest[:1] == ["compose"] and STARTS & set(rest[1:]) else None


def _run_options(args: list[str]) -> tuple[dict[str, str], str | None, str]:
    """docker run's -e assignments, its image (None when the reading stops before one), and where the reading stopped."""
    env, i = {}, 0
    while i < len(args) and args[i].startswith("-") and args[i] != "--":
        word, name, value = args[i], "", ""
        if word.startswith("--") and "=" in word:
            name, _, value = word.partition("=")
        elif word in RUN_VALUES and i + 1 < len(args):
            name, value, i = word, args[i + 1], i + 1
        elif word[:2] in RUN_VALUES and len(word) > 2:
            name, value = word[:2], word[2:]
        elif word not in RUN_FLAGS and not re.fullmatch(r"-[ditPq]+", word):
            return env, None, f"{word}, an option it does not know: write it --option=value, or add it to RUN_FLAGS or RUN_VALUES"
        env |= _assignments([value]) if name in ("-e", "--env") else {}
        i += 1
    i += i < len(args) and args[i] == "--"
    return (env, args[i], "") if i < len(args) else (env, None, "the end of the command")


def _container(seen: Seen, command: str, stop: str, lines: list[str]) -> Seen:
    image, own = seen.image, repository(seen.image).startswith("looninspect")  # looninspect-db passed already
    marked = any(MARKER in t.lower() for t in takewhile(lambda t: t.lstrip().startswith("#"), reversed(lines[: seen.line - 1])))
    if keeps_out(seen.env) or repository(image) in NOT_THE_APP or ("$" in image and marked):
        seen.passed = "the setting" if keeps_out(seen.env) else "the comment" if "$" in image else "not the app"
    elif image == "?":
        seen.why = f"{command} starts a container {NEITHER}, and this check cannot tell its image: it stopped at {stop}."
    elif "$" in image:
        seen.why = (f"{command} starts {image}, which this check cannot read, {NEITHER}. Give it UPDATE_CHECK=false or, if "
                    f"it is never LoonInspect, say what it is in a '# {MARKER}: …' comment directly above.")
    else:
        seen.why = (f"{command} starts {'LoonInspect, ' * own}{image}, {NEITHER}, so from v1.2.0 LoonSec's production service "
                    f"would count it as an install (#821): give it UPDATE_CHECK=false{', or add it to NOT_THE_APP' * (not own)}.")
    return seen


def _script(path: str, text: str, first: int, env: dict, lines: list[str], where: str, compose: set) -> list[Seen]:
    """Every container start and compose start in a workflow step's run, or in a shell file; `compose`: the files it reads."""
    found = []
    for match in DOCKER.finditer(text):
        begin = text.rfind("\n", 0, match.start()) + 1
        line = first + text.count("\n", 0, match.start())
        end = text.find(quote, match.end()) if (quote := text[match.start() - 1 : match.start()]) in ("'", '"') else -1
        if text[begin : match.start()].lstrip().startswith("#") or not (started := _start(text, match.start(), end)):
            continue
        command, args, closed = started
        if not closed:
            seen = Seen(path, line, "?", why=f"this check cannot read this {command}: an open quote, or a backslash at its end.")
        elif "compose" in command:
            seen = Seen(path, line, command, {**env, **_assignments(re.findall(r"^export\s+(\w+=\S*)", text[:begin], re.M))})
            named = re.findall(r"(?:^| )(?:--file[= ]|-f ?)(\S+)", " ".join(takewhile(lambda word: word not in STARTS, args)))
            named += [f.strip("\"'") for v in re.findall(r"\bCOMPOSE_FILE=(\S+)", text) for f in v.split(":")]  # anywhere in it
            unread = [f for f in named + seen.env.get("COMPOSE_FILE", "").split(":") if f and f.removeprefix("./") not in compose]
            seen.passed = "the setting" if keeps_out(seen.env) and not unread else None
            seen.why = None if seen.passed else f"{command} starts " + (
                f"{unread[0]}, not a tracked compose file, so this check cannot read it: start one that is (#821)." if unread
                else f"a stack {NEITHER} set for it: give it UPDATE_CHECK=false in the step's env, or export it first (#821).")
        else:
            run_env, image, stop = _run_options(args)
            seen = _container(Seen(path, line, image or "?", run_env), command, stop, lines)
        seen.where = where
        found.append(seen)
    return found


def check(root: Path, paths: list[str]) -> list[Seen]:
    """Every container start, compose start and compose service in the files at `paths`, relative to `root`."""
    found, data, texts = [], {}, {p: (root / p).read_text(errors="replace") for p in sorted(paths) if (root / p).is_file()}
    for path in (p for p in texts if p.endswith((".yml", ".yaml"))):  # a compose file is told by what it holds, not its name
        try:
            data[path] = _load(texts[path])
        except yaml.YAMLError as exc:  # compose may read what PyYAML cannot, so a file this check cannot load fails
            found.append(Seen(path, 1, "?", where=path, why=f"this check cannot load it as YAML: {' '.join(str(exc).split())}"))
    compose = SHIPPED | {p for p, d in data.items() if isinstance(d.get("services"), dict)}  # no workflow has a top-level one
    for path, text in texts.items():
        lines = text.splitlines()
        if path.startswith(".github/workflows/") and path in data:
            for job_id, job in (data[path].get("jobs") or {}).items():
                for n, step in enumerate((job or {}).get("steps") or [], 1):
                    if run := step.get("run"):
                        env = {**_env(data[path]), **_env(job), **_env(step)}
                        found += _script(path, run, run.line, env, lines, f"job {job_id}, step {step.get('name') or n}", compose)
        elif path in compose - SHIPPED:
            for name, service in ((n, s if isinstance(s, dict) else {}) for n, s in data[path]["services"].items()):
                image, build, app = service.get("image"), service.get("build"), name == "app" or "extends" in service
                context = str((build.get("context") if isinstance(build, dict) else build) or "").strip("./")
                if app or (image and repository(image) not in NOT_THE_APP) or (build and context != "ops/postgres"):
                    seen = Seen(path, name.line, str(image or "its image"), _env(service), path)
                    found.append(_container(seen, f"service {name}", "", lines))  # a service: the same rule as a container
        elif path.endswith(".sh") or re.match(r"#!\s*\S*(?:/|env\s+)(?:ba)?sh\b", text):
            found += _script(path, text, 1, {}, lines, path, compose)
    return found


def main() -> int:
    if yaml is None:
        print("::error::PyYAML is not installed, so this check cannot read the workflows: run it with `uv run` from backend/.")
        return 1
    seen = check(ROOT, subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT, text=True).split("\0"))
    for s in (s for s in seen if s.why):
        print(f"::error file={s.path},line={s.line}::{s.where}: {s.why}")
    marked = ", ".join(f"{s.path}:{s.line} ({s.image})" for s in seen if s.passed == "the comment") or "none"
    print(f"{len(seen)} read, {sum(bool(s.why) for s in seen)} that would be counted; on a '# {MARKER}' comment: {marked}.")
    return 1 if any(s.why for s in seen) else 0


if __name__ == "__main__":
    sys.exit(main())
