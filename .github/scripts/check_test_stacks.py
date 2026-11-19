#!/usr/bin/env python3
"""Nothing this repository starts for a test may be counted by LoonSec's production service as an install (#821).

It fails a container a workflow step or a tracked shell script starts, and a service a compose file other than SHIPPED
defines, that could be LoonInspect and has neither UPDATE_CHECK=false nor an UPDATE_CHECK_URL off LoonSec's production
hosts. Without the setting, a container passes only on an image NOT_THE_APP names or, an image it cannot read, on a
`# not the app image` comment directly above it; an option it does not know fails, as it can then not tell which word is
the image. A compose start passes on the step's env or an earlier `export`. Unseen: what an action, a job's `services:`
or a program other than sh starts, a command built at run time, an --env-file, LoonInspect.app (#820), docs/.
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
GLOBAL_VALUES = {"-c", "--context", "-H", "--host", "--config", "-l", "--log-level", "--tlscacert", "--tlscert", "--tlskey"}
# docker run's options (`docker run --help`): the image is the first word that is neither one of them nor a value.
RUN_FLAGS = {"-d", "--detach", "--rm", "-i", "--interactive", "-t", "--tty", "--init", "--privileged", "-P", "--publish-all",
             "--read-only", "-q"}
RUN_VALUES = set(" ".join(("-e --env --env-file -p --publish -v --volume --mount -u --user -w --workdir --name --network",
                           "--entrypoint --platform -h --hostname --add-host -l --label -m --memory --restart --pull")).split())


@dataclass
class Seen:
    path: str
    line: int
    image: str
    env: dict = field(default_factory=dict)
    where: str = ""
    passed: str | None = None  # "the setting", "not the app" or "the comment"
    why: str | None = None  # why it would be counted


class Text(str):
    line = 1  # where a YAML string's text starts, below a block's indicator


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
    return yaml.load(text, Loader=loader) or {}


def _assignments(words) -> dict[str, str]:
    pairs = (str(word).partition("=") for word in words)
    return {name: value.strip("\"'") for name, eq, value in pairs if eq and re.fullmatch(r"[A-Za-z_]\w*", name)}


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


def _start(text: str, i: int) -> tuple[str, list[str], bool] | None:
    """The command at text[i], its arguments split as sh splits them, and whether its quotes close, when it starts a
    container or a compose stack. It ends at an operator, a newline or a comment."""
    lexer = shlex.shlex(re.sub(r"\\\n", " ", text[i:]), posix=True, punctuation_chars=OPERATORS)
    lexer.whitespace, lexer.whitespace_split, lexer.commenters = " \t\r", True, ""
    words, closed, starts = [], True, {"up", "run", "create", "start", "restart"}
    try:
        words += takewhile(lambda word: not word or word[0] not in OPERATORS + "#", lexer)
    except ValueError:  # quotes that do not close: a start this cannot read, if it is a start at all
        closed = False
    rest = words[1:]
    if words[0].endswith("docker-compose"):
        return ("docker-compose", rest, closed) if starts & set(rest) else None
    while rest and rest[0].startswith("-"):
        rest = rest[2:] if rest[0] in GLOBAL_VALUES else rest[1:]
    rest = rest[1:] if rest[:1] == ["container"] else rest
    if rest[:1] in (["run"], ["create"]):
        return "docker " + rest[0], rest[1:], closed
    return ("docker compose", rest[1:], closed) if rest[:1] == ["compose"] and starts & set(rest[1:]) else None


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
                    "would count it as an install (#821): give it UPDATE_CHECK=false"
                    + ("." if own else ", or name it in NOT_THE_APP."))
    return seen


def _script(path: str, text: str, first: int, env: dict, lines: list[str], where: str) -> list[Seen]:
    """Every container start and compose start in a workflow step's run, or in a shell file."""
    found = []
    for match in DOCKER.finditer(text):
        begin = text.rfind("\n", 0, match.start()) + 1
        line = first + text.count("\n", 0, match.start())
        if text[begin : match.start()].lstrip().startswith("#") or not (started := _start(text, match.start())):
            continue
        command, args, closed = started
        if not closed:
            seen = Seen(path, line, "?", why=f"a quote in this {command} does not close, so this check cannot read it.")
        elif "compose" in command:
            seen = Seen(path, line, command, {**env, **_assignments(re.findall(r"^\s*export\s+(\w+=\S*)", text[:begin], re.M))})
            seen.passed = "the setting" if keeps_out(seen.env) else None
            seen.why = None if seen.passed else (f"{command} starts a stack {NEITHER} set for it: give it UPDATE_CHECK=false "
                                                 "in the step's env, or export it first (#821).")
        else:
            run_env, image, stop = _run_options(args)
            seen = _container(Seen(path, line, image or "?", run_env), command, stop, lines)
        seen.where = where
        found.append(seen)
    return found


def check(root: Path, paths: list[str]) -> list[Seen]:
    """Every container start, compose start and compose service in the files at `paths`, relative to `root`."""
    found = []
    for path in sorted(p for p in paths if (root / p).is_file()):
        text = (root / path).read_text(errors="replace")
        lines = text.splitlines()
        if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            data = _load(text)
            for job_id, job in (data.get("jobs") or {}).items():
                for n, step in enumerate((job or {}).get("steps") or [], 1):
                    if run := step.get("run"):
                        env = {**_env(data), **_env(job), **_env(step)}
                        found += _script(path, run, run.line, env, lines, f"job {job_id}, step {step.get('name') or n}")
        elif re.search(r"(?:^|/)(?:docker-)?compose(?:\.[\w-]+)*\.ya?ml$", path) and path not in SHIPPED:
            for name, service in (_load(text).get("services") or {}).items():
                image, build = (service or {}).get("image"), (service or {}).get("build")
                context = str((build.get("context") if isinstance(build, dict) else build) or "").strip("./")
                if name == "app" or (image and repository(image) not in NOT_THE_APP) or (build and context != "ops/postgres"):
                    seen = Seen(path, name.line, str(image or "the image it builds"), _env(service), path)
                    found.append(_container(seen, f"service {name}", "", lines))  # a service: the same rule as a container
        elif path.endswith(".sh") or re.match(r"#!\s*\S*(?:/|env\s+)(?:ba)?sh\b", text):
            found += _script(path, text, 1, {}, lines, path)
    return found


def main() -> int:
    if yaml is None:
        print("::error::PyYAML is not installed, so this check cannot read the workflows: run it with a python3 that has "
              "it, as GitHub's runner images do, or with `uv run python` from backend/.")
        return 1
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True, text=True).stdout
    seen = check(ROOT, tracked.split("\0"))
    for s in (s for s in seen if s.why):
        print(f"::error file={s.path},line={s.line}::{s.where}: {s.why}")
    marked = ", ".join(f"{s.path}:{s.line} ({s.image})" for s in seen if s.passed == "the comment") or "none"
    print(f"{len(seen)} read, {sum(bool(s.why) for s in seen)} that would be counted; on a '# {MARKER}' comment: {marked}.")
    return 1 if any(s.why for s in seen) else 0


if __name__ == "__main__":
    sys.exit(main())
