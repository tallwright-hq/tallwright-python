# SPDX-License-Identifier: Apache-2.0
"""Whether a run of `.github/workflows/publish.yml` may reach its upload job. Standard library only.

    python tools/release.py tag sdk-v1.0.0rc1 [REF]        the tag names the SDK's version, at a commit main holds
    python tools/release.py environment pypi               the upload job's environment holds a person to it
    python tools/release.py release sdk-v1.0.0rc1          a person makes the release tags, and listed these sums
    python tools/release.py sums DIST [sdk-v1.0.0rc1]      the wheels in DIST are the ones the release recorded
    python tools/release.py index pypi DIST                what the index already holds is these bytes

THE TAG. A release is one version at one commit. The workflow checks out `refs/tags/<tag>`, never a branch,
whose head moves. The tag is `sdk-v<version>`, the version `tallwright-cloud` declares, at a commit on main.
`tallwright-core` keeps a version of its own, and an index takes each version of it once. REF, when given,
is the ref the run was started on, and must be `refs/tags/<tag>`: the workflow that runs, its upload job
included, is that ref's, so the commit judged here is the commit whose workflow runs.

THE ENVIRONMENT. The upload job runs in a GitHub environment, and that is where a person is asked: a
required reviewer approves the job before it can ask for the token it trades for an upload credential.
That fails in four ways, and each one is refused here: the environment does not exist (a job that names
an environment nobody created creates it, with no protection rule); it has no required reviewer; an
administrator may bypass its rules; deployments are not limited to the release tags.

THE RELEASE. Every check here runs from the commit the tag names, so whoever can make or move a release
tag writes the checks. An active ruleset must restrict the creation, update and deletion of
`refs/tags/sdk-v*`, so that a deploy key can do none of them. GitHub shows who may bypass a ruleset only
to those who may edit it; where it is shown, a deploy key on that list refuses, and where it is not, that
none is there is the owner's setting. The release tag is made in GitHub's web UI, by publishing the
release, and its description lists the SHA-256 of the two wheels as Tallwright's release run showed
them. `release/<tag>.sha256` travels with the source it vouches for, and whoever writes the one can write
the other; the release's list is written by the person who published it, so the record must be that list.

THE SUMS. Each release records the SHA-256 of its two wheels in `release/<tag>.sha256`, as Tallwright's
own build made and tested them. A wheel built here from this repository must be those bytes, so what is
uploaded is what was tested, and this repository's source is what it was built from.

THE INDEX. An index never takes a file twice. A wheel whose version the index already holds is left out of
the upload when the index holds exactly these bytes, and refuses the run when it holds other ones. The SDK
requires the core, so its wheel is uploaded only by a run in which the index already holds the core's
wheel beside it, byte for byte: the run that uploads a new core holds the SDK back, and the next run
uploads it. No run leaves the SDK on an index that lacks the core it requires.

Exit 0 when nothing stands, 1 otherwise. Nothing is uploaded from here; `index` may remove from DIST a wheel
the index already holds, byte for byte, and the SDK's wheel while its core is not there yet.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SDK = "tallwright-cloud"
#: The distribution the SDK requires: an index must hold it before it takes the SDK.
CORE = "tallwright-core"
TAG_PREFIX = "sdk-v"
#: The one deployment policy the upload's environment may have: the release tags, nothing else.
RELEASE_TAGS = (TAG_PREFIX + "*", "tag")
#: The release tags as a ruleset names them, and what it must restrict: making one, moving one, deleting one.
RELEASE_TAG_REFS = "refs/tags/" + TAG_PREFIX + "*"
TAG_RULES = ("creation", "update", "deletion")
INDEXES = {"testpypi": "https://test.pypi.org", "pypi": "https://pypi.org"}
#: One line a person lists in a release: `<sha256>  <wheel>`, spaces around it forgiven.
_LISTED = re.compile(r"\s*([0-9a-f]{64})\s+(\S+\.whl)\s*")

#: A GitHub REST call, `repos/<owner>/<repo>/` already in front of the path: the answer's text, or None.
Ask = Callable[[str], str | None]
#: An index's JSON API: the answer's text for a path below `/pypi/`, None for a 404. Anything else raises.
Look = Callable[[str, str], str | None]


def declared_version(root: Path = ROOT) -> str:
    """The version the SDK declares in its pyproject."""
    project = tomllib.loads((root / "packages" / SDK / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return str(project["version"])


def tag_problems(tag: str, version: str, *, on_main: bool, ref: str | None = None) -> list[str]:
    """Why ``tag`` does not name the SDK's version at a commit main holds, or nothing. ``ref``, when given, is
    the ref the run was started on, whose workflow is the one that runs."""
    problems = [] if on_main else ["the tagged commit is not on main, so no review and no main CI stand behind it"]
    if ref is not None and ref != f"refs/tags/{tag}":
        problems.append(
            f"this run was started on {ref!r}, and the workflow that runs, its upload job included, is that ref's: "
            f"a release runs on refs/tags/{tag}, the tag it publishes"
        )
    if not tag.startswith(TAG_PREFIX):
        return [*problems, f"{tag!r} is not a release tag: a run publishes a tag {TAG_PREFIX}<version>, never a branch"]
    if tag.removeprefix(TAG_PREFIX) != version:
        problems.append(f"{tag} names {tag.removeprefix(TAG_PREFIX)!r}, and {SDK} declares {version!r}")
    return problems


def _json(answer: str | None) -> object:
    try:
        return json.loads(answer) if answer is not None else None
    except ValueError:
        return None


def environment_problems(name: str, environment: str | None, policies: str | None) -> list[str]:
    """Why the environment ``name`` does not hold a person to the upload, or nothing.

    ``environment`` and ``policies`` are GitHub's answers to `environments/<name>` and
    `environments/<name>/deployment-branch-policies`, or None where there was no answer. Anything this
    cannot read is a refusal: an answer nobody understood is not an approval.
    """
    found = _json(environment)
    if not isinstance(found, dict):
        return [
            f"the environment {name!r} cannot be read: it does not exist, or this run may not read it. A job that "
            "names an environment nobody created creates it, with no protection rule"
        ]
    rules = found.get("protection_rules")
    reviewers = [
        reviewer
        for rule in (rules if isinstance(rules, list) else [])
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers"
        for reviewer in rule.get("reviewers") or []
    ]
    problems = []
    if not reviewers:
        problems.append(f"{name!r} has no required reviewer, so nobody is asked before the upload starts")
    if found.get("can_admins_bypass") is not False:
        problems.append(
            f"administrators may bypass {name!r}'s rules (can_admins_bypass is {found.get('can_admins_bypass')!r}), "
            "so the person they bind can step around them"
        )
    branch_policy = found.get("deployment_branch_policy")
    listed = _json(policies)
    tags = sorted(
        (str(policy.get("name")), str(policy.get("type", "branch")))
        for policy in (listed.get("branch_policies") or [] if isinstance(listed, dict) else [])
        if isinstance(policy, dict)
    )
    if branch_policy != {"protected_branches": False, "custom_branch_policies": True} or tags != [RELEASE_TAGS]:
        problems.append(
            f"{name!r} does not limit deployments to the release tags ({RELEASE_TAGS[0]}, and nothing else): it "
            f"says {branch_policy!r} and lists {tags or 'no policy it could read'}"
        )
    return problems


def _covers_the_release_tags(conditions: object) -> bool:
    """Whether a ruleset's conditions take in every release tag: all tags, or `refs/tags/sdk-v*`, none left out."""
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    include = ref_name.get("include") if isinstance(ref_name, dict) else None
    exclude = ref_name.get("exclude") if isinstance(ref_name, dict) else None
    return isinstance(include, list) and bool({"~ALL", RELEASE_TAG_REFS} & {str(p) for p in include}) and not exclude


def tag_rules_problems(rulesets: list[object]) -> list[str]:
    """Why a release tag can be made, moved or deleted by a deploy key, or nothing.

    ``rulesets`` are GitHub's answers, parsed, for each tag ruleset of the repository (`rulesets/<id>`).
    """
    covering = [
        found for found in rulesets
        if isinstance(found, dict) and found.get("target") == "tag" and found.get("enforcement") == "active"
        and _covers_the_release_tags(found.get("conditions"))
    ]
    restricted = {
        rule.get("type")
        for found in covering
        for rule in (found["rules"] if isinstance(found.get("rules"), list) else [])
        if isinstance(rule, dict)
    }
    problems = []
    missing = [rule for rule in TAG_RULES if rule not in restricted]
    if missing:
        problems.append(
            f"no active ruleset restricts the {', '.join(missing)} of {RELEASE_TAG_REFS}: a deploy key can then make or "
            "move a release tag at any commit, and this workflow and every check here run from the commit it names"
        )
    bypassed = sorted(
        str(found.get("name"))
        for found in covering
        if any(isinstance(actor, dict) and actor.get("actor_type") == "DeployKey" for actor in found.get("bypass_actors") or [])
    )
    if bypassed:
        problems.append(f"a deploy key may bypass {bypassed}, which protect the release tags, so it can make or move one")
    return problems


def protection_problems(ask: Ask) -> list[str]:
    """Why a release tag can be made, moved or deleted by a deploy key, asked of GitHub, or nothing."""
    listed = _json(ask("rulesets"))
    if not isinstance(listed, list):
        return ["the repository's rulesets cannot be read, so whether a deploy key can make or move a release tag cannot be told"]
    return tag_rules_problems([
        _json(ask(f"rulesets/{entry.get('id')}"))
        for entry in listed
        if isinstance(entry, dict) and entry.get("target") == "tag"
    ])


def listed_sums(text: str) -> dict[str, str]:
    """The `<sha256>  <wheel>` lines of a text a person wrote, file name to SHA-256; empty when one is listed twice."""
    sums: dict[str, str] = {}
    for line in text.splitlines():
        match = _LISTED.fullmatch(line)
        if match:
            digest, name = match.groups()
            if name in sums:
                return {}
            sums[name] = digest
    return sums


def release_problems(tag: str, release: str | None, wanted: dict[str, str] | None) -> list[str]:
    """Why the sums ``tag`` records are not the ones listed in the release a person published for it, or nothing.

    ``release`` is GitHub's answer to `releases/tags/<tag>`, and ``wanted`` what `release/<tag>.sha256` records.
    """
    found = _json(release)
    if not isinstance(found, dict) or found.get("tag_name") != tag:
        return [
            f"no published release of {tag} can be read. A person publishes it in GitHub's web UI, which makes the tag, "
            "and lists in its description the SHA-256 of the two wheels as Tallwright's release run showed them"
        ]
    body = found.get("body")
    listed = listed_sums(body) if isinstance(body, str) else {}
    if not listed:
        return [f"the release {tag} lists no `<sha256>  <wheel>` line, or one wheel twice, so which bytes it is cannot be told"]
    recorded_here = wanted or {}
    return [
        f"for {name}, the release {tag} lists {listed.get(name, 'nothing')} and release/{tag}.sha256 records "
        f"{recorded_here.get(name, 'nothing')}: the record travels with the source it vouches for, the list is the person's"
        for name in sorted(set(listed) | set(recorded_here))
        if listed.get(name) != recorded_here.get(name)
    ]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def recorded(tag: str, root: Path = ROOT) -> dict[str, str] | None:
    """The wheels a release recorded, file name to SHA-256, or None when it recorded none."""
    path = root / "release" / f"{tag}.sha256"
    if not path.is_file():
        return None
    sums: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        digest, _, name = line.partition("  ")
        if len(digest) != 64 or not name or name in sums:
            return {}
        sums[name] = digest
    return sums


def sums_problems(wheels: dict[str, str], wanted: dict[str, str] | None, tag: str) -> list[str]:
    """Why the wheels built here are not the bytes ``tag`` recorded, or nothing."""
    if wanted is None:
        return [f"release/{tag}.sha256 is not here, so which bytes this release is cannot be told"]
    if not wanted:
        return [f"release/{tag}.sha256 cannot be read: one `<sha256>  <file name>` line for each wheel"]
    problems = [f"{name} was built here and is not recorded for {tag}" for name in sorted(set(wheels) - set(wanted))]
    problems += [f"{name} is recorded for {tag} and was not built here" for name in sorted(set(wanted) - set(wheels))]
    problems += [
        f"{name} built here is not the wheel {tag} recorded, byte for byte"
        for name in sorted(set(wheels) & set(wanted))
        if wheels[name] != wanted[name]
    ]
    return problems


def _wheel_name(name: str) -> tuple[str, str]:
    """(project, version) of a wheel file name."""
    project, version = name.split("-")[:2]
    return project.replace("_", "-"), version


def index_problems(index: str, wheels: dict[str, str], look: Look) -> tuple[list[str], list[str], list[str]]:
    """(the wheels the index already holds byte for byte, the SDK's wheels that wait for their core, why the run
    is refused) for ``wheels`` on ``index``.

    The SDK waits unless the index holds, byte for byte, the one core wheel beside it: uploaded in the same run,
    the SDK could reach the index and its core not (refused, squatted, or a run that failed half way), and the
    SDK would stay there, requiring a core that somebody else may then upload.
    """
    held, problems = [], []
    for name, digest in sorted(wheels.items()):
        project, version = _wheel_name(name)
        answer = look(index, f"{project}/{version}/json")
        if answer is None:
            continue
        files = _json(answer)
        urls = files.get("urls") if isinstance(files, dict) else None
        same = [
            entry for entry in (urls if isinstance(urls, list) else [])
            if isinstance(entry, dict) and entry.get("filename") == name
        ]
        if len(same) == 1 and (same[0].get("digests") or {}).get("sha256") == digest:
            held.append(name)
        elif same:
            problems.append(f"{index} holds {name} with other bytes: one version is one set of bytes")
        else:
            problems.append(f"{index} holds {project} {version} without {name}: a version is uploaded whole, once")
    cores = [name for name in wheels if _wheel_name(name)[0] == CORE]
    waiting = [] if len(cores) == 1 and cores[0] in held else sorted(
        name for name in wheels if _wheel_name(name)[0] == SDK and name not in held
    )
    if not problems and len(held) + len(waiting) == len(wheels):
        problems.append(
            f"{', '.join(waiting)} waits for the one {CORE} wheel beside it to be on {index}, and this run uploads none"
            if waiting else f"{index} holds every one of these wheels already, so there is nothing to upload"
        )
    return held, waiting, problems


def _ask_github(path: str) -> str | None:  # pragma: no cover - networked: gh and GitHub
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if not repository:
        return None
    try:
        return subprocess.run(
            ["gh", "api", f"repos/{repository}/{path}"], capture_output=True, text=True, encoding="utf-8", check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None


def _look(index: str, path: str) -> str | None:  # pragma: no cover - networked: the index
    try:
        with urllib.request.urlopen(f"{INDEXES[index]}/pypi/{path}", timeout=30) as answer:  # noqa: S310
            return str(answer.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise


def _on_main() -> bool:  # pragma: no cover - asks git, in the workflow's full checkout
    return subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", "HEAD", "refs/remotes/origin/main"],
        capture_output=True, check=False,
    ).returncode == 0


def _wheels(dist: Path) -> dict[str, str]:
    return {p.name: _sha256(p) for p in sorted(dist.iterdir()) if p.suffix == ".whl"}


def main(
    argv: list[str] | None = None,
    ask: Ask = _ask_github,
    look: Look = _look,
    on_main: Callable[[], bool] = _on_main,
    root: Path = ROOT,
) -> int:
    args = sys.argv[1:] if argv is None else argv
    shapes = {"tag": {2, 3}, "environment": {2}, "release": {2}, "sums": {2, 3}, "index": {3}}
    if not args or len(args) not in shapes.get(args[0], set()) or (
        args[0] in ("environment", "index") and args[1] not in INDEXES
    ):
        print(__doc__)
        return 2
    question = args[0]
    done = ""
    if question == "tag":
        problems = tag_problems(args[1], declared_version(root), on_main=on_main(), ref=args[2] if len(args) == 3 else None)
    elif question == "environment":
        problems = environment_problems(
            args[1], ask(f"environments/{args[1]}"), ask(f"environments/{args[1]}/deployment-branch-policies")
        )
    elif question == "release":
        problems = protection_problems(ask) + release_problems(
            args[1], ask(f"releases/tags/{urllib.parse.quote(args[1], safe='')}"), recorded(args[1], root)
        )
    elif question == "sums":
        tag = args[2] if len(args) == 3 else TAG_PREFIX + declared_version(root)
        problems = sums_problems(_wheels(Path(args[1])), recorded(tag, root), tag)
    else:
        dist = Path(args[2])
        held, waiting, problems = index_problems(args[1], _wheels(dist), look)
        if not problems:
            for name in held + waiting:
                (dist / name).unlink()
            done = "".join(f"\nalready on {args[1]}, byte for byte, so not uploaded again: {name}" for name in held)
            done += "".join(
                f"\nheld back until {args[1]} holds the {CORE} wheel this run uploads; run again after it: {name}"
                for name in waiting
            )
    for problem in problems:
        print(f"REFUSED: {problem}")
    if not problems:
        print(f"{' '.join(args)}: nothing stands{done}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
