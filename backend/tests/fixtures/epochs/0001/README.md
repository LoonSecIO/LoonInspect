# The fixture corpus epoch, `0001`

Copied verbatim from **LoonVD-Internal, PR #12 (`issue-7/epoch-format`), 2026-09-10**,
`sharedAssets/fixtures/epochs/0001/`. Not edited here and never regenerated here: the
digests inside `manifest.json` are what this container's loader verifies, so a byte
changed on this side would prove the loader wrong rather than the epoch bad. The format
is that branch's `sharedAssets/contract/epoch.md`.

```
manifest.json       the index — format, epoch_id, asof, the objects and their digests
rows.jsonl.gz       3 rows, one per assessed build
titles.jsonl.gz     3 titles, the assessed-titles manifest
current.json        the pointer — signature = sha256(manifest.json)
epoch-0001.tar.gz   the transfer bundle: 0001/{manifest.json,rows.jsonl.gz,titles.jsonl.gz}
```

In the real store `current.json` sits beside `epochs/` and the bundle is a copy for
transport; the fixture flattens all five into one directory so a test needs nothing else.
The loader downloads **the bundle** (`epoch-0001.tar.gz`) and verifies it against the
signature the pointer carries — the loose objects are here so a test can assert the
bundle's manifest is byte-identical to the published one.

## What is in it

| App | Build | `key_full` | The epoch's answer |
| --- | --- | --- | --- |
| `Wireshark.app` / `org.wireshark.Wireshark` | 4.2.0 | `v1:c63d39b2…` | a row: 17 CVE ids, 0 KEV, 9 high, 8 medium, oldest published 2024-01-03 |
| `LoonVD Fixture Clean.app` / `io.loonsec.fixture.clean` | 2.6.0 | `v1:b0f49e67…` | a row with no ids — **assessed and clean is a row, never an absent row** |
| `LoonVD Fixture Stale.app` / `io.loonsec.fixture.stale` | 3.1.4 | `v1:73c5b9ce…` | a row with no ids |
| the same title | 3.2.0 | `v1:09c47c6b…` | **no row.** Its `key_title` is in `titles.jsonl.gz` with `catalog_last_modified: 2025-03-04T11:20:00Z`, so the answer depends on the pod's own Jamf stamp — the branch [#381](https://github.com/LoonSecIO/LoonInspect/issues/381) owns |
| `LoonVD Fixture Unknown.app` / `io.loonsec.fixture.unknown` | 1.0.0 | — | in no object at all: `unknown_app` |

Only the Wireshark row is real — the 17 ids are what NVD returned for
`cpe:2.3:a:wireshark:wireshark:4.2.0` on 2026-09-10, and **17 is a fact about that day**,
not a claim about the world. No test here asserts it against NVD and nothing here reaches
NVD. The three `io.loonsec.fixture.*` identities are constructed to exercise a rule.

The `key_title` / `key_full` values were computed with this repository's own frozen
`app/core/content_keys.py` (`app_full_key(name, bundleId, shortVersion, None)` — note the
`None`), which is why `tests/test_vuln_library.py` can assert them as literals: the two
sides of the join hash the same tuple or the corpus silently answers nothing.
