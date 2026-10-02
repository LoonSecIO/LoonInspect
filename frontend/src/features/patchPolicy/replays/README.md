# Patch-policy reference replays

Each `.json` here is one whole output of LoonVD's patch-policy replay, copied byte for byte.
LoonInspect draws these files and computes nothing in them (#614, first slice).

| File | App | `run_id` | Source |
| --- | --- | --- | --- |
| `wireshark-2026-10-02.json` | Wireshark, the per-line "Wireshark 4.4" Jamf title | `8e578b5804537684112659c2bcc38695ce6e8db412851f147d194d216001fe4c` | `LoonSecIO/LoonVD-Internal`, `sharedAssets/fixtures/patch_policy/wireshark-2026-10-02.json` at commit `e788edcc04b781fdebf1aa70731dd14ff52ceda2` (branch `claude/patch-policy-fixture`, LoonVD-Internal pull request 89, not yet merged when copied on 2026-10-02) |

The file's SHA-256 is `cc3f343c6f037070f478e0a87fe0b8db3c73cc3562742a8f4af84ccb2b090482`.
What every number means, and which definitions are ruled, is `docs/PATCH-POLICY-REPLAY.md` in
that repository; the definitions also ride in each file as `definitions` and `clocks`, and the
page prints them from there.

These are reference analyses of a hypothetical device. They are not a tenant's exposure, they
are never stored as a tenant metric, and no inventory is read to draw them.

## Adding or replacing one

1. Copy the new output here without editing it. The name is `<app>-<catalog snapshot date>.json`.
2. Add or update its row in `../replayIndex.ts`: the app's name, its bundle IDs and the `run_id`.
3. Update the table above.
4. Run `npm test`. `replay.test.ts` reads every indexed file through the same check the page
   uses, so a file of another `kind` or `schema`, or one whose totals disagree, fails there
   and not in front of a reader.

This directory is how the files reach the page for this slice only. The distribution from
LoonVD through LoonSupport is not designed here.
