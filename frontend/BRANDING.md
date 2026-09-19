# Lakeside Console

Implements issue #601 and the selected direction B from the design review.

## Source of truth

[LoonSecIO/loon-design v0.1.0](https://github.com/LoonSecIO/loon-design/tree/v0.1.0),
commit `063775ce7605f9c589f7c0a7bd1469a75d95fef1`:

- `src/brand/tokens.json` and `tokens.css` are verbatim copies of the release source and generated CSS.
- `public/brand/` holds the supplied original/reversed marks and lake illustration,
  with the upstream license and brand-use terms.
- The mark stays at least 32px with 8px clear space. Dark mode selects the supplied
  reversed artwork; no inversion filter, new geometry, or red-eye recoloring.
- Fonts are self-hosted Archivo, Public Sans, and JetBrains Mono, copied from
  LoonMarketing's existing Latin/Latin Extended assets at commit
  `4d16f7e`. Each family's upstream OFL notice is included in `public/fonts/`.
  Font license sources: `google/fonts/ofl/{archivo,publicsans,jetbrainsmono}/OFL.txt`.

Read the upstream `guide/brand.md` and `guide/interfaces.md` before changing this
mapping. Update the version deliberately; do not edit the vendored tokens.

## Application mapping and adaptations

The existing Tailwind utilities map to LoonSec semantic tokens in `src/index.css`.
`primary` uses action/action-text, navigation uses navigation/navigation-text, and
the active location uses selected/selected-text. Destructive controls pair danger
with danger-surface. Existing feature status semantics remain unchanged.

Two application-only derived colors are necessary because v0.1.0 does not define
quiet separators or hover surfaces: `app-rule` mixes 18% text into surface, and
`app-wash` mixes 5%. These are decorative grouping/hover treatments, not essential
control boundaries. Inputs retain the full brand border token. A future shared
separator token can replace this mapping without changing components.

The existing `.dark` class remains for feature utilities; the pre-paint script and
theme hook also set `data-loon-theme`, as required by the upstream CSS. This avoids
replacing the user's stored theme preference or briefly painting the wrong theme.

All operational language and navigation entries remain localized. The new sign-in
introduction has English and German copy. Illustration is confined to the desktop
sign-in entrance. No decorative sidebar footer is added. The existing build-version
readout remains because it is an operational diagnostic, not decorative branding.

LoonInspect's existing `LoonLogo`/favicon assets elsewhere retain their established
geometry; the navbar and sign-in use the supplied brand-release files directly.
Per-feature charts and explicit severity colors are not globally recolored: their
domain meaning and labels must be reviewed before any future semantic migration.

Existing feature filter forms still include placeholder-only fields, and some timestamp
labels use the browser's locale without a written timezone. These predate this change;
this shared-shell rollout does not claim full interface-guide compliance for every
feature. They need a separate field-label/time-display pass so established filtering
and date meaning are reviewed together. New sign-in controls retain persistent labels.
Native input/select/textarea boundaries use the full brand border token.

## Plan → build → verify

1. Start from merged main, including inventory summaries and the finding ledger UI.
2. Apply shared tokens, fonts, navigation, type hierarchy, and sign-in presentation.
3. Preserve API calls, permissions, routes, summary consent/provider settings,
   unknown-versus-zero states, and publication/detection clocks.
4. Run frontend checks and image build; inspect both themes, narrow layouts,
   sidebar modes, mobile keyboard focus, data tables, and settings.
5. Independent reviewer owns merge. No schema, wire or posture changes.
