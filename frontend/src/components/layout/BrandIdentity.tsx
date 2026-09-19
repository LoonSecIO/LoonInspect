/** Supplied LoonSec artwork, with a separate reversed asset that preserves the red eye. */
export function BrandIdentity() {
  return (
    <div className="app-brand">
      <img className="brand-light" src="/brand/loon-mark.svg" alt="" />
      <img className="brand-dark" src="/brand/loon-mark-reversed.svg" alt="" />
      <span>Loon<span className="app-brand-word">Inspect</span></span>
    </div>
  );
}
