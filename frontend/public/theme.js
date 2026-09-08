// Apply the theme before first paint. /login and /setup render outside App, so
// nothing mounts useTheme there — without this, pre-auth pages ignore the saved
// theme entirely. Mirrors getInitialTheme() in src/hooks/useTheme.ts: stored
// choice first, OS preference as fallback.
//
// A file rather than an inline <script> so the Content-Security-Policy can say
// `script-src 'self'` with no hash and no nonce (#187): a hash would have to live in
// Python and change every time this file did, with no test able to see the two drift
// apart; a nonce would turn the static shell into a templated body. Served verbatim
// from frontend/public, unhashed, under the no-cache policy the shell itself gets.
(function () {
  var stored = null;
  try {
    stored = localStorage.getItem("theme");
  } catch (e) {
    // Storage unavailable (privacy mode) — fall through to the OS preference.
  }
  var dark =
    stored === "dark" ||
    (stored !== "light" && window.matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.classList.toggle("dark", dark);
})();
