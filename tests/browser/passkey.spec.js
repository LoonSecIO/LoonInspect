const { test, expect } = require('@playwright/test');

// Passkeys (#955), end to end in Chromium with its virtual authenticator over the DevTools protocol: no person, no
// hardware. A browser offers WebAuthn only to a secure context, which over plain HTTP is a loopback host alone, so the
// runner shares the app container's network namespace (compose.yml) and http://localhost:8001 is the app itself. The
// two addresses a passkey can never work at are checked as well: plain HTTP at a host name, and an IP address.
const email = 'browser-smoke@example.com';
const password = process.env.SMOKE_ADMIN_PASSWORD;
const LOCAL = 'http://localhost:8001';
const NAME = 'Chromium virtual authenticator';

let errors;

test.beforeAll(async ({ browser }) => {
  if (!password) throw new Error('Set SMOKE_ADMIN_PASSWORD for the disposable stack.');
  const setup = await browser.newContext({ baseURL: LOCAL });
  try {
    // This file runs before smoke.spec.js, so it may be the one to claim the disposable instance.
    if ((await (await setup.request.get('/api/auth/status')).json()).setupRequired) {
      const claimToken = process.env.SMOKE_CLAIM_TOKEN;
      if (!claimToken) throw new Error('Pass the first-run claim token from this disposable stack.');
      const claimed = await setup.request.post('/api/auth/setup', {
        data: { claimToken, email, password, displayName: 'Smoke Admin', shareCommunityData: false },
      });
      expect(claimed.status()).toBe(201);
    }
  } finally {
    await setup.close();
  }
});

test.beforeEach(async ({ page }) => {
  errors = [];
  page.on('console', message => {
    if (message.type() === 'error') errors.push(`${new URL(page.url()).pathname}: ${message.text()}`);
  });
  page.on('pageerror', error => errors.push(`${new URL(page.url()).pathname}: ${error.message}`));
});

test.afterEach(async () => {
  expect(errors, 'Browser console errors and uncaught exceptions').toEqual([]);
});

async function signInWithPassword(page) {
  await page.goto('/login');
  await page.getByLabel('Email').fill(email);
  await page.getByLabel('Password', { exact: true }).fill(password);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('main').getByRole('heading', { level: 1, name: 'Overview', exact: true })).toBeVisible();
}

function passkeySection(page) {
  return page.getByRole('main').locator('div.rounded-lg').filter({ has: page.getByRole('heading', { name: 'Passkeys', exact: true }) });
}

test.describe('at http://localhost', () => {
  test.use({ baseURL: LOCAL });

  test('a passkey added on My Account signs in by itself, and nothing else is typed', async ({ page, context }) => {
    const devtools = await context.newCDPSession(page);
    await devtools.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await devtools.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        ctap2Version: 'ctap2_1',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        isUserVerified: true,
        automaticPresenceSimulation: true,
      },
    });

    await signInWithPassword(page);
    await page.goto('/settings/my-account');
    const section = passkeySection(page);
    await expect(section.getByText('No passkeys yet.')).toBeVisible();
    await section.getByRole('button', { name: 'Add a passkey' }).click();
    await section.locator('#passkeyName').fill(NAME);
    await section.locator('#passkeyPassword').fill(password);
    await section.locator('form').getByRole('button', { name: 'Add a passkey' }).click();
    await expect(section.getByText(`${NAME} is added.`, { exact: false })).toBeVisible();
    await expect(section.getByText('Works at localhost', { exact: true })).toBeVisible();
    const { credentials } = await devtools.send('WebAuthn.getCredentials', { authenticatorId });
    expect(credentials).toHaveLength(1);
    expect(credentials[0]).toMatchObject({ rpId: 'localhost', isResidentCredential: true });

    // Signed out, then in again with the passkey alone. The email field holds a conditional request open, and the
    // virtual authenticator answers it with the one passkey it holds, as a person picking it from the autofill menu
    // does: the session comes from that answer, with nothing typed and nothing clicked.
    const overview = page.getByRole('main').getByRole('heading', { level: 1, name: 'Overview', exact: true });
    expect((await page.request.post('/api/auth/logout')).status()).toBe(204);
    const fromAutofill = page.waitForResponse(response => new URL(response.url()).pathname === '/api/auth/login/passkey');
    await page.goto('/login');
    expect((await fromAutofill).status()).toBe(200);
    await expect(overview).toBeVisible();
    const signedIn = await (await page.request.get('/api/auth/passkeys')).json();
    expect(signedIn).toEqual([expect.objectContaining({ name: NAME, host: 'localhost', lastUsedAt: expect.any(String) })]);

    // A browser without the conditional form, which this page makes Chromium for the next load: no request is
    // held open, and Sign in with a passkey asks in the browser's own dialog instead.
    expect((await page.request.post('/api/auth/logout')).status()).toBe(204);
    await page.addInitScript(() => {
      PublicKeyCredential.isConditionalMediationAvailable = async () => false;
    });
    await page.goto('/login');
    await expect(page.getByLabel('Email')).toHaveAttribute('autocomplete', 'username webauthn');
    const fromButton = page.waitForResponse(response => new URL(response.url()).pathname === '/api/auth/login/passkey');
    await page.getByRole('button', { name: 'Sign in with a passkey' }).click();
    expect((await fromButton).status()).toBe(200);
    await expect(overview).toBeVisible();
    // Two signatures, each over its own challenge: this authenticator's counter climbs, and both counts were taken.
    const after = await devtools.send('WebAuthn.getCredentials', { authenticatorId });
    expect(after.credentials[0].signCount).toBeGreaterThanOrEqual(2);
  });
});

for (const { base, refused } of [
  { base: 'http://looninspect.test:8001', refused: 'Passkeys need HTTPS, and this page was reached at http://looninspect.test:8001 over plain HTTP.' },
  { base: 'http://127.0.0.1:8001', refused: 'Passkeys need a host name, and this page was reached at http://127.0.0.1:8001, which is an IP address.' },
]) {
  test.describe(`at ${base}`, () => {
    test.use({ baseURL: base });

    test('no passkey control is offered, and My Account says why, with the address and what to open instead', async ({ page }) => {
      const asked = [];
      page.on('request', request => {
        if (new URL(request.url()).pathname.startsWith('/api/auth/login/passkey')) asked.push(request.url());
      });
      await page.goto('/login');
      await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible();
      await page.waitForLoadState('networkidle');
      await expect(page.getByRole('button', { name: 'Sign in with a passkey' })).toHaveCount(0);
      expect(asked, 'the sign-in page asks for no passkey challenge here').toEqual([]);

      await signInWithPassword(page);
      await page.goto('/settings/my-account');
      const section = passkeySection(page);
      await expect(section.getByText(`No passkey can be added or used at ${base}:`, { exact: false })).toBeVisible();
      await expect(section.getByText('http://localhost:8001 on the machine it runs on', { exact: false })).toBeVisible();
      await expect(section.getByRole('button', { name: 'Add a passkey' })).toHaveCount(0);

      // The server holds the same line, in its own words.
      const options = await page.request.post('/api/auth/login/passkey/options');
      expect(options.status()).toBe(409);
      expect((await options.json()).detail).toContain(refused);
    });
  });
}
