const { test, expect } = require('@playwright/test');

const appName = 'Smoke Catalog.app';
const sections = [
  { label: 'Overview', path: '/', heading: 'Overview' },
  { label: 'Devices', path: '/devices', heading: 'Devices' },
  { label: 'Patch Plans', path: '/patch-plans', heading: 'Patch Plans' },
  // On a fresh installation without a vulnerability corpus, Posture opens Compliance.
  { label: 'Posture', path: '/posture/compliance', heading: 'Compliance evidence' },
  { label: 'Settings', path: '/settings/connections', heading: 'MDM Connections' },
];

let loginCookies;
let errors;
let pending;

test.beforeAll(async ({ browser }, testInfo) => {
  const email = 'browser-smoke@example.com';
  const password = process.env.SMOKE_ADMIN_PASSWORD;
  if (!password) throw new Error('Set SMOKE_ADMIN_PASSWORD for the disposable stack.');
  const auth = await browser.newContext({ baseURL: testInfo.project.use.baseURL });
  try {
    const status = await auth.request.get('/api/auth/status');
    expect(status.status()).toBe(200);
    if ((await status.json()).setupRequired) {
      const claimToken = process.env.SMOKE_CLAIM_TOKEN;
      if (!claimToken) throw new Error('Pass the first-run claim token from this disposable stack.');
      const setup = await auth.request.post('/api/auth/setup', {
        data: { claimToken, email, password, displayName: 'Smoke Admin', shareCommunityData: false },
      });
      expect(setup.status()).toBe(201);
    }
    await auth.clearCookies();
    const login = await auth.request.post('/api/auth/login', { data: { email, password } });
    expect(login.status()).toBe(200);
    loginCookies = await auth.cookies();
    const catalog = await auth.request.get('/api/catalog');
    expect(catalog.status()).toBe(200);
    expect((await catalog.json()).items).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: appName, version: '4.2.1' }),
    ]));
  } finally {
    await auth.close();
  }
});

test.beforeEach(async ({ page }) => {
  await page.context().addCookies(loginCookies);
  errors = [];
  pending = new Set();
  const record = message => errors.push(`${new URL(page.url()).pathname}: ${message}`);
  page.on('console', message => {
    if (message.type() === 'error') record(message.text());
  });
  page.on('pageerror', error => record(error.message));
  page.on('request', request => {
    if (['fetch', 'xhr'].includes(request.resourceType())) pending.add(request);
  });
  page.on('requestfinished', request => pending.delete(request));
  page.on('requestfailed', request => pending.delete(request));
  await page.goto('/');
});

test.afterEach(async () => {
  await expect.poll(() => pending.size, { message: 'Waiting for page data' }).toBe(0);
  expect(errors, 'Browser console errors and uncaught exceptions').toEqual([]);
});

for (const { label, path, heading } of sections) {
  test(`${label} opens from the sidebar`, async ({ page }) => {
    const sidebar = page.locator('aside nav');
    const main = page.getByRole('main');
    if (label === 'Overview') {
      // A new top-level destination needs its own heading check.
      await expect(sidebar.locator('.app-nav-group > a')).toHaveCount(sections.length);
    }
    // Overview may announce a changing attention count alongside its label.
    const link = sidebar.getByRole('link', label === 'Overview' ? { name: /^Overview\b/ } : { name: label, exact: true });
    await expect(link).toHaveAttribute('href', path);
    if (label === 'Patch Plans') {
      const plans = page.waitForResponse(response => new URL(response.url()).pathname === '/api/application-patch-plans');
      await link.click();
      expect((await plans).status()).toBe(200);
    } else {
      await link.click();
    }
    await expect(page).toHaveURL(url => url.pathname === path);
    await expect(main.getByRole('heading', { level: 1, name: heading, exact: true })).toBeVisible();
    if (label === 'Overview') {
      await expect(main.getByRole('heading', { name: 'Since you last looked', exact: true })).toBeVisible();
    } else if (label === 'Devices') {
      // The initial list is debounced. An empty network queue can precede the first request.
      await expect(main.getByRole('link', { name: 'smoke-mac', exact: true })).toBeVisible();
    } else if (label === 'Settings') {
      await expect(main.getByRole('cell', { name: /^Browser smoke fixture\b/ })).toBeVisible();
    } else if (label === 'Posture') {
      await expect(main.getByRole('heading', { name: 'By rule', exact: true })).toBeVisible();
    }
  });
}

test('Devices → Applications → Catalog shows the installed build in both lists', async ({ page }) => {
  const sidebar = page.locator('aside nav');
  const main = page.getByRole('main');
  await sidebar.getByRole('link', { name: 'Devices', exact: true }).click();
  await expect(main.getByRole('link', { name: 'smoke-mac', exact: true })).toBeVisible();
  await sidebar.getByRole('link', { name: 'Applications', exact: true }).click();
  await expect(page).toHaveURL(url => url.pathname === '/devices/applications');
  await expect(main.getByRole('heading', { level: 1, name: 'Applications', exact: true })).toBeVisible();
  await expect(main.getByRole('link', { name: appName, exact: true })).toBeVisible();
  await main.getByRole('link', { name: 'Catalog', exact: true }).click();
  await expect(page).toHaveURL(url => url.pathname === '/devices/applications/catalog');
  await expect(main.getByRole('cell', { name: appName, exact: true })).toBeVisible();
});
