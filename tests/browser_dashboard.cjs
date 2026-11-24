const assert = require('node:assert/strict');
const {chromium} = require('playwright-core');
const fs = require('node:fs');
const path = require('node:path');
const {NETGUARD_ADMIN_TOKEN, NETGUARD_PORT = '8000', NETGUARD_SCREENSHOTS} = process.env;
const url = 'http://127.0.0.1:' + NETGUARD_PORT;
assert(NETGUARD_ADMIN_TOKEN, 'Set NETGUARD_ADMIN_TOKEN for a fresh mock installation.');
async function screenshot(page, name) {
  if (!NETGUARD_SCREENSHOTS) return;
  fs.mkdirSync(NETGUARD_SCREENSHOTS, {recursive: true});
  await page.screenshot({path: path.join(NETGUARD_SCREENSHOTS, name), fullPage: true});
}
(async () => {
  const browser = await chromium.launch({executablePath: process.env.NETGUARD_CHROMIUM || undefined,
    args: process.env.NETGUARD_CHROMIUM_NO_SANDBOX === '1' ? ['--no-sandbox'] : []});
  const context = await browser.newContext({viewport: {width: 1440,height:1024}});
  const page = await context.newPage();
  const issues = [];
  page.on('pageerror', error => issues.push(error.message));
  page.on('console', message => {if (message.type() === 'error' && /Content Security Policy/.test(message.text())) issues.push(message.text());});
  page.setDefaultTimeout(10000);
  try {
    await page.goto(url);
    await page.getByLabel('Access token').fill(NETGUARD_ADMIN_TOKEN);
    await page.getByRole('button',{name:'Open console'}).click();
    await page.locator('#device-count').getByText('5',{exact:true}).waitFor();
    await page.locator('#network-map canvas').first().waitFor();
    await page.locator('#activity').getByText('web.login').first().waitFor();
    await screenshot(page, 'netguard-desktop.png');
    await page.getByRole('link',{name:'Network Topology'}).click();
    await page.locator('#device option').nth(1).waitFor({state:'attached'});
    await page.route('**/api/v1/networks/*/topology', async route => {
      const response = await route.fetch();
      const baseline = await response.json();
      baseline.network.devices[0].name = '<b>Untrusted device label</b>';
      await route.fulfill({response, json:baseline});
    });
    await page.reload();
    await page.locator('#device option').first().waitFor({state:'attached'});
    assert.equal(await page.locator('#device option').first().textContent(), '<b>Untrusted device label</b>');
    assert.equal(await page.locator('#device option b').count(),0);
    await page.unrouteAll();
    await page.getByRole('link',{name:'Security Audit'}).click();
    await page.getByRole('button',{name:'Run audit'}).click();
    await page.locator('#audit-detail').getByText('dmz cash',{exact:true}).waitFor();
    await page.locator('#audit-detail').getByText('unknown',{exact:true}).waitFor();
    await page.getByRole('link',{name:'Honeypot Events'}).click();
    await page.getByText('offline-fixture',{exact:false}).first().waitFor();
    await page.route('**/api/v1/honeypot/events', async route => {
      const response = await route.fetch();
      const observations = await response.json();
      observations[0].sensor = '<b>Untrusted sensor label</b>';
      await route.fulfill({response, json:observations});
    });
    await page.getByRole('button',{name:'Refresh'}).click();
    await page.getByText('<B>UNTRUSTED SENSOR LABEL</B>',{exact:false}).waitFor();
    assert.equal(await page.locator('#honeypot-list b').count(),0);
    await page.unrouteAll();
    await page.getByRole('link',{name:'Greenfield Designer'}).click();
    await page.getByRole('button',{name:'Start design'}).click();
    await page.getByText('awaiting input',{exact:true}).first().waitFor();
    await page.locator('select[name=organization]').selectOption('retail');
    await page.locator('select[name=availability]').selectOption('single');
    for (const [key, value] of Object.entries({sites:'2',users_per_site:'15',devices_per_site:'7',registers_per_site:'0',throughput_mbps:'100',packets_per_second:'18000',budget_minor:'20000',currency:'USD',region:'US',address_pool:'10.80.0.0/16'})) await page.locator(`input[name=${key}]`).fill(value);
    await page.getByRole('button',{name:'Submit requirements to open task'}).click();
    await page.getByText('succeeded',{exact:true}).first().waitFor();
    await page.locator('[aria-label="Generated Greenfield diagram"] canvas').first().waitFor();
    const taskId = await page.locator('#task-id').inputValue();
    const target = '**/api/v1/tasks/' + taskId;
    await page.route(target, async route => {
      const response = await route.fetch();
      const task = await response.json();
      task.status = 'recovery_required';
      task.artifacts = [{name:'topology.mmd',content:'<b>Untrusted artifact</b>'}];
      await route.fulfill({response, json:task});
    });
    await page.getByRole('button',{name:'Open / refresh'}).click();
    await page.getByText('recovery required',{exact:true}).waitFor();
    await page.getByText('topology.mmd',{exact:true}).click();
    await page.locator('pre').getByText('<b>Untrusted artifact</b>').waitFor();
    assert.equal(await page.locator('pre b').count(),0);
    await page.unrouteAll();
    await page.getByRole('link',{name:'AI Workspace'}).click();
    await page.locator('#custom-goal').evaluate(field => { field.value = '{"kind":"invalid"}'; });
    await page.getByRole('button',{name:'Generate route plan'}).click();
    await page.locator('#status').getByText('Check the input fields and submit again.').waitFor();
    await page.locator('#custom-goal').evaluate(field => { field.value = ''; });
    await page.locator('#route-device').selectOption({label:'Infra spoke'});
    await page.locator('#route-subnet').selectOption({label:'Cash / Payment · 10.20.0.0/16'});
    await page.locator('#dry-run').uncheck();
    await page.getByRole('button',{name:'Generate route plan'}).click();
    await page.getByText('awaiting approval',{exact:true}).first().waitFor();
    await page.getByRole('link',{name:'Change Plans & Approvals'}).click();
    await page.getByRole('button',{name:'Review plan'}).click();
    await page.getByRole('button',{name:'Approve mock change'}).click();
    await page.getByText('Execution evidence',{exact:true}).waitFor();
    await page.getByRole('link',{name:'Network Topology'}).click();
    await page.getByText('Revision 2',{exact:false}).first().waitFor();
    await page.setViewportSize({width:320,height:800});
    await page.getByRole('link',{name:'Overview'}).click();
    await page.locator('#revision-count').getByText('2',{exact:true}).waitFor();
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await screenshot(page, 'netguard-mobile.png');
    assert.deepEqual(issues,[]);
    console.log('Browser PASS: desktop/mobile, audit, observations, Greenfield, approval, topology revision, HTML text rendering');
  } catch (error) {
    console.log(await page.locator('#status').textContent().catch(()=>null), issues);
    await screenshot(page, 'netguard-failure.png').catch(()=>{});
    throw error;
  } finally {
    await browser.close();
  }
})().catch(error => {console.error(error.message); process.exitCode=1;});
