const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const http=require('node:http');
const path=require('node:path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'playwright');

test('Browser: profiles, validation, downloads, sharing, persistence and responsive layout',async()=>{
  const root=path.join(__dirname,'..');
  const server=http.createServer((req,res)=>{
    const file={'/':'index.html','/app.js':'app.js','/styles.css':'styles.css'}[req.url.split('?')[0]];
    if(!file){res.writeHead(404);res.end();return}
    res.setHeader('Content-Type',file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'text/html');res.end(fs.readFileSync(path.join(root,file)));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  let browser;
  try{
    browser=await chromium.launch({headless:true,...(process.env.CHROMIUM_PATH?{executablePath:process.env.CHROMIUM_PATH}:{}),args:['--no-sandbox']});
    const context=await browser.newContext({viewport:{width:1440,height:1000},permissions:['clipboard-read','clipboard-write']});
    const page=await context.newPage();const errors=[];page.on('pageerror',e=>errors.push(e.message));
    await context.route('https://fonts.googleapis.com/**',r=>r.fulfill({body:''}));
    const url=`http://127.0.0.1:${server.address().port}/`;
    await page.goto(url);assert.equal(await page.locator('.preset').count(),18);
    for(const id of await page.locator('.preset').evaluateAll(nodes=>nodes.map(n=>n.dataset.id))){
      await page.locator('#clear-all').click();await page.locator(`[data-id="${id}"]`).click();assert.match(await page.locator('#code-output').innerText(),/-w \//);
    }
    for(const profile of await page.locator('#profiles button').all()){
      await profile.click();assert.ok(await page.locator('.preset.active').count()>0);
    }
    assert.equal(await page.locator('#profile-guidance').isVisible(),true);
    assert.match(await page.locator('#code-output').innerText(),/privileged_exec/);
    assert.equal(await page.locator('#download-button').isDisabled(),true);
    await page.locator('#log-host').fill('logs.example.com');
    assert.equal(await page.locator('#tls-settings').isVisible(),true);
    for(const tab of ['rules','rsyslog','install','verify']){
      await page.locator(`[data-tab="${tab}"]`).click();
      const content=await page.locator('#code-output').innerText();assert.ok(content.length>50);
      const downloadPromise=page.waitForEvent('download');await page.locator('#download-button').click();
      const download=await downloadPromise;const downloaded=fs.readFileSync(await download.path(),'utf8');assert.equal(downloaded,content);
      await page.locator('#copy-button').click();assert.equal(await page.evaluate(()=>navigator.clipboard.readText()),content);
    }
    await page.locator('[data-tab="rules"]').click();
    await page.reload();assert.match(await page.locator('#code-output').innerText(),/privileged_exec/);
    await page.locator('#clear-all').click();assert.equal(await page.locator('#profile-guidance').isVisible(),false);
    await page.locator('#destination').selectOption('local');
    await page.locator('#custom-path').fill('/opt/my-app/config.yml');await page.locator('#custom-key').fill('my_app');await page.locator('#path-form button').click();
    assert.match(await page.locator('#code-output').innerText(),/-w \/opt\/my-app\/config.yml -p wa -k my_app/);
    for(const [file,key] of [['/opt/bad path','safe'],['/opt/a','$(id)']]){
      const dialogPromise=page.waitForEvent('dialog').then(async dialog=>{const message=dialog.message();await dialog.accept();return message});
      await page.locator('#custom-path').fill(file);await page.locator('#custom-key').fill(key);await page.locator('#path-form button').click();assert.ok(await dialogPromise);assert.equal(await page.locator('.custom-row').count(),1);
    }
    await page.locator('#share-config').click();const shared=await page.evaluate(()=>navigator.clipboard.readText());assert.ok(shared.includes('#config='));
    const other=await context.newPage();await other.goto(shared);assert.match(await other.locator('#code-output').innerText(),/my_app/);await other.close();
    const jsonPromise=page.waitForEvent('download');await page.locator('#save-config').click();const json=JSON.parse(fs.readFileSync(await (await jsonPromise).path(),'utf8'));assert.equal(json.custom[0][2],'my_app');
    await page.locator('.custom-row button').click();assert.equal(await page.locator('.custom-row').count(),0);
    await page.locator('#load-demo').click();assert.match(await page.locator('#code-output').innerText(),/example_app/);
    await page.locator('#log-port').fill('65536');assert.equal(await page.locator('#download-button').isDisabled(),true);assert.match(await page.locator('#warnings').innerText(),/65535/);
    await page.locator('#log-port').fill('6514');assert.equal(await page.locator('#download-button').isDisabled(),false);
    await page.locator('#transport').selectOption('udp');assert.equal(await page.locator('#tls-settings').isVisible(),false);assert.match(await page.locator('#warnings').innerText(),/UDP/);
    await page.locator('#transport').selectOption('tls');await page.locator('#tls-ca').fill('/etc/ca file');assert.equal(await page.locator('#download-button').isDisabled(),true);await page.locator('#tls-ca').fill('/etc/rsyslog.d/ca.pem');
    for(const width of [320,375,650,768,850,1024,1440]){
      await page.setViewportSize({width,height:900});
      const overflowing=await page.evaluate(()=>[...document.querySelectorAll('body *')].filter(x=>x.getBoundingClientRect().right>innerWidth+1).map(x=>x.tagName+'.'+x.className));
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true,`Horizontal overflow at ${width}px: ${overflowing.join(', ')}`);
    }
    await page.goto(url+'#config='+Buffer.from('{"custom":[null]}').toString('base64'));assert.match(await page.locator('#warnings').innerText(),/Не удалось загрузить/);
    const blocked=await browser.newContext();await blocked.addInitScript(()=>{Object.defineProperty(window,'localStorage',{get(){throw Error('blocked')}})});
    const blockedPage=await blocked.newPage();blockedPage.on('pageerror',e=>errors.push(e.message));await blockedPage.goto(url);assert.equal(await blockedPage.locator('.preset').count(),18);await blocked.close();
    assert.deepEqual(errors,[]);
    console.log('Browser scenarios passed, including 7 viewport widths.');
  }finally{if(browser)await browser.close();await new Promise(resolve=>server.close(resolve))}
});
