const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {spawnSync}=require('node:child_process');
const source=fs.readFileSync(path.join(__dirname,'../app.js'),'utf8');

function app({saved=null,hash='',storageBlocked=false}={}){
  const elements=new Map();
  function element(id){if(!elements.has(id))elements.set(id,{value:'',textContent:'',innerHTML:'',dataset:{},children:[],hidden:false,disabled:false,classList:{toggle(){},add(){},remove(){}},setAttribute(){},addEventListener(type,fn){this[type]=fn},append(x){this.children.push(x)}});return elements.get(id)}
  for(const [id,value] of Object.entries({distro:'debian',destination:'local','log-host':'','log-port':'6514',transport:'tcp','tls-ca':'/etc/rsyslog.d/ca.pem'}))element('#'+id).value=value;
  const storage=new Map(saved===null?[]:[['auditdnexus-config',saved]]);
  const context=vm.createContext({URL,console,setTimeout(){},Date,location:{hash},window:{addEventListener(){}},document:{querySelector:element,querySelectorAll(){return []},createElement(){return element('created-'+Math.random())}},localStorage:{getItem(k){if(storageBlocked)throw Error('Blocked');return storage.get(k)},setItem(k,v){if(storageBlocked)throw Error('Blocked');storage.set(k,v)}},atob:x=>Buffer.from(x,'base64').toString('binary'),escape,unescape,encodeURIComponent,decodeURIComponent});
  vm.runInContext(source,context);
  return {run:code=>vm.runInContext(code,context),element,storage};
}

test('Every preset and profile generates rules; RB marker survives reload and reset',()=>{
  const a=app();
  const counts=a.run('presets.map(p=>{active.clear();active.add(p[0]);return rules().length})');
  assert.equal(counts.length,18);assert.ok(counts.every(x=>x>0));
  for(const button of a.element('#profiles').children){button.click();assert.ok(a.run('rules().length')>0)}
  assert.equal(a.run('rbLinuxRules().filter(x=>x.startsWith("-")).length'),10);
  assert.match(a.run('rulesText()'),/privileged_exec/);
  assert.equal(a.element('#profile-guidance').hidden,false);
  const b=app({saved:a.storage.get('auditdnexus-config')});assert.match(b.run('rulesText()'),/privileged_exec/);
  b.element('#clear-all').onclick();assert.equal(b.run('rbLinuxRules().length'),0);
});

test('Valid paths and keys are accepted; unsafe input and oversized keys rejected',()=>{
  const a=app();
  for(const rule of [['/opt/app/config.yml','wa','my_app'],['/srv/данные','rwax','key-1.2']])assert.equal(a.run(`watchError(${JSON.stringify(rule)})`),'');
  for(const rule of [['/','wa','root'],['relative','wa','key'],['/tmp/a b','wa','key'],['/tmp/a\n-w /etc/passwd','wa','key'],['/tmp/../etc','wa','key'],['/tmp/a','ww','key'],['/tmp/a','','key'],['/tmp/a','wa','$(id)'],['/tmp/a','wa',';id'],['/tmp/a','wa','x'.repeat(32)],['/tmp/a','wa',5]])assert.ok(a.run(`watchError(${JSON.stringify(rule)})`));
});

test('Hostname/IP and port validation covers injection, malformed IPv4 and IPv6',()=>{
  const a=app();
  for(const host of ['logs.example.com','localhost','192.168.1.2','::1','2001:db8::1','2001:0db8:0000:0000:0000:0000:0000:0001'])assert.equal(a.run(`validHost(${JSON.stringify(host)})`),true,host);
  for(const host of ['','https://logs.example.com','logs.example.com:6514','999.1.2.3','1.2.3','-logs.example','logs..example','logs"\nstop','2001:invalid::1'])assert.equal(a.run(`validHost(${JSON.stringify(host)})`),false,host);
  a.element('#destination').value='rsyslog';a.element('#log-host').value='logs.example.com';
  for(const port of ['0','65536','1e3','-1','123"','']){a.element('#log-port').value=port;assert.ok(a.run('configErrors().length'))}
  for(const port of ['1','514','65535']){a.element('#log-port').value=port;assert.equal(a.run('configErrors().length'),0)}
});

test('Invalid state is rejected atomically and cannot mutate unrelated DOM elements',()=>{
  const a=app();a.run('active.add("auth")');
  for(const state of [null,[],{active:'auth'},{active:['unknown']},{custom:[null]},{custom:[['/tmp/a','wa',';id']]},{cfg:{distro:'bad'}},{cfg:{host:'x"'}},{cfg:{port:'70000'}},{cfg:{destination:42}}]){
    assert.throws(()=>a.run(`applyState(${JSON.stringify(state)})`));assert.equal(a.run('active.has("auth")'),true);
  }
  a.run('applyState({cfg:{"custom-path":"/malicious"}})');assert.equal(a.element('#custom-path').value,'');
  for(const saved of ['null','{broken','{"custom":[null]}']){const b=app({saved});assert.match(b.element('#warnings').innerHTML,/Не удалось загрузить/);assert.equal(b.run('rules().length'),0)}
  const b=app({hash:'#config='+Buffer.from(JSON.stringify({active:['auth'],custom:[],cfg:{}})).toString('base64')});assert.ok(b.run('rules().length')>0);
  assert.doesNotThrow(()=>app({storageBlocked:true}));
});

test('All 36 deployment combinations generate syntactically valid shell scripts',()=>{
  const a=app();a.run('active.add("auth")');
  for(const distro of ['debian','rhel','fedora'])for(const destination of ['local','rsyslog','graylog','siem'])for(const transport of ['tcp','tls','udp']){
    a.run(`applyState({active:['auth'],cfg:${JSON.stringify({distro,destination,transport,host:'logs.example.com'})}})`);
    for(const fn of ['installText','verifyText']){const output=a.run(fn+'()');const result=spawnSync('bash',['-n'],{input:output,encoding:'utf8',timeout:5000});assert.equal(result.status,0,result.stderr||String(result.error))}
    const install=a.run('installText()');assert.doesNotMatch(install,/systemctl restart auditd/);
    if(distro==='debian')assert.match(install,/sudo apt-get update\nsudo apt-get install -y/);else assert.match(install,/sudo dnf install -y audit/);
    if(destination==='local'){assert.doesNotMatch(install,/install -y .*rsyslog/);assert.doesNotMatch(a.run('verifyText()'),/sudo rsyslogd/)}
    else {const config=a.run('rsyslogText()');assert.match(config,/Target="logs.example.com"/);if(transport==='tls'){assert.match(config,/DefaultNetstreamDriverCAFile/);assert.match(config,/StreamDriverPermittedPeers="logs.example.com"/);assert.match(install,/rsyslog-gnutls/)}if(transport==='udp')assert.doesNotMatch(config,/StreamDriver|queue.type/)}
  }
});

test('Incomplete remote settings produce explanatory output instead of executable installer',()=>{
  const a=app();a.element('#destination').value='rsyslog';a.element('#log-host').value='"\nmalicious';
  assert.ok(a.run('configErrors().length'));assert.doesNotMatch(a.run('rsyslogText()'),/malicious/);assert.doesNotMatch(a.run('installText()'),/apt-get|dnf/);
});

test('Installer execution uses sudo for package commands and stops before changes on missing files',()=>{
  const directory=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'auditdnexus-install-'));
  try{
    const sudo=path.join(directory,'sudo'),log=path.join(directory,'commands.log');
    fs.writeFileSync(sudo,'#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$AUDITDNEXUS_TEST_LOG"\nif [[ "$1 $2" == "test -e" && "${AUDITDNEXUS_MISSING_PATH:-}" == "1" ]]; then exit 1; fi\nexit 0\n',{mode:0o755});
    const a=app();
    for(const distro of ['debian','rhel','fedora']){
      a.run(`applyState({custom:[['/etc/passwd','wa','identity']],cfg:{distro:'${distro}',destination:'rsyslog',host:'logs.example.com',transport:'tls'}})`);
      fs.writeFileSync(path.join(directory,'auditdnexus.rules'),a.run('rulesText()'));fs.writeFileSync(path.join(directory,'60-auditdnexus.conf'),a.run('rsyslogText()'));
      fs.writeFileSync(log,'');
      const result=spawnSync('bash',[],{input:a.run('installText()'),cwd:directory,env:{...process.env,PATH:directory+':'+process.env.PATH,AUDITDNEXUS_TEST_LOG:log},encoding:'utf8',timeout:10000});
      assert.equal(result.status,0,result.stderr);const commands=fs.readFileSync(log,'utf8');
      if(distro==='debian')assert.match(commands,/apt-get update\napt-get install -y auditd rsyslog rsyslog-gnutls/);else assert.match(commands,/dnf install -y audit rsyslog rsyslog-gnutls/);
      assert.match(commands,/augenrules --load/);assert.match(commands,/rsyslogd -N1/);
    }
    fs.writeFileSync(log,'');
    const missingPath=spawnSync('bash',[],{input:a.run('installText()'),cwd:directory,env:{...process.env,PATH:directory+':'+process.env.PATH,AUDITDNEXUS_TEST_LOG:log,AUDITDNEXUS_MISSING_PATH:'1'},encoding:'utf8',timeout:10000});
    assert.equal(missingPath.status,1);assert.match(missingPath.stderr,/Watch path does not exist/);assert.doesNotMatch(fs.readFileSync(log,'utf8'),/install -m 640|augenrules/);
    fs.unlinkSync(path.join(directory,'auditdnexus.rules'));fs.writeFileSync(log,'');
    const result=spawnSync('bash',[],{input:a.run('installText()'),cwd:directory,env:{...process.env,PATH:directory+':'+process.env.PATH,AUDITDNEXUS_TEST_LOG:log},encoding:'utf8',timeout:10000});
    assert.equal(result.status,1);assert.match(result.stderr,/Missing auditdnexus.rules/);assert.equal(fs.readFileSync(log,'utf8'),'');
  }finally{fs.rmSync(directory,{recursive:true,force:true})}
});

test('rsyslog validates generated TCP, UDP and TLS snippets without touching system services',t=>{
  const executable=process.env.RSYSLOGD||'/usr/sbin/rsyslogd';
  if(!fs.existsSync(executable)){t.skip('rsyslogd is not installed');return}
  const directory=fs.mkdtempSync(path.join(require('node:os').tmpdir(),'auditdnexus-rsyslog-'));
  try{const a=app();for(const transport of ['tcp','udp','tls']){
    a.run(`applyState({cfg:{destination:'rsyslog',host:'127.0.0.1',transport:'${transport}',ca:'/etc/ssl/certs/ca-certificates.crt'}})`);
    const filename=path.join(directory,transport+'.conf');fs.writeFileSync(filename,`global(workDirectory="${directory}")\n`+a.run('rsyslogText()'));
    const result=spawnSync(executable,['-N1','-f',filename],{encoding:'utf8',timeout:10000});assert.equal(result.status,0,result.stderr||String(result.error));
  }}finally{fs.rmSync(directory,{recursive:true,force:true})}
});
