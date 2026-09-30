const presets=[
['auth','⌁','SSH и авторизация','sshd, sudoers и события входа',[['/etc/ssh/sshd_config','wa','ssh_config'],['/etc/ssh/sshd_config.d','wa','ssh_config'],['/etc/sudoers','wa','sudoers'],['/etc/sudoers.d','wa','sudoers']]],
['identity','◉','Учётные записи','Пользователи, группы, пароли и shadow',[['/etc/passwd','wa','identity'],['/etc/group','wa','identity'],['/etc/shadow','wa','identity'],['/etc/gshadow','wa','identity']]],
['pam','⊞','PAM и security policy','PAM, лимиты и политики доступа',[['/etc/pam.d','wa','pam'],['/etc/security','wa','security_policy'],['/etc/login.defs','wa','login_policy']]],
['system','⚙','Система и службы','systemd, hostname и модули',[['/etc/systemd/system','wa','systemd'],['/usr/lib/systemd/system','wa','systemd'],['/etc/hostname','wa','system_config'],['/etc/modprobe.d','wa','kernel_modules']]],
['schedule','◷','Cron и задачи','Cron, at и фоновые задания',[['/etc/crontab','wa','cron'],['/etc/cron.d','wa','cron'],['/etc/cron.daily','wa','cron'],['/var/spool/cron','wa','cron']]],
['network','↔','Сеть и firewall','DNS, интерфейсы и фильтрация',[['/etc/hosts','wa','network_config'],['/etc/resolv.conf','wa','network_config'],['/etc/network','wa','network_config'],['/etc/nftables.conf','wa','firewall']]],
['packages','▣','Пакеты и обновления','APT, DNF, YUM и история ПО',[['/etc/apt','wa','package_manager'],['/etc/dnf','wa','package_manager'],['/etc/yum.conf','wa','package_manager'],['/var/log/apt','wa','package_manager']]],
['certificates','◇','Сертификаты и ключи','TLS, CA и ключи root SSH',[['/etc/ssl','wa','certificates'],['/etc/pki','wa','certificates'],['/etc/letsencrypt','wa','certificates'],['/root/.ssh','wa','root_ssh_keys']]],
['web','◫','Веб-серверы','Nginx, Apache и web-контент',[['/etc/nginx','wa','nginx'],['/etc/apache2','wa','apache'],['/etc/httpd','wa','apache'],['/var/www','wa','web_content']]],
['databases','◈','Базы данных','PostgreSQL, MySQL и Redis',[['/etc/postgresql','wa','postgresql'],['/etc/mysql','wa','mysql'],['/etc/my.cnf','wa','mysql'],['/etc/redis','wa','redis']]],
['containers','□','Контейнеры','Docker, containerd и Podman',[['/etc/docker','wa','docker'],['/etc/containerd','wa','containerd'],['/etc/containers','wa','containers']]],
['boot','▲','Загрузка и kernel','GRUB, sysctl и параметры ядра',[['/etc/default/grub','wa','boot_config'],['/boot/grub','wa','boot_config'],['/boot/grub2','wa','boot_config'],['/etc/sysctl.d','wa','kernel_config']]],
['admin','⌘','Администрирование','Управление пользователями и sudo',[['/usr/sbin/useradd','x','user_management'],['/usr/sbin/userdel','x','user_management'],['/usr/sbin/usermod','x','user_management'],['/usr/bin/passwd','x','password_change'],['/usr/sbin/visudo','x','sudoers_change']]],
['usb','⊙','USB и носители','Монтирование и udev-правила',[['/etc/udev/rules.d','wa','udev_rules'],['/etc/fstab','wa','mount_config'],['/bin/mount','x','mounts'],['/bin/umount','x','mounts']]],
['virtualization','⬡','Виртуализация','KVM, libvirt и QEMU',[['/etc/libvirt','wa','libvirt'],['/var/lib/libvirt','wa','libvirt'],['/etc/qemu','wa','qemu']]],
['backup','◰','Резервные копии','Borg, Restic и rsnapshot',[['/etc/borgmatic','wa','backup'],['/etc/restic','wa','backup'],['/etc/rsnapshot.conf','wa','backup']]],
['logs','▤','Auditd и журналы','Конфигурация демона и правила',[['/etc/audit/auditd.conf','wa','audit_config'],['/etc/audit/rules.d','wa','audit_rules'],['/var/log/audit','wa','audit_log']]],
['mail','✉','Почта и уведомления','Postfix, Exim и aliases',[['/etc/postfix','wa','postfix'],['/etc/exim4','wa','exim'],['/etc/aliases','wa','mail_config']]]
];
const profileMap={minimal:['auth','identity','logs'],server:['auth','identity','pam','system','schedule','network','logs'],web:['auth','identity','web','certificates','network','packages','logs'],database:['auth','identity','databases','backup','certificates','logs'],container:['auth','identity','containers','network','packages','logs'],incident:['auth','identity','pam','system','network','admin','usb','boot','logs'],belarus130:['auth','identity','pam','system','schedule','network','packages','certificates','boot','admin','logs']};
const profileNames={minimal:'Минимум',server:'Linux server',web:'Web server',database:'Database',container:'Docker host',incident:'Incident response',belarus130:'РБ · Linux baseline'};
const $=s=>document.querySelector(s);const active=new Set();let custom=[];let currentTab='rules';
const grid=$('#preset-grid'),profiles=$('#profiles'),code=$('#code-output code');
function esc(v){return String(v).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'}[c]))}
const defaults={distro:'debian',destination:'local',host:'',port:'6514',transport:'tcp',ca:'/etc/rsyslog.d/ca.pem'};
let stateNotice='';
function cfg(){return {distro:$('#distro').value,destination:$('#destination').value,host:$('#log-host').value.trim(),port:$('#log-port').value.trim(),transport:$('#transport').value,ca:$('#tls-ca').value.trim()}}
function validPath(path){return typeof path==='string'&&path.length<=4096&&path!=='/'&&/^\/[\p{L}\p{N}_./:@+-]+$/u.test(path)&&!path.split('/').some(x=>x==='.'||x==='..')}
function watchError(rule){if(!Array.isArray(rule)||rule.length!==3)return 'Некорректная структура правила.';const [path,perms,key]=rule;if(!validPath(path))return 'Укажите абсолютный путь без пробелов, спецсимволов и компонентов . или ..; корень / не поддерживается.';if(typeof perms!=='string'||!/^([rwax]){1,4}$/.test(perms)||new Set(perms).size!==perms.length)return 'Выберите события r, w, a или x без повторов.';if(typeof key!=='string'||!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,30}$/.test(key))return 'Ключ: 1–31 символ, латинские буквы, цифры, _, . и -; первый символ — буква, цифра или _.';return ''}
function validHost(host){if(typeof host!=='string'||!host||host.length>253)return false;if(host.includes(':')){try{return /^[0-9a-f:]+$/i.test(host)&&new URL(`https://[${host}]/`).hostname.startsWith('[')}catch{return false}}if(/^[\d.]+$/.test(host))return host.split('.').length===4&&host.split('.').every(x=>/^\d{1,3}$/.test(x)&&Number(x)<=255);return host.split('.').every(x=>/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(x))}
function configErrors(c=cfg()){const errors=[];if(!['debian','rhel','fedora'].includes(c.distro))errors.push('Выберите поддерживаемый дистрибутив.');if(!['local','rsyslog','graylog','siem'].includes(c.destination))errors.push('Выберите назначение логов.');if(!['tcp','tls','udp'].includes(c.transport))errors.push('Выберите транспорт TCP, TLS или UDP.');if(c.destination!=='local'){if(!validHost(c.host))errors.push('Укажите корректный hostname, IPv4 или IPv6 без порта и схемы URL.');if(!/^\d{1,5}$/.test(c.port)||Number(c.port)<1||Number(c.port)>65535)errors.push('Порт должен быть числом от 1 до 65535.');if(c.transport==='tls'&&!validPath(c.ca))errors.push('Укажите абсолютный путь к доверенному CA для TLS без пробелов и спецсимволов.')}return errors}
function normalizeState(s){if(!s||typeof s!=='object'||Array.isArray(s))throw Error('Ожидался объект конфигурации.');const ids=new Set([...presets.map(p=>p[0]),'belarus130']);if(s.active!==undefined&&(!Array.isArray(s.active)||s.active.length>ids.size||s.active.some(x=>!ids.has(x))))throw Error('Некорректный список пресетов.');if(s.custom!==undefined&&(!Array.isArray(s.custom)||s.custom.length>500))throw Error('Некорректный список собственных путей.');const watches=s.custom||[];for(const rule of watches){const error=watchError(rule);if(error)throw Error(error)}if(s.cfg!==undefined&&(!s.cfg||typeof s.cfg!=='object'||Array.isArray(s.cfg)))throw Error('Некорректные настройки доставки.');const c={...defaults};for(const k of Object.keys(defaults)){if(s.cfg&&Object.hasOwn(s.cfg,k)){if(typeof s.cfg[k]!=='string')throw Error('Настройки должны быть строками.');c[k]=s.cfg[k].trim()}}if(!['debian','rhel','fedora'].includes(c.distro)||!['local','rsyslog','graylog','siem'].includes(c.destination)||!['tcp','tls','udp'].includes(c.transport)||!/^\d{1,5}$/.test(c.port)||Number(c.port)<1||Number(c.port)>65535||c.host&&!validHost(c.host)||!validPath(c.ca))throw Error('Некорректные настройки доставки.');return {active:[...new Set(s.active||[])],custom:watches.map(r=>[...r]),cfg:c}}
function rules(){const seen=new Set();return [...presets.filter(p=>active.has(p[0])).flatMap(p=>p[4]),...custom].filter(r=>{const k=r[0]+'|'+r[1];if(seen.has(k))return false;seen.add(k);return true})}
function rbLinuxRules(){return active.has('belarus130')?['# RB Linux baseline: event types for OAC Order No. 130; centralized retention requirement is from OAC Order No. 66.','# Review for kernel architecture and workload before applying.','-w /var/run/utmp -p wa -k session_events','-w /var/log/wtmp -p wa -k session_events','-w /var/log/btmp -p wa -k failed_logins','-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k privileged_exec','-a always,exit -F arch=b64 -S open,openat,creat,truncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access_denied','-a always,exit -F arch=b64 -S open,openat,creat,truncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access_denied','-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=unset -k object_delete','-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time_change','-w /etc/localtime -p wa -k time_change','-w /var/log/audit -p wa -k audit_log_access']:[]}
function rulesText(){const out=rules(),system=rbLinuxRules(),rb130=active.has('belarus130'),watchRules=out.length?out.map(r=>`-w ${r[0]} -p ${r[1]} -k ${r[2]}`).join('\n'):'# Select a preset in AuditdNexus to generate rules.';return `# AuditdNexus — generated auditd rules\n# Review all paths on the target system before deployment.\n${rb130?'# RB Linux baseline: technical baseline only; validate against the applicable system class and approved documentation.\n':''}# Generated: ${new Date().toISOString().slice(0,10)}\n\n${system.length?system.join('\n')+'\n\n':''}${watchRules}\n`}
function rsyslogText(){
  const c=cfg();
  if(c.destination==='local')return '# Local auditd only\n# auditd writes events to /var/log/audit/audit.log.\n';
  const errors=configErrors(c);if(errors.length)return '# '+errors.join('\n# ')+'\n';
  const tls=c.transport==='tls',protocol=c.transport==='udp'?'udp':'tcp';
  return `# /etc/rsyslog.d/60-auditdnexus.conf
# Forward auditd log records generated by AuditdNexus.
${tls?`global(DefaultNetstreamDriverCAFile="${c.ca}")\n`:''}module(load="imfile")

input(type="imfile" File="/var/log/audit/audit.log" Tag="auditd:"
      Facility="local6" Severity="info" PersistStateInterval="100")

if ($syslogtag startswith "auditd:") then {
  action(type="omfwd" Target="${c.host}" Port="${c.port}" Protocol="${protocol}"
${tls?`         StreamDriver="gtls" StreamDriverMode="1"
         StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="${c.host}"\n`:''}${protocol==='tcp'?`         action.resumeRetryCount="-1"
         queue.type="LinkedList" queue.size="10000"\n`:''}  )
  stop
}
`;
}
function installText(){
  const c=cfg(),errors=configErrors(c);if(errors.length)return '# '+errors.join('\n# ')+'\n';
  const deb=c.distro==='debian',remote=c.destination!=='local',tls=remote&&c.transport==='tls';
  const pkg=(deb?'auditd':'audit')+(remote?' rsyslog':'')+(tls?' rsyslog-gnutls':'');
  return `#!/usr/bin/env bash
set -euo pipefail

# Run from the directory containing the downloaded configuration files.
# Check prerequisites before changing system configuration.
test -s auditdnexus.rules || { echo "Missing auditdnexus.rules" >&2; exit 1; }
${remote?'test -s 60-auditdnexus.conf || { echo "Missing 60-auditdnexus.conf" >&2; exit 1; }\n':''}${tls?`sudo test -s '${c.ca}' || { echo "Install the trusted CA certificate at ${c.ca} first." >&2; exit 1; }\n`:''}

# 1. Install required services
${deb?`sudo apt-get update\nsudo apt-get install -y ${pkg}`:`sudo dnf install -y ${pkg}`}
sudo systemctl enable --now auditd
${remote?'sudo systemctl enable --now rsyslog\n':''}
# 2. Install and load auditd rules; a daemon restart is not required.
while read -r directive path rest; do
  if [[ "$directive" == "-w" ]] && ! sudo test -e "$path"; then
    echo "Watch path does not exist: $path. Review auditdnexus.rules." >&2
    exit 1
  fi
done < auditdnexus.rules
sudo install -d -m 750 /etc/audit/rules.d
sudo install -m 640 auditdnexus.rules /etc/audit/rules.d/auditdnexus.rules
sudo augenrules --load

${remote?'# 3. Install rsyslog forwarding configuration\nsudo install -m 640 60-auditdnexus.conf /etc/rsyslog.d/60-auditdnexus.conf\nsudo rsyslogd -N1\nsudo systemctl restart rsyslog\n':'# Remote forwarding is not selected.\n'}# 4. Verify loaded rules
sudo auditctl -l
`;
}
function verifyText(){const r=rules(),key=r[0]?.[2]||'ssh_config';return `# Check auditd service and loaded rules\nsudo systemctl status auditd --no-pager\nsudo auditctl -l\n\n# Search events by a selected key\nsudo ausearch -k ${key} -i\n\n# Summary for today\nsudo ausearch -ts today -i\nsudo aureport --summary -i\n\n${cfg().destination==='local'?'# Remote forwarding is not selected.\n':'# Validate rsyslog config (does not confirm delivery).\nsudo rsyslogd -N1\n'}`}
function tabData(){return {rules:{text:rulesText(),file:'auditdnexus.rules'},rsyslog:{text:rsyslogText(),file:'60-auditdnexus.conf'},install:{text:installText(),file:'install-auditdnexus.sh'},verify:{text:verifyText(),file:'verify-auditdnexus.sh'}}[currentTab]}
function warningText(){const r=rules(),c=cfg(),w=[...configErrors(c)];if(stateNotice)w.push(stateNotice);if(!r.length)w.push('Выберите хотя бы один пресет или добавьте свой путь.');if(r.some(x=>x[1].includes('r')))w.push('Аудит чтения может быстро увеличить объём журналов — используйте его точечно.');if(c.destination!=='local'&&c.transport==='tls')w.push('Установите доверенный CA на сервер и проверьте, что сертификат коллектора содержит указанное имя.');if(active.has('belarus130'))w.push('РБ · Linux baseline: направьте события в центральный контур и храните их не менее 365 дней по применимым требованиям ОАЦ №66; состав источников и порядок реагирования утвердите у ответственного за ИБ.');if(c.transport==='tcp'&&c.destination!=='local')w.push('TCP не шифрует события. Для production предпочтительнее TLS или изолированная сеть.');if(c.transport==='udp'&&c.destination!=='local')w.push('UDP не гарантирует доставку и не шифрует данные. Используйте его только для некритичных событий в доверенной сети.');return w}
function profileGuidance(){return active.has('belarus130')?'<b>ДОБАВЬТЕ СВОЙ ПУТЬ ДЛЯ ИСТОЧНИКОВ ВАШЕЙ СИСТЕМЫ</b><span>Базовые системные правила уже выбраны. Добавьте конфигурации и данные прикладных компонентов, которых нет в типовом Linux.</span><ul><li><code>/etc/&lt;app&gt;</code>, <code>/opt/&lt;app&gt;</code>, <code>/srv/&lt;app&gt;</code> — приложения и их конфигурации;</li><li><code>/etc/postgresql</code>, <code>/etc/mysql</code> — если используются СУБД;</li><li><code>/etc/nginx</code>, <code>/etc/apache2</code> — web-сервисы;</li><li>пути агентов EDR/антивируса, VPN, средств криптографической защиты и их журналов.</li></ul><small>Не добавляйте каталоги с высокой частотой записи без оценки нагрузки. События приложений, СУБД, сети и СЗИ также необходимо направить в центральный коллектор собственными агентами или syslog.</small>':''}
function render(){const r=rules(),explained=[...active].map(id=>presets.find(x=>x[0]===id)).filter(Boolean);document.querySelectorAll('.preset').forEach(x=>{const on=active.has(x.dataset.id);x.classList.toggle('active',on);x.setAttribute('aria-pressed',on)});$('#hero-count').textContent=String(r.length+rbLinuxRules().filter(x=>x.startsWith('-')).length).padStart(2,'0');$('#custom-list').innerHTML=custom.map((x,i)=>`<div class="custom-row"><code>${esc(x[0])}</code><span>-${esc(x[1])}</span><small>${esc(x[2])}</small><button type="button" data-remove="${i}">×</button></div>`).join('');const g=$('#profile-guidance'),guide=profileGuidance();g.hidden=!guide;g.innerHTML=guide;const w=warningText();$('#warnings').innerHTML=w.length?`<b>ПРОВЕРЬТЕ ПЕРЕД DEPLOY</b>${w.map(x=>`<span>${esc(x)}</span>`).join('')}`:'<b class="ok">✓ CONFIGURATION LOOKS GOOD</b><span>Пути всё равно нужно проверить на целевой машине.</span>';const d=tabData();code.textContent=d.text;$('#download-button').textContent=`Скачать ${d.file} ↓`;$('#explain-list').innerHTML=explained.length?explained.map(p=>`<div><b>${p[2]}</b><span>${p[3]}</span></div>`).join(''):'<p class="empty">Выберите пресеты — здесь появится объяснение набора аудита.</p>';$('#tls-settings').hidden=cfg().destination==='local'||cfg().transport!=='tls';const invalid=configErrors().length>0;document.querySelectorAll('#copy-button,#download-button,#save-config,#share-config').forEach(x=>x.disabled=invalid);try{localStorage.setItem('auditdnexus-config',JSON.stringify(normalizeState(state())))}catch{if(!invalid){stateNotice='Браузер не разрешает сохранение настроек. Используйте JSON или ссылку.';$('#warnings').innerHTML+=`<span>${esc(stateNotice)}</span>`}}}
function state(){return {active:[...active],custom,cfg:cfg()}}
function applyState(s){const next=normalizeState(s);active.clear();next.active.forEach(x=>active.add(x));custom=next.custom;Object.entries(next.cfg).forEach(([k,v])=>$('#'+({host:'log-host',port:'log-port',ca:'tls-ca'}[k]||k)).value=v);stateNotice='';render()}
presets.forEach(p=>{const b=document.createElement('button');b.type='button';b.className='preset';b.dataset.id=p[0];b.innerHTML=`<span class="preset-title"><i>${p[1]}</i><strong>${p[2]}</strong><em>✓</em></span><small>${p[3]}</small>`;b.addEventListener('click',()=>{active.has(p[0])?active.delete(p[0]):active.add(p[0]);render()});grid.append(b)});
Object.entries(profileNames).forEach(([id,name])=>{const b=document.createElement('button');b.type='button';b.textContent=name;b.addEventListener('click',()=>{active.clear();profileMap[id].forEach(x=>active.add(x));if(id==='belarus130'){active.add('belarus130');$('#destination').value='rsyslog';$('#transport').value='tls'}render();b.classList.add('picked');setTimeout(()=>b.classList.remove('picked'),500)});profiles.append(b)});
$('#path-form').addEventListener('submit',e=>{
  e.preventDefault();const d=new FormData(e.currentTarget),path=d.get('path').trim(),perms=d.getAll('permission').join(''),key=d.get('key').trim().replace(/\s+/g,'_')||'custom_path';
  const rule=[path,perms,key],error=watchError(rule);if(error)return alert(error);
  if(custom.length>=500)return alert('Максимум 500 собственных путей.');
  if(rules().some(r=>r[0]===path&&r[1]===perms))return alert('Правило для этого пути и событий уже существует.');
  custom.push(rule);e.currentTarget.reset();e.currentTarget.querySelector('[value="w"]').checked=true;e.currentTarget.querySelector('[value="a"]').checked=true;render()
});
$('#custom-list').addEventListener('click',e=>{if(e.target.dataset.remove!==undefined){custom.splice(+e.target.dataset.remove,1);render()}});$('#clear-all').onclick=()=>{active.clear();custom=[];render()};document.querySelectorAll('#distro,#destination,#log-host,#log-port,#transport,#tls-ca').forEach(x=>x.addEventListener('input',render));document.querySelectorAll('.tab').forEach(x=>x.onclick=()=>{currentTab=x.dataset.tab;document.querySelectorAll('.tab').forEach(y=>y.classList.toggle('active',y===x));render()});
$('#copy-button').onclick=async()=>{const value=code.textContent;try{await navigator.clipboard.writeText(value)}catch{const t=document.createElement('textarea');t.value=value;document.body.append(t);t.select();document.execCommand('copy');t.remove()}$('#copy-button').textContent='✓ Скопировано';setTimeout(()=>$('#copy-button').textContent='⧉ Копировать',1300)};$('#download-button').onclick=()=>{const d=tabData(),a=document.createElement('a');a.href=URL.createObjectURL(new Blob([d.text],{type:'text/plain'}));a.download=d.file;a.click();URL.revokeObjectURL(a.href)};
$('#save-config').onclick=()=>{const a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(state(),null,2)],{type:'application/json'}));a.download='auditdnexus-config.json';a.click();URL.revokeObjectURL(a.href)};$('#share-config').onclick=async()=>{const v=btoa(unescape(encodeURIComponent(JSON.stringify(state()))));if(v.length>200000)return alert('Конфигурация слишком большая для ссылки. Сохраните JSON.');const url=`${location.origin}${location.pathname}#config=${v}`;try{await navigator.clipboard.writeText(url);$('#share-config').textContent='✓ Ссылка скопирована'}catch{prompt('Скопируйте ссылку:',url)}setTimeout(()=>$('#share-config').textContent='Скопировать ссылку',1500)};$('#load-demo').onclick=()=>applyState({active:profileMap.web,custom:[['/opt/example-app','wa','example_app']],cfg:{distro:'debian',destination:'rsyslog',host:'logs.example.com',port:'6514',transport:'tls'}});
try{
  const hash=location.hash.match(/^#config=(.+)$/);
  if(hash){if(hash[1].length>200000)throw Error('Слишком большая конфигурация.');applyState(JSON.parse(decodeURIComponent(escape(atob(hash[1])))))}
  else{const saved=localStorage.getItem('auditdnexus-config');if(saved){if(saved.length>200000)throw Error('Слишком большая конфигурация.');applyState(JSON.parse(saved))}}
}catch{stateNotice='Не удалось загрузить сохранённую конфигурацию: данные повреждены или содержат недопустимые значения.'}
$('#year').textContent=new Date().getFullYear();render();
window.addEventListener('hashchange',()=>{
  const hash=location.hash.match(/^#config=(.+)$/);if(!hash)return;
  try{if(hash[1].length>200000)throw Error('Слишком большая конфигурация.');applyState(JSON.parse(decodeURIComponent(escape(atob(hash[1])))))}
  catch{stateNotice='Не удалось загрузить конфигурацию из ссылки: данные повреждены или содержат недопустимые значения.';render()}
});
