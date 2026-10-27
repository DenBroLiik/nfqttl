'use strict';
const $=id=>document.getElementById(id);
const executable='/data/adb/modules/nfqttl/nfqttl';
let busy=false,dirty=false,callbackId=0;
function execute(command){return new Promise((resolve,reject)=>{if(!window.ksu||typeof window.ksu.exec!=='function'){reject(new Error('Открой эту панель через KernelSU → Модули → Nfqttl → WebUI.'));return;}
 const name='nfqttl_callback_'+Date.now()+'_'+callbackId++;
 window[name]=(errno,stdout,stderr)=>{delete window[name];if(Number(errno)!==0)reject(new Error(stderr||stdout||'Команда не выполнена'));else resolve(stdout);};
 try{window.ksu.exec(executable+' '+command,JSON.stringify({}),name);}catch(e){delete window[name];reject(e);}});}
function notice(message,error=false){$('notice').hidden=false;$('notice').classList.toggle('error',error);$('notice').textContent=message;}
function setBusy(value){busy=value;document.querySelectorAll('button').forEach(b=>b.disabled=value);}
function parse(text){return Object.fromEntries(text.split('\n').filter(x=>x.includes('=')).map(x=>{const i=x.indexOf('=');return[x.slice(0,i),x.slice(i+1)];}));}
async function refresh(){const s=parse(await execute('snapshot'));const running=s.RUNNING==='1',paused=s.PAUSED==='1',phase=s.STATE_PHASE;
 const titles={'active':'Правила активны','idle':'Ожидание раздачи','recovering':'Восстановление','installing':'Настройка правил','boot-wait':'Ожидание загрузки','error':'Нужна проверка','cleanup-error':'Ошибка очистки'};
 $('headline').textContent=running?(titles[phase]||'Запуск службы'):(paused?'Модуль на паузе':'Служба остановлена');
 $('badge').textContent=running?(phase==='active'?'Работает':'Служба включена'):'Выключено';
 $('detail').textContent=running&&phase==='active'?'TTL/HL правила установлены. Фактический путь пакетов проверяется диагностикой.':running?'Служба отслеживает сеть.':'Включи службу, чтобы применять правила раздачи.';
 $('toggle').textContent=running?'Приостановить модуль':'Включить модуль';$('toggle').dataset.command=running?'stop':'start';
 $('backend').textContent=running?(s.STATE_BACKEND==='kernel'?'В ядре':s.STATE_BACKEND==='nfqueue'?'NFQUEUE':'—'):'—';
 const modes={normalize:'HL',block:'Блок',pass:'Без изменений','pass-no-ip6tables':'Недоступно'};
 $('ipv6').textContent=running?(modes[s.STATE_IPV6_MODE]||'—'):'—';$('workers').textContent=running?(s.STATE_WORKERS||'0'):'0';
 $('phase').textContent=phase||'—';const interfaces=s.STATE_INTERFACES||'';
 $('downstream').textContent=(interfaces.match(/downstream:(.*?) upstream:/)||[])[1]?.trim()||'—';
 $('upstream').textContent=(interfaces.match(/upstream:(.*)/)||[])[1]?.trim()||'—';$('queue').textContent=s.STATE_QUEUE_STATS||'В режиме ядра очереди NFQUEUE не нужны.';
 $('sqm').textContent='CAKE: '+(s.STATE_SQM_STATUS||'disabled');
 if(!dirty){for(const key of ['TTL','IPV6_HL','BACKEND','IPV6_MODE','WORKERS','SQM_UP_KBIT','SQM_DOWN_KBIT','SQM_UP_IFACE','SQM_DOWN_IFACE']){if(key==='WORKERS'&&![...$(key).options].some(x=>x.value===s[key]))$(key).add(new Option(s[key],s[key]));$(key).value=s[key]??(key.endsWith('_KBIT')?'0':'');}$('DISABLE_OFFLOAD').checked=s.DISABLE_OFFLOAD==='1';}
 if(s.STATE_LAST_ERROR)notice(s.STATE_LAST_ERROR,true);
}
async function operation(fn){if(busy)return;setBusy(true);try{await fn();}catch(e){notice(e.message,true);}finally{setBusy(false);}}
$('refresh').onclick=()=>operation(refresh);
$('toggle').onclick=()=>operation(async()=>{const command=$('toggle').dataset.command;if(!['start','stop'].includes(command))return;notice('Применяем…');await execute(command);notice(command==='start'?'Служба запускается. Обнови состояние через несколько секунд.':'Модуль приостановлен. Настройки offload восстановлены, если их не меняли другие приложения.');await refresh();});
$('settings').addEventListener('input',()=>{dirty=true;});
$('settings').onsubmit=event=>{event.preventDefault();operation(async()=>{let args=[];for(const key of ['TTL','IPV6_HL','WORKERS']){const v=$(key).value;if(!/^\d{1,3}$/.test(v))throw new Error('Введи целое число');const n=Number(v);if(n<1||n>(key==='WORKERS'?8:255))throw new Error('Значение вне диапазона');args.push(key+'='+n);}
 for(const [key,allowed] of [['BACKEND',['auto','kernel','nfqueue']],['IPV6_MODE',['auto','normalize','block','pass']]]){const v=$(key).value;if(!allowed.includes(v))throw new Error('Недопустимый режим');args.push(key+'='+v);}
 for(const direction of ['UP','DOWN']){const rateKey='SQM_'+direction+'_KBIT',ifaceKey='SQM_'+direction+'_IFACE';const rate=$(rateKey).value,iface=$(ifaceKey).value.trim();if(!/^\d{1,7}$/.test(rate)||Number(rate)>1000000||(Number(rate)>0&&Number(rate)<100))throw new Error('CAKE: 0 или 100–1000000 кбит/с');if(iface&&!/^[A-Za-z0-9_.:-]{1,15}$/.test(iface))throw new Error('Недопустимое имя интерфейса');if(Number(rate)>0&&(!iface||!$('DISABLE_OFFLOAD').checked))throw new Error('Для CAKE нужны интерфейс и отключённый offload');args.push(rateKey+'='+Number(rate),ifaceKey+'='+iface);}
 args.push('DISABLE_OFFLOAD='+($('DISABLE_OFFLOAD').checked?'1':'0'));await execute('configure '+args.join(' '));dirty=false;notice('Сохранено. Если служба работала, она перезапущена. После изменения offload перезапусти точку доступа.');await refresh();});};
$('logs').onclick=()=>operation(async()=>{$('output').textContent=await execute('logs')||'Журнал пуст.';});
$('doctor').onclick=()=>operation(async()=>{notice('Проверяем возможности ядра и сети…');$('output').textContent=await execute('doctor');notice('Проверка завершена.');});
$('verify').onclick=()=>operation(async()=>{notice('Идёт проверка 8 секунд. Запусти загрузку на клиенте раздачи…');let text;try{text=await execute('verify --seconds 8');}catch(e){text=e.message;}$('output').textContent=text;notice(/VERIFY_RESULT=PASS/.test(text)?'Поток проходит через правила.':/VERIFY_RESULT=FAIL/.test(text)?'Найдена утечка TTL. Подробности ниже.':'Вывод неоднозначен: нужен трафик от клиента.',/VERIFY_RESULT=FAIL/.test(text));});
operation(refresh);
