import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3001);
const sessions = new Map();

const mime = {
  '.html':'text/html; charset=utf-8',
  '.js':'text/javascript; charset=utf-8',
  '.css':'text/css; charset=utf-8',
  '.json':'application/json; charset=utf-8'
};

const send=(res,code,body,headers={})=>{
  const b=Buffer.isBuffer(body)?body:Buffer.from(String(body));
  res.writeHead(code,{'content-length':b.length,...headers});
  res.end(b);
};
const json=(res,code,obj)=>send(res,code,JSON.stringify(obj),{'content-type':'application/json; charset=utf-8'});
const readBody=async req=>{
  const a=[];
  for await(const c of req) a.push(c);
  if(!a.length) return {};
  const raw=Buffer.concat(a).toString('utf8');
  return raw ? JSON.parse(raw) : {};
};
const b64=o=>Buffer.from(JSON.stringify(o)).toString('base64url');

function signature(meetingNumber,role=0){
  const key=process.env.ZOOM_CLIENT_ID, secret=process.env.ZOOM_CLIENT_SECRET;
  if(!key||!secret) throw new Error('Zoom credentials kiritilmagan');
  const iat=Math.floor(Date.now()/1000)-30, exp=iat+7200;
  const h=b64({alg:'HS256',typ:'JWT'});
  const p=b64({appKey:key,sdkKey:key,mn:String(meetingNumber).replace(/\D/g,''),role:Number(role)||0,iat,exp,tokenExp:exp});
  const u=`${h}.${p}`;
  const s=crypto.createHmac('sha256',secret).update(u).digest('base64url');
  return {signature:`${u}.${s}`,sdkKey:key};
}

function auth(req,res,url){
  const expected=process.env.MONITOR_KEY;
  if(!expected) return true;
  const got=req.headers['x-monitor-key'] || url?.searchParams?.get('key');
  if(got!==expected){json(res,401,{error:'Monitor kaliti noto‘g‘ri'});return false;}
  return true;
}

function escXml(v=''){
  return String(v).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;').replaceAll("'",'&apos;');
}
function colName(n){let s='';while(n){n--;s=String.fromCharCode(65+n%26)+s;n=Math.floor(n/26);}return s;}
function sheetXml(rows){
  const body=rows.map((row,ri)=>{
    const cells=row.map((v,ci)=>{
      const ref=`${colName(ci+1)}${ri+1}`,style=ri===0?' s="1"':'';
      if(typeof v==='number'&&Number.isFinite(v)) return `<c r="${ref}"${style}><v>${v}</v></c>`;
      return `<c r="${ref}" t="inlineStr"${style}><is><t>${escXml(v ?? '')}</t></is></c>`;
    }).join('');
    return `<row r="${ri+1}">${cells}</row>`;
  }).join('');
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"/></sheetViews><sheetFormatPr defaultRowHeight="15"/><sheetData>${body}</sheetData></worksheet>`;
}
const crcTable=(()=>{const t=new Uint32Array(256);for(let n=0;n<256;n++){let c=n;for(let k=0;k<8;k++)c=(c&1)?0xEDB88320^(c>>>1):(c>>>1);t[n]=c>>>0;}return t;})();
function crc32(buf){let c=0xFFFFFFFF;for(const b of buf)c=crcTable[(c^b)&0xFF]^(c>>>8);return(c^0xFFFFFFFF)>>>0;}
function dosDateTime(date=new Date()){const y=Math.max(1980,date.getFullYear());return{time:(date.getHours()<<11)|(date.getMinutes()<<5)|(date.getSeconds()>>1),date:((y-1980)<<9)|((date.getMonth()+1)<<5)|date.getDate()};}
function zipStore(files){
  const locals=[],centrals=[];let offset=0;const dt=dosDateTime();
  for(const[name,data]of files){
    const nameBuf=Buffer.from(name),body=Buffer.isBuffer(data)?data:Buffer.from(String(data)),crc=crc32(body),local=Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50,0);local.writeUInt16LE(20,4);local.writeUInt16LE(0,6);local.writeUInt16LE(0,8);local.writeUInt16LE(dt.time,10);local.writeUInt16LE(dt.date,12);local.writeUInt32LE(crc,14);local.writeUInt32LE(body.length,18);local.writeUInt32LE(body.length,22);local.writeUInt16LE(nameBuf.length,26);local.writeUInt16LE(0,28);locals.push(local,nameBuf,body);
    const central=Buffer.alloc(46);central.writeUInt32LE(0x02014b50,0);central.writeUInt16LE(20,4);central.writeUInt16LE(20,6);central.writeUInt16LE(0,8);central.writeUInt16LE(0,10);central.writeUInt16LE(dt.time,12);central.writeUInt16LE(dt.date,14);central.writeUInt32LE(crc,16);central.writeUInt32LE(body.length,20);central.writeUInt32LE(body.length,24);central.writeUInt16LE(nameBuf.length,28);central.writeUInt16LE(0,30);central.writeUInt16LE(0,32);central.writeUInt16LE(0,34);central.writeUInt16LE(0,36);central.writeUInt32LE(0,38);central.writeUInt32LE(offset,42);centrals.push(central,nameBuf);offset+=local.length+nameBuf.length+body.length;
  }
  const centralSize=centrals.reduce((n,b)=>n+b.length,0),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(0,4);end.writeUInt16LE(0,6);end.writeUInt16LE(files.length,8);end.writeUInt16LE(files.length,10);end.writeUInt32LE(centralSize,12);end.writeUInt32LE(offset,16);end.writeUInt16LE(0,20);return Buffer.concat([...locals,...centrals,end]);
}
function reportRows(s){
  const people=[['F.I.Sh.','Kirish','Chiqish','Kamera o‘chirish soni','Kamera o‘chiq daqiqa','Telefon/PSTN']];
  for(const p of Object.values(s.people)){const ms=p.cameraOffMs+(p.offSince?Date.now()-p.offSince:0);people.push([p.name,p.joined,p.left,p.cameraOffCount,Number((ms/60000).toFixed(2)),p.phone?'Ha':'Yo‘q']);}
  const events=[['Vaqt','F.I.Sh.','Hodisa','Izoh']];
  for(const e of s.events)events.push([new Date(e.at).toLocaleString('uz-UZ',{timeZone:'Asia/Tashkent'}),e.name||'',e.type||'',e.message||'']);
  return{people,events};
}
function makeXlsx(s){
  const{people,events}=reportRows(s);
  return zipStore([
    ['[Content_Types].xml','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>'],
    ['_rels/.rels','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'],
    ['xl/workbook.xml','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Qatnashchilar" sheetId="1" r:id="rId1"/><sheet name="Hodisalar" sheetId="2" r:id="rId2"/></sheets></workbook>'],
    ['xl/_rels/workbook.xml.rels','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'],
    ['xl/styles.xml','<?xml version="1.0" encoding="UTF-8" standalone="yes"?><styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="2"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/></cellXfs></styleSheet>'],
    ['xl/worksheets/sheet1.xml',sheetXml(people)],['xl/worksheets/sheet2.xml',sheetXml(events)]
  ]);
}
function latestSession(){const arr=[...sessions.values()];return arr.length?arr[arr.length-1]:null;}
function safeFilename(s){const stamp=new Date(s.startedAt).toISOString().slice(0,16).replaceAll(':','-').replace('T','_'),meeting=String(s.meetingNumber||'meeting').replace(/\D/g,'');return`zoom_hisobot_${meeting}_${stamp}.xlsx`;}

async function tg(method,payload,form=false){
  const token=process.env.TELEGRAM_BOT_TOKEN;if(!token)throw new Error('TELEGRAM_BOT_TOKEN kiritilmagan');
  const r=await fetch(`https://api.telegram.org/bot${token}/${method}`,form?{method:'POST',body:payload}:{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)}),d=await r.json();if(!r.ok||!d.ok)throw new Error(d.description||'Telegram xatosi');return d;
}
const sendTelegramText=(chatId,text)=>tg('sendMessage',{chat_id:chatId,text});
async function sendTelegramReport(chatId,s){
  const form=new FormData();form.set('chat_id',String(chatId));form.set('caption',`Zoom hisoboti\nMeeting: ${s.meetingNumber}\nBoshlangan: ${new Date(s.startedAt).toLocaleString('uz-UZ',{timeZone:'Asia/Tashkent'})}`);form.set('document',new Blob([makeXlsx(s)],{type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}),safeFilename(s));return tg('sendDocument',form,true);
}
async function telegramWebhook(req,res){
  const secret=process.env.TELEGRAM_WEBHOOK_SECRET;if(secret&&req.headers['x-telegram-bot-api-secret-token']!==secret)return send(res,403,'Forbidden');
  let update={};try{update=await readBody(req)}catch{return send(res,200,'OK');}
  const msg=update.message;if(!msg?.chat?.id||msg.chat.type!=='private')return send(res,200,'OK');
  const allowed=String(process.env.TELEGRAM_ALLOWED_USER_ID||'').trim();if(allowed&&String(msg.from?.id)!==allowed){await sendTelegramText(msg.chat.id,'Bu botdan foydalanishga ruxsat yo‘q.').catch(()=>{});return send(res,200,'OK');}
  const text=String(msg.text||'').trim();
  if(/^\/start(?:@\w+)?(?:\s|$)/i.test(text))await sendTelegramText(msg.chat.id,'Zoom hisobot boti tayyor.\n\n/hisobot — oxirgi Zoom monitoring sessiyasini Excel fayl qilib olish.').catch(()=>{});
  else if(/^\/hisobot(?:@\w+)?(?:\s|$)/i.test(text)){const s=latestSession();if(!s)await sendTelegramText(msg.chat.id,'Hozircha monitoring hisoboti yo‘q. Avval web saytda Zoom monitoringni boshlang.').catch(()=>{});else await sendTelegramReport(msg.chat.id,s).catch(async e=>{await sendTelegramText(msg.chat.id,`Excel yuborishda xatolik: ${e.message}`).catch(()=>{});});}
  else await sendTelegramText(msg.chat.id,'Excel olish uchun /hisobot yozing.').catch(()=>{});
  return send(res,200,'OK');
}
function publicBaseUrl(){const raw=process.env.PUBLIC_URL||process.env.RAILWAY_STATIC_URL||process.env.RAILWAY_SERVICE_ZOOMMONITORING_URL||process.env.RAILWAY_PUBLIC_DOMAIN;if(!raw)return'';return/^https?:\/\//i.test(raw)?raw:`https://${raw}`;}
async function configureTelegramWebhook(){const token=process.env.TELEGRAM_BOT_TOKEN,base=publicBaseUrl();if(!token||!base)return;const payload={url:`${base.replace(/\/$/,'')}/telegram/webhook`,allowed_updates:['message']};if(process.env.TELEGRAM_WEBHOOK_SECRET)payload.secret_token=process.env.TELEGRAM_WEBHOOK_SECRET;await tg('setWebhook',payload);console.log('Telegram webhook configured');}

async function api(req,res,url){
  if(url.pathname==='/api/health')return json(res,200,{ok:true,zoomConfigured:!!(process.env.ZOOM_CLIENT_ID&&process.env.ZOOM_CLIENT_SECRET),telegramConfigured:!!process.env.TELEGRAM_BOT_TOKEN,sessions:sessions.size});
  if(!auth(req,res,url))return;
  if(url.pathname==='/api/signature'&&req.method==='POST'){const b=await readBody(req);return json(res,200,signature(b.meetingNumber,b.role));}
  if(url.pathname==='/api/session/start'&&req.method==='POST'){const b=await readBody(req),id=crypto.randomUUID();sessions.set(id,{id,meetingNumber:String(b.meetingNumber||''),startedAt:new Date().toISOString(),events:[],people:{}});return json(res,200,{id});}
  if(url.pathname==='/api/event'&&req.method==='POST'){
    const b=await readBody(req),s=sessions.get(b.sessionId);if(!s)return json(res,404,{error:'Session topilmadi'});s.events.push({...b,at:new Date().toISOString()});
    if(b.name){const p=s.people[b.userId]||{name:b.name,joined:0,left:0,cameraOffCount:0,cameraOffMs:0,offSince:null,phone:false};p.name=b.name;p.phone=!!b.phone;if(b.type==='joined'){p.joined++;if(b.video===false&&!p.offSince){p.cameraOffCount++;p.offSince=Date.now();}}if(b.type==='left'){p.left++;if(p.offSince){p.cameraOffMs+=Date.now()-p.offSince;p.offSince=null;}}if(b.type==='camera_off'&&!p.offSince){p.cameraOffCount++;p.offSince=Date.now();}if(b.type==='camera_on'&&p.offSince){p.cameraOffMs+=Date.now()-p.offSince;p.offSince=null;}s.people[b.userId]=p;}
    return json(res,200,{ok:true});
  }
  const stopMatch=url.pathname.match(/^\/api\/session\/([^/]+)\/stop$/);if(stopMatch&&req.method==='POST'){const s=sessions.get(stopMatch[1]);if(!s)return json(res,404,{error:'Session topilmadi'});const now=Date.now();for(const p of Object.values(s.people)){if(p.offSince){p.cameraOffMs+=now-p.offSince;p.offSince=null;}}s.endedAt=new Date(now).toISOString();return json(res,200,{ok:true});}
  const x=url.pathname.match(/^\/api\/session\/([^/]+)\/report\.xlsx$/);if(x){const s=sessions.get(x[1]);if(!s)return json(res,404,{error:'Session topilmadi'});return send(res,200,makeXlsx(s),{'content-type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','content-disposition':`attachment; filename="${safeFilename(s)}"`});}
  if(url.pathname==='/api/report/latest.xlsx'){const s=latestSession();if(!s)return json(res,404,{error:'Hisobot topilmadi'});return send(res,200,makeXlsx(s),{'content-type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','content-disposition':`attachment; filename="${safeFilename(s)}"`});}
  return json(res,404,{error:'API topilmadi'});
}

async function route(req,res){
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  if(url.pathname==='/telegram/webhook'&&req.method==='POST'){try{return await telegramWebhook(req,res)}catch(e){console.error('Telegram webhook error:',e);return send(res,200,'OK');}}
  if(url.pathname.startsWith('/api/')){try{return await api(req,res,url)}catch(e){console.error(e);return json(res,500,{error:e.message});}}
  const map={'/':'index.html','/index.html':'index.html','/main.js':'main.js','/style.css':'style.css'},f=map[url.pathname];if(!f)return send(res,404,'Not found',{'content-type':'text/plain'});
  try{const data=await fs.readFile(path.join(__dirname,f));return send(res,200,data,{'content-type':mime[path.extname(f)]||'application/octet-stream'});}catch{return send(res,404,'Not found');}
}

const server=http.createServer(route);server.listen(PORT,'0.0.0.0',()=>{console.log(`Zoom Monitor: ${PORT}`);configureTelegramWebhook().catch(e=>console.error('Telegram setup:',e.message));});
