import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT || 3001);
const sessions = new Map();

const mime = {'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json; charset=utf-8'};
const send=(res,code,body,headers={})=>{const b=Buffer.isBuffer(body)?body:Buffer.from(String(body));res.writeHead(code,{'content-length':b.length,...headers});res.end(b)};
const json=(res,code,obj)=>send(res,code,JSON.stringify(obj),{'content-type':'application/json; charset=utf-8'});
const readBody=async req=>{const a=[];for await(const c of req)a.push(c);return a.length?JSON.parse(Buffer.concat(a).toString('utf8')):{}};
const b64=o=>Buffer.from(JSON.stringify(o)).toString('base64url');
function signature(meetingNumber,role=0){
  const key=process.env.ZOOM_CLIENT_ID, secret=process.env.ZOOM_CLIENT_SECRET;
  if(!key||!secret) throw new Error('Zoom credentials kiritilmagan');
  const iat=Math.floor(Date.now()/1000)-30, exp=iat+7200;
  const h=b64({alg:'HS256',typ:'JWT'}), p=b64({appKey:key,sdkKey:key,mn:String(meetingNumber).replace(/\D/g,''),role:Number(role)||0,iat,exp,tokenExp:exp});
  const u=`${h}.${p}`, s=crypto.createHmac('sha256',secret).update(u).digest('base64url');
  return {signature:`${u}.${s}`,sdkKey:key};
}
function auth(req,res){const expected=process.env.MONITOR_KEY;if(!expected)return true;const got=req.headers['x-monitor-key'];if(got!==expected){json(res,401,{error:'Monitor kaliti noto‘g‘ri'});return false}return true}
async function telegram(text){
  const token=process.env.TELEGRAM_BOT_TOKEN, chat_id=process.env.TELEGRAM_CHAT_ID;
  if(!token||!chat_id) throw new Error('Telegram sozlanmagan');
  const r=await fetch(`https://api.telegram.org/bot${token}/sendMessage`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({chat_id,text,parse_mode:'HTML',disable_web_page_preview:true})});
  const d=await r.json();if(!r.ok||!d.ok)throw new Error(d.description||'Telegram xatosi');return d;
}
function esc(s=''){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}
async function api(req,res,url){
  if(url.pathname==='/api/health') return json(res,200,{ok:true,zoomConfigured:!!(process.env.ZOOM_CLIENT_ID&&process.env.ZOOM_CLIENT_SECRET),telegramConfigured:!!(process.env.TELEGRAM_BOT_TOKEN&&process.env.TELEGRAM_CHAT_ID)});
  if(!auth(req,res)) return;
  if(url.pathname==='/api/signature'&&req.method==='POST'){const b=await readBody(req);return json(res,200,signature(b.meetingNumber,b.role));}
  if(url.pathname==='/api/test-telegram'&&req.method==='POST'){await telegram('✅ <b>Zoom monitoring</b> Telegram ulanishi ishlayapti.');return json(res,200,{ok:true});}
  if(url.pathname==='/api/session/start'&&req.method==='POST'){const b=await readBody(req);const id=crypto.randomUUID();sessions.set(id,{id,meetingNumber:String(b.meetingNumber||''),startedAt:new Date().toISOString(),events:[],people:{}});return json(res,200,{id});}
  if(url.pathname==='/api/event'&&req.method==='POST'){const b=await readBody(req),s=sessions.get(b.sessionId);if(!s)return json(res,404,{error:'Session topilmadi'});const e={...b,at:new Date().toISOString()};s.events.push(e);if(b.name){const p=s.people[b.userId]||{name:b.name,joined:0,left:0,cameraOffCount:0,cameraOffMs:0,offSince:null,phone:false};p.name=b.name;p.phone=!!b.phone;if(b.type==='joined')p.joined++;if(b.type==='left'){p.left++;if(p.offSince){p.cameraOffMs+=Date.now()-p.offSince;p.offSince=null}}if(b.type==='camera_off'&&!p.offSince){p.cameraOffCount++;p.offSince=Date.now()}if(b.type==='camera_on'&&p.offSince){p.cameraOffMs+=Date.now()-p.offSince;p.offSince=null}s.people[b.userId]=p;}
    if(b.notify){const icon=b.type==='joined'?'✅':b.type==='left'?'🚪':b.type==='camera_off'?'🔴':b.type==='camera_on'?'🟢':'ℹ️';telegram(`${icon} <b>${esc(b.name||'Qatnashchi')}</b>\n${esc(b.message||b.type)}`).catch(()=>{});}return json(res,200,{ok:true});}
  const m=url.pathname.match(/^\/api\/session\/([^/]+)\/report\.csv$/);if(m){const s=sessions.get(m[1]);if(!s)return json(res,404,{error:'Session topilmadi'});const rows=[['F.I.Sh.','Kirish','Chiqish','Kamera o‘chirish','Kamera o‘chiq daqiqa','Telefon']];for(const p of Object.values(s.people)){let ms=p.cameraOffMs+(p.offSince?Date.now()-p.offSince:0);rows.push([p.name,p.joined,p.left,p.cameraOffCount,(ms/60000).toFixed(2),p.phone?'Ha':'Yo‘q'])}const csv='\uFEFF'+rows.map(r=>r.map(v=>`"${String(v).replaceAll('"','""')}"`).join(',')).join('\n');return send(res,200,csv,{'content-type':'text/csv; charset=utf-8','content-disposition':'attachment; filename="zoom-report.csv"'});}
  return json(res,404,{error:'API topilmadi'});
}
async function route(req,res){
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  if(url.pathname.startsWith('/api/')){try{return await api(req,res,url)}catch(e){return json(res,500,{error:e.message})}}
  const map={'/':'index.html','/index.html':'index.html','/main.js':'main.js','/style.css':'style.css'};const f=map[url.pathname];if(!f)return send(res,404,'Not found',{'content-type':'text/plain'});
  try{const data=await fs.readFile(path.join(__dirname,f));return send(res,200,data,{'content-type':mime[path.extname(f)]||'application/octet-stream'})}catch{return send(res,404,'Not found')}
}
http.createServer(route).listen(PORT,'0.0.0.0',()=>console.log(`Zoom Monitor: ${PORT}`));
