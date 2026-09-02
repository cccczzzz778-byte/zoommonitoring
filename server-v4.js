import http from 'node:http';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const PORT=Number(process.env.PORT||3001);
const CORE_PORT=Number(process.env.CORE_PORT||3002);
const oauthSessions=new Map();
const pendingStates=new Map();

const core=spawn(process.execPath,[path.join(__dirname,'server-v3.js')],{
  env:{...process.env,PORT:String(CORE_PORT)},stdio:['ignore','inherit','inherit']
});
core.on('exit',(code)=>{console.error('Core server stopped:',code);process.exit(code??1)});

const send=(res,code,body,headers={})=>{const b=Buffer.isBuffer(body)?body:Buffer.from(String(body));res.writeHead(code,{'content-length':b.length,...headers});res.end(b)};
const json=(res,code,obj,headers={})=>send(res,code,JSON.stringify(obj),{'content-type':'application/json; charset=utf-8',...headers});
const readBody=async req=>{const a=[];for await(const c of req)a.push(c);if(!a.length)return{};return JSON.parse(Buffer.concat(a).toString('utf8'))};
const cookieMap=req=>Object.fromEntries(String(req.headers.cookie||'').split(';').map(x=>x.trim()).filter(Boolean).map(x=>{const i=x.indexOf('=');return i<0?[x,'']:[x.slice(0,i),decodeURIComponent(x.slice(i+1))]}));
const sidCookie=sid=>`zm_sid=${encodeURIComponent(sid)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=2592000`;
const stateCookie=state=>`zm_oauth_state=${encodeURIComponent(state)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
const clearStateCookie='zm_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
const publicBase=()=>{const raw=process.env.PUBLIC_URL||process.env.RAILWAY_STATIC_URL||process.env.RAILWAY_SERVICE_ZOOMMONITORING_URL||process.env.RAILWAY_PUBLIC_DOMAIN||'zoommonitoring-production.up.railway.app';return /^https?:\/\//i.test(raw)?raw:`https://${raw}`};
const redirectUri=()=>process.env.ZOOM_OAUTH_REDIRECT_URI||`${publicBase().replace(/\/$/,'')}/oauth/zoom/callback`;
const clientId=()=>String(process.env.ZOOM_CLIENT_ID||'').trim();
const clientSecret=()=>String(process.env.ZOOM_CLIENT_SECRET||'').trim();

function monitorAuth(req){const expected=String(process.env.MONITOR_KEY||'');if(!expected)return true;return req.headers['x-monitor-key']===expected;}
function basicAuth(){return 'Basic '+Buffer.from(`${clientId()}:${clientSecret()}`).toString('base64')}

async function tokenRequest(params){
  const body=new URLSearchParams(params);
  const r=await fetch('https://zoom.us/oauth/token',{method:'POST',headers:{authorization:basicAuth(),'content-type':'application/x-www-form-urlencoded'},body});
  const d=await r.json().catch(()=>({}));
  if(!r.ok||!d.access_token)throw new Error(d.reason||d.error_description||d.error||`Zoom OAuth HTTP ${r.status}`);
  return d;
}
async function refreshIfNeeded(session){
  if(session.accessToken&&Date.now()<session.expiresAt-60000)return session.accessToken;
  if(!session.refreshToken)throw new Error('Zoom avtorizatsiyasi eskirgan. Qayta kiring.');
  const d=await tokenRequest({grant_type:'refresh_token',refresh_token:session.refreshToken});
  session.accessToken=d.access_token;session.refreshToken=d.refresh_token||session.refreshToken;session.expiresAt=Date.now()+Number(d.expires_in||3600)*1000;session.scope=d.scope||session.scope;
  return session.accessToken;
}
async function getObf(session,meeting){
  const access=await refreshIfNeeded(session);
  const mn=String(meeting||'').replace(/\D/g,'');
  if(!mn)throw new Error('Meeting ID noto‘g‘ri');
  const u=new URL('https://api.zoom.us/v2/users/me/token');u.searchParams.set('type','onbehalf');u.searchParams.set('meeting_id',mn);
  const r=await fetch(u,{headers:{authorization:`Bearer ${access}`}});
  const d=await r.json().catch(()=>({}));
  if(!r.ok||!d.token){
    const msg=d.message||d.reason||d.error||`Zoom API HTTP ${r.status}`;
    throw new Error(`${msg}. OBF olish uchun avtorizatsiya qilingan Zoom foydalanuvchi ayni meeting ichida bo‘lishi va app user:read:token scope'iga ega bo‘lishi kerak.`);
  }
  return d.token;
}

function proxy(req,res){
  const opts={hostname:'127.0.0.1',port:CORE_PORT,path:req.url,method:req.method,headers:{...req.headers,host:`127.0.0.1:${CORE_PORT}`}};
  const p=http.request(opts,r=>{res.writeHead(r.statusCode||502,r.headers);r.pipe(res)});p.on('error',e=>json(res,502,{error:'Core server unavailable',detail:e.message}));req.pipe(p);
}

async function route(req,res){
  const url=new URL(req.url,`http://${req.headers.host||'localhost'}`);
  if(url.pathname==='/'||url.pathname==='/index.html'){
    try{return send(res,200,await fs.readFile(path.join(__dirname,'index-v4.html')),{'content-type':'text/html; charset=utf-8','cache-control':'no-store'})}catch{return proxy(req,res)}
  }
  if(url.pathname==='/main.js'){
    try{return send(res,200,await fs.readFile(path.join(__dirname,'main-v4.js')),{'content-type':'text/javascript; charset=utf-8','cache-control':'no-store'})}catch{return proxy(req,res)}
  }
  if(url.pathname==='/api/oauth/start'&&req.method==='POST'){
    if(!monitorAuth(req))return json(res,401,{error:'Monitor kaliti noto‘g‘ri'});
    if(!clientId()||!clientSecret())return json(res,500,{error:'Zoom OAuth credentiallari yo‘q'});
    const body=await readBody(req).catch(()=>({}));
    let sid=cookieMap(req).zm_sid;if(!sid)sid=crypto.randomUUID();
    const state=crypto.randomBytes(24).toString('base64url');
    pendingStates.set(state,{sid,meeting:String(body.meetingNumber||''),createdAt:Date.now()});
    const auth=new URL('https://zoom.us/oauth/authorize');auth.searchParams.set('response_type','code');auth.searchParams.set('client_id',clientId());auth.searchParams.set('redirect_uri',redirectUri());auth.searchParams.set('state',state);
    return json(res,200,{authorizationUrl:auth.toString(),redirectUri:redirectUri()},{'set-cookie':[sidCookie(sid),stateCookie(state)]});
  }
  if(url.pathname==='/oauth/zoom/callback'&&req.method==='GET'){
    const cookies=cookieMap(req);
    const code=url.searchParams.get('code');
    const queryState=url.searchParams.get('state');
    const state=queryState||cookies.zm_oauth_state||'';
    const err=url.searchParams.get('error');
    const p=state?pendingStates.get(state):null;
    if(err)return send(res,400,`Zoom authorization failed: ${err}`,{'content-type':'text/plain; charset=utf-8','set-cookie':clearStateCookie});
    if(!code||!state||!p||Date.now()-p.createdAt>10*60*1000)return send(res,400,'OAuth state/code invalid yoki eskirgan. Saytga qaytib Zoom bilan avtorizatsiya tugmasini yana bosing.',{'content-type':'text/plain; charset=utf-8','set-cookie':clearStateCookie});
    if(cookies.zm_sid&&cookies.zm_sid!==p.sid)return send(res,400,'OAuth sessiya mos kelmadi. Qayta avtorizatsiya qiling.',{'content-type':'text/plain; charset=utf-8','set-cookie':clearStateCookie});
    pendingStates.delete(state);
    try{
      const d=await tokenRequest({grant_type:'authorization_code',code,redirect_uri:redirectUri()});
      oauthSessions.set(p.sid,{accessToken:d.access_token,refreshToken:d.refresh_token,expiresAt:Date.now()+Number(d.expires_in||3600)*1000,scope:d.scope||'',authorizedAt:new Date().toISOString()});
      return send(res,302,'',{'location':`/?zoom_auth=ok${p.meeting?`&meeting=${encodeURIComponent(p.meeting)}`:''}`,'set-cookie':[sidCookie(p.sid),clearStateCookie]});
    }catch(e){return send(res,500,`Zoom token exchange xatosi: ${e.message}`,{'content-type':'text/plain; charset=utf-8','set-cookie':clearStateCookie})}
  }
  if(url.pathname==='/api/oauth/status'&&req.method==='GET'){
    if(!monitorAuth(req))return json(res,401,{error:'Monitor kaliti noto‘g‘ri'});
    const sid=cookieMap(req).zm_sid,s=sid?oauthSessions.get(sid):null;
    return json(res,200,{authorized:!!s,scope:s?.scope||'',redirectUri:redirectUri(),reviewRequiredForExternalMeetings:true});
  }
  if(url.pathname==='/api/obf'&&req.method==='POST'){
    if(!monitorAuth(req))return json(res,401,{error:'Monitor kaliti noto‘g‘ri'});
    const sid=cookieMap(req).zm_sid,s=sid?oauthSessions.get(sid):null;if(!s)return json(res,401,{error:'Avval Zoom bilan avtorizatsiya qiling'});
    const b=await readBody(req).catch(()=>({}));
    try{return json(res,200,{obfToken:await getObf(s,b.meetingNumber)})}catch(e){return json(res,400,{error:e.message})}
  }
  if(url.pathname==='/api/oauth/logout'&&req.method==='POST'){
    if(!monitorAuth(req))return json(res,401,{error:'Monitor kaliti noto‘g‘ri'});const sid=cookieMap(req).zm_sid;if(sid)oauthSessions.delete(sid);return json(res,200,{ok:true},{'set-cookie':['zm_sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0',clearStateCookie]});
  }
  return proxy(req,res);
}

http.createServer((req,res)=>route(req,res).catch(e=>json(res,500,{error:e.message}))).listen(PORT,'0.0.0.0',()=>console.log(`Zoom Monitor v4.1 gateway: ${PORT} -> core ${CORE_PORT}`));
