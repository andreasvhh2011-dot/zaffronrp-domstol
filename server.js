const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const ROOT=__dirname, PUB=path.join(ROOT,'public'), DATA=path.join(ROOT,'data');
const PORT=process.env.PORT||3000; const sessions=new Map();
function read(n){try{return JSON.parse(fs.readFileSync(path.join(DATA,n),'utf8'))}catch{return []}}
function write(n,d){fs.writeFileSync(path.join(DATA,n),JSON.stringify(d,null,2))}
function json(res,status,obj){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});res.end(JSON.stringify(obj))}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>200000)req.destroy()});req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch(e){reject(e)}})})}
function cookie(req){return (req.headers.cookie||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('sid='))?.slice(4)}
function user(req){return sessions.get(cookie(req))||null}
function safe(s,max=5000){return String(s??'').trim().slice(0,max)}
function id(prefix){return prefix+'-'+new Date().getFullYear()+'-'+crypto.randomBytes(4).toString('hex').toUpperCase()}
function hashPassword(password,salt=crypto.randomBytes(16).toString('hex')){return `${salt}:${crypto.scryptSync(password,salt,64).toString('hex')}`}
function checkPassword(password,stored){
  if(!stored)return false;
  if(!stored.includes(':'))return crypto.timingSafeEqual(Buffer.from(password),Buffer.from(stored));
  const [salt,hash]=stored.split(':');const actual=crypto.scryptSync(password,salt,64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(actual,'hex'),Buffer.from(hash,'hex'));
}
const mime={'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml'};
async function api(req,res){
 if(req.method==='POST'&&req.url==='/api/login'){
  const b=await body(req), users=read('users.json'), u=users[b.username];
  if(!u||!checkPassword(String(b.password||''),u.password))return json(res,401,{error:'Forkert brugernavn eller adgangskode'});
  const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{username:b.username,role:u.role,name:u.name});
  res.writeHead(200,{'Set-Cookie':`sid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=28800`,'Content-Type':'application/json','Cache-Control':'no-store'});return res.end(JSON.stringify({user:sessions.get(sid)}));
 }
 if(req.method==='POST'&&req.url==='/api/logout'){const sid=cookie(req);sessions.delete(sid);res.writeHead(200,{'Set-Cookie':'sid=; Max-Age=0; Path=/','Content-Type':'application/json'});return res.end('{}')}
 if(req.url==='/api/me'){return json(res,200,{user:user(req)})}
 if(req.method==='POST'&&req.url==='/api/cases'){
  const b=await body(req);const c={id:id('ZRP'),createdAt:new Date().toISOString(),status:'Afventer',name:safe(b.name,150),rpName:safe(b.rpName,150),email:safe(b.email,180),phone:safe(b.phone,80),discord:safe(b.discord,120),subject:safe(b.subject,250),description:safe(b.description,10000),category:safe(b.category,80),priority:safe(b.priority,40)};
  if(!c.name||!c.email||!c.subject||!c.description)return json(res,400,{error:'Udfyld navn, e-mail, emne og beskrivelse'});
  const arr=read('cases.json');arr.push(c);write('cases.json',arr);return json(res,201,{case:c});
 }
 if(req.method==='POST'&&req.url==='/api/messages'){
  const b=await body(req);const m={id:id('MSG'),createdAt:new Date().toISOString(),fromName:safe(b.fromName,150),fromEmail:safe(b.fromEmail,180),phone:safe(b.phone,80),rpName:safe(b.rpName,150),discord:safe(b.discord,120),caseId:safe(b.caseId,80),recipient:safe(b.recipient,80),subject:safe(b.subject,250),message:safe(b.message,10000),status:'Ulæst'};
  if(!m.fromName||!m.fromEmail||!m.recipient||!m.subject||!m.message)return json(res,400,{error:'Udfyld alle nødvendige felter'});
  const arr=read('messages.json');arr.push(m);write('messages.json',arr);return json(res,201,{message:m});
 }
 if(req.method==='GET'&&req.url==='/api/inbox'){
  const u=user(req);if(!u)return json(res,401,{error:'Login kræves'});const all=read('messages.json');const arr=u.role==='Administrator'?all:all.filter(m=>m.recipient.toLowerCase()===u.role.toLowerCase()||m.recipient.toLowerCase()==='alle');return json(res,200,{messages:arr.reverse()});
 }
 if(req.method==='POST'&&req.url==='/api/inbox/read'){
  const u=user(req);if(!u)return json(res,401,{error:'Login kræves'});const b=await body(req);let arr=read('messages.json');arr=arr.map(m=>(m.id===b.id&&(u.role==='Administrator'||m.recipient.toLowerCase()===u.role.toLowerCase()||m.recipient.toLowerCase()==='alle'))?{...m,status:'Læst'}:m);write('messages.json',arr);return json(res,200,{ok:true});
 }
 if(req.method==='GET'&&req.url==='/api/cases'){
  const u=user(req);if(!u)return json(res,401,{error:'Login kræves'});return json(res,200,{cases:read('cases.json').reverse()});
 }
 if(req.method==='POST'&&req.url==='/api/cases/status'){
  const u=user(req);if(!u||!['Dommer','Administrator'].includes(u.role))return json(res,403,{error:'Kun dommere og administratorer kan behandle sager'});
  const b=await body(req);const caseId=safe(b.id,80);const status=safe(b.status,40);const hearingDate=safe(b.hearingDate,20);const hearingTime=safe(b.hearingTime,10);const courtroom=safe(b.courtroom,100);
  if(!caseId||!status)return json(res,400,{error:'Sagsnummer og status mangler'});
  if(status==='Accepteret'&&(!/^\d{4}-\d{2}-\d{2}$/.test(hearingDate)||!/^\d{2}:\d{2}$/.test(hearingTime)))return json(res,400,{error:'Ved accept skal dato og tidspunkt udfyldes'});
  if(!['Accepteret','Afvist'].includes(status))return json(res,400,{error:'Ugyldig status'});
  const arr=read('cases.json');const i=arr.findIndex(c=>c.id===caseId);if(i<0)return json(res,404,{error:'Sagen blev ikke fundet'});
  arr[i]={...arr[i],status,processedAt:new Date().toISOString(),processedBy:u.name||u.username};
  if(status==='Accepteret'){arr[i].hearingDate=hearingDate;arr[i].hearingTime=hearingTime;arr[i].courtroom=courtroom||'Ikke fastsat';}
  else {delete arr[i].hearingDate;delete arr[i].hearingTime;delete arr[i].courtroom;}
  write('cases.json',arr);return json(res,200,{case:arr[i]});
 }
 if(req.method==='POST'&&req.url==='/api/admin/password'){
  const u=user(req);if(!u||u.role!=='Administrator')return json(res,403,{error:'Kun administrator kan ændre adgangskoder'});
  const b=await body(req);const target=safe(b.username,40), pw=String(b.password||'');const users=read('users.json');
  if(!users[target])return json(res,404,{error:'Brugeren findes ikke'});if(pw.length<12)return json(res,400,{error:'Adgangskoden skal være mindst 12 tegn'});
  users[target].password=hashPassword(pw);write('users.json',users);return json(res,200,{ok:true,message:`Adgangskoden for ${target} er ændret`});
 }
 if(req.method==='GET'&&req.url==='/api/admin/users'){
  const u=user(req);if(!u||u.role!=='Administrator')return json(res,403,{error:'Kun administrator'});const users=read('users.json');return json(res,200,{users:Object.entries(users).map(([username,x])=>({username,role:x.role,name:x.name}))});
 }
 return json(res,404,{error:'Ikke fundet'});
}
const server=http.createServer(async(req,res)=>{try{if(req.url.startsWith('/api/'))return await api(req,res);let p=new URL(req.url,'http://x').pathname;if(p==='/')p='/index.html';let file=path.normalize(path.join(PUB,p));if(!file.startsWith(PUB))return json(res,403,{error:'Forbidden'});if(!fs.existsSync(file)||fs.statSync(file).isDirectory())return json(res,404,{error:'Not found'});res.writeHead(200,{'Content-Type':mime[path.extname(file)]||'text/plain'});fs.createReadStream(file).pipe(res)}catch(e){console.error(e);json(res,500,{error:'Serverfejl'})}});
server.listen(PORT,()=>console.log(`ZaffronRP Domstol kører på port ${PORT}`));

