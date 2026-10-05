const $=id=>document.getElementById(id);
let mode="login", me=null, currentServer=null, currentChannel=null, socket=null;
let privateKey=null;
const b64=u8=>btoa(String.fromCharCode(...new Uint8Array(u8)));
const unb64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function digestPassword(password,salt){
  const base=await crypto.subtle.importKey("raw",new TextEncoder().encode(password),"PBKDF2",false,["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2",salt:new TextEncoder().encode(salt),iterations:150000,hash:"SHA-256"},base,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}
async function makeIdentity(password){
  const kp=await crypto.subtle.generateKey({name:"RSA-OAEP",modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:"SHA-256"},true,["encrypt","decrypt"]);
  const pub=await crypto.subtle.exportKey("spki",kp.publicKey);
  const priv=await crypto.subtle.exportKey("pkcs8",kp.privateKey);
  const iv=crypto.getRandomValues(new Uint8Array(12)), key=await digestPassword(password,"private-key-v1");
  const enc=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,priv);
  localStorage.setItem("e2ee-private",JSON.stringify({iv:b64(iv),data:b64(enc)}));
  return {publicKey:b64(pub),privateKey:kp.privateKey};
}
async function loadIdentity(password){
  const raw=localStorage.getItem("e2ee-private"); if(!raw) return null;
  const x=JSON.parse(raw),key=await digestPassword(password,"private-key-v1");
  try{
    const priv=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(x.iv)},key,unb64(x.data));
    privateKey=await crypto.subtle.importKey("pkcs8",priv,{name:"RSA-OAEP",hash:"SHA-256"},false,["decrypt"]);
    return true;
  }catch{return false}
}
async function importPub(s){
  return crypto.subtle.importKey("spki",unb64(s),{name:"RSA-OAEP",hash:"SHA-256"},false,["encrypt"]);
}
async function newChannelKey(){
  return crypto.subtle.generateKey({name:"AES-GCM",length:256},true,["encrypt","decrypt"]);
}
async function wrapKey(key,pub){
  const raw=await crypto.subtle.exportKey("raw",key);
  return b64(await crypto.subtle.encrypt({name:"RSA-OAEP"},await importPub(pub),raw));
}
async function unwrapKey(enc){
  const raw=await crypto.subtle.decrypt({name:"RSA-OAEP"},privateKey,unb64(enc));
  return crypto.subtle.importKey("raw",raw,{name:"AES-GCM"},false,["encrypt","decrypt"]);
}
async function encryptText(key,text){
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,new TextEncoder().encode(text));
  return {ciphertext:b64(ct),iv:b64(iv)};
}
async function decryptText(key,cipher,iv){
  const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv:unb64(iv)},key,unb64(cipher));
  return new TextDecoder().decode(pt);
}
async function api(url,opts={}){
  const r=await fetch(url,{...opts,headers:{"Content-Type":"application/json",...(opts.headers||{})}});
  const d=await r.json().catch(()=>({}));
  if(!r.ok) throw Error(d.error||"حدث خطأ");
  return d;
}
function showApp(){ $("auth").classList.add("hidden");$("app").classList.remove("hidden");$("me").textContent=me.username; }
$("loginTab").onclick=()=>setMode("login"); $("registerTab").onclick=()=>setMode("register");
function setMode(x){mode=x;$("loginTab").classList.toggle("active",x==="login");$("registerTab").classList.toggle("active",x==="register");$("authBtn").textContent=x==="login"?"دخول":"إنشاء حساب";}
$("authBtn").onclick=async()=>{
  $("authError").textContent="";
  try{
    const username=$("username").value.trim(),password=$("password").value;
    if(mode==="register"){
      const id=await makeIdentity(password); privateKey=id.privateKey;
      const d=await api("/api/auth/register",{method:"POST",body:JSON.stringify({username,password,publicKey:id.publicKey})});
      me=d.user;
    }else{
      const d=await api("/api/auth/login",{method:"POST",body:JSON.stringify({username,password})});
      me=d.user;
      if(!await loadIdentity(password)) throw Error("المفتاح الخاص غير موجود أو كلمة المرور مختلفة. هذا يحمي المحادثات: لا يوجد استرجاع من الخادم.");
    }
    showApp(); await loadServers();
  }catch(e){$("authError").textContent=e.message}
};
$("logout").onclick=async()=>{await api("/api/auth/logout",{method:"POST"});location.reload()};
async function loadServers(){
  const d=await api("/api/servers");$("serverList").innerHTML="";
  d.servers.forEach(s=>{const b=document.createElement("button");b.className="serverBtn";b.textContent=s.name.slice(0,2);b.title=s.name;b.onclick=()=>selectServer(s);$("serverList").append(b)});
}
$("newServer").onclick=async()=>{
  const name=prompt("اسم السيرفر"); if(!name)return;
  const d=await api("/api/servers",{method:"POST",body:JSON.stringify({name})}); await loadServers(); selectServer(d.server);
};
$("joinServer").onclick=async()=>{
  const inviteCode=prompt("رمز الدعوة"); if(!inviteCode)return;
  try{await api("/api/servers/join",{method:"POST",body:JSON.stringify({inviteCode})});await loadServers()}catch(e){alert(e.message)}
};
async function selectServer(s){
  currentServer=s;$("serverName").textContent=s.name;
  const d=await api(`/api/servers/${s.id}/channels`);$("channelList").innerHTML="";
  d.channels.forEach(c=>{const b=document.createElement("button");b.className="channelBtn";b.textContent="# "+c.name;b.onclick=()=>selectChannel(c);$("channelList").append(b)});
  if(d.channels[0]) selectChannel(d.channels[0]);
}
$("newChannel").onclick=async()=>{
  if(!currentServer)return;
  const name=prompt("اسم القناة");if(!name)return;
  try{await api(`/api/servers/${currentServer.id}/channels`,{method:"POST",body:JSON.stringify({name})});await selectServer(currentServer)}catch(e){alert(e.message)}
};
let channelKey=null;
async function ensureChannelKey(){
  try{
    const d=await api(`/api/channels/${currentChannel.id}/key`);
    channelKey=await unwrapKey(d.encryptedKey); return;
  }catch{}
  // No key yet: create one and distribute it to every current member.
  const m=await api(`/api/servers/${currentServer.id}/members`);
  channelKey=await newChannelKey();
  const envelopes=[];
  for(const u of m.members) envelopes.push({userId:u.id,encryptedKey:await wrapKey(channelKey,u.public_key)});
  await api(`/api/channels/${currentChannel.id}/keys`,{method:"POST",body:JSON.stringify({envelopes})});
}
async function selectChannel(c){
  currentChannel=c;$("channelName").textContent="# "+c.name;$("messages").innerHTML="";$("messageInput").disabled=false;$("composer button").disabled=false;
  await ensureChannelKey();
  const d=await api(`/api/channels/${c.id}/messages`);
  for(const m of d.messages) await renderMessage(m);
  if(!socket){socket=io();socket.on("connect",()=>{$("status").textContent="● متصل";});socket.on("new_message",async m=>{if(String(m.channel_id)===String(currentChannel?.id)) await renderMessage(m)})}
  socket.emit("join_channel",c.id);
}
async function renderMessage(m){
  let body="رسالة مشفّرة غير قابلة للفتح";
  try{body=await decryptText(channelKey,m.ciphertext,m.iv)}catch{}
  const el=document.createElement("div");el.className="msg";
  el.innerHTML=`<div class="who">${escapeHtml(m.username||"مستخدم")}</div><div class="body"></div>`;
  el.querySelector(".body").textContent=body;$("messages").append(el);$("messages").scrollTop=$("messages").scrollHeight;
}
function escapeHtml(x){return String(x).replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
$("composer").onsubmit=async e=>{
  e.preventDefault();const text=$("messageInput").value.trim();if(!text||!currentChannel)return;
  try{
    const enc=await encryptText(channelKey,text);
    await api(`/api/channels/${currentChannel.id}/messages`,{method:"POST",body:JSON.stringify(enc)});
    $("messageInput").value="";
  }catch(e){alert(e.message)}
};
(async()=>{
  try{const d=await api("/api/auth/me");me=d.user;
    if(localStorage.getItem("e2ee-private")){ $("authError").textContent="أدخل كلمة مرورك لتسجيل الدخول وفتح مفتاحك الخاص."; }
  }catch{}
})();