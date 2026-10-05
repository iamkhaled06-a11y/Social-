import express from "express";
import http from "http";
import cookieParser from "cookie-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import fs from "fs";
import pg from "pg";
import { Server as SocketServer } from "socket.io";

const { Pool } = pg;
const app = express();
const httpServer = http.createServer(app);
const io = new SocketServer(httpServer, { cors: { origin: false } });

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me";
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

app.use(express.json({ limit: "256kb" }));
app.use(cookieParser());
app.use(express.static("public"));

const q = (text, params=[]) => pool.query(text, params);

async function initDb() {
  const schema = fs.readFileSync("./schema.sql", "utf8");
  await q(schema);
  // Existing databases created by the first prototype may have old columns.
  await q(`UPDATE users SET public_key = '' WHERE public_key IS NULL`);
  await q(`UPDATE messages SET ciphertext = '' WHERE ciphertext IS NULL`);
  await q(`UPDATE messages SET iv = '' WHERE iv IS NULL`);
}
const sign = u => jwt.sign({ id: u.id, username: u.username }, JWT_SECRET, { expiresIn:"30d" });

function auth(req,res,next){
  try {
    const token=req.cookies.token;
    if(!token) return res.status(401).json({error:"غير مسجل الدخول"});
    req.user=jwt.verify(token,JWT_SECRET);
    next();
  } catch { res.status(401).json({error:"انتهت الجلسة"}); }
}
function setCookie(res, token){
  res.cookie("token", token, { httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production", maxAge:30*24*3600*1000 });
}

app.post("/api/auth/register", async (req,res)=>{
  try {
    const {username,password,publicKey}=req.body;
    if(!username || !password || !publicKey) return res.status(400).json({error:"الاسم وكلمة المرور والمفتاح العام مطلوبة"});
    if(username.length<3 || username.length>32 || password.length<8) return res.status(400).json({error:"الاسم 3-32 حرفا وكلمة المرور 8 أحرف على الأقل"});
    const hash=await bcrypt.hash(password,12);
    const r=await q("INSERT INTO users(username,password_hash,public_key) VALUES($1,$2,$3) RETURNING id,username,public_key",[username,hash,publicKey]);
    setCookie(res,sign(r.rows[0]));
    res.json({user:r.rows[0]});
  } catch(e) {
    if(e.code==="23505") return res.status(409).json({error:"اسم المستخدم مستخدم"});
    console.error(e); res.status(500).json({error:"خطأ في الخادم"});
  }
});

app.post("/api/auth/login", async (req,res)=>{
  try {
    const {username,password}=req.body;
    const r=await q("SELECT id,username,password_hash,public_key FROM users WHERE username=$1",[username]);
    if(!r.rowCount || !(await bcrypt.compare(password,r.rows[0].password_hash))) return res.status(401).json({error:"بيانات الدخول غير صحيحة"});
    setCookie(res,sign(r.rows[0]));
    res.json({user:{id:r.rows[0].id,username:r.rows[0].username,public_key:r.rows[0].public_key}});
  } catch(e){ console.error(e); res.status(500).json({error:"خطأ في الخادم"}); }
});

app.post("/api/auth/logout",(req,res)=>{ res.clearCookie("token"); res.json({ok:true}); });
app.get("/api/auth/me",auth,async(req,res)=>{
  const r=await q("SELECT id,username,public_key FROM users WHERE id=$1",[req.user.id]);
  res.json({user:r.rows[0]});
});

app.get("/api/servers",auth,async(req,res)=>{
  const r=await q(`SELECT s.id,s.name,s.description,s.invite_code,s.owner_id
    FROM servers s JOIN server_members m ON m.server_id=s.id
    WHERE m.user_id=$1 ORDER BY s.created_at`,[req.user.id]);
  res.json({servers:r.rows});
});

app.post("/api/servers",auth,async(req,res)=>{
  const {name,description=""}=req.body;
  if(!name?.trim()) return res.status(400).json({error:"اسم السيرفر مطلوب"});
  const invite=crypto.randomBytes(8).toString("hex");
  const c=await q("BEGIN");
  try {
    const s=await q("INSERT INTO servers(name,description,owner_id,invite_code) VALUES($1,$2,$3,$4) RETURNING *",[name.trim(),description,req.user.id,invite]);
    const server=s.rows[0];
    await q("INSERT INTO server_members(server_id,user_id,role) VALUES($1,$2,'owner')",[server.id,req.user.id]);
    const ch=await q("INSERT INTO channels(server_id,name) VALUES($1,'عام') RETURNING id",[server.id]);
    await q("COMMIT");
    // The first channel has no plaintext key; owner creates/distributes its E2EE key from browser.
    res.json({server,channel:{id:ch.rows[0].id,name:"عام"}});
  } catch(e){ await q("ROLLBACK"); console.error(e); res.status(500).json({error:"تعذر إنشاء السيرفر"}); }
});

app.post("/api/servers/join",auth,async(req,res)=>{
  const {inviteCode}=req.body;
  const s=await q("SELECT id,name,description,owner_id FROM servers WHERE invite_code=$1",[inviteCode]);
  if(!s.rowCount) return res.status(404).json({error:"رمز الدعوة غير صحيح"});
  await q("INSERT INTO server_members(server_id,user_id,role) VALUES($1,$2,'member') ON CONFLICT DO NOTHING",[s.rows[0].id,req.user.id]);
  res.json({server:s.rows[0]});
});

app.get("/api/servers/:id/members",auth,async(req,res)=>{
  const ok=await q("SELECT 1 FROM server_members WHERE server_id=$1 AND user_id=$2",[req.params.id,req.user.id]);
  if(!ok.rowCount) return res.status(403).json({error:"لا تملك صلاحية"});
  const r=await q(`SELECT u.id,u.username,u.public_key,m.role FROM users u
    JOIN server_members m ON m.user_id=u.id WHERE m.server_id=$1 ORDER BY u.username`,[req.params.id]);
  res.json({members:r.rows});
});

app.get("/api/servers/:id/channels",auth,async(req,res)=>{
  const ok=await q("SELECT 1 FROM server_members WHERE server_id=$1 AND user_id=$2",[req.params.id,req.user.id]);
  if(!ok.rowCount) return res.status(403).json({error:"لا تملك صلاحية"});
  const r=await q("SELECT id,name FROM channels WHERE server_id=$1 ORDER BY id",[req.params.id]);
  res.json({channels:r.rows});
});

app.post("/api/servers/:id/channels",auth,async(req,res)=>{
  const {name}=req.body;
  const ok=await q("SELECT role FROM server_members WHERE server_id=$1 AND user_id=$2",[req.params.id,req.user.id]);
  if(!ok.rowCount || !["owner","admin"].includes(ok.rows[0].role)) return res.status(403).json({error:"للمالك أو المشرف فقط"});
  const r=await q("INSERT INTO channels(server_id,name) VALUES($1,$2) RETURNING id,name",[req.params.id,name?.trim()||"جديد"]);
  res.json({channel:r.rows[0]});
});

app.get("/api/channels/:id/messages",auth,async(req,res)=>{
  const ok=await q(`SELECT 1 FROM server_members m JOIN channels c ON c.server_id=m.server_id
    WHERE c.id=$1 AND m.user_id=$2`,[req.params.id,req.user.id]);
  if(!ok.rowCount) return res.status(403).json({error:"لا تملك صلاحية"});
  const r=await q(`SELECT m.id,m.user_id,u.username,m.ciphertext,m.iv,m.created_at
    FROM messages m JOIN users u ON u.id=m.user_id WHERE m.channel_id=$1
    ORDER BY m.id DESC LIMIT 100`,[req.params.id]);
  res.json({messages:r.rows.reverse()});
});

/* E2EE key envelopes: the browser creates a random AES-GCM key per channel
   and encrypts (wraps) that key separately for every member's public key.
   The server can store envelopes but cannot decrypt them. */
app.post("/api/channels/:id/keys",auth,async(req,res)=>{
  const {envelopes}=req.body;
  if(!Array.isArray(envelopes) || envelopes.length===0) return res.status(400).json({error:"مفاتيح القناة مطلوبة"});
  const ok=await q(`SELECT 1 FROM server_members m JOIN channels c ON c.server_id=m.server_id
    WHERE c.id=$1 AND m.user_id=$2`,[req.params.id,req.user.id]);
  if(!ok.rowCount) return res.status(403).json({error:"لا تملك صلاحية"});
  for(const x of envelopes){
    if(!Number.isInteger(Number(x.userId)) || typeof x.encryptedKey!=="string") continue;
    await q(`INSERT INTO channel_keys(channel_id,user_id,encrypted_key)
      VALUES($1,$2,$3) ON CONFLICT(channel_id,user_id)
      DO UPDATE SET encrypted_key=EXCLUDED.encrypted_key,created_at=now()`,
      [req.params.id,Number(x.userId),x.encryptedKey]);
  }
  res.json({ok:true});
});

app.get("/api/channels/:id/key",auth,async(req,res)=>{
  const r=await q(`SELECT k.encrypted_key FROM channel_keys k
    WHERE k.channel_id=$1 AND k.user_id=$2`,[req.params.id,req.user.id]);
  if(!r.rowCount) return res.status(404).json({error:"لا يوجد مفتاح مشفّر لهذا المستخدم"});
  res.json({encryptedKey:r.rows[0].encrypted_key});
});

app.post("/api/channels/:id/messages",auth,async(req,res)=>{
  const {ciphertext,iv}=req.body;
  const ok=await q(`SELECT 1 FROM server_members m JOIN channels c ON c.server_id=m.server_id
    WHERE c.id=$1 AND m.user_id=$2`,[req.params.id,req.user.id]);
  if(!ok.rowCount) return res.status(403).json({error:"لا تملك صلاحية"});
  if(typeof ciphertext!=="string" || typeof iv!=="string") return res.status(400).json({error:"رسالة مشفّرة مطلوبة"});
  const r=await q(`INSERT INTO messages(channel_id,user_id,ciphertext,iv)
    VALUES($1,$2,$3,$4) RETURNING id,user_id,ciphertext,iv,created_at`,[req.params.id,req.user.id,ciphertext,iv]);
  const msg={...r.rows[0],username:req.user.username};
  io.to("channel:"+req.params.id).emit("new_message",msg);
  res.json({message:msg});
});

io.use((socket,next)=>{
  try {
    const raw=socket.handshake.headers.cookie||"";
    const token=raw.split(";").map(x=>x.trim()).find(x=>x.startsWith("token="))?.slice(6);
    socket.user=jwt.verify(token,JWT_SECRET);
    next();
  } catch { next(new Error("unauthorized")); }
});

io.on("connection",socket=>{
  socket.on("join_channel",async(channelId,ack)=>{
    try {
      const ok=await q(`SELECT 1 FROM server_members m JOIN channels c ON c.server_id=m.server_id
        WHERE c.id=$1 AND m.user_id=$2`,[channelId,socket.user.id]);
      if(!ok.rowCount) return ack?.({ok:false,error:"غير مصرح"});
      socket.join("channel:"+channelId);
      ack?.({ok:true});
    } catch { ack?.({ok:false,error:"خطأ"}); }
  });
});

const start=async()=>{
  await initDb();
  httpServer.listen(PORT,"0.0.0.0",()=>console.log(`Listening on ${PORT}`));
};
start().catch(e=>{console.error(e);process.exit(1)});