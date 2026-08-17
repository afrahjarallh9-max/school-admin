const express = require("express");
const multer = require("multer");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const DATA = path.join(__dirname, "data");
const UPLOADS = path.join(DATA, "uploads");
fs.mkdirSync(UPLOADS, {recursive:true});

const db = new sqlite3.Database(path.join(DATA, "school.db"));
db.serialize(()=>{
  db.run(`CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','employee')), active INTEGER DEFAULT 1
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS records(
    id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL, title TEXT NOT NULL,
    date TEXT, notes TEXT, attachment_name TEXT, attachment_path TEXT,
    created_by INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS recipients(
    id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER, user_id INTEGER,
    status TEXT DEFAULT 'pending', responded_at TEXT,
    UNIQUE(record_id,user_id)
  )`);
  db.get("SELECT id FROM users WHERE username='admin'", (e,row)=>{
    if(!row){
      const hash=bcrypt.hashSync("123456",10);
      db.run("INSERT INTO users(name,username,password,role) VALUES(?,?,?,'admin')",
        ["مديرة المدرسة","admin",hash]);
    }
  });
});

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(express.static(__dirname));

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS,
    filename: (req,file,cb)=>{
      const safe=Date.now()+"-"+file.originalname.replace(/[^\w\u0600-\u06FF.\- ]/g,"_");
      cb(null,safe);
    }
  }),
  limits:{fileSize:15*1024*1024}
});

function auth(req,res,next){
  try{
    const token=(req.headers.authorization||"").replace("Bearer ","");
    req.user=jwt.verify(token,SECRET); next();
  }catch(e){res.status(401).json({error:"غير مصرح"});}
}
function admin(req,res,next){if(req.user.role!=="admin")return res.status(403).json({error:"للمديرة فقط"});next();}
function q(sql,params=[]){return new Promise((resolve,reject)=>db.all(sql,params,(e,r)=>e?reject(e):resolve(r)));}
function one(sql,params=[]){return new Promise((resolve,reject)=>db.get(sql,params,(e,r)=>e?reject(e):resolve(r)));}

app.post("/api/login", async(req,res)=>{
  const {username,password}=req.body;
  const u=await one("SELECT * FROM users WHERE username=? AND active=1",[username]);
  if(!u || !bcrypt.compareSync(password,u.password)) return res.status(401).json({error:"اسم المستخدم أو كلمة المرور غير صحيحة"});
  const token=jwt.sign({id:u.id,name:u.name,role:u.role},SECRET,{expiresIn:"30d"});
  res.json({token,user:{id:u.id,name:u.name,role:u.role}});
});

app.get("/api/me",auth,(req,res)=>res.json(req.user));

app.get("/api/employees",auth,admin,async(req,res)=>{
  res.json(await q("SELECT id,name,username,active FROM users WHERE role='employee' ORDER BY name"));
});

app.post("/api/employees",auth,admin,async(req,res)=>{
  const {name,username,password}=req.body;
  if(!name||!username||!password)return res.status(400).json({error:"أكمل البيانات"});
  try{
    const hash=await bcrypt.hash(password,10);
    await new Promise((resolve,reject)=>db.run(
      "INSERT INTO users(name,username,password,role) VALUES(?,?,?,'employee')",
      [name,username,hash],e=>e?reject(e):resolve()));
    res.json({ok:true});
  }catch(e){res.status(400).json({error:"اسم المستخدم مستخدم مسبقاً"});}
});

app.post("/api/records",auth,admin,upload.single("attachment"),async(req,res)=>{
  const {type,title,date,notes,recipients}=req.body;
  if(!type||!title)return res.status(400).json({error:"العنوان والقسم مطلوبان"});
  await new Promise((resolve,reject)=>db.run(
    `INSERT INTO records(type,title,date,notes,attachment_name,attachment_path,created_by)
     VALUES(?,?,?,?,?,?,?)`,
    [type,title,date||"",notes||"",req.file?.originalname||"",req.file?.filename||"",req.user.id],
    function(e){if(e)reject(e);else req.recordId=this.lastID;resolve();}
  ));
  const ids=JSON.parse(recipients||"[]");
  for(const uid of ids){
    await new Promise((resolve,reject)=>db.run(
      "INSERT OR IGNORE INTO recipients(record_id,user_id) VALUES(?,?)",
      [req.recordId,uid],e=>e?reject(e):resolve()));
  }
  res.json({ok:true,id:req.recordId});
});

app.get("/api/records",auth,async(req,res)=>{
  if(req.user.role==="admin"){
    const rows=await q(`SELECT r.*, COUNT(x.id) recipients,
      SUM(CASE WHEN x.status='approved' THEN 1 ELSE 0 END) approved,
      SUM(CASE WHEN x.status='read' THEN 1 ELSE 0 END) read_count
      FROM records r LEFT JOIN recipients x ON x.record_id=r.id
      GROUP BY r.id ORDER BY r.id DESC`);
    res.json(rows);
  }else{
    res.json(await q(`SELECT r.*,x.status,x.responded_at
      FROM recipients x JOIN records r ON r.id=x.record_id
      WHERE x.user_id=? ORDER BY r.id DESC`,[req.user.id]));
  }
});

app.get("/api/records/:id/file",auth,async(req,res)=>{
  const r=await one("SELECT * FROM records WHERE id=?",[req.params.id]);
  if(!r||!r.attachment_path)return res.status(404).end();
  if(req.user.role==="employee"){
    const ok=await one("SELECT id FROM recipients WHERE record_id=? AND user_id=?",[r.id,req.user.id]);
    if(!ok)return res.status(403).end();
  }
  res.download(path.join(UPLOADS,r.attachment_path),r.attachment_name);
});

app.post("/api/records/:id/respond",auth,async(req,res)=>{
  const {status}=req.body;
  if(!["read","approved","rejected"].includes(status))return res.status(400).json({error:"حالة غير صحيحة"});
  const r=await one("SELECT id FROM recipients WHERE record_id=? AND user_id=?",[req.params.id,req.user.id]);
  if(!r)return res.status(403).json({error:"غير مخصص لك"});
  await new Promise((resolve,reject)=>db.run(
    "UPDATE recipients SET status=?,responded_at=CURRENT_TIMESTAMP WHERE record_id=? AND user_id=?",
    [status,req.params.id,req.user.id],e=>e?reject(e):resolve()));
  res.json({ok:true});
});

app.get("/api/records/:id/recipients",auth,admin,async(req,res)=>{
  res.json(await q(`SELECT u.id,u.name,u.username,x.status,x.responded_at
    FROM recipients x JOIN users u ON u.id=x.user_id WHERE x.record_id=? ORDER BY u.name`,[req.params.id]));
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.listen(PORT,()=>console.log("School Admin running on "+PORT));
