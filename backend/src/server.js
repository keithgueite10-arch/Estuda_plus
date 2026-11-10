import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import path from 'path';
import { fileURLToPath } from 'url';

const { Pool } = pg;
const app = express();
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change-me';
app.use(cors()); app.use(express.json({limit:'2mb'}));

async function migrate(){
 await pool.query(`CREATE TABLE IF NOT EXISTS users(
 id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
 CREATE TABLE IF NOT EXISTS user_progress(
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, data JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ DEFAULT now());
 CREATE TABLE IF NOT EXISTS seen_questions(
 user_id INTEGER REFERENCES users(id) ON DELETE CASCADE, fingerprint TEXT NOT NULL, first_seen_at TIMESTAMPTZ DEFAULT now(), last_seen_at TIMESTAMPTZ DEFAULT now(), times_seen INTEGER NOT NULL DEFAULT 1, PRIMARY KEY(user_id,fingerprint));
 CREATE INDEX IF NOT EXISTS idx_seen_questions_user ON seen_questions(user_id);
 `);
}
function tokenFor(u){return jwt.sign({id:u.id,email:u.email},SECRET,{expiresIn:'30d'});}
function auth(req,res,next){const h=req.headers.authorization||''; const t=h.startsWith('Bearer ')?h.slice(7):null; if(!t)return res.status(401).json({error:'Não autenticado'}); try{req.user=jwt.verify(t,SECRET);next()}catch{return res.status(401).json({error:'Sessão inválida'})}}

app.post('/api/auth/register', async (req,res)=>{try{const {name,email,password}=req.body; if(!name||!email||!password||password.length<6)return res.status(400).json({error:'Preenche nome, email e uma palavra-passe com pelo menos 6 caracteres.'}); const hash=await bcrypt.hash(password,12); const r=await pool.query('INSERT INTO users(name,email,password_hash) VALUES($1,$2,$3) RETURNING id,name,email',[name,email.toLowerCase(),hash]); const u=r.rows[0]; await pool.query('INSERT INTO user_progress(user_id,data) VALUES($1,$2)',[u.id,{}]); res.json({token:tokenFor(u),user:{id:u.id,name:u.name,email:u.email}})}catch(e){res.status(400).json({error:e.code==='23505'?'Este email já está registado.':'Não foi possível criar a conta.'})}});
app.post('/api/auth/login', async (req,res)=>{const {email,password}=req.body; const r=await pool.query('SELECT * FROM users WHERE email=$1',[String(email||'').toLowerCase()]); const u=r.rows[0]; if(!u||!(await bcrypt.compare(password||'',u.password_hash)))return res.status(401).json({error:'Email ou palavra-passe incorretos.'}); res.json({token:tokenFor(u),user:{id:u.id,name:u.name,email:u.email}})});
app.get('/api/progress',auth,async(req,res)=>{const r=await pool.query('SELECT data,updated_at FROM user_progress WHERE user_id=$1',[req.user.id]);res.json(r.rows[0]||{data:{}})});
app.put('/api/progress',auth,async(req,res)=>{await pool.query(`INSERT INTO user_progress(user_id,data,updated_at) VALUES($1,$2,now()) ON CONFLICT(user_id) DO UPDATE SET data=EXCLUDED.data,updated_at=now()`,[req.user.id,req.body.data||{}]);res.json({ok:true})});
app.post('/api/questions/reserve',auth,async(req,res)=>{const qs=Array.isArray(req.body.questions)?req.body.questions:[]; const fresh=[]; for(const q of qs){const f=String(q.fingerprint||''); if(!f)continue; const x=await pool.query('SELECT 1 FROM seen_questions WHERE user_id=$1 AND fingerprint=$2',[req.user.id,f]); if(x.rowCount===0){await pool.query('INSERT INTO seen_questions(user_id,fingerprint) VALUES($1,$2)',[req.user.id,f]); fresh.push(f)} } res.json({fresh});});
app.post('/api/tutor',auth,async(req,res)=>{const question=String(req.body.question||'').trim(); if(!question)return res.status(400).json({error:'Escreve uma pergunta.'}); if(!process.env.OPENAI_API_KEY)return res.status(503).json({error:'O Tutor IA ainda não foi ligado a um provedor de IA. Configure OPENAI_API_KEY no servidor.'}); try{const r=await fetch('https://api.openai.com/v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json','Authorization':`Bearer ${process.env.OPENAI_API_KEY}`},body:JSON.stringify({model:process.env.OPENAI_MODEL||'gpt-4.1-mini',messages:[{role:'system',content:'És o Tutor IA da Estuda+. Responde em português claro, correto e educativo. Explica passo a passo quando necessário.'},{role:'user',content:question}],temperature:0.3})}); const d=await r.json(); if(!r.ok)throw new Error(d.error?.message||'Erro do provedor'); res.json({answer:d.choices?.[0]?.message?.content||'Sem resposta.'})}catch(e){res.status(502).json({error:'Falha no Tutor IA: '+e.message})}});

const __dirname=path.dirname(fileURLToPath(import.meta.url));
app.use(express.static(path.resolve(__dirname,'../public')));
app.get('*',(req,res)=>res.sendFile(path.resolve(__dirname,'../public/index.html')));
migrate().then(()=>app.listen(PORT,()=>console.log('Estuda+ online em '+PORT))).catch(e=>{console.error(e);process.exit(1)});
