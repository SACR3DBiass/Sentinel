"""
SENTINEL Lite — Simplified phishing triage for friends & family.
Mounts at /lite via the main app.py.
"""
import os, json, time, uuid, asyncio, bcrypt, jwt, re
import imaplib as _imap
import email as _email
from datetime import datetime, timedelta
from email.header import decode_header as _decode_header
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import db

app = FastAPI(title="SENTINEL Lite")

JWT_SECRET = db.JWT_SECRET
JWT_EXPIRY_HOURS = db.JWT_EXPIRY_HOURS

LITE_PROMPT = """You are a phishing detection AI. Analyze the email below and determine if it is phishing, scam, or legitimate.

Respond with ONLY valid JSON:
{
  "threat_level": "safe" or "suspicious" or "malicious",
  "confidence": 0.0 to 1.0,
  "reason": "One short sentence explaining your verdict"
}

Be decisive. Most emails are safe. Flag only genuine threats."""

LITE_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SENTINEL Lite</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:#0a0a0a;color:#f5f5f5;min-height:100vh}
.topbar{position:fixed;top:0;left:0;right:0;z-index:100;padding:12px 24px;display:flex;justify-content:space-between;align-items:center;background:rgba(10,10,10,0.95);backdrop-filter:blur(20px);border-bottom:1px solid #1a1a1a}
.topbar-left{display:flex;align-items:center;gap:12px}
.logo{display:flex;align-items:center;gap:8px;text-decoration:none;color:#f5f5f5}
.logo svg{width:24px;height:24px}
.logo-text{font-weight:800;font-size:15px;letter-spacing:-0.02em}
.lite-badge{background:linear-gradient(135deg,#DC2626,#991B1B);color:white;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase}
.topbar-right{display:flex;align-items:center;gap:8px}
.btn{background:#111;border:1px solid #2a2a2a;color:#ccc;padding:8px 16px;border-radius:8px;font-size:13px;font-weight:500;cursor:pointer;transition:all 0.2s;font-family:inherit;display:inline-flex;align-items:center;gap:6px;text-decoration:none}
.btn:hover{border-color:#444;background:#1a1a1a;color:#f5f5f5;transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn.primary{background:linear-gradient(135deg,#DC2626,#B91C1C);border-color:rgba(220,38,38,0.4);color:white;font-weight:600}
.btn.primary:hover{box-shadow:0 4px 20px rgba(220,38,38,0.35)}
.btn.ghost{background:transparent;border-color:#2a2a2a;color:#aaa}
.btn.sm{padding:6px 12px;font-size:12px}
.main{padding:72px 24px 24px;max-width:900px;margin:0 auto}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px}
.stat-card{background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:14px 16px;text-align:center}
.stat-card .label{font-size:11px;font-weight:500;color:#888;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:4px}
.stat-card .value{font-size:28px;font-weight:800;font-family:'JetBrains Mono',monospace}
.stat-card .value.red{color:#DC2626}.stat-card .value.yellow{color:#EAB308}.stat-card .value.green{color:#22C55E}
.email-list{display:flex;flex-direction:column;gap:8px}
.email-card{background:#111;border:1px solid #1e1e1e;border-radius:10px;padding:14px 16px;cursor:pointer;transition:all 0.2s;display:flex;align-items:flex-start;gap:12px}
.email-card:hover{border-color:#333;background:#151515}
.dot{width:10px;height:10px;border-radius:50%;flex-shrink:0;margin-top:5px}
.dot.safe{background:#22C55E}.dot.suspicious{background:#EAB308}.dot.malicious{background:#DC2626}
.email-info{flex:1;min-width:0}
.email-subject{font-weight:600;font-size:14px;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.email-from{font-size:12px;color:#888;margin-bottom:3px}
.email-reason{font-size:12px;color:#aaa;font-style:italic}
.email-time{font-size:11px;color:#555;flex-shrink:0;font-family:'JetBrains Mono',monospace}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:center;padding:16px;z-index:200}
.modal{background:#161616;border:1px solid #1a1a1a;border-radius:16px;width:100%;max-width:600px;max-height:80vh;overflow-y:auto;padding:24px}
.modal h2{font-size:18px;font-weight:700;margin-bottom:16px}
.modal-close{float:right;background:none;border:none;color:#666;font-size:20px;cursor:pointer}
.modal-close:hover{color:#f5f5f5}
.field{margin-bottom:14px}
.field label{display:block;font-size:12px;font-weight:600;color:#888;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.05em}
.field input,.field textarea,.field select{width:100%;background:#0a0a0a;border:1px solid #2a2a2a;color:#f5f5f5;padding:10px 14px;border-radius:8px;font-size:13px;font-family:inherit;transition:border-color 0.2s}
.field input:focus,.field textarea:focus{outline:none;border-color:#DC2626;box-shadow:0 0 0 2px rgba(220,38,38,0.15)}
.field textarea{resize:vertical;min-height:100px}
.verdict-badge{display:inline-block;padding:4px 12px;border-radius:6px;font-size:12px;font-weight:700;text-transform:uppercase}
.verdict-badge.safe{background:rgba(34,197,94,0.15);color:#22C55E}
.verdict-badge.suspicious{background:rgba(234,179,8,0.15);color:#EAB308}
.verdict-badge.malicious{background:rgba(220,38,38,0.15);color:#DC2626}
.actions{display:flex;gap:10px;margin-bottom:20px;flex-wrap:wrap}
.loading{text-align:center;padding:40px;color:#666}
.empty{text-align:center;padding:60px 20px;color:#666}
.empty h3{font-size:18px;margin-bottom:8px;color:#aaa}
.empty p{font-size:14px;margin-bottom:16px}
.toast{position:fixed;top:80px;right:20px;padding:12px 20px;border-radius:8px;font-size:13px;font-weight:500;z-index:300;animation:slideIn 0.3s ease-out}
.toast.success{background:#0d3320;border:1px solid #166534;color:#86EFAC}
.toast.error{background:#450a0a;border:1px solid #7f1d1d;color:#FCA5A5}
.toast.info{background:#0c1a3d;border:1px solid #1e3a5f;color:#93C5FD}
.toast.warning{background:#422006;border:1px solid #713f12;color:#FDE68A}
@keyframes slideIn{from{opacity:0;transform:translateX(100%)}to{opacity:1;transform:translateX(0)}}
@keyframes fadeUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}
.fade-up{animation:fadeUp 0.3s ease-out}
.scan-pulse{animation:pulse 1s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.5}}
@media(max-width:768px){.stats-grid{grid-template-columns:repeat(2,1fr)}.main{padding:72px 12px 12px}}
</style>
</head>
<body>
<div id="root"></div>
<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<script type="text/babel">
var useState=React.useState,useEffect=React.useEffect;
function getToken(){return localStorage.getItem('sentinel_lite_token')}
function logout(){localStorage.removeItem('sentinel_lite_token');window.location.href='/lite/login'}

var API={
  base:'/lite/api',
  opts:function(){return{headers:{'Authorization':'Bearer '+getToken(),'Content-Type':'application/json'}}},
  get:function(p){return fetch(this.base+p,this.opts()).then(function(r){if(r.status===401){logout();throw new Error('Session expired')}return r.json()})},
  post:function(p,b){return fetch(this.base+p,Object.assign({},this.opts(),{method:'POST',body:JSON.stringify(b)})).then(function(r){if(r.status===401){logout();throw new Error('Session expired')}return r.json()})},
  del:function(p){return fetch(this.base+p,Object.assign({},this.opts(),{method:'DELETE'})).then(function(r){if(r.status===401){logout();throw new Error('Session expired')}return r.json()})}
};

function App(){
  var _emails=useState([]),emails=_emails[0],setEmails=_emails[1];
  var _conns=useState([]),conns=_conns[0],setConns=_conns[1];
  var _filter=useState('all'),filter=_filter[0],setFilter=_filter[1];
  var _user=useState(null),user=_user[0],setUser=_user[1];
  var _loading=useState(true),loading=_loading[0],setLoading=_loading[1];
  var _scanning,setScanning=useState(false);
  var _showPaste,setShowPaste=useState(false);
  var _showConn,setShowConn=useState(false);
  var _showDetail,setShowDetail=useState(null);
  var _groqKey,setGroqKey=useState('');
  var _showKeyModal,setShowKeyModal=useState(false);
  var _toast,setToast=useState(null);
  var _pasteFrom,setPasteFrom=useState('');
  var _pasteSubject,setPasteSubject=useState('');
  var _pasteContent,setPasteContent=useState('');
  var _connForm,setConnForm=useState({label:'My Email',imap_host:'imap.gmail.com',imap_port:993,imap_username:'',imap_password:'',imap_folder:'INBOX'});

  function toast(type,msg){setToast({type,msg});setTimeout(function(){setToast(null)},3000)}

  useEffect(function(){
    if(!getToken()){window.location.href='/lite/login';return}
    API.get('/auth/me').then(function(r){
      setUser(r);
      if(!r.groq_key_set){setShowKeyModal(true)}
      loadData();
    }).catch(function(){logout()});
  },[]);

  function loadData(){
    Promise.all([API.get('/emails'),API.get('/connections')]).then(function(r){
      setEmails(r[0].emails||[]);
      setConns(r[1].connections||[]);
      setLoading(false);
    }).catch(function(){setLoading(false)});
  }

  var total=emails.length;
  var malicious=emails.filter(function(e){return e.threat_level==='malicious'}).length;
  var suspicious=emails.filter(function(e){return e.threat_level==='suspicious'}).length;
  var safe=emails.filter(function(e){return e.threat_level==='safe'}).length;
  var filtered=filter==='all'?emails:emails.filter(function(e){return e.threat_level===filter});

  function handleScan(){
    setScanning(true);
    toast('info','Scanning inbox...');
    API.post('/scan',{}).then(function(r){
      setScanning(false);
      if(r.emails_found>0){toast('success',r.emails_found+' email(s) analyzed');loadData()}
      else{toast('info','No new emails found')}
    }).catch(function(e){setScanning(false);toast('error','Scan failed: '+e.message)});
  }

  function handlePaste(){
    if(!_pasteContent.trim()){toast('error','Paste email content');return}
    API.post('/analyze',{from_address:_pasteFrom,subject:_pasteSubject,body:_pasteContent}).then(function(r){
      setShowPaste(false);setPasteContent('');setPasteFrom('');setPasteSubject('');
      toast('success','Email analyzed');loadData();
    }).catch(function(e){toast('error','Analysis failed: '+e.message)});
  }

  function handleAddConn(){
    API.post('/connections',_connForm).then(function(r){
      setShowConn(false);toast('success','Connection added');loadData();
    }).catch(function(e){toast('error','Failed: '+e.message)});
  }

  function handleSaveKey(){
    API.post('/settings/groq-key',{api_key:_groqKey}).then(function(r){
      setShowKeyModal(false);toast('success','API key saved');
    }).catch(function(e){toast('error','Failed to save key')});
  }

  function handleDeleteConn(id){
    API.del('/connections/'+id).then(function(){toast('success','Connection removed');loadData()});
  }

  if(!user)return null;

  if(loading) return React.createElement('div',{className:'loading'},'Loading...');

  if(showKeyModal) return React.createElement('div',{className:'modal-overlay'},
    React.createElement('div',{className:'modal fade-up'},
      React.createElement('h2',null,'Welcome to SENTINEL Lite!'),
      React.createElement('p',{style:{color:'#888',fontSize:14,marginBottom:20}},'To start scanning emails, you need a free Groq API key:'),
      React.createElement('ol',{style:{color:'#aaa',fontSize:13,marginBottom:20,paddingLeft:20}},
        React.createElement('li',{style:{marginBottom:6}},React.createElement('a',{href:'https://console.groq.com/keys',target:'_blank',style:{color:'#DC2626'}},'Go to console.groq.com/keys')),
        React.createElement('li',{style:{marginBottom:6}},'Create a free account (takes 30 seconds)'),
        React.createElement('li',{style:{marginBottom:6}},'Click "Create API Key"'),
        React.createElement('li',null,'Paste it below')
      ),
      React.createElement('div',{className:'field'},
        React.createElement('label',null,'Groq API Key'),
        React.createElement('input',{type:'password',placeholder:'gsk_xxxxxxxxxxxxxxxxxxxxxx',value:_groqKey,onChange:function(e){setGroqKey(e.target.value)}})
      ),
      React.createElement('button',{className:'btn primary',onClick:handleSaveKey,style:{width:'100%'}},'Save Key & Start')
    )
  );

  var detailEmail=_showDetail;

  return React.createElement('div',null,
    toast?React.createElement('div',{className:'toast '+toast.type},toast.msg):null,
    React.createElement('div',{className:'topbar'},
      React.createElement('div',{className:'topbar-left'},
        React.createElement('a',{href:'/lite',className:'logo'},
          React.createElement('svg',{viewBox:'0 0 36 36',fill:'none',width:24,height:24},React.createElement('path',{d:'M18 2L3 10v16l15 8 15-8V10L18 2z',fill:'#DC2626',opacity:0.9})),
          React.createElement('span',{className:'logo-text'},'SENTINEL'),
          React.createElement('span',{className:'lite-badge'},'Lite')
        )
      ),
      React.createElement('div',{className:'topbar-right'},
        React.createElement('button',{className:'btn sm ghost',onClick:function(){setShowKeyModal(true)}},'API Key'),
        React.createElement('button',{className:'btn sm ghost',onClick:logout},'Logout')
      )
    ),
    React.createElement('div',{className:'main'},
      React.createElement('div',{className:'stats-grid fade-up'},
        React.createElement('div',{className:'stat-card'},React.createElement('div',{className:'label'},'Total'),React.createElement('div',{className:'value'},total)),
        React.createElement('div',{className:'stat-card'},React.createElement('div',{className:'label'},'Malicious'),React.createElement('div',{className:'value red'},malicious)),
        React.createElement('div',{className:'stat-card'},React.createElement('div',{className:'label'},'Suspicious'),React.createElement('div',{className:'value yellow'},suspicious)),
        React.createElement('div',{className:'stat-card'},React.createElement('div',{className:'label'},'Safe'),React.createElement('div',{className:'value green'},safe))
      ),
      React.createElement('div',{className:'actions'},
        React.createElement('button',{className:'btn primary',onClick:handleScan,disabled:_scanning},_scanning?React.createElement('span',{className:'scan-pulse'},'Scanning...'):'Scan Inbox'),
        React.createElement('button',{className:'btn',onClick:function(){setShowPaste(true)}},'Paste Email'),
        React.createElement('button',{className:'btn',onClick:function(){setShowConn(true)}},'Connections'),
        React.createElement('div',{style:{flex:1}}),
        React.createElement('div',{style:{display:'flex',gap:6}},
          ['all','malicious','suspicious','safe'].map(function(f){
            return React.createElement('button',{key:f,onClick:function(){setFilter(f)},className:'btn sm',style:{borderColor:filter===f?'#DC2626':'#2a2a2a',color:filter===f?'#DC2626':'#888'}},f.charAt(0).toUpperCase()+f.slice(1)+' ('+(f==='all'?total:f==='malicious'?malicious:f==='suspicious'?suspicious:safe)+')');
          })
        )
      ),
      React.createElement('div',{className:'email-list'},
        filtered.length===0?React.createElement('div',{className:'empty'},React.createElement('h3',null,'No emails yet'),React.createElement('p',null,'Scan your inbox or paste an email to get started')):null,
        filtered.map(function(e){
          return React.createElement('div',{key:e.id,className:'email-card fade-up',onClick:function(){setShowDetail(e)}},
            React.createElement('div',{className:'dot '+(e.threat_level||'safe')}),
            React.createElement('div',{className:'email-info'},
              React.createElement('div',{className:'email-subject'},e.subject||'(no subject)'),
              React.createElement('div',{className:'email-from'},e.from_address||e.sender||'unknown'),
              React.createElement('div',{className:'email-reason'},e.reason||e.ai_reason||'')
            ),
            React.createElement('div',{className:'email-time'},e.received_at?new Date(e.received_at).toLocaleDateString():'')
          );
        })
      )
    ),
    detailEmail?React.createElement('div',{className:'modal-overlay',onClick:function(){setShowDetail(null)}},
      React.createElement('div',{className:'modal fade-up',onClick:function(e){e.stopPropagation()}},
        React.createElement('button',{className:'modal-close',onClick:function(){setShowDetail(null)}},'\u00d7'),
        React.createElement('div',{style:{marginBottom:16}},
          React.createElement('span',{className:'verdict-badge '+(detailEmail.threat_level||'safe')},(detailEmail.threat_level||'safe').toUpperCase()),
          React.createElement('span',{style:{marginLeft:10,fontSize:12,color:'#666'}},detailEmail.confidence?Math.round(detailEmail.confidence*100)+'% confidence':'')
        ),
        React.createElement('div',{className:'field'},React.createElement('label',null,'Subject'),React.createElement('div',{style:{fontSize:14}},detailEmail.subject||'(no subject)')),
        React.createElement('div',{className:'field'},React.createElement('label',null,'From'),React.createElement('div',{style:{fontSize:14}},detailEmail.from_address||detailEmail.sender||'unknown')),
        React.createElement('div',{className:'field'},React.createElement('label',null,'To'),React.createElement('div',{style:{fontSize:14}},detailEmail.to||'')),
        React.createElement('div',{className:'field'},React.createElement('label',null,'AI Verdict'),React.createElement('div',{style:{fontSize:14,color:'#aaa'}},detailEmail.reason||detailEmail.ai_reason||'No reasoning available')),
        detailEmail.body_text?React.createElement('div',{className:'field'},React.createElement('label',null,'Email Body'),React.createElement('pre',{style:{background:'#0a0a0a',border:'1px solid #1a1a1a',borderRadius:8,padding:12,fontSize:12,fontFamily:'JetBrains Mono',color:'#888',whiteSpace:'pre-wrap',wordBreak:'break-word',maxHeight:200,overflow:'auto'}},detailEmail.body_text)):null
      )
    ):null,
    showPaste?React.createElement('div',{className:'modal-overlay',onClick:function(){setShowPaste(false)}},
      React.createElement('div',{className:'modal fade-up',onClick:function(e){e.stopPropagation()}},
        React.createElement('button',{className:'modal-close',onClick:function(){setShowPaste(false)}},'\u00d7'),
        React.createElement('h2',null,'Paste Email for Analysis'),
        React.createElement('div',{className:'field'},React.createElement('label',null,'From (optional)'),React.createElement('input',{placeholder:'sender@example.com',value:_pasteFrom,onChange:function(e){setPasteFrom(e.target.value)}})),
        React.createElement('div',{className:'field'},React.createElement('label',null,'Subject (optional)'),React.createElement('input',{placeholder:'Email subject',value:_pasteSubject,onChange:function(e){setPasteSubject(e.target.value)}})),
        React.createElement('div',{className:'field'},React.createElement('label',null,'Email Content *'),React.createElement('textarea',{placeholder:'Paste the full email content here...',value:_pasteContent,onChange:function(e){setPasteContent(e.target.value)}})),
        React.createElement('button',{className:'btn primary',onClick:handlePaste,style:{width:'100%'}},'Analyze')
      )
    ):null,
    showConn?React.createElement('div',{className:'modal-overlay',onClick:function(){setShowConn(false)}},
      React.createElement('div',{className:'modal fade-up',onClick:function(e){e.stopPropagation()}},
        React.createElement('button',{className:'modal-close',onClick:function(){setShowConn(false)}},'\u00d7'),
        React.createElement('h2',null,'Email Connections'),
        conns.length>0?React.createElement('div',{style:{marginBottom:16}},
          conns.map(function(c){
            return React.createElement('div',{key:c.id,style:{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #1a1a1a',borderRadius:8,marginBottom:8}},
              React.createElement('div',null,
                React.createElement('div',{style:{fontWeight:600,fontSize:14}},c.label),
                React.createElement('div',{style:{fontSize:12,color:'#666'}},c.imap_username)
              ),
              React.createElement('button',{className:'btn sm',style:{color:'#DC2626',borderColor:'rgba(220,38,38,0.3)'},onClick:function(){handleDeleteConn(c.id)}},'Remove')
            );
          })
        ):React.createElement('p',{style:{color:'#666',fontSize:13,marginBottom:16}},'No connections yet. Add one below:'),
        React.createElement('h3',{style:{fontSize:14,marginBottom:12}},'Add Connection'),
        React.createElement('div',{className:'field'},React.createElement('label',null,'Label'),React.createElement('input',{value:_connForm.label,onChange:function(e){setConnForm(Object.assign({},_connForm,{label:e.target.value}))}})),
        React.createElement('div',{className:'field'},React.createElement('label',null,'IMAP Host'),React.createElement('input',{value:_connForm.imap_host,onChange:function(e){setConnForm(Object.assign({},_connForm,{imap_host:e.target.value}))}})),
        React.createElement('div',{className:'field'},React.createElement('label',null,'Email Address'),React.createElement('input',{placeholder:'you@gmail.com',value:_connForm.imap_username,onChange:function(e){setConnForm(Object.assign({},_connForm,{imap_username:e.target.value}))}})),
        React.createElement('div',{className:'field'},React.createElement('label',null,'App Password'),React.createElement('input',{type:'password',placeholder:'xxxx-xxxx-xxxx-xxxx',value:_connForm.imap_password,onChange:function(e){setConnForm(Object.assign({},_connForm,{imap_password:e.target.value}))}})),
        React.createElement('button',{className:'btn primary',onClick:handleAddConn,style:{width:'100%'}},'Add Connection')
      )
    ):null
  );
}

ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(App));
</script>
</body>
</html>"""

LITE_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SENTINEL Lite - Login</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:#0a0a0a;color:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#111;border:1px solid #1e1e1e;border-radius:16px;padding:40px;width:100%;max-width:400px;margin:16px}
h1{font-size:24px;font-weight:800;margin-bottom:4px}
.sub{color:#666;font-size:14px;margin-bottom:24px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12px;font-weight:600;color:#888;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.05em}
.field input{width:100%;background:#0a0a0a;border:1px solid #2a2a2a;color:#f5f5f5;padding:10px 14px;border-radius:8px;font-size:14px;font-family:inherit}
.field input:focus{outline:none;border-color:#DC2626;box-shadow:0 0 0 2px rgba(220,38,38,0.15)}
.btn{width:100%;background:linear-gradient(135deg,#DC2626,#B91C1C);border:1px solid rgba(220,38,38,0.4);color:white;padding:12px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
.btn:hover{box-shadow:0 4px 20px rgba(220,38,38,0.35)}
.error{color:#FCA5A5;font-size:13px;margin-bottom:12px}
.link{color:#DC2626;font-size:13px;text-align:center;margin-top:16px;display:block;text-decoration:none}
.link:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="card">
<h1>SENTINEL <span style="color:#DC2626">Lite</span></h1>
<p class="sub">Phishing protection made simple</p>
<div id="error" class="error" style="display:none"></div>
<div class="field"><label>Username or Email</label><input id="username" type="text" placeholder="username or email" autofocus></div>
<div class="field"><label>Password</label><div style="position:relative"><input id="password" type="password" style="width:100%;padding-right:44px"><button type="button" onclick="togglePw('password',this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#666;padding:4px"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button></div></div>
<button class="btn" onclick="doLogin()">Sign In</button>
<a class="link" href="/lite/register">Don't have an account? Register</a>
</div>
<script>
function togglePw(id, btn) {
  var inp = document.getElementById(id);
  var isPw = inp.type === 'password';
  inp.type = isPw ? 'text' : 'password';
  btn.innerHTML = isPw
    ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
    : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
}
document.getElementById('password').addEventListener('keydown',function(e){if(e.key==='Enter')doLogin()});
function doLogin(){
  var u=document.getElementById('username').value.trim();
  var p=document.getElementById('password').value;
  if(!u||!p){showErr('Fill in all fields');return}
  fetch('/lite/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})})
  .then(function(r){return r.json()}).then(function(d){
    if(d.token){localStorage.setItem('sentinel_lite_token',d.token);window.location.href='/lite'}
    else{showErr(d.detail||'Login failed')}
  }).catch(function(e){showErr('Connection error')});
}
function showErr(m){var e=document.getElementById('error');e.textContent=m;e.style.display='block'}
</script>
</body>
</html>"""

LITE_REGISTER_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SENTINEL Lite - Register</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Inter',sans-serif;background:#0a0a0a;color:#f5f5f5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#111;border:1px solid #1e1e1e;border-radius:16px;padding:40px;width:100%;max-width:400px;margin:16px}
h1{font-size:24px;font-weight:800;margin-bottom:4px}
.sub{color:#666;font-size:14px;margin-bottom:24px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12px;font-weight:600;color:#888;margin-bottom:6px;text-transform:uppercase;letter-spacing:0.05em}
.field input{width:100%;background:#0a0a0a;border:1px solid #2a2a2a;color:#f5f5f5;padding:10px 14px;border-radius:8px;font-size:14px;font-family:inherit}
.field input:focus{outline:none;border-color:#DC2626;box-shadow:0 0 0 2px rgba(220,38,38,0.15)}
.btn{width:100%;background:linear-gradient(135deg,#DC2626,#B91C1C);border:1px solid rgba(220,38,38,0.4);color:white;padding:12px;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit}
.btn:hover{box-shadow:0 4px 20px rgba(220,38,38,0.35)}
.error{color:#FCA5A5;font-size:13px;margin-bottom:12px}
.link{color:#DC2626;font-size:13px;text-align:center;margin-top:16px;display:block;text-decoration:none}
.link:hover{text-decoration:underline}
</style>
</head>
<body>
<div class="card">
<h1>Create Account</h1>
<p class="sub">Join SENTINEL Lite for free phishing protection</p>
<div id="error" class="error" style="display:none"></div>
<div class="field"><label>Username</label><input id="username" type="text" autofocus></div>
<div class="field"><label>Email</label><input id="email" type="email"></div>
<div class="field"><label>Password</label><div style="position:relative"><input id="password" type="password" style="width:100%;padding-right:44px"><button type="button" onclick="togglePw('password',this)" style="position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#666;padding:4px"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button></div></div>
<button class="btn" onclick="doRegister()">Create Account</button>
<a class="link" href="/lite/login">Already have an account? Sign in</a>
</div>
<script>
function togglePw(id, btn) {
  var inp = document.getElementById(id);
  var isPw = inp.type === 'password';
  inp.type = isPw ? 'text' : 'password';
  btn.innerHTML = isPw
    ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
    : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
}
document.getElementById('password').addEventListener('keydown',function(e){if(e.key==='Enter')doRegister()});
function doRegister(){
  var u=document.getElementById('username').value.trim();
  var e=document.getElementById('email').value.trim();
  var p=document.getElementById('password').value;
  if(!u||!e||!p){showErr('Fill in all fields');return}
  if(!e.includes('@')){showErr('Invalid email');return}
  fetch('/lite/api/auth/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,email:e,password:p})})
  .then(function(r){return r.json()}).then(function(d){
    if(d.status==='success'){window.location.href='/lite/login'}
    else{showErr(d.detail||'Registration failed')}
  }).catch(function(){showErr('Connection error')});
}
function showErr(m){var e=document.getElementById('error');e.textContent=m;e.style.display='block'}
</script>
</body>
</html>"""


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def _verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

def _create_token(user_id: str, username: str) -> str:
    payload = {"user_id": user_id, "username": username, "exp": datetime.utcnow() + timedelta(hours=JWT_EXPIRY_HOURS)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def _get_current_user(request: Request) -> Optional[dict]:
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if not token:
        token = request.cookies.get("sentinel_lite_token", "")
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        uid = payload.get("user_id")
        username = payload.get("username")
        if not uid:
            return None
        return {"user_id": uid, "username": username}
    except Exception:
        return None


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str

class LoginRequest(BaseModel):
    username: str  # accepts username OR email
    password: str

class AnalyzeRequest(BaseModel):
    from_address: str = ""
    subject: str = ""
    body: str

class GroqKeyRequest(BaseModel):
    api_key: str

class ConnRequest(BaseModel):
    label: str = "My Email"
    imap_host: str = "imap.gmail.com"
    imap_port: int = 993
    imap_username: str
    imap_password: str
    imap_folder: str = "INBOX"


# ============================================================================
# PAGE ROUTES
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def lite_index():
    return RedirectResponse("/lite/login")

@app.get("/login", response_class=HTMLResponse)
async def lite_login_page():
    return LITE_LOGIN_PAGE

@app.get("/register", response_class=HTMLResponse)
async def lite_register_page():
    return LITE_REGISTER_PAGE

@app.get("/dashboard", response_class=HTMLResponse)
async def lite_dashboard_page():
    return LITE_PAGE


# ============================================================================
# AUTH API
# ============================================================================

@app.post("/api/auth/register", include_in_schema=False)
async def lite_register(payload: RegisterRequest, request: Request, response: Response):
    import re as _re
    username = db.sanitize_input(payload.username, max_len=30)
    email = db.sanitize_input(payload.email, max_len=100).lower()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Invalid email address")
    existing = db.user_get_by_username(username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    existing_email = db.user_get_by_email(email)
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not _re.search(r"[A-Z]", payload.password) or not _re.search(r"[0-9]", payload.password):
        raise HTTPException(status_code=400, detail="Password must contain an uppercase letter and a number")
    pw_hash = _hash_password(payload.password)
    org_id = None
    if db.get_supabase():
        org_id = db.get_or_create_default_org()
    user = db.user_create(username, email, pw_hash, org_id, user_id=None)
    if not user:
        raise HTTPException(status_code=409, detail="Email or username already taken")
    db.user_set_role(user["id"], "friend")
    token = _create_token(user["id"], user["username"])
    refresh = db.refresh_token_create(user["id"])
    response.set_cookie(key="sentinel_lite_token", value=token, httponly=True, samesite="lax", max_age=900)
    response.set_cookie(key="sentinel_lite_refresh", value=refresh, httponly=True, samesite="lax", max_age=86400 * 7)
    ip = request.client.host if request.client else "unknown"
    db.audit_log("register", user["id"], username, "lite account created", ip=ip)
    return {"status": "success", "token": token, "username": user["username"]}

@app.post("/api/auth/login", include_in_schema=False)
async def lite_login(payload: LoginRequest, request: Request, response: Response):
    import re as _re
    identifier = db.sanitize_input(payload.username, max_len=100).lower()
    lockout = db.check_login_lockout(identifier)
    if lockout:
        raise HTTPException(status_code=423, detail=f"Account locked. Try again in {lockout}s.")
    user = db.user_resolve_login(identifier)
    if not user or not _verify_password(payload.password, user["password_hash"]):
        db.record_login_failure(identifier)
        ip = request.client.host if request.client else "unknown"
        db.audit_log("login_failed", username=identifier, details="bad credentials (lite)", ip=ip, success=False)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    db.clear_login_failures(identifier)
    token = _create_token(user["id"], user["username"])
    refresh = db.refresh_token_create(user["id"])
    response.set_cookie(key="sentinel_lite_token", value=token, httponly=True, samesite="lax", max_age=900)
    response.set_cookie(key="sentinel_lite_refresh", value=refresh, httponly=True, samesite="lax", max_age=86400 * 7)
    ip = request.client.host if request.client else "unknown"
    db.audit_log("login", user["id"], user["username"], "success (lite)", ip=ip)
    return {"status": "success", "token": token, "username": user["username"]}

@app.get("/api/auth/me", include_in_schema=False)
async def lite_me(request: Request):
    user = _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    groq_key = db.user_groq_key_get(user["user_id"])
    return {"user_id": user["user_id"], "username": user["username"], "groq_key_set": bool(groq_key)}

@app.post("/api/auth/logout", include_in_schema=False)
async def lite_logout(response: Response, request: Request):
    user = _get_current_user(request)
    if user:
        db.refresh_token_revoke(user["user_id"])
        ip = request.client.host if request.client else "unknown"
        db.audit_log("logout", user["user_id"], user.get("username", ""), ip=ip)
    response.delete_cookie("sentinel_lite_token")
    response.delete_cookie("sentinel_lite_refresh")
    return {"status": "success"}

@app.post("/api/auth/refresh", include_in_schema=False)
async def lite_refresh_token(request: Request, response: Response):
    refresh = request.cookies.get("sentinel_lite_refresh", "")
    if not refresh:
        raise HTTPException(status_code=401, detail="No refresh token")
    user_id = db.refresh_token_validate(refresh)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    user = db.user_get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    new_token = _create_token(user["id"], user["username"])
    new_refresh = db.refresh_token_create(user["id"])
    db.refresh_token_revoke(user_id)
    response.set_cookie(key="sentinel_lite_token", value=new_token, httponly=True, samesite="lax", max_age=900)
    response.set_cookie(key="sentinel_lite_refresh", value=new_refresh, httponly=True, samesite="lax", max_age=86400 * 7)
    return {"status": "success", "token": new_token, "username": user["username"]}


# ============================================================================
# GROQ KEY API
# ============================================================================

@app.post("/api/settings/groq-key")
async def lite_save_groq_key(payload: GroqKeyRequest, request: Request):
    user = _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db.user_groq_key_save(user["user_id"], payload.api_key)
    return {"status": "success"}


# ============================================================================
# EMAIL ANALYSIS API
# ============================================================================

@app.post("/api/analyze")
async def lite_analyze(payload: AnalyzeRequest, request: Request):
    user = _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    groq_key = db.user_groq_key_get(user["user_id"])
    if not groq_key:
        raise HTTPException(status_code=400, detail="No Groq API key set. Go to Settings to add one.")
    from groq import Groq
    client = Groq(api_key=groq_key)
    email_text = f"From: {payload.from_address}\nSubject: {payload.subject}\n\n{payload.body}"
    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[{"role": "system", "content": LITE_PROMPT}, {"role": "user", "content": email_text}],
            response_format={"type": "json_object"},
            temperature=0.2,
            max_tokens=256,
        )
        result = json.loads(response.choices[0].message.content)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {e}")
    threat_level = (result.get("threat_level") or "safe").lower().strip()
    if threat_level not in ("safe", "suspicious", "malicious"):
        threat_level = "safe"
    email_id = f"email-{uuid.uuid4().hex[:12]}"
    record = {
        "id": email_id,
        "from_address": payload.from_address,
        "sender": payload.from_address,
        "subject": payload.subject,
        "body_text": payload.body,
        "threat_level": threat_level,
        "confidence": result.get("confidence", 0.5),
        "reason": result.get("reason", ""),
        "ai_reason": result.get("reason", ""),
        "received_at": datetime.utcnow().isoformat(),
        "source": "paste",
    }
    db.store_set(user["user_id"], email_id, record)
    return {"status": "success", "threat_level": threat_level, "confidence": result.get("confidence", 0.5), "reason": result.get("reason", "")}


# ============================================================================
# EMAIL LIST API
# ============================================================================

@app.get("/api/emails")
async def lite_list_emails(request: Request):
    user = _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    store = db.store_get(user["user_id"])
    emails = list(store.values())
    emails.sort(key=lambda x: x.get("received_at", ""), reverse=True)
    return {"emails": emails}

@app.delete("/api/emails")
async def lite_clear_emails(request: Request):
    user = _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db.store_clear(user["user_id"])
    return {"status": "success"}


# ============================================================================
# IMAP CONNECTIONS API
# ============================================================================

@app.get("/api/connections")
async def lite_list_connections(request: Request):
    user = _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    conns = db.email_connection_list(user["user_id"])
    return {"connections": conns}

@app.post("/api/connections")
async def lite_create_connection(payload: ConnRequest, request: Request):
    user = _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = db.user_get_by_id(user["user_id"])
    org_id = user_db.get("org_id") if user_db else None
    if not org_id:
        org_id = db.get_or_create_default_org()
    conn = db.email_connection_create(
        user_id=user["user_id"], org_id=org_id or "", label=payload.label,
        provider="custom", imap_host=payload.imap_host, imap_port=payload.imap_port,
        imap_username=payload.imap_username, imap_password_enc=payload.imap_password,
        imap_folder=payload.imap_folder, scan_interval=30,
    )
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to create connection")
    return {"status": "success", "connection_id": conn["id"]}

@app.delete("/api/connections/{conn_id}")
async def lite_delete_connection(conn_id: str, request: Request):
    user = _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    db.email_connection_delete(conn_id, user["user_id"])
    return {"status": "success"}


# ============================================================================
# IMAP SCAN API
# ============================================================================

@app.post("/api/scan")
async def lite_scan(request: Request):
    user = _get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    groq_key = db.user_groq_key_get(user["user_id"])
    if not groq_key:
        raise HTTPException(status_code=400, detail="No Groq API key set.")
    conns = db.email_connection_list(user["user_id"])
    active_conns = [c for c in conns if c.get("is_active", True)]
    if not active_conns:
        raise HTTPException(status_code=400, detail="No active email connections. Add one in Connections.")
    total_found = 0
    for conn in active_conns:
        conn_full = db.email_connection_get(conn["id"], user["user_id"])
        if not conn_full or not conn_full.get("imap_password_enc"):
            continue
        try:
            mail = _imap.IMAP4_SSL(conn_full["imap_host"], conn_full["imap_port"])
            mail.login(conn_full["imap_username"], conn_full["imap_password_enc"])
            mail.select(conn_full.get("imap_folder", "INBOX"))
            _, msg_nums = mail.search(None, "UNSEEN")
            email_ids = msg_nums[0].split() if msg_nums[0] else []
            MAX_PER_SCAN = 15
            emails_to_scan = email_ids[-MAX_PER_SCAN:] if len(email_ids) > MAX_PER_SCAN else email_ids
            existing = db.store_get(user["user_id"])
            existing_mids = set()
            for rec in existing.values():
                mid = rec.get("message_id", "")
                if mid:
                    existing_mids.add(mid)
            from groq import Groq
            client = Groq(api_key=groq_key)
            for eid in emails_to_scan:
                try:
                    mid_check = f"imap-{eid.decode()}"
                    if mid_check in existing_mids:
                        continue
                    _, msg_data = mail.fetch(eid, "(RFC822)")
                    raw = msg_data[0][1]
                    msg = _email.message_from_bytes(raw)
                    def _dec(raw_hdr):
                        if raw_hdr is None: return ""
                        parts = _decode_header(raw_hdr)
                        decoded = []
                        for part, charset in parts:
                            if isinstance(part, bytes):
                                decoded.append(part.decode(charset or "utf-8", errors="replace"))
                            else:
                                decoded.append(part)
                        return " ".join(decoded)
                    from_addr = _dec(msg.get("From", ""))
                    subject = _dec(msg.get("Subject") or "(no subject)")
                    body_text = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                payload = part.get_payload(decode=True)
                                if payload:
                                    body_text += payload.decode(part.get_content_charset() or "utf-8", errors="replace")
                    else:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            body_text = payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
                    email_text = f"From: {from_addr}\nSubject: {subject}\n\n{body_text[:2000]}"
                    try:
                        response = client.chat.completions.create(
                            model="llama-3.3-70b-versatile",
                            messages=[{"role": "system", "content": LITE_PROMPT}, {"role": "user", "content": email_text}],
                            response_format={"type": "json_object"},
                            temperature=0.2,
                            max_tokens=256,
                        )
                        result = json.loads(response.choices[0].message.content)
                    except Exception:
                        result = {"threat_level": "safe", "confidence": 0.5, "reason": "Analysis failed"}
                    threat_level = (result.get("threat_level") or "safe").lower().strip()
                    if threat_level not in ("safe", "suspicious", "malicious"):
                        threat_level = "safe"
                    email_id = f"email-{uuid.uuid4().hex[:12]}"
                    record = {
                        "id": email_id,
                        "message_id": mid_check,
                        "from_address": from_addr,
                        "sender": from_addr,
                        "subject": subject,
                        "body_text": body_text[:5000],
                        "threat_level": threat_level,
                        "confidence": result.get("confidence", 0.5),
                        "reason": result.get("reason", ""),
                        "ai_reason": result.get("reason", ""),
                        "received_at": datetime.utcnow().isoformat(),
                        "source": "imap_scan",
                    }
                    db.store_set(user["user_id"], email_id, record)
                    total_found += 1
                    time.sleep(0.3)
                except Exception as e:
                    print(f"[SENTINEL-LITE] Scan email error: {e}", flush=True)
            try:
                mail.logout()
            except Exception:
                pass
        except Exception as e:
            print(f"[SENTINEL-LITE] IMAP connection error: {e}", flush=True)
    return {"status": "success", "emails_found": total_found}
