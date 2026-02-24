import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const SUPABASE_URL       = Deno.env.get('SUPABASE_URL')!;
const SERVICE_ROLE_KEY   = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const SESSION_HOURS      = 8;
const ALLOWED_BUCKETS    = ['audio', 'images'];
const ALLOWED_AUDIO_COLS = [
  'audio_presentation_url','audio_demo_url','audio_demo_promo_url',
  'audio_demo_joue_url','audio_demo_instit_url'
];

function db() {
  return createClient(SUPABASE_URL, SERVICE_ROLE_KEY, { auth:{ persistSession:false } });
}

function corsHeaders(req: Request) {
  return {
    'Access-Control-Allow-Origin':  req.headers.get('Origin') || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-session-token',
  };
}

function json(data: unknown, status = 200, req?: Request): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type':'application/json', ...(req?corsHeaders(req):{}) }
  });
}

async function generateToken(): Promise<string> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

async function broadcast(table: string): Promise<void> {
  try {
    await fetch(`${SUPABASE_URL}/realtime/v1/api/broadcast`, {
      method: 'POST',
      headers: {
        'Content-Type':  'application/json',
        'Authorization': `Bearer ${SERVICE_ROLE_KEY}`,
        'apikey':        SERVICE_ROLE_KEY
      },
      body: JSON.stringify({
        messages: [{ topic:'catalogue-updates', event:'data_changed', payload:{ table } }]
      })
    });
  } catch { /* silencieux */ }
}

interface SessionInfo {
  user_id:    number;
  username:   string;
  role:       string;
  comedian_id: number | null;
}

async function validateSession(token: string | null): Promise<SessionInfo | null> {
  if (!token) return null;
  const client = db();
  const { data } = await client
    .from('app_sessions')
    .select('user_id,username,role,comedian_id,expires_at')
    .eq('token', token)
    .single();
  if (!data) return null;
  if (new Date(data.expires_at) < new Date()) {
    await client.from('app_sessions').delete().eq('token', token);
    return null;
  }
  const newExpiry = new Date(Date.now()+SESSION_HOURS*3600*1000).toISOString();
  await client.from('app_sessions')
    .update({ last_seen:new Date().toISOString(), expires_at:newExpiry })
    .eq('token', token);
  return { user_id:data.user_id, username:data.username, role:data.role, comedian_id:data.comedian_id??null };
}

Deno.serve(async (req: Request) => {
  if (req.method === 'OPTIONS') return new Response(null,{status:204,headers:corsHeaders(req)});
  if (req.method !== 'POST') return json({error:'Method not allowed'},405,req);

  let body: { action:string; payload?:Record<string,unknown> };
  try { body = await req.json(); }
  catch { return json({error:'Corps JSON invalide'},400,req); }

  const { action, payload = {} } = body;
  const sessionToken = req.headers.get('x-session-token');
  const client = db();

  if (action === 'init_settings') {
    const { data, error } = await client.from('app_settings').select('*').single();
    if (error) return json({error:error.message},500,req);
    return json({data},200,req);
  }

  if (action === 'get_shared_selection') {
    const { token } = payload as {token:string};
    if (!token) return json({error:'token manquant'},400,req);
    const { data } = await client.from('shared_selections').select('*').eq('token',token).single();
    return json({data:data||null},200,req);
  }

  if (action === 'login') {
    const { username, password } = payload as {username:string;password:string};
    if (!username||!password) return json({error:'Identifiants manquants'},400,req);
    const hash = await sha256(password);
    const { data:user } = await client
      .from('app_users')
      .select('id,username,email,role,comedian_id,active,created_at')
      .eq('username', username.trim())
      .eq('password_hash', hash)
      .eq('active', true)
      .single();
    if (!user) return json({error:'Identifiant ou mot de passe incorrect'},401,req);
    const token   = await generateToken();
    const expires = new Date(Date.now()+SESSION_HOURS*3600*1000).toISOString();
    await client.from('app_sessions').insert({token,user_id:user.id,username:user.username,role:user.role,comedian_id:user.comedian_id??null,expires_at:expires});
    return json({data:{token,user}},200,req);
  }

  const session = await validateSession(sessionToken);

  if (action === 'restore_session') {
    if (!session) return json({data:null},200,req);
    const { data:user } = await client.from('app_users').select('id,username,email,role,comedian_id,active,created_at').eq('username',session.username).eq('active',true).single();
    return json({data:user||null},200,req);
  }

  if (!session) return json({error:'Session invalide ou expirée'},401,req);

  const { role } = session;
  const isAdmin         = role === 'admin';
  const isAdminOrStudio = isAdmin || role === 'studio' || role === 'manager';

  if (action === 'sign_out') {
    await client.from('app_sessions').delete().eq('token',sessionToken);
    return json({data:null},200,req);
  }

  if (action === 'init') {
    const [
      {data:comedians},{data:absences},{data:users},
      {data:templates},{data:settings},{data:logs}
    ] = await Promise.all([
      client.from('comedians').select('*').order('name'),
      client.from('absences').select('*'),
      client.from('app_users').select('id,username,email,role,comedian_id,active,created_at').order('username'),
      client.from('email_templates').select('*'),
      client.from('app_settings').select('*').single(),
      client.from('app_logs').select('*').order('created_at',{ascending:false}).limit(100),
    ]);
    return json({data:{comedians,absences,users,templates,settings,logs}},200,req);
  }

  if (action === 'reload_comedians') {
    const [{data:c},{data:a}] = await Promise.all([
      client.from('comedians').select('*').order('name'),
      client.from('absences').select('*'),
    ]);
    return json({data:{comedians:c,absences:a}},200,req);
  }

  if (action === 'reload_users') {
    const {data} = await client.from('app_users').select('id,username,email,role,comedian_id,active,created_at').order('username');
    return json({data},200,req);
  }

  if (action === 'reload_templates') {
    const {data} = await client.from('email_templates').select('*');
    return json({data},200,req);
  }

  if (action === 'reload_settings') {
    const {data} = await client.from('app_settings').select('*').single();
    return json({data},200,req);
  }

  if (action === 'upsert_comedian') {
    if (!isAdminOrStudio) return json({error:'Accès refusé'},403,req);
    const { comedianRow, absenceRows, isNew } = payload as {comedianRow:Record<string,unknown>;absenceRows:Record<string,unknown>[];isNew:boolean};
    let savedId: number;
    if (!isNew) {
      const {id,...rest}=comedianRow; const {error}=await client.from('comedians').update(rest).eq('id',id);
      if (error) return json({error:error.message},500,req); savedId=id as number;
    } else {
      const {id:_id,...rest}=comedianRow; const {data,error}=await client.from('comedians').insert(rest).select('id').single();
      if (error) return json({error:error.message},500,req); savedId=data.id;
    }
    await client.from('absences').delete().eq('comedian_id',savedId);
    if (absenceRows&&absenceRows.length>0) {
      const rows=absenceRows.map((a:Record<string,unknown>)=>({...a,comedian_id:savedId}));
      await client.from('absences').insert(rows);
    }
    const [{data:c},{data:a}]=await Promise.all([
      client.from('comedians').select('*').eq('id',savedId).single(),
      client.from('absences').select('*').eq('comedian_id',savedId),
    ]);
    broadcast('comedians');
    return json({data:{comedian:c,absences:a,savedId}},200,req);
  }

  if (action === 'delete_comedian') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    const {id}=payload as {id:number};
    const {error}=await client.from('comedians').delete().eq('id',id);
    if (error) return json({error:error.message},500,req);
    broadcast('comedians');
    return json({data:null},200,req);
  }

  if (action === 'bulk_insert_comedians') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    const {rows}=payload as {rows:Record<string,unknown>[]};
    const {data,error}=await client.from('comedians').insert(rows).select('id,name,email');
    if (error) return json({error:error.message},500,req);
    broadcast('comedians');
    return json({data},200,req);
  }

  if (action === 'delete_all_comedians') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    const {error}=await client.from('comedians').delete().neq('id',0);
    if (error) return json({error:error.message},500,req);
    broadcast('comedians');
    return json({data:null},200,req);
  }

  if (action === 'delete_comedians_by_classement') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    const {classement,ids}=payload as {classement:string;ids:number[]};
    if (!ids||ids.length===0) return json({data:null},200,req);
    const {error}=await client.from('comedians').delete().in('id',ids);
    if (error) return json({error:error.message},500,req);
    broadcast('comedians');
    return json({data:null},200,req);
  }

  if (action === 'delete_comedians_by_ids') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    const {ids}=payload as {ids:number[]};
    if (!ids||ids.length===0) return json({data:null},200,req);
    const {error}=await client.from('comedians').delete().in('id',ids);
    if (error) return json({error:error.message},500,req);
    broadcast('comedians');
    return json({data:null},200,req);
  }

  if (action === 'update_audio_field') {
    if (!isAdminOrStudio) return json({error:'Accès refusé'},403,req);
    const {comedianId,columnName,value}=payload as {comedianId:number;columnName:string;value:string|null};
    if (!ALLOWED_AUDIO_COLS.includes(columnName)) return json({error:'Colonne non autorisée'},400,req);
    const patch:Record<string,unknown>={};
    patch[columnName]=value||null;
    const {error}=await client.from('comedians').update(patch).eq('id',comedianId);
    if (error) return json({error:error.message},500,req);
    broadcast('comedians');
    return json({data:null},200,req);
  }

  if (action === 'insert_absence_direct') {
    const {comedianId,absence}=payload as {comedianId:number;absence:Record<string,unknown>};
    const row={...absence,comedian_id:comedianId};
    const {data,error}=await client.from('absences').insert(row).select('*').single();
    if (error) return json({error:error.message},500,req);
    broadcast('absences');
    return json({data},200,req);
  }

  if (action === 'delete_absence_direct') {
    const {comedianId,absenceLocalId}=payload as {comedianId:number;absenceLocalId:number};
    let deleted=false;
    if (absenceLocalId) {
      const {data:byLocal}=await client.from('absences').delete().eq('comedian_id',comedianId).eq('local_id',absenceLocalId).select('id');
      deleted=Array.isArray(byLocal)&&byLocal.length>0;
    }
    if (!deleted) await client.from('absences').delete().eq('comedian_id',comedianId).eq('id',absenceLocalId);
    broadcast('absences');
    return json({data:null},200,req);
  }

  if (action === 'upsert_user') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    const {userRow,isNew}=payload as {userRow:Record<string,unknown>;isNew:boolean};
    if (isNew) {
      const {id:_id,...rest}=userRow;
      const {data,error}=await client.from('app_users').insert(rest).select('id,username,email,role,comedian_id,active,created_at').single();
      if (error) return json({error:error.message},500,req);
      broadcast('users');
      return json({data},200,req);
    } else {
      const {id,...rest}=userRow;
      const {error}=await client.from('app_users').update(rest).eq('id',id);
      if (error) return json({error:error.message},500,req);
      const {data:refreshed}=await client.from('app_users').select('id,username,email,role,comedian_id,active,created_at').eq('id',id).single();
      broadcast('users');
      return json({data:refreshed},200,req);
    }
  }

  if (action === 'delete_user') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    const {id}=payload as {id:number};
    await client.from('app_sessions').delete().eq('user_id',id);
    const {error}=await client.from('app_users').delete().eq('id',id);
    if (error) return json({error:error.message},500,req);
    broadcast('users');
    return json({data:null},200,req);
  }

  if (action === 'bulk_insert_users') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    const {rows}=payload as {rows:Record<string,unknown>[]};
    const {error}=await client.from('app_users').insert(rows);
    if (error) return json({error:error.message},500,req);
    broadcast('users');
    return json({data:null},200,req);
  }

  if (action === 'save_email_templates') {
    if (!isAdminOrStudio) return json({error:'Accès refusé'},403,req);
    const {rows}=payload as {rows:Record<string,unknown>[]};
    const ids=rows.map((r:Record<string,unknown>)=>r.id as string);
    await client.from('email_templates').delete().in('id',ids);
    const {error}=await client.from('email_templates').insert(rows);
    if (error) return json({error:error.message},500,req);
    return json({data:null},200,req);
  }

  if (action === 'delete_email_template') {
    if (!isAdminOrStudio) return json({error:'Accès refusé'},403,req);
    const {id}=payload as {id:string};
    const {error}=await client.from('email_templates').delete().eq('id',id);
    if (error) return json({error:error.message},500,req);
    return json({data:null},200,req);
  }

  if (action === 'save_shared_selection') {
    const {token,selData}=payload as {token:string;selData:{comedianIds:number[];createdBy?:string;recipientEmail?:string}};
    const {error}=await client.from('shared_selections').insert({token,comedian_ids:selData.comedianIds,created_by:selData.createdBy||null,recipient_email:selData.recipientEmail||null});
    if (error) return json({error:error.message},500,req);
    return json({data:null},200,req);
  }

  if (action === 'insert_log') {
    const {log}=payload as {log:Record<string,unknown>};
    await client.from('app_logs').insert({username:log.username,role:log.role,action:log.action,created_at:log.timestamp});
    return json({data:null},200,req);
  }

  if (action === 'clear_logs') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    await client.from('app_logs').delete().neq('id',0);
    return json({data:null},200,req);
  }

  if (action === 'save_settings') {
    if (!isAdmin) return json({error:'Accès refusé'},403,req);
    const {settings}=payload as {settings:Record<string,unknown>};
    const {error}=await client.from('app_settings').upsert({id:1,...settings,updated_at:new Date().toISOString()},{onConflict:'id'});
    if (error) return json({error:error.message},500,req);
    broadcast('settings');
    return json({data:null},200,req);
  }

  if (action === 'get_upload_url') {
    const {bucket,path}=payload as {bucket:string;path:string};
    if (!ALLOWED_BUCKETS.includes(bucket)) return json({error:'Bucket non autorisé'},400,req);
    const {data,error}=await client.storage.from(bucket).createSignedUploadUrl(path);
    if (error) return json({error:error.message},500,req);
    return json({data},200,req);
  }

  if (action === 'get_public_url') {
    const {bucket,path}=payload as {bucket:string;path:string};
    if (!ALLOWED_BUCKETS.includes(bucket)) return json({error:'Bucket non autorisé'},400,req);
    const {data}=client.storage.from(bucket).getPublicUrl(path);
    return json({data},200,req);
  }

  if (action === 'delete_storage_file') {
    const {bucket,filePath}=payload as {bucket:string;filePath:string};
    if (!ALLOWED_BUCKETS.includes(bucket)) return json({error:'Bucket non autorisé'},400,req);
    await client.storage.from(bucket).remove([filePath]);
    return json({data:null},200,req);
  }

  return json({error:`Action inconnue : ${action}`},400,req);
});
