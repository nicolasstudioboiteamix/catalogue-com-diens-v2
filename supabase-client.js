const SESSION_KEY = 'catalogue_session_token';
// sessionStorage : isolé par onglet/fenêtre → pas d'auto-login dans un nouvel onglet
let _sessionToken = sessionStorage.getItem(SESSION_KEY) || null;

function _setSession(token) {
    _sessionToken = token;
    if (token) sessionStorage.setItem(SESSION_KEY, token);
    else        sessionStorage.removeItem(SESSION_KEY);
}

async function apiCall(action, payload = {}) {
    const headers = { 'Content-Type': 'application/json' };
    if (_sessionToken) headers['x-session-token'] = _sessionToken;

    let res;
    try {
        res = await fetch(SUPABASE_CONFIG.EDGE_URL, {
            method:  'POST',
            headers,
            body:    JSON.stringify({ action, payload })
        });
    } catch(netErr) {
        throw new Error('Impossible de joindre le serveur. Vérifiez votre connexion.');
    }

    let result;
    try { result = await res.json(); }
    catch { throw new Error(`Réponse serveur invalide (HTTP ${res.status})`); }

    if (res.status === 401) {
        _setSession(null);
        throw new Error('Session expirée. Veuillez vous reconnecter.');
    }
    if (res.status === 405) {
        throw new Error('Erreur 405 : vérifiez que l\'URL de l\'Edge Function est correcte dans js/config.js');
    }
    if (!res.ok || result.error) {
        throw new Error(result.error || `Erreur HTTP ${res.status}`);
    }
    return result.data;
}

const AppState = {
    comedians: [], users: [], logs: [], sharedSelections: {}, emailTemplates: {},
    settings: {
        studioName:'Catalogue Comédiens', studioLogoUrl:null, studioLogoName:null,
        logoLightMode:'dark-bg'
    },
    ready: false
};

async function hashPassword(password) {
    const encoded = new TextEncoder().encode(password);
    const hash    = await crypto.subtle.digest('SHA-256', encoded);
    return Array.from(new Uint8Array(hash)).map(b=>b.toString(16).padStart(2,'0')).join('');
}

function dbToComedian(row, comedianAbsences) {
    return {
        id:row.id, name:row.name||'', email:row.email||'', phone:row.phone||'',
        sexe:row.sexe||'', classement:row.classement||'',
        seances_dirigees:!!row.seances_dirigees, voix_off:!!row.voix_off,
        voix_jouee:!!row.voix_jouee, voix_enfant:!!row.voix_enfant, chant:!!row.chant,
        voix_jeune:!!row.voix_jeune, voix_adulte:!!row.voix_adulte,
        voix_mature:!!row.voix_mature, voix_accent:!!row.voix_accent,
        timbre_grave:!!row.timbre_grave, timbre_medium:!!row.timbre_medium,
        timbre_aigu:!!row.timbre_aigu, timbre_texture:!!row.timbre_texture,
        style_dynamique:!!row.style_dynamique, style_pose:!!row.style_pose,
        style_naturel:!!row.style_naturel, style_institutionnel:!!row.style_institutionnel,
        voixUrgente:!!row.voix_urgente, commentaireInterne:row.commentaire_interne||'',
        presentation:row.presentation||'', profilePic:row.profile_pic_url||null,
        audioPresentation:row.audio_presentation_url||null, audioDemo:row.audio_demo_url||null,
        audioDemoPromo:row.audio_demo_promo_url||null, audioDemoJoue:row.audio_demo_joue_url||null,
        audioDemoInstit:row.audio_demo_instit_url||null,
        identifiantsSent:!!row.identifiants_sent, username:row.username||'',
        password:row.password_hash||'', active:!!row.active, createdAt:row.created_at,
        absences: comedianAbsences || []
    };
}

function comedianToDB(comedian, includeId=true) {
    const row = {
        name:comedian.name, email:comedian.email, phone:comedian.phone||null,
        sexe:comedian.sexe||null, classement:comedian.classement||null,
        seances_dirigees:!!comedian.seances_dirigees, voix_off:!!comedian.voix_off,
        voix_jouee:!!comedian.voix_jouee, voix_enfant:!!comedian.voix_enfant, chant:!!comedian.chant,
        voix_jeune:!!comedian.voix_jeune, voix_adulte:!!comedian.voix_adulte,
        voix_mature:!!comedian.voix_mature, voix_accent:!!comedian.voix_accent,
        timbre_grave:!!comedian.timbre_grave, timbre_medium:!!comedian.timbre_medium,
        timbre_aigu:!!comedian.timbre_aigu, timbre_texture:!!comedian.timbre_texture,
        style_dynamique:!!comedian.style_dynamique, style_pose:!!comedian.style_pose,
        style_naturel:!!comedian.style_naturel, style_institutionnel:!!comedian.style_institutionnel,
        voix_urgente:!!comedian.voixUrgente, commentaire_interne:comedian.commentaireInterne||'',
        presentation:comedian.presentation||'', profile_pic_url:comedian.profilePic||null,
        audio_presentation_url:comedian.audioPresentation||null, audio_demo_url:comedian.audioDemo||null,
        audio_demo_promo_url:comedian.audioDemoPromo||null, audio_demo_joue_url:comedian.audioDemoJoue||null,
        audio_demo_instit_url:comedian.audioDemoInstit||null,
        identifiants_sent:!!comedian.identifiantsSent, username:comedian.username||null,
        password_hash:comedian.password||null, active:!!comedian.active
    };
    if (includeId && comedian.id) row.id = comedian.id;
    return row;
}

function dbToUser(row) {
    return {
        id:row.id, username:row.username, email:row.email||'',
        role:row.role, comedianId:row.comedian_id||null,
        active:!!row.active, createdAt:row.created_at
    };
}

function userToDB(user) {
    const row = {
        username:user.username, email:user.email||null,
        role:user.role, comedian_id:user.comedianId||null, active:!!user.active
    };
    if (user.password) row.password_hash = user.password;
    return row;
}

function applySettings(data) {
    if (!data) return;
    AppState.settings.studioName     = data.studio_name     || 'Catalogue Comédiens';
    AppState.settings.studioLogoUrl  = data.studio_logo_url  || null;
    AppState.settings.studioLogoName = data.studio_logo_name || null;
    AppState.settings.logoLightMode  = data.logo_light_mode  || 'dark-bg';
}

function buildComedianList(comedianRows, absenceRows) {
    return (comedianRows||[]).map(c => {
        const abs=(absenceRows||[]).filter(a=>a.comedian_id===c.id).map(a=>({
            id:a.local_id||a.id, start:a.start_date, end:a.end_date,
            startTime:a.start_time||'', endTime:a.end_time||'', comment:a.comment||''
        }));
        return dbToComedian(c, abs);
    });
}

const SupabaseDB = {
    async initSettings() {
        try { const data=await apiCall('init_settings'); applySettings(data); } catch(e){}
    },

    async init() {
        const data = await apiCall('init');
        AppState.comedians      = buildComedianList(data.comedians, data.absences);
        AppState.users          = (data.users||[]).map(dbToUser);
        AppState.emailTemplates = {};
        (data.templates||[]).forEach(t=>{AppState.emailTemplates[t.id]={id:t.id,name:t.name,category:t.category,builtin:t.builtin,subject:t.subject,body:t.body,rules:t.rules||''};});
        applySettings(data.settings);
        AppState.logs = (data.logs||[]).map(l=>({timestamp:l.created_at,username:l.username,role:l.role,action:l.action}));
        AppState.ready = true;
    },

    async authenticate(username, password) {
        const data = await apiCall('login',{username,password});
        if (!data) return null;
        _setSession(data.token);
        return dbToUser(data.user);
    },

    async signOut() {
        try { await apiCall('sign_out'); } catch(e){}
        _setSession(null);
    },

    clearLocalSession() { _setSession(null); },

    async restoreSession() {
        if (!_sessionToken) return null;
        try { const u=await apiCall('restore_session'); return u?dbToUser(u):null; }
        catch(e){ _setSession(null); return null; }
    },

    async createAuthUser() {},

    async upsertUser(user) {
        const row   = userToDB(user);
        const isNew = !(user.id && AppState.users.find(u=>u.id===user.id));
        if (!isNew) row.id = user.id;
        const data  = await apiCall('upsert_user',{userRow:row,isNew});
        const saved = dbToUser(data);
        if (isNew) AppState.users.push(saved);
        else { const idx=AppState.users.findIndex(u=>u.id===user.id); if(idx>=0) AppState.users[idx]=saved; }
    },

    async deleteUser(userId) {
        await apiCall('delete_user',{id:userId});
        AppState.users = AppState.users.filter(u=>u.id!==userId);
    },

    async upsertComedian(comedian) {
        const {absences,...rest} = comedian;
        const comedianRow = comedianToDB(rest);
        const isNew       = !(comedian.id && AppState.comedians.some(c=>c.id===comedian.id));
        const absenceRows = (absences||[]).map(a=>({start_date:a.start,end_date:a.end,start_time:a.startTime||null,end_time:a.endTime||null,comment:a.comment||null,local_id:a.id}));
        const data  = await apiCall('upsert_comedian',{comedianRow,absenceRows,isNew});
        const {savedId} = data;
        const freshAbs  = (data.absences||[]).map(a=>({id:a.local_id||a.id,start:a.start_date,end:a.end_date,startTime:a.start_time||'',endTime:a.end_time||'',comment:a.comment||''}));
        const freshComedian = dbToComedian(data.comedian,freshAbs);
        const idx = AppState.comedians.findIndex(c=>c.id===savedId);
        if (idx>=0) AppState.comedians[idx]=freshComedian; else AppState.comedians.push(freshComedian);
        Object.assign(comedian,freshComedian);
    },

    async deleteComedian(comedianId) {
        await apiCall('delete_comedian',{id:comedianId});
        AppState.comedians = AppState.comedians.filter(c=>c.id!==comedianId);
    },

    async bulkInsertComedians(rows) {
        return await apiCall('bulk_insert_comedians',{rows:rows.map(c=>{const r=comedianToDB(c);delete r.id;return r;})});
    },

    async bulkInsertUsers(usersList) {
        await apiCall('bulk_insert_users',{rows:usersList.map(u=>{const r=userToDB(u);delete r.id;return r;})});
    },

    async deleteAllComedians() {
        await apiCall('delete_all_comedians');
        AppState.comedians = [];
    },

    async deleteComediansByClassement(classement) {
        const ids = AppState.comedians.filter(c=>c.classement===classement).map(c=>c.id);
        if (!ids.length) return;
        await apiCall('delete_comedians_by_classement',{classement,ids});
        AppState.comedians = AppState.comedians.filter(c=>c.classement!==classement);
    },

    async deleteComediansByIds(ids) {
        await apiCall('delete_comedians_by_ids',{ids});
        AppState.comedians = AppState.comedians.filter(c=>!ids.includes(c.id));
    },

    async saveEmailTemplates(templates) {
        const rows=Object.values(templates).map(t=>({id:t.id,name:t.name,category:t.category,builtin:!!t.builtin,subject:t.subject,body:t.body,rules:t.rules||'',updated_at:new Date().toISOString()}));
        if (!rows.length) return;
        await apiCall('save_email_templates',{rows});
        AppState.emailTemplates = templates;
    },

    async deleteEmailTemplate(id) {
        await apiCall('delete_email_template',{id});
        delete AppState.emailTemplates[id];
    },

    async saveSharedSelection(token,data) {
        await apiCall('save_shared_selection',{token,selData:data});
        AppState.sharedSelections[token] = data;
    },

    async getSharedSelection(token) {
        if (AppState.sharedSelections[token]) return AppState.sharedSelections[token];
        const data = await apiCall('get_shared_selection',{token});
        if (!data) return null;
        const result={comedianIds:data.comedian_ids,createdBy:data.created_by};
        AppState.sharedSelections[token]=result;
        return result;
    },

    async insertLog(log) {
        await apiCall('insert_log',{log});
        AppState.logs.unshift(log);
        if (AppState.logs.length>100) AppState.logs.splice(100);
    },

    async clearLogs() {
        await apiCall('clear_logs');
        AppState.logs = [];
    },

    async saveSettings() {
        await apiCall('save_settings',{settings:{
            studio_name:     AppState.settings.studioName,
            studio_logo_url: AppState.settings.studioLogoUrl||null,
            studio_logo_name:AppState.settings.studioLogoName||null,
            logo_light_mode: AppState.settings.logoLightMode||'dark-bg'
        }});
    },

    _dataUrlToBlob(dataUrl) {
        const [header,base64]=dataUrl.split(',');
        const mimeType=header.match(/:(.*?);/)[1];
        const binary=atob(base64);
        const arr=new Uint8Array(binary.length);
        for(let i=0;i<binary.length;i++) arr[i]=binary.charCodeAt(i);
        return new Blob([arr],{type:mimeType});
    },

    async _uploadViaSignedUrl(dataUrl,bucket,filename,contentType) {
        const {signedUrl,path}=await apiCall('get_upload_url',{bucket,path:filename});
        const blob=this._dataUrlToBlob(dataUrl);
        const res=await fetch(signedUrl,{method:'PUT',headers:{'Content-Type':contentType||blob.type||'application/octet-stream'},body:blob});
        if (!res.ok) throw new Error(`Upload Storage échoué : ${res.status}`);
        const {publicUrl}=await apiCall('get_public_url',{bucket,path});
        return publicUrl;
    },

    async uploadAudio(dataUrl,filename) { return this._uploadViaSignedUrl(dataUrl,'audio',filename,'audio/mpeg'); },
    async uploadImage(dataUrl,filename) { const blob=this._dataUrlToBlob(dataUrl); return this._uploadViaSignedUrl(dataUrl,'images',filename,blob.type||'image/jpeg'); },

    getPublicUrl(bucket,path) {
        const base=SUPABASE_CONFIG.EDGE_URL.replace('/functions/v1/api','');
        return `${base}/storage/v1/object/public/${bucket}/${path}`;
    },

    async deleteStorageFile(bucket,url) {
        if (!url||url.startsWith('data:')) return;
        try { const marker=`/storage/v1/object/public/${bucket}/`; const fp=url.split(marker)[1]; if(fp) await apiCall('delete_storage_file',{bucket,filePath:fp}); } catch(e){}
    },

    async reloadComedians() {
        const data=await apiCall('reload_comedians');
        AppState.comedians=buildComedianList(data.comedians,data.absences);
    },

    async reloadUsers() {
        const data=await apiCall('reload_users');
        AppState.users=(data||[]).map(dbToUser);
    },

    async reloadTemplates() {
        const data=await apiCall('reload_templates');
        AppState.emailTemplates={};
        (data||[]).forEach(t=>{AppState.emailTemplates[t.id]={id:t.id,name:t.name,category:t.category,builtin:t.builtin,subject:t.subject,body:t.body,rules:t.rules||''};});
    },

    async reloadSettings() {
        const data=await apiCall('reload_settings');
        applySettings(data);
    },

    async updateAudioField(comedianId,columnName,value) {
        await apiCall('update_audio_field',{comedianId,columnName,value});
    },

    async insertAbsenceDirect(comedianId,absence) {
        const data=await apiCall('insert_absence_direct',{comedianId,absence:{start_date:absence.start,end_date:absence.end,start_time:absence.startTime||null,end_time:absence.endTime||null,comment:absence.comment||null,local_id:absence.id}});
        const comedian=AppState.comedians.find(c=>c.id===comedianId);
        if (comedian) { if(!comedian.absences) comedian.absences=[]; comedian.absences.push({id:data.local_id||data.id,start:data.start_date,end:data.end_date,startTime:data.start_time||'',endTime:data.end_time||'',comment:data.comment||''}); }
        return data;
    },

    async deleteAbsenceDirect(comedianId,absenceLocalId) {
        await apiCall('delete_absence_direct',{comedianId,absenceLocalId});
        const comedian=AppState.comedians.find(c=>c.id===comedianId);
        if (comedian&&comedian.absences) comedian.absences=comedian.absences.filter(a=>a.id!==absenceLocalId);
    },

    async subscribeRealtime(onUpdate) {
        if (!SUPABASE_CONFIG.ANON_KEY || SUPABASE_CONFIG.ANON_KEY === 'VOTRE_CLE_ANON_ICI') {
            console.warn('[Realtime] Clé anon manquante dans config.js — Realtime désactivé.');
            return null;
        }
        return new Promise((resolve) => {
            const script = document.createElement('script');
            script.src = 'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js';
            script.onload = () => {
                const rt = window.supabase.createClient(
                    SUPABASE_CONFIG.SUPABASE_URL,
                    SUPABASE_CONFIG.ANON_KEY,
                    { realtime:{ params:{ eventsPerSecond:10 } }, auth:{ persistSession:false } }
                );
                const channel = rt.channel('catalogue-updates');
                channel
                    .on('broadcast', { event:'data_changed' }, (msg) => {
                        onUpdate(msg.payload?.table || 'all');
                    })
                    .subscribe((status) => {
                        if (status === 'SUBSCRIBED') resolve(channel);
                    });
            };
            script.onerror = () => { console.warn('[Realtime] Chargement SDK échoué.'); resolve(null); };
            document.head.appendChild(script);
        });
    }
};
