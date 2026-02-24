const SUPABASE_CONFIG = {
    EDGE_URL:     'https://rwvmzncnxvxdafonabfh.supabase.co/functions/v1/api',
    SUPABASE_URL: 'https://rwvmzncnxvxdafonabfh.supabase.co',
    ANON_KEY:     'VOTRE_CLE_ANON_ICI'
};

const CONFIG = {
    VERSION: '20260224000000',
    ROLES: { ADMIN:'admin', MANAGER:'manager', STUDIO:'studio', COMEDIAN:'comedian', CLIENT:'client' },
    ROLE_LABELS: { admin:'Administrateur', manager:'Manager', studio:'Équipe Studio', comedian:'Comédien', client:'Client' },
    CLASSEMENT: { INTERNE:'interne', EXTERNE:'externe' },
    LIMITS: { MAX_FILE_SIZE:5*1024*1024, MAX_LOGS:100, MAX_CLIENT_SELECTION:3, PASSWORD_MIN_LENGTH:12 },
    LOG_TYPES: {
        CREATION:'creation', MODIFICATION:'modification', ACTIVATION:'activation',
        DESACTIVATION:'desactivation', SUPPRESSION:'suppression', PASSWORD_RESET:'reinitialisation_mdp',
        EMAIL_SENT:'envoi_email', ABSENCE:'gestion_absence', LOGIN:'connexion', LOGOUT:'deconnexion'
    },
    DEFAULT_EMAIL_TEMPLATES: {
        identifiants: {
            id:'identifiants', name:'Envoi identifiants',
            subject:'Vos identifiants de connexion — {{studio}}',
            body:'Bonjour {{prenom}},\n\nBienvenue ! Voici vos identifiants :\n\nIdentifiant : {{username}}\nMot de passe : {{password}}\n\nLien : {{lien}}\n\nCordialement,\n{{studio}}'
        },
        reset_password: {
            id:'reset_password', name:'Réinitialisation mot de passe',
            subject:'Votre nouveau mot de passe — {{studio}}',
            body:'Bonjour {{prenom}},\n\nVotre mot de passe a été réinitialisé.\n\nNouveau mot de passe : {{password}}\n\nLien : {{lien}}\n\nCordialement,\n{{studio}}'
        }
    }
};

const Utils = {
    formatDate(d) {
        if (!d) return '';
        return new Date(d).toLocaleDateString('fr-FR',{day:'2-digit',month:'2-digit',year:'numeric'});
    },
    formatDateTime(d) { if (!d) return ''; return new Date(d).toLocaleString('fr-FR'); },
    capitalize(s) { if (!s) return ''; return s.charAt(0).toUpperCase()+s.slice(1).toLowerCase(); },
    generateId() { return Date.now()+Math.floor(Math.random()*1000); },
    generateSecurePassword(length=12) {
        const set='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%&*';
        let p='ABCDEFGHIJKLMNOPQRSTUVWXYZ'[Math.floor(Math.random()*26)];
        p+='abcdefghijklmnopqrstuvwxyz'[Math.floor(Math.random()*26)];
        p+='0123456789'[Math.floor(Math.random()*10)];
        p+='!@#$%&*'[Math.floor(Math.random()*7)];
        for(let i=p.length;i<length;i++) p+=set[Math.floor(Math.random()*set.length)];
        return p.split('').sort(()=>Math.random()-.5).join('');
    },
    simulateEmail(to,subject,body) {
        const a=document.createElement('a');
        a.href='mailto:'+encodeURIComponent(to)+'?subject='+encodeURIComponent(subject)+'&body='+encodeURIComponent(body);
        a.style.display='none'; document.body.appendChild(a); a.click();
        setTimeout(()=>document.body.removeChild(a),200);
    },
    replaceEmailVariables(tpl,vars) {
        let r=tpl;
        for(const[k,v] of Object.entries(vars)) r=r.replace(new RegExp(`{{${k}}}`,'g'),v||'');
        return r;
    }
};

function addLog(username,role,action) {
    SupabaseDB.insertLog({timestamp:new Date().toISOString(),username:username||'système',role:role||'',action:action||''}).catch(()=>{});
}
