
const THEME_KEY = 'catalogue_theme'; // 'dark' | 'light' | 'auto'

function isDaytime() {
    const h = new Date().getHours();
    return h >= 7 && h < 21;
}

function applyTheme(mode) {
    const effective = mode === 'auto' ? (isDaytime() ? 'light' : 'dark') : mode;
    document.documentElement.setAttribute('data-theme', effective === 'light' ? 'light' : 'dark');
    updateThemeButton(mode);
}

function updateThemeButton(mode) {
    const icon  = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    const btn   = document.getElementById('themeToggleBtn');
    if (!icon || !label) return;

    const isDark = document.documentElement.getAttribute('data-theme') !== 'light';

    if (mode === 'auto') {
        icon.textContent  = isDark ? '🌙' : '☀️';
        label.textContent = 'Auto';
    } else if (mode === 'light') {
        icon.textContent  = '☀️';
        label.textContent = 'Clair';
    } else {
        icon.textContent  = '🌙';
        label.textContent = 'Sombre';
    }

    if (btn) {
        btn.style.borderColor = isDark ? 'rgba(255,255,255,0.15)' : 'rgba(0,0,0,0.15)';
        btn.style.color       = isDark ? '#7070a0' : '#6060a0';
    }
}

function cycleTheme() {
    const current = localStorage.getItem(THEME_KEY) || 'auto';
    const next = current === 'auto' ? 'dark' : current === 'dark' ? 'light' : 'auto';
    localStorage.setItem(THEME_KEY, next);
    applyTheme(next);

    const labels = { auto: 'Thème automatique (heure)', dark: 'Thème sombre', light: 'Thème clair' };
    if (typeof showToast === 'function') showToast(labels[next]);
}

(function initTheme() {
    const saved = localStorage.getItem(THEME_KEY) || 'auto';
    applyTheme(saved);

    if (saved === 'auto') {
        const msToNextHour = (60 - new Date().getMinutes()) * 60000;
        setTimeout(function checkAuto() {
            if ((localStorage.getItem(THEME_KEY) || 'auto') === 'auto') applyTheme('auto');
            setTimeout(checkAuto, 3600000);
        }, msToNextHour);
    }
})();

function getClientDisplayName(comedian, allComedians) {
    const firstName = comedian.name.split(' ')[0];
    const hasDuplicate = allComedians.filter(c => c.name.split(' ')[0].toLowerCase() === firstName.toLowerCase()).length > 1;
    if (hasDuplicate) {
        const parts = comedian.name.split(' ');
        const initial = parts.length > 1 ? ' ' + parts[parts.length - 1].charAt(0).toUpperCase() + '.' : '';
        return firstName + initial;
    }
    return firstName;
}

function getAudioData(path) {
    if (!path) return null;
    return path; // URL Supabase Storage ou data URL
}

function isAbsenceActive(absence) {
    const now = new Date();
    const endDate = new Date(absence.end);
    if (absence.endTime) {
        const [h, m] = absence.endTime.split(':').map(Number);
        endDate.setHours(h, m, 59, 999);
    } else {
        endDate.setHours(23, 59, 59, 999);
    }
    return endDate >= now;
}

async function checkSharedView() {
    const params = new URLSearchParams(window.location.search);
    const token  = params.get('share');
    if (!token) return false;

    const selection = await SupabaseDB.getSharedSelection(token);
    if (!selection) {
        document.getElementById('loginPage').innerHTML = `
            <div style="display:flex; align-items:center; justify-content:center; min-height:100vh; padding:30px;">
                <div style="text-align:center; background:var(--card-bg); padding:40px; border-radius:15px; max-width:500px;">
                    <div style="font-size:3em;">🔗</div>
                    <h2 style="color:var(--accent); margin:15px 0;">Lien invalide ou expiré</h2>
                    <p style="color:var(--text-muted);">Ce lien de partage n'existe pas ou a été supprimé.</p>
                    <button class="btn" onclick="window.location.href=window.location.pathname" style="margin-top:20px;">
                        ← Retour à l'accueil
                    </button>
                </div>
            </div>`;
        return true;
    }

    const selectionIds = (selection.comedianIds || []).map(id => String(id));
    const selected = AppState.comedians.filter(c => selectionIds.includes(String(c.id)));

    console.log('🔗 Vue partagée:', token, '— IDs sélection:', selectionIds, '— Comédiens trouvés:', selected.length);

    renderSharedView(selected, token);
    return true;
}

function renderSharedView(comedians, token) {
    document.getElementById('loginPage').classList.add('hidden');
    const mainApp = document.getElementById('mainApp');
    mainApp.classList.remove('hidden');

    ['adminNav','adminContent','studioContent','comedianContent','clientContent'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.classList.add('hidden');
    });

    let sharedView = document.getElementById('sharedView');
    if (!sharedView) {
        sharedView = document.createElement('div');
        sharedView.id = 'sharedView';
        mainApp.querySelector('.main-content') 
            ? mainApp.querySelector('.main-content').appendChild(sharedView)
            : mainApp.appendChild(sharedView);
    }
    sharedView.classList.remove('hidden');

    const html = comedians.map(comedian => {
        const displayName = getClientDisplayName(comedian, comedians);

        const tags = [];
        if (comedian.voix_off)    tags.push('Voix off');
        if (comedian.voix_jouee)  tags.push('Voix jouée');
        if (comedian.voix_enfant) tags.push('Voix enfant');
        if (comedian.chant)       tags.push('Chant');
        if (comedian.voix_jeune)  tags.push('Voix jeune');
        if (comedian.voix_adulte) tags.push('Voix adulte');
        if (comedian.voix_mature) tags.push('Voix mature');
        const tagsHTML = tags.map(t => `<span class="tag">${t}</span>`).join('');

        const presData = getAudioData(comedian.audioPresentation);
        const demoData = getAudioData(comedian.audioDemo);

        const audioPres = presData ? `
            <div class="audio-block">
                <span class="audio-label">🎤 Présentation</span>
                <audio controls controlsList="nodownload" oncontextmenu="return false" class="audio-player"><source src="${presData}" type="audio/mpeg"></audio>
            </div>` : '';
        const audioDemo = demoData ? `
            <div class="audio-block">
                <span class="audio-label">🎵 Démo</span>
                <audio controls controlsList="nodownload" oncontextmenu="return false" class="audio-player"><source src="${demoData}" type="audio/mpeg"></audio>
            </div>` : '';
        const sharedDemoPromo  = getAudioData(comedian.audioDemoPromo);
        const sharedDemoJoue   = getAudioData(comedian.audioDemoJoue);
        const sharedDemoInstit = getAudioData(comedian.audioDemoInstit);
        const sharedDemosBlock = (sharedDemoPromo || sharedDemoJoue || sharedDemoInstit) ? `
            <div class="audio-block" style="border-top:1px solid var(--border);padding-top:10px;margin-top:6px;">
                <span class="audio-label" style="display:block;margin-bottom:8px;">🎙️ Démos</span>
                ${sharedDemoPromo  ? `<span style="font-size:0.78em;color:var(--text-muted);display:block;margin:0 0 2px;">📣 Promo</span><audio controls controlsList="nodownload" oncontextmenu="return false" class="audio-player"><source src="${sharedDemoPromo}" type="audio/mpeg"></audio>` : ''}
                ${sharedDemoJoue   ? `<span style="font-size:0.78em;color:var(--text-muted);display:block;margin:8px 0 2px;">🎭 Jouée</span><audio controls controlsList="nodownload" oncontextmenu="return false" class="audio-player"><source src="${sharedDemoJoue}" type="audio/mpeg"></audio>` : ''}
                ${sharedDemoInstit ? `<span style="font-size:0.78em;color:var(--text-muted);display:block;margin:8px 0 2px;">🏛️ Institutionnelle</span><audio controls controlsList="nodownload" oncontextmenu="return false" class="audio-player"><source src="${sharedDemoInstit}" type="audio/mpeg"></audio>` : ''}
            </div>` : '';

        const photo = comedian.profilePic
            ? `<img src="${comedian.profilePic}" alt="${displayName}" style="width:100%; height:180px; object-fit:cover; border-radius:10px 10px 0 0;">`
            : '';

        return `
            <div class="card">
                ${photo}
                <div style="padding:20px;">
                    <h3>${displayName}</h3>
                    <p style="color:var(--text-muted); margin:4px 0 10px;">${comedian.sexe}</p>
                    <div class="card-tags">${tagsHTML}</div>
                    ${comedian.presentation ? `<p style="color:var(--text-muted); font-size:0.9em; margin-top:10px;">${comedian.presentation}</p>` : ''}
                    ${audioPres}
                    ${audioDemo}
                    ${sharedDemosBlock}
                </div>
            </div>`;
    }).join('');

    sharedView.innerHTML = `
        <div style="padding:20px 0;">
            <div style="text-align:center; margin-bottom:30px; padding:25px; background:linear-gradient(135deg,rgba(233,69,96,0.1),rgba(78,204,163,0.1)); border-radius:15px; border-left:4px solid var(--accent);">
                <h2 style="color:var(--accent); margin:0 0 8px;">🎙️ Sélection de comédiens</h2>
                <p style="color:var(--text-muted); margin:0;">${comedians.length} comédien${comedians.length > 1 ? 's' : ''} sélectionné${comedians.length > 1 ? 's' : ''} — Écoutez les audios ci-dessous</p>
            </div>
            <div class="cards-grid">
                ${html}
            </div>
        </div>`;
}

        function initializeApp() {
        }

        
        async function broadcastUpdate(type) {
            if (type === 'comedians') {
                await SupabaseDB.reloadComedians();
            } else if (type === 'users') {
                await SupabaseDB.reloadUsers();
            }
            refreshCurrentView();
        }
        window.broadcastUpdate = broadcastUpdate;
        
        function refreshCurrentView() {
            if (!currentUser) return;
            applyLogoEverywhere();
            const _role = getEffectiveRole();
            if (_role === 'studio' || _role === 'manager') {
                applyFiltersStudio();
                loadAbsences();
            } else if (_role === 'client') {
                applyFiltersClient();
            } else if (_role === 'comedian') {
                loadComedianProfile();
            } else if (_role === 'admin') {
                loadComediansForAdmin();
                loadUsers();
                const adminAbsSection = document.getElementById('adminAbsencesList');
                if (adminAbsSection) loadAdminAbsences();
            }
        }

        function resetFiltersStudio() {
            const s = document.getElementById('searchName');
            if (s) s.value = '';
            const ids = [
                'filterFemme','filterHomme',
                'filterSeances','filterVoixOff','filterVoixJouee','filterVoixEnfant','filterChant',
                'filterVoixJeune','filterVoixAdulte','filterVoixMature','filterVoixAccent',
                'filterTimbreGrave','filterTimbreMedium','filterTimbreAigu','filterTimbreTexture',
                'filterStyleDynamique','filterStylePose','filterStyleNaturel','filterStyleInstitutionnel',
                'filterInterne','filterExterne','filterVoixUrgente','filterDisponibilite'
            ];
            ids.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.checked = false;
            });
            const dispo = document.getElementById('disponibiliteSelector');
            if (dispo) dispo.classList.add('hidden');
            document.getElementById('comediansGrid').innerHTML = '';
            document.getElementById('emptyState').style.display = 'block';
            document.getElementById('emptyState').innerHTML = `
                <div class="icon">🔍</div>
                <h3>Commencez votre recherche</h3>
                <p>Utilisez les filtres ci-dessus pour rechercher des comédiens</p>
            `;
        }

        function resetFiltersClient() {
            const s = document.getElementById('searchNameClient');
            if (s) s.value = '';
            const ids = [
                'filterFemmeClient','filterHommeClient',
                'filterVoixOffClient','filterVoixJoueeClient','filterVoixEnfantClient','filterChantClient',
                'filterVoixJeuneClient','filterVoixAdulteClient','filterVoixMatureClient','filterVoixAccentClient',
                'filterTimbreGraveClient','filterTimbreMediumClient','filterTimbreAiguClient','filterTimbreTextureClient',
                'filterStyleDynamiqueClient','filterStylePoseClient','filterStyleNaturelClient','filterStyleInstitutionnelClient'
            ];
            ids.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.checked = false;
            });
            applyFiltersClient();
        }

        let _generatedPassword = '';
        let _appFilterDebounceTimer = null;

        function generateUserPassword() {
            _generatedPassword = Utils.generateSecurePassword(12);
            const field = document.getElementById('newPassword');
            if (!field) return;
            field.value = _generatedPassword;
            field.type = 'text';
            field.style.background = 'rgba(78,204,163,0.18)';
            field.style.border = '2px solid #4ecca3';
            field.focus();
            const btn = field.parentElement.querySelector('button');
            if (btn) {
                const orig = btn.textContent;
                btn.textContent = '✅ Copié !';
                btn.style.background = '#4ecca3';
                setTimeout(() => { btn.textContent = orig; btn.style.background = ''; }, 2000);
            }
            if (navigator.clipboard) {
                navigator.clipboard.writeText(_generatedPassword).catch(() => {});
            }
        }

        let currentUser = null;

        (function() { var _run = function() {
            initializeApp();

            document.addEventListener('click', function(e) {
                const menu = document.getElementById('userDeleteMenu');
                const dd   = document.getElementById('userDeleteDropdown');
                if (dd && menu && !menu.contains(e.target)) {
                    dd.style.display = 'none';
                }
            });
            applyLogoEverywhere();
            
            const loginForm = document.getElementById('loginForm');
            if (loginForm) {
                loginForm.addEventListener('submit', async function(e) {
                    e.preventDefault();
                    const btn = loginForm.querySelector('button[type="submit"]');
                    btn.disabled = true;
                    btn.textContent = 'Connexion…';
                    const username = document.getElementById('loginUsername').value.trim();
                    const password = document.getElementById('loginPassword').value.trim();
                    
                    try {
                        const user = await SupabaseDB.authenticate(username, password);
                        if (user) {
                            currentUser = user;
                            window._currentUser = user;
                            btn.textContent = 'Chargement…';
                            await SupabaseDB.init(); // charge users, comedians, templates
                            addLog(user.username, user.role, 'Connexion');
                            showApp();
                        } else {
                            document.getElementById('loginError').textContent = 'Identifiant ou mot de passe incorrect';
                            document.getElementById('loginError').style.display = 'block';
                        }
                    } catch(err) {
                        document.getElementById('loginError').textContent = 'Erreur de connexion. Vérifiez votre connexion internet.';
                        document.getElementById('loginError').style.display = 'block';
                    } finally {
                        btn.disabled = false;
                        btn.textContent = 'Se connecter';
                    }
                });
            }
        }; if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', _run); } else { _run(); } })();

        function showApp() {
            if (!currentUser && window._currentUser) currentUser = window._currentUser;
            if (!currentUser) { console.error('showApp() appelé sans utilisateur connecté'); return; }
            document.getElementById('loginPage').classList.add('hidden');
            document.getElementById('mainApp').classList.remove('hidden');
            document.getElementById('userName').textContent = currentUser.username;
            document.getElementById('userRole').textContent = getRoleLabel(currentUser.role);
            
            document.getElementById('adminNav').classList.add('hidden');
            document.getElementById('adminContent').classList.add('hidden');
            document.getElementById('studioContent').classList.add('hidden');
            document.getElementById('comedianContent').classList.add('hidden');
            if (document.getElementById('clientContent')) {
                document.getElementById('clientContent').classList.add('hidden');
            }
            
            const _effRole = getEffectiveRole();
            if (_effRole === 'admin') {
                document.getElementById('adminNav').classList.remove('hidden');
                document.getElementById('adminContent').classList.remove('hidden');
                showAdminSection('users');
            } else if (_effRole === 'studio' || _effRole === 'manager') {
                document.getElementById('studioContent').classList.remove('hidden');
                applyFiltersStudio();
                loadAbsences();
            } else if (_effRole === 'client') {
                document.getElementById('clientContent').classList.remove('hidden');
                loadClientContent();
            } else if (_effRole === 'comedian') {
                document.getElementById('comedianContent').classList.remove('hidden');
                loadComedianProfile();
            }
            
            applyLogoEverywhere();
            updateThemeButton(localStorage.getItem('catalogue_theme') || 'auto');
            setTimeout(() => {
            }, 300);
        }

        function getRoleLabel(role) {
            const labels = {
                'admin': 'Administrateur',
                'studio': 'Équipe Studio',
                'manager': 'Manager',
                'comedian': 'Comédien',
                'client': 'Client'
            };
            return labels[role] || role;
        }

        async function logout() {
            addLog(currentUser.username, currentUser.role, 'Déconnexion');
            await SupabaseDB.signOut();
            currentUser = null;
            window._currentUser = null;
            document.getElementById('mainApp').classList.add('hidden');
            document.getElementById('loginPage').classList.remove('hidden');
            document.getElementById('loginForm').reset();
            document.getElementById('loginError').style.display = 'none';
        }

        function showAdminSection(section) {
            document.querySelectorAll('#adminNav .nav-tab').forEach(tab => {
                const onclick = tab.getAttribute('onclick') || '';
                if (onclick.includes("'" + section + "'") || onclick.includes('"' + section + '"')) {
                    tab.classList.add('active');
                } else {
                    tab.classList.remove('active');
                }
            });
            
            document.getElementById('adminUsersSection').classList.add('hidden');
            document.getElementById('adminComediansSection').classList.add('hidden');
            document.getElementById('adminDatabaseSection').classList.add('hidden');
            document.getElementById('adminAbsencesSection').classList.add('hidden');
            document.getElementById('adminLogsSection').classList.add('hidden');
            const settingsEl = document.getElementById('adminSettingsSection');
            if (settingsEl) settingsEl.classList.add('hidden');
            
            if (section === 'users') {
                document.getElementById('adminUsersSection').classList.remove('hidden');
                loadUsers();
            } else if (section === 'comedians') {
                document.getElementById('adminComediansSection').classList.remove('hidden');
                loadComediansForAdmin();
            } else if (section === 'database') {
                document.getElementById('adminDatabaseSection').classList.remove('hidden');
                loadDatabaseView();
            } else if (section === 'absences') {
                document.getElementById('adminAbsencesSection').classList.remove('hidden');
                loadAdminAbsences();
            } else if (section === 'logs') {
                document.getElementById('adminLogsSection').classList.remove('hidden');
                loadLogs();
            } else if (section === 'settings') {
                if (settingsEl) settingsEl.classList.remove('hidden');
                loadSettingsPanel();
            }
        }

        function loadSettingsPanel() {
            const name = AppState.settings.studioName || '';
            const input = document.getElementById('studioNameInput');
            if (input) input.value = name;
            updateLogoPreview();
            const logoModeSelect = document.getElementById('logoLightModeSelect');
            if (logoModeSelect) logoModeSelect.value = AppState.settings.logoLightMode || 'dark-bg';
            const emailTab = document.getElementById('settings-tab-emails');
            if (emailTab && emailTab.style.display !== 'none') initEmailManager();
        }

        function showSettingsTab(tab) {
            document.getElementById('settings-tab-general').style.display = tab === 'general' ? '' : 'none';
            document.getElementById('settings-tab-emails').style.display  = tab === 'emails'  ? '' : 'none';
            document.querySelectorAll('.settings-tab').forEach(btn => {
                const isActive = btn.id === 'stab-' + tab;
                btn.style.background   = isActive ? 'var(--accent-dim)' : 'transparent';
                btn.style.color        = isActive ? 'var(--accent)'     : 'var(--text-muted)';
                btn.style.borderBottom = isActive ? '2px solid var(--accent)' : '2px solid transparent';
                btn.style.fontWeight   = isActive ? '600' : '500';
            });
            if (tab === 'emails') initEmailManager();
        }

        const EMAIL_VARS = {
            comedien: [
                { key: '{{prenom}}',         label: 'Prénom',           desc: 'Prénom du comédien' },
                { key: '{{nom}}',            label: 'Nom complet',      desc: 'Nom complet du comédien' },
                { key: '{{email}}',          label: 'Email',            desc: 'Email du comédien' },
                { key: '{{odp}}',            label: 'N° ODP',           desc: 'Numéro de commande' },
                { key: '{{client}}',         label: 'Client',           desc: 'Nom du client' },
                { key: '{{date_livraison}}', label: 'Date livraison',   desc: 'Date de livraison souhaitée' },
                { key: '{{heure_livraison}}',label: 'Heure livraison',  desc: 'Heure de livraison' },
                { key: '{{texte}}',          label: 'Texte',            desc: 'Texte à enregistrer' },
                { key: '{{studio}}',         label: 'Studio',           desc: 'Nom du studio' },
                { key: '{{expediteur}}',     label: 'Expéditeur',       desc: 'Utilisateur qui envoie' },
            ],
            client: [
                { key: '{{prenom}}',          label: 'Prénom',          desc: 'Prénom du client' },
                { key: '{{nb_comediens}}',    label: 'Nb comédiens',    desc: 'Nombre de comédiens sélectionnés' },
                { key: '{{liste_comediens}}', label: 'Liste comédiens', desc: 'Liste numérotée des comédiens' },
                { key: '{{lien_selection}}',  label: 'Lien sélection',  desc: 'Lien de partage' },
                { key: '{{message}}',         label: 'Message',         desc: 'Message personnalisé' },
                { key: '{{studio}}',          label: 'Studio',          desc: 'Nom du studio' },
                { key: '{{expediteur}}',      label: 'Expéditeur',      desc: 'Utilisateur' },
            ],
            studio: [
                { key: '{{client}}',          label: 'Client',          desc: 'Nom du client' },
                { key: '{{nb_comediens}}',    label: 'Nb comédiens',    desc: 'Nombre de comédiens' },
                { key: '{{liste_comediens}}', label: 'Liste comédiens', desc: 'Liste des comédiens' },
                { key: '{{expediteur}}',      label: 'Expéditeur',      desc: 'Contact client' },
                { key: '{{message}}',         label: 'Message',         desc: 'Message du client' },
                { key: '{{studio}}',          label: 'Studio',          desc: 'Nom du studio' },
            ],
            systeme: [
                { key: '{{prenom}}',    label: 'Prénom',      desc: "Prénom de l'utilisateur" },
                { key: '{{username}}',  label: 'Identifiant', desc: 'Identifiant de connexion' },
                { key: '{{password}}',  label: 'Mot de passe',desc: 'Mot de passe généré' },
                { key: '{{lien}}',      label: 'Lien',        desc: 'Lien de connexion' },
                { key: '{{studio}}',    label: 'Studio',      desc: 'Nom du studio' },
                { key: '{{role}}',      label: 'Rôle',        desc: 'Rôle attribué' },
            ]
        };

        const DEFAULT_TEMPLATES = {
            commande_urgente: {
                id: 'commande_urgente', name: 'Demande voix urgente', category: 'comedien', builtin: true,
                subject: '🚨 Demande urgente{{odp_subject}} — {{studio}}',
                body: 'Bonjour {{prenom}},\n\nNous avons besoin de toi pour une mission urgente.\n\n' +
                      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' +
                      '{{odp_line}}{{client_line}}' +
                      '⏰ HEURE DE LIVRAISON SOUHAITÉE : {{heure_livraison}}\n' +
                      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' +
                      '📝 TEXTE À ENREGISTRER\n\n{{texte}}\n\n' +
                      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' +
                      'Merci de confirmer ta disponibilité dès que possible.\n\n' +
                      'Cordialement,\n{{expediteur}} — {{studio}}',
                rules: 'Envoi direct au comédien concerné. Ne pas envoyer en dehors des heures ouvrées sauf urgence absolue.'
            },
            commande_odp: {
                id: 'commande_odp', name: 'Commande ODP', category: 'comedien', builtin: true,
                subject: '[ODP {{odp}}] Commande enregistrement — {{client}}',
                body: 'Bonjour,\n\nVous avez une nouvelle commande d\'enregistrement.\n\n' +
                      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' +
                      '📋 NUMÉRO ODP : {{odp}}\n' +
                      '👤 CLIENT : {{client}}\n' +
                      '📅 LIVRAISON SOUHAITÉE : {{date_livraison}} à {{heure_livraison}}\n' +
                      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n' +
                      '📝 TEXTE À ENREGISTRER\n\n{{texte}}\n\n' +
                      '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n' +
                      'Merci de confirmer votre disponibilité par retour de mail.\n\n' +
                      'Cordialement,\n{{expediteur}} — {{studio}}',
                rules: 'Envoyé en BCC à tous les comédiens sélectionnés. Chaque comédien ne voit pas les autres destinataires.'
            },
            envoi_selection_client: {
                id: 'envoi_selection_client', name: 'Envoi sélection au client', category: 'client', builtin: true,
                subject: 'Sélection de {{nb_comediens}} comédien(s)',
                body: 'Bonjour,\n\nVoici une sélection de {{nb_comediens}} comédien(s) pour vous :\n\n' +
                      '{{message}}\n{{liste_comediens}}\n\n' +
                      '▶ Consultez et écoutez les audios via ce lien :\n{{lien_selection}}\n\n' +
                      'Ce lien ne nécessite pas de connexion.\n\n' +
                      'Cordialement,\n{{expediteur}}',
                rules: 'Un lien de partage unique est généré automatiquement. Valable sans connexion.'
            },
            selection_vers_studio: {
                id: 'selection_vers_studio', name: 'Sélection client vers studio', category: 'studio', builtin: true,
                subject: 'Sélection de {{nb_comediens}} comédien(s) — {{expediteur}}',
                body: 'Bonjour {{prenom}},\n\n{{expediteur}} vous envoie une sélection de {{nb_comediens}} comédien(s) :\n\n' +
                      '{{message}}\n{{liste_comediens}}\n\n' +
                      'Cordialement,\n{{expediteur}}',
                rules: 'Envoyé par le client vers un membre de l\'équipe studio.'
            },
            identifiants: {
                id: 'identifiants', name: 'Envoi identifiants', category: 'systeme', builtin: true,
                subject: 'Vos identifiants de connexion — {{studio}}',
                body: 'Bonjour {{prenom}},\n\nBienvenue ! Voici vos identifiants de connexion :\n\n' +
                      'Identifiant : {{username}}\nMot de passe : {{password}}\n\nLien : {{lien}}\n\n' +
                      'Cordialement,\n{{studio}}',
                rules: 'Envoyé automatiquement lors de la création d\'un compte utilisateur.'
            },
            reset_password: {
                id: 'reset_password', name: 'Réinitialisation mot de passe', category: 'systeme', builtin: true,
                subject: 'Votre nouveau mot de passe — {{studio}}',
                body: 'Bonjour {{prenom}},\n\nVotre mot de passe a été réinitialisé.\n\n' +
                      'Nouveau mot de passe : {{password}}\n\nLien : {{lien}}\n\n' +
                      'Cordialement,\n{{studio}}',
                rules: 'Envoyé lors d\'une réinitialisation manuelle par l\'administrateur.'
            }
        };

        let currentEmailCategory = 'comedien';
        let currentTemplateId    = null;
        let emailPreviewOpen     = false;

        function getEmailTemplates() {
            const merged = JSON.parse(JSON.stringify(DEFAULT_TEMPLATES));
            Object.assign(merged, JSON.parse(JSON.stringify(AppState.emailTemplates)));
            return merged;
        }

        async function saveEmailTemplates(tpls) {
            await SupabaseDB.saveEmailTemplates(tpls);
            AppState.emailTemplates = JSON.parse(JSON.stringify(tpls));
        }

        function initEmailManager() {
            showEmailCategory('comedien');
        }

        function showEmailCategory(cat) {
            currentEmailCategory = cat;
            document.querySelectorAll('.email-cat-tab').forEach(btn => {
                const isActive = btn.id === 'ecat-' + cat;
                btn.style.background = isActive ? 'var(--teal-dim)'               : 'transparent';
                btn.style.border     = isActive ? '1px solid rgba(62,207,168,.3)' : '1px solid var(--border)';
                btn.style.color      = isActive ? 'var(--teal)'                   : 'var(--text-muted)';
                btn.style.fontWeight = isActive ? '700'                            : '600';
            });
            renderTemplateList();
            clearEditor();
        }

        function renderTemplateList() {
            const tpls = getEmailTemplates();
            const list = document.getElementById('emailTemplateList');
            if (!list) return;
            const filtered = Object.values(tpls).filter(t => t.category === currentEmailCategory);
            list.innerHTML = '';
            if (filtered.length === 0) {
                list.innerHTML = '<p style="color:var(--text-muted);font-size:.85em;padding:var(--s3);">Aucun template dans cette catégorie.</p>';
                return;
            }
            filtered.forEach(tpl => {
                const isActive = tpl.id === currentTemplateId;
                const item = document.createElement('div');
                item.style.cssText = 'padding:10px var(--s4);border-radius:var(--r2);cursor:pointer;transition:all .2s;' +
                    'border:1px solid ' + (isActive ? 'var(--accent)' : 'var(--border)') + ';' +
                    'background:' + (isActive ? 'var(--accent-dim)' : 'var(--surface)') + ';';
                item.innerHTML =
                    '<div style="display:flex;align-items:center;gap:8px;">' +
                        '<div style="flex:1;min-width:0;">' +
                            '<div style="font-weight:600;font-size:.88em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:' + (isActive ? 'var(--accent)' : 'var(--text)') + ';">' + tpl.name + '</div>' +
                            '<div style="font-size:.72em;color:var(--text-muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">' + tpl.subject + '</div>' +
                        '</div>' +
                        (tpl.builtin
                            ? '<span style="font-size:.65em;background:var(--surface-3);color:var(--text-muted);padding:2px 6px;border-radius:10px;flex-shrink:0;">défaut</span>'
                            : '<span style="font-size:.65em;background:var(--teal-dim);color:var(--teal);padding:2px 6px;border-radius:10px;flex-shrink:0;border:1px solid rgba(62,207,168,.2);">perso</span>') +
                    '</div>';
                item.addEventListener('click', () => openTemplateEditor(tpl.id));
                item.addEventListener('mouseenter', () => { if (tpl.id !== currentTemplateId) { item.style.background = 'var(--surface-2)'; item.style.borderColor = 'var(--border-hover)'; } });
                item.addEventListener('mouseleave', () => { if (tpl.id !== currentTemplateId) { item.style.background = 'var(--surface)'; item.style.borderColor = 'var(--border)'; } });
                list.appendChild(item);
            });
        }

        function openTemplateEditor(tplId) {
            currentTemplateId = tplId;
            const tpls = getEmailTemplates();
            const tpl  = tpls[tplId];
            if (!tpl) return;
            document.getElementById('emailEditorTitle').textContent       = tpl.name;
            document.getElementById('emailEditorDesc').textContent        = tpl.builtin ? 'Template système — réinitialisable' : 'Template personnalisé';
            document.getElementById('emailEditorFields').style.display    = '';
            document.getElementById('emailEditorEmpty').style.display     = 'none';
            document.getElementById('emailEditorSaveBtn').style.display   = '';
            document.getElementById('emailEditorResetBtn').style.display  = tpl.builtin ? '' : 'none';
            document.getElementById('emailEditorDeleteBtn').style.display = tpl.builtin ? 'none' : '';
            document.getElementById('tplName').value     = tpl.name;
            document.getElementById('tplCategory').value = tpl.category;
            document.getElementById('tplSubject').value  = tpl.subject;
            document.getElementById('tplBody').value     = tpl.body;
            document.getElementById('tplRules').value    = tpl.rules || '';
            renderVarsChips(tpl.category);
            updateEmailPreview();
            renderTemplateList();
        }

        function renderVarsChips(cat) {
            const container = document.getElementById('tplVarsAvailable');
            if (!container) return;
            const vars = EMAIL_VARS[cat] || EMAIL_VARS.comedien;
            container.innerHTML = '';
            vars.forEach(v => {
                const chip = document.createElement('button');
                chip.title     = v.desc;
                chip.textContent = v.key;
                chip.style.cssText = 'padding:3px 10px;background:var(--surface-3);border:1px solid var(--border);' +
                    'border-radius:20px;color:var(--teal);font-family:monospace;font-size:.78em;' +
                    'cursor:pointer;transition:all .15s;font-weight:600;';
                chip.addEventListener('click', () => insertVarAtCursor(v.key));
                chip.addEventListener('mouseenter', () => { chip.style.background = 'var(--teal-dim)'; chip.style.borderColor = 'rgba(62,207,168,.3)'; });
                chip.addEventListener('mouseleave', () => { chip.style.background = 'var(--surface-3)'; chip.style.borderColor = 'var(--border)'; });
                container.appendChild(chip);
            });
        }

        function insertVarAtCursor(varKey) {
            const ta = document.getElementById('tplBody');
            if (!ta) return;
            const start = ta.selectionStart, end = ta.selectionEnd;
            ta.value = ta.value.substring(0, start) + varKey + ta.value.substring(end);
            ta.selectionStart = ta.selectionEnd = start + varKey.length;
            ta.focus();
            updateEmailPreview();
        }

        function updateEmailPreview() {
            const subject = document.getElementById('tplSubject')?.value || '';
            const body    = document.getElementById('tplBody')?.value    || '';
            const studio  = AppState.settings.studioName || 'Studio';
            const ex = { prenom:'Jean', nom:'Jean Dupont', email:'jean@exemple.com', username:'jean.dupont',
                password:'Motdepasse123!', lien:'https://monapp.com', studio:studio, mission:'Spot radio 30s',
                odp:'ODP-2024-001', client:'Marque XYZ', date_livraison:'Vendredi 20 décembre',
                heure_livraison:'17h00', texte:'Bonjour et bienvenue chez Marque XYZ...', expediteur:'Marie',
                nb_comediens:'3', liste_comediens:'1. Sophie — Féminin\n2. Marc — Masculin\n3. Claire — Féminin',
                lien_selection:'https://monapp.com?share=abc123', message:'Super sélection !', role:'Client' };
            let ps = subject, pb = body;
            Object.entries(ex).forEach(([k,v]) => {
                const re = new RegExp('{{' + k + '}}', 'g');
                ps = ps.replace(re, v); pb = pb.replace(re, v);
            });
            const subEl = document.getElementById('previewSubject');
            const bdEl  = document.getElementById('previewBody');
            if (subEl) subEl.textContent = ps;
            if (bdEl)  bdEl.textContent  = pb;
        }

        function toggleEmailPreview() {
            emailPreviewOpen = !emailPreviewOpen;
            document.getElementById('emailPreviewContent').style.display = emailPreviewOpen ? '' : 'none';
            document.getElementById('previewToggleBtn').textContent = emailPreviewOpen ? '▲ Masquer' : '▼ Afficher';
        }

        async function saveCurrentTemplate() {
            if (!currentTemplateId) return;
            const tpls = getEmailTemplates();
            const tpl  = tpls[currentTemplateId];
            if (!tpl) return;
            tpl.name     = document.getElementById('tplName').value.trim() || tpl.name;
            tpl.category = document.getElementById('tplCategory').value;
            tpl.subject  = document.getElementById('tplSubject').value.trim();
            tpl.body     = document.getElementById('tplBody').value;
            tpl.rules    = document.getElementById('tplRules').value.trim();
            try {
                await saveEmailTemplates(tpls);
                showToast('✓ Template "' + tpl.name + '" enregistré');
                document.getElementById('emailEditorTitle').textContent = tpl.name;
                currentEmailCategory = tpl.category;
                showEmailCategory(tpl.category);
                currentTemplateId = tpl.id;
                renderTemplateList();
            } catch(err) {
                alert('❌ Erreur lors de l\'enregistrement : ' + (err.message || err));
            }
        }

        async function resetCurrentTemplate() {
            if (!currentTemplateId || !DEFAULT_TEMPLATES[currentTemplateId]) return;
            if (!confirm('Réinitialiser ce template aux valeurs par défaut ?')) return;
            const tpls = getEmailTemplates();
            tpls[currentTemplateId] = JSON.parse(JSON.stringify(DEFAULT_TEMPLATES[currentTemplateId]));
            await saveEmailTemplates(tpls);
            openTemplateEditor(currentTemplateId);
            showToast('↺ Template réinitialisé');
        }

        async function deleteCurrentTemplate() {
            if (!currentTemplateId) return;
            const tpls = getEmailTemplates();
            const tpl  = tpls[currentTemplateId];
            if (!tpl || tpl.builtin) return;
            if (!confirm('Supprimer le template "' + tpl.name + '" ?')) return;
            delete tpls[currentTemplateId];
            saveEmailTemplates(tpls);
            currentTemplateId = null;
            clearEditor();
            renderTemplateList();
            showToast('🗑️ Template supprimé');
        }

        function clearEditor() {
            currentTemplateId = null;
            document.getElementById('emailEditorFields').style.display    = 'none';
            document.getElementById('emailEditorEmpty').style.display     = '';
            document.getElementById('emailEditorSaveBtn').style.display   = 'none';
            document.getElementById('emailEditorResetBtn').style.display  = 'none';
            document.getElementById('emailEditorDeleteBtn').style.display = 'none';
            document.getElementById('emailEditorTitle').textContent = 'Sélectionnez un template';
            document.getElementById('emailEditorDesc').textContent  = 'Cliquez sur un template dans la liste pour l\'éditer';
        }

        function openNewTemplateModal() {
            document.getElementById('newTplName').value     = '';
            document.getElementById('newTplSubject').value  = '';
            document.getElementById('newTplCategory').value = currentEmailCategory;
            openModal('newTemplateModal');
        }

        async function createNewTemplate() {
            const name    = document.getElementById('newTplName').value.trim();
            const subject = document.getElementById('newTplSubject').value.trim();
            const cat     = document.getElementById('newTplCategory').value;
            if (!name || !subject) { alert('Veuillez remplir le nom et l\'objet.'); return; }
            const tpls = getEmailTemplates();
            const id   = 'custom_' + Date.now();
            tpls[id] = { id, name, category: cat, builtin: false,
                subject, body: 'Bonjour {{prenom}},\n\n\n\nCordialement,\n{{expediteur}} — {{studio}}', rules: '' };
            await saveEmailTemplates(tpls);
            closeModal('newTemplateModal');
            currentEmailCategory = cat;
            showEmailCategory(cat);
            currentTemplateId = id;
            openTemplateEditor(id);
            showToast('✓ Template créé');
        }

        function getTemplate(id) {
            const tpls = getEmailTemplates();
            return tpls[id] || DEFAULT_TEMPLATES[id] || null;
        }

        function handleLogoUpload(event) {
            const file = event.target.files[0];
            if (!file) return;
            if (file.size > 2 * 1024 * 1024) {
                alert('Le fichier est trop lourd (max 2 Mo). Utilisez un logo plus léger.');
                return;
            }
            const reader = new FileReader();
            reader.onload = async function(e) {
                try {
                    const ext      = file.name.split('.').pop();
                    const filename = `logo_${Date.now()}.${ext}`;
                    const url      = await SupabaseDB.uploadImage(e.target.result, filename);
                    AppState.settings.studioLogoUrl  = url;
                    AppState.settings.studioLogoName = file.name;
                    await SupabaseDB.saveSettings();
                    updateLogoPreview();
                    applyLogoEverywhere();
                    showToast('✓ Logo enregistré avec succès');
                } catch(err) {
                    alert('❌ Erreur upload logo: ' + (err.message || err));
                }
            };
            reader.readAsDataURL(file);
        }

        async function removeLogo() {
            if (!confirm('Supprimer le logo du studio ?')) return;
            await SupabaseDB.deleteStorageFile('images', AppState.settings.studioLogoUrl);
            AppState.settings.studioLogoUrl  = null;
            AppState.settings.studioLogoName = null;
            await SupabaseDB.saveSettings();
            updateLogoPreview();
            applyLogoEverywhere();
            showToast('Logo supprimé');
        }

        function updateLogoPreview() {
            const logo = AppState.settings.studioLogoUrl;
            const name = AppState.settings.studioLogoName || '';
            const placeholder = document.getElementById('logoPreviewPlaceholder');
            const content = document.getElementById('logoPreviewContent');
            const img = document.getElementById('logoPreviewImg');
            const nameEl = document.getElementById('logoPreviewName');
            if (logo) {
                if (placeholder) placeholder.style.display = 'none';
                if (content) content.style.display = 'flex';
                if (img) img.src = logo;
                if (nameEl) nameEl.textContent = name;
            } else {
                if (placeholder) placeholder.style.display = 'flex';
                if (content) content.style.display = 'none';
            }
            const lightPreview = document.getElementById('logoLightPreview');
            const lightEmpty   = document.getElementById('logoLightPreviewEmpty');
            const logoMode     = AppState.settings.logoLightMode || 'dark-bg';
            if (lightPreview && lightEmpty) {
                if (logo) {
                    lightPreview.src = logo;
                    lightPreview.style.display = 'inline';
                    lightPreview.style.background = logoMode === 'dark-bg' ? '#1a1a2e' : 'transparent';
                    lightPreview.style.padding    = logoMode === 'dark-bg' ? '3px 6px'  : '0';
                    lightPreview.style.borderRadius = '4px';
                    lightEmpty.style.display = 'none';
                } else {
                    lightPreview.style.display = 'none';
                    lightEmpty.style.display = 'inline';
                }
            }
        }

        function applyLogoEverywhere() {
            const logo      = AppState.settings.studioLogoUrl;
            const studioName = AppState.settings.studioName || 'Catalogue Comédiens';
            const logoMode  = AppState.settings.logoLightMode || 'dark-bg';

            document.documentElement.setAttribute('data-logo-bg', logoMode === 'light-bg' ? 'light' : logoMode === 'none' ? 'none' : 'dark');

            const headerContainer = document.getElementById('headerLogoContainer');
            if (headerContainer) {
                if (logo) {
                    headerContainer.innerHTML = '<img class="header-logo-img" src="' + logo + '" alt="Logo studio">';
                } else {
                    headerContainer.innerHTML = '<span style="font-size:1.4em;">🎭</span>';
                }
            }

            const loginContainer = document.getElementById('loginLogoContainer');
            if (loginContainer) {
                if (logo) {
                    loginContainer.innerHTML = '<img class="login-studio-logo" src="' + logo + '" alt="Logo studio">';
                } else {
                    loginContainer.innerHTML = '<span class="login-default-icon" id="loginDefaultIcon">🎭</span>';
                }
            }

            const headerTitle = document.getElementById('headerTitle');
            if (headerTitle) headerTitle.textContent = studioName;

            const loginSubtitle = document.getElementById('loginSubtitle');
            if (loginSubtitle) loginSubtitle.textContent = studioName;
        }
        window.applyLogoEverywhere   = applyLogoEverywhere;
        function applyBannerEverywhere() {
            try {
            const banner   = document.getElementById('globalBanner');
            const textWrap = document.getElementById('globalBannerTextWrap');
            const imgWrap  = document.getElementById('globalBannerImageWrap');
            const bannerT  = document.getElementById('globalBannerText');
            const bannerImg= document.getElementById('globalBannerImg');
            if (!banner) return;

            // Conversion booléenne robuste (Supabase peut renvoyer true/false/'true'/'false'/1/0)
            const rawActive = AppState.settings.bannerActive;
            const active    = rawActive === true || rawActive === 'true' || rawActive === 1;
            const mode      = AppState.settings.bannerMode  || 'text';
            const text      = AppState.settings.bannerText  || '';
            const color     = AppState.settings.bannerColor || '#e74c3c';
            const imageUrl  = AppState.settings.bannerImageUrl || '';
            // Nettoyer les rôles : trim de chaque élément pour éviter ' studio' != 'studio'
            const roles = (AppState.settings.bannerRoles || 'admin,studio,manager,comedian,client')
                            .split(',').map(r => r.trim()).filter(Boolean);

            // Résoudre currentUser : variable locale OU window._currentUser
            const _user    = (typeof currentUser !== 'undefined' ? currentUser : null)
                             || window._currentUser || null;
            const userRole = _user ? _user.role : null;
            const roleAllowed = !!(userRole && roles.includes(userRole));

            console.log('[Banner] active=' + active + ' role=' + userRole + ' allowed=' + roleAllowed + ' mode=' + mode + ' text="' + text.slice(0,20) + '"');

            if (!active || !roleAllowed) {
                banner.style.display = 'none';
                return;
            }

            if (mode === 'image' && imageUrl) {
                if (textWrap) textWrap.style.display = 'none';
                if (imgWrap)  imgWrap.style.display  = 'block';
                if (bannerImg) bannerImg.src = imageUrl;
                banner.style.backgroundColor = 'transparent';
                banner.style.display = 'block';
            } else if (mode === 'text' && text.trim()) {
                if (imgWrap)  imgWrap.style.display  = 'none';
                if (textWrap) textWrap.style.display = 'block';
                if (bannerT)  bannerT.textContent    = text;
                banner.style.backgroundColor = color;
                const r = parseInt(color.slice(1,3),16) || 0;
                const g = parseInt(color.slice(3,5),16) || 0;
                const b = parseInt(color.slice(5,7),16) || 0;
                const lum = (0.299*r + 0.587*g + 0.114*b) / 255;
                banner.style.color = lum > 0.55 ? '#1a1a2e' : '#ffffff';
                banner.style.display = 'block';
            } else {
                // Bannière active mais pas de contenu valide
                banner.style.display = 'none';
                console.warn('[Banner] active=true mais pas de contenu (text vide ou mode invalide)');
            }
            } catch(err) { console.error('[Banner] applyBannerEverywhere erreur:', err); }
        }

        window.applyBannerEverywhere = applyBannerEverywhere;
        window.showApp               = showApp;
        window.refreshCurrentView    = refreshCurrentView;
        window.checkSharedView       = checkSharedView;
        window.DEFAULT_TEMPLATES     = DEFAULT_TEMPLATES;

        function previewStudioName() {
            const val = document.getElementById('studioNameInput').value;
            const headerTitle = document.getElementById('headerTitle');
            if (headerTitle) headerTitle.textContent = val || 'Catalogue Comédiens';
        }

        async function saveLogoLightMode(val) {
            AppState.settings.logoLightMode = val;
            await SupabaseDB.saveSettings();
            applyLogoEverywhere();
            showToast('Réglage logo enregistré');
        }

        async function saveStudioName() {
            try {
                const val = document.getElementById('studioNameInput').value.trim();
                AppState.settings.studioName = val || 'Catalogue Comédiens';
                await SupabaseDB.saveSettings();
                applyLogoEverywhere();
                showToast('Nom enregistré');
            } catch(err) {
                console.error('saveStudioName:', err);
                showToast('Erreur lors de la sauvegarde');
            }
        }

        function showToast(msg) {
            const existing = document.querySelector('.toast');
            if (existing) existing.remove();
            const t = document.createElement('div');
            t.className = 'toast';
            t.textContent = msg;
            document.body.appendChild(t);
            setTimeout(() => t.remove(), 3000);
        }

        async function normalizeAudio(dataUrl, targetLUFS = -14) {
            return new Promise((resolve, reject) => {
                const audio = new Audio(dataUrl);
                audio.addEventListener('canplaythrough', async () => {
                    try {
                        const response   = await fetch(dataUrl);
                        const arrayBuf   = await response.arrayBuffer();
                        const offCtx     = new OfflineAudioContext(1, 44100 * 60, 44100);
                        const srcBuf     = await offCtx.decodeAudioData(arrayBuf);
                        const analyser   = offCtx.createAnalyser();
                        const srcNode    = offCtx.createBufferSource();
                        srcNode.buffer   = srcBuf;
                        srcNode.connect(analyser);
                        analyser.connect(offCtx.destination);
                        srcNode.start();
                        const rendered   = await offCtx.startRendering();
                        const channelData= rendered.getChannelData(0);
                        let rms = 0;
                        for (let i = 0; i < channelData.length; i++) rms += channelData[i] * channelData[i];
                        rms = Math.sqrt(rms / channelData.length);
                        const currentLUFS = 20 * Math.log10(rms);
                        const gainDb      = targetLUFS - currentLUFS;
                        const gainLinear  = Math.pow(10, gainDb / 20);
                        const renderCtx   = new OfflineAudioContext(srcBuf.numberOfChannels, srcBuf.length, srcBuf.sampleRate);
                        const src2        = renderCtx.createBufferSource();
                        src2.buffer       = srcBuf;
                        const gainNode    = renderCtx.createGain();
                        gainNode.gain.value = gainLinear;
                        src2.connect(gainNode);
                        gainNode.connect(renderCtx.destination);
                        src2.start();
                        const normalizedBuf = await renderCtx.startRendering();
                        const wavBlob       = audioBufferToWav(normalizedBuf);
                        const reader        = new FileReader();
                        reader.onload       = e => resolve(e.target.result);
                        reader.readAsDataURL(wavBlob);
                    } catch(err) { reject(err); }
                }, { once: true });
                audio.load();
            });
        }

        function audioBufferToWav(buffer) {
            const numChannels = buffer.numberOfChannels;
            const sampleRate  = buffer.sampleRate;
            const length      = buffer.length * numChannels * 2 + 44;
            const ab          = new ArrayBuffer(length);
            const view        = new DataView(ab);
            const writeStr    = (v, o, s) => { for(let i=0;i<s.length;i++) v.setUint8(o+i,s.charCodeAt(i)); };
            writeStr(view, 0, 'RIFF');
            view.setUint32(4, length - 8, true);
            writeStr(view, 8, 'WAVE');
            writeStr(view, 12, 'fmt ');
            view.setUint32(16, 16, true);
            view.setUint16(20, 1, true);
            view.setUint16(22, numChannels, true);
            view.setUint32(24, sampleRate, true);
            view.setUint32(28, sampleRate * numChannels * 2, true);
            view.setUint16(32, numChannels * 2, true);
            view.setUint16(34, 16, true);
            writeStr(view, 36, 'data');
            view.setUint32(40, buffer.length * numChannels * 2, true);
            let offset = 44;
            for (let i = 0; i < buffer.length; i++) {
                for (let c = 0; c < numChannels; c++) {
                    const sample = Math.max(-1, Math.min(1, buffer.getChannelData(c)[i]));
                    view.setInt16(offset, sample < 0 ? sample * 0x8000 : sample * 0x7FFF, true);
                    offset += 2;
                }
            }
            return new Blob([ab], { type: 'audio/wav' });
        }

        let _previewRole = null;

        function getEffectiveRole() {
            const user = window._currentUser;
            if (!user) return null;
            return _previewRole || user.role;
        }

        function setPreviewRole(role) {
            _previewRole = role;

            // Barre orange d'aperçu
            const bar   = document.getElementById('adminPreviewBar');
            const label = document.getElementById('adminPreviewLabel');
            if (bar)   bar.style.display = role ? 'flex' : 'none';
            if (label && role) label.textContent = CONFIG.ROLE_LABELS[role] || role;

            // Masquer toutes les sections
            ['adminNav','adminContent','studioContent','comedianContent','clientContent'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.classList.add('hidden');
            });

            if (!role) {
                document.getElementById('adminNav').classList.remove('hidden');
                document.getElementById('adminContent').classList.remove('hidden');
                showAdminSection('users');
            } else if (role === 'studio' || role === 'manager') {
                const sc = document.getElementById('studioContent');
                if (sc) sc.classList.remove('hidden');
                try { applyFiltersStudio(); } catch(e) { console.error('[preview studio] applyFiltersStudio:', e); }
                try { loadAbsences(); }         catch(e) { console.error('[preview studio] loadAbsences:', e); }
            } else if (role === 'client') {
                const cc = document.getElementById('clientContent');
                if (cc) cc.classList.remove('hidden');
                try { loadClientContent(); } catch(e) { console.error('[preview client] loadClientContent:', e); }
            } else if (role === 'comedian') {
                const co = document.getElementById('comedianContent');
                if (co) co.classList.remove('hidden');
                try { loadComedianProfile(); } catch(e) { console.error('[preview comedian] loadComedianProfile:', e); }
            }

            try { applyLogoEverywhere(); }   catch(e) {}
            try { applyBannerEverywhere(); } catch(e) {}
        }

        function exitPreviewRole() {
            setPreviewRole(null);
        }

        window.setPreviewRole  = setPreviewRole;
        window.exitPreviewRole = exitPreviewRole;
        window.getEffectiveRole= getEffectiveRole;

        function loadUsers() {
            loadUsersByRole();
        }

        // ── État courant des filtres utilisateurs ──────────────
        let _userFilterRole = 'all';
        let _userFilterText = '';

        function loadUsersByRole() {
            filterUsers(); // déléguer à filterUsers qui gère tout
        }

        function selectUserRolePill(btn, role) {
            document.querySelectorAll('.user-role-pill').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            _userFilterRole = role;
            filterUsers();
        }

        function clearUserSearch() {
            const inp = document.getElementById('userSearchInput');
            if (inp) inp.value = '';
            _userFilterText = '';
            filterUsers();
        }

        function resetUserFilters() {
            _userFilterRole = 'all';
            _userFilterText = '';
            const inp = document.getElementById('userSearchInput');
            if (inp) inp.value = '';
            document.querySelectorAll('.user-role-pill').forEach(p => {
                p.classList.toggle('active', p.dataset.role === 'all');
            });
            filterUsers();
        }

        function _highlightTerm(text, term) {
            if (!term) return escapeHtml(text);
            const escaped = escapeHtml(text);
            const escapedTerm = escapeHtml(term).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            return escaped.replace(new RegExp(`(${escapedTerm})`, 'gi'),
                '<span class="user-search-highlight">$1</span>');
        }

        function escapeHtml(str) {
            return String(str || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
        }

        function filterUsers(debounced) {
            if (debounced) {
                clearTimeout(_appFilterDebounceTimer);
                _appFilterDebounceTimer = setTimeout(function() { filterUsers(false); }, 150);
                return;
            }
            const rawText = (document.getElementById('userSearchInput') || {}).value || '';
            _userFilterText = rawText.trim().toLowerCase();

            const clearBtn = document.getElementById('userSearchClear');
            if (clearBtn) clearBtn.style.display = _userFilterText ? 'inline-block' : 'none';

            const resetBtn = document.getElementById('userFilterReset');
            if (resetBtn) resetBtn.style.display = (_userFilterRole !== 'all' || _userFilterText) ? 'inline-block' : 'none';

            let users = AppState.users.slice();

            if (_userFilterRole !== 'all') {
                users = users.filter(u => u.role === _userFilterRole);
            }

            if (_userFilterText) {
                users = users.filter(u =>
                    (u.username || '').toLowerCase().includes(_userFilterText) ||
                    (u.email    || '').toLowerCase().includes(_userFilterText)
                );
            }

            const countEl = document.getElementById('userSearchCount');
            const total = AppState.users.length;
            if (countEl) {
                const filtered = users.length;
                if (filtered === total && !_userFilterText && _userFilterRole === 'all') {
                    countEl.textContent = `${total} utilisateur${total > 1 ? 's' : ''}`;
                } else {
                    countEl.innerHTML = `<strong style="color:var(--accent)">${filtered}</strong> / ${total}`;
                }
            }

            const emptyEl = document.getElementById('userSearchEmpty');
            const container = document.getElementById('usersListByRole');
            if (!container) return;

            if (users.length === 0) {
                container.innerHTML = '';
                if (emptyEl) emptyEl.style.display = 'block';
                return;
            }
            if (emptyEl) emptyEl.style.display = 'none';

            const roleGroups = {
                admin:   { label: 'Administrateurs',  icon: '🛡️', color: 'var(--accent)',  users: [] },
                manager: { label: 'Managers',          icon: '📋', color: '#8e44ad',         users: [] },
                studio:  { label: 'Équipe Studio',     icon: '🎙️', color: 'var(--teal)',     users: [] },
                client:  { label: 'Clients',           icon: '👤', color: '#2980b9',         users: [] },
                comedian:{ label: 'Comédiens',         icon: '🎭', color: '#e67e22',         users: [] }
            };

            users.forEach(u => { if (roleGroups[u.role]) roleGroups[u.role].users.push(u); });

            container.innerHTML = '';

            Object.keys(roleGroups).forEach(roleKey => {
                const group = roleGroups[roleKey];
                if (group.users.length === 0) return;

                const section = document.createElement('div');
                section.className = 'role-section';
                section.style.borderLeftColor = group.color;

                section.innerHTML = `
                    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:var(--s4);">
                        <h3 style="margin:0;display:flex;align-items:center;gap:8px;color:var(--text);">
                            <span style="font-size:1.1em;">${group.icon}</span>
                            ${group.label}
                            <span style="background:${group.color};color:#fff;font-size:0.72em;font-weight:700;padding:2px 8px;border-radius:10px;min-width:20px;text-align:center;">
                                ${group.users.length}
                            </span>
                        </h3>
                    </div>`;

                const tableWrap = document.createElement('div');
                tableWrap.className = 'table-container';
                tableWrap.style.borderRadius = 'var(--r2)';

                const table = document.createElement('table');
                table.style.width = '100%';
                table.innerHTML = `
                    <thead>
                        <tr>
                            <th>Identifiant</th>
                            <th>Email</th>
                            <th style="text-align:center;">Statut</th>
                            <th style="text-align:right;">Actions</th>
                        </tr>
                    </thead>
                    <tbody></tbody>`;

                const tbody = table.querySelector('tbody');
                group.users.forEach((user, idx) => {
                    const tr = document.createElement('tr');
                    tr.style.animationDelay = `${idx * 30}ms`;
                    tr.className = 'user-row';

                    const usernameHl = _highlightTerm(user.username || '', _userFilterText);
                    const emailHl    = _highlightTerm(user.email    || 'N/A', _userFilterText);

                    tr.innerHTML = `
                        <td style="font-weight:600;">${usernameHl}</td>
                        <td style="color:var(--text-muted);font-size:0.88em;">${emailHl}</td>
                        <td style="text-align:center;">
                            <span class="tag ${user.active ? 'status-active' : 'status-inactive'}"
                                  style="border-color:${user.active ? 'rgba(30,158,120,0.3)' : 'var(--border)'};">
                                ${user.active ? '● Actif' : '○ Inactif'}
                            </span>
                        </td>
                        <td style="text-align:right;white-space:nowrap;">
                            <button class="btn-icon btn-small" onclick="openEditUser(${user.id})" title="Modifier">✏️ Modifier</button>
                            <button class="btn-icon btn-small" onclick="toggleUserStatus(${user.id})" title="${user.active ? 'Désactiver' : 'Activer'}">${user.active ? '⏸ Désactiver' : '▶ Activer'}</button>
                            <button class="btn-icon btn-small" onclick="sendUserCredentials(${user.id})" title="Envoyer identifiants" style="background:#1a6b5a;">📧 Identifiants</button>
                            <button class="btn-icon btn-small" onclick="deleteUser(${user.id})" title="Supprimer" style="background:#c0392b;">🗑️ Supprimer</button>
                        </td>`;
                    tbody.appendChild(tr);
                });

                tableWrap.appendChild(table);
                section.appendChild(tableWrap);
                container.appendChild(section);
            });
        }

        // ── Export utilisateurs CSV ────────────────────────────
        function exportUsersCSV() {
            const users = AppState.users.slice();
            if (users.length === 0) { alert('Aucun utilisateur a exporter.'); return; }
            const headers = ['username', 'email', 'role', 'comedianId', 'active'];
            const rows = users.map(u => [
                u.username || '',
                u.email || '',
                u.role || '',
                u.comedianId || '',
                u.active ? 'oui' : 'non'
            ]);
            const csv = [headers, ...rows].map(r => r.map(v => '"' + String(v).replace(/"/g, '""') + '"').join(',')).join('\n');
            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'utilisateurs_' + new Date().toISOString().split('T')[0] + '.csv';
            a.click();
            URL.revokeObjectURL(url);
        }

        // ── Import utilisateurs CSV ────────────────────────────
        async function importUsersCSV(input) {
            const file = input.files[0];
            if (!file) return;
            input.value = '';
            const text = await file.text();
            const lines = text.trim().split('\n').filter(l => l.trim());
            if (lines.length < 2) { alert('Fichier CSV vide ou invalide.'); return; }

            const parseRow = row => {
                const vals = [];
                let cur = '', inQ = false;
                for (let i = 0; i < row.length; i++) {
                    const c = row[i];
                    if (c === '"' && row[i+1] === '"') { cur += '"'; i++; }
                    else if (c === '"') inQ = !inQ;
                    else if (c === ',' && !inQ) { vals.push(cur.trim()); cur = ''; }
                    else cur += c;
                }
                vals.push(cur.trim());
                return vals;
            };

            const header = parseRow(lines[0]).map(h => h.toLowerCase().replace(/"/g, ''));
            const idxUsername = header.indexOf('username');
            const idxEmail    = header.indexOf('email');
            const idxRole     = header.indexOf('role');
            const idxActive   = header.indexOf('active');

            if (idxUsername === -1 || idxRole === -1) {
                alert('Colonnes requises manquantes: username, role');
                return;
            }

            let imported = 0, skipped = 0;
            const existingUsernames = AppState.users.map(u => u.username.toLowerCase());

            for (let i = 1; i < lines.length; i++) {
                const vals = parseRow(lines[i]);
                const username = vals[idxUsername] || '';
                if (!username || existingUsernames.includes(username.toLowerCase())) { skipped++; continue; }
                const role = vals[idxRole] || 'studio';
                const validRoles = ['admin', 'studio', 'manager', 'client', 'comedian'];
                if (!validRoles.includes(role)) { skipped++; continue; }
                const plainPwd = Utils.generateSecurePassword(10);
                const hashed = await hashPassword(plainPwd);
                const newUser = {
                    username,
                    email: idxEmail >= 0 ? vals[idxEmail] : '',
                    password: hashed,
                    role,
                    comedianId: null,
                    active: idxActive < 0 || !vals[idxActive] || vals[idxActive].toLowerCase() !== 'non',
                    createdAt: new Date().toISOString()
                };
                await SupabaseDB.upsertUser(newUser);
                existingUsernames.push(username.toLowerCase());
                imported++;
            }
            await broadcastUpdate('users');
            alert('Import termine : ' + imported + ' utilisateur(s) crees, ' + skipped + ' ignore(s).\n\nLes mots de passe ont ete generes automatiquement. Utilisez "Envoyer identifiants" pour les notifier.');
        }

        async function deleteUsersByRole(role) {
            const roleLabels = {
                'admin': 'Administrateurs',
                'manager': 'Managers', 
                'studio': 'Studio',
                'client': 'Clients',
                'comedian': 'Comédiens'
            };
            
            const users = AppState.users.slice();
            const usersToDelete = users.filter(u => u.role === role);
            
            if (usersToDelete.length === 0) {
                alert(`Aucun utilisateur ${roleLabels[role]} à supprimer.`);
                return;
            }
            
            const confirmation = confirm(`⚠️ ATTENTION !\n\nSupprimer TOUS les utilisateurs ${roleLabels[role]} ?\n\n${usersToDelete.length} utilisateur(s) seront supprimés.\n\nCette action est IRRÉVERSIBLE !`);
            
            if (!confirmation) return;
            
            const secondConfirm = prompt(`Pour confirmer, tapez le nombre d'utilisateurs à supprimer (${usersToDelete.length}) :`);
            
            if (secondConfirm !== usersToDelete.length.toString()) {
                alert('Suppression annulée : nombre incorrect.');
                return;
            }
            
            const idsToDelete = AppState.users.filter(u => u.role === role).map(u => u.id);
            for (const uid of idsToDelete) { await SupabaseDB.deleteUser(uid); }
            await broadcastUpdate('users');
            
            addLog(CONFIG.LOG_TYPES.SUPPRESSION, `Suppression en masse: ${usersToDelete.length} utilisateurs ${roleLabels[role]}`, 'user', null);
            
            alert(`✅ ${usersToDelete.length} utilisateur(s) ${roleLabels[role]} supprimé(s) avec succès.`);
            
            loadUsers();
        }

        async function toggleUserStatus(userId) {
            const user = AppState.users.find(u => u.id === userId);
            if (user) {
                user.active = !user.active;
                await SupabaseDB.upsertUser(user);
                await broadcastUpdate('users');
                loadUsers();
            }
        }

        async function deleteUser(userId) {
            if (userId === 1) {
                alert('Impossible de supprimer le compte admin principal !');
                return;
            }
            if (confirm('Êtes-vous sûr de vouloir supprimer cet utilisateur ?')) {
                await SupabaseDB.deleteUser(userId);
                await broadcastUpdate('users');
                loadUsers();
            }
        }

        
        let _editingUserId = null;
        let generatedPasswordForUser = null;

        function openEditUser(userId) {
            const users = AppState.users.slice();
            const user = users.find(u => String(u.id) === String(userId));
            if (!user) return;

            _editingUserId = String(user.id); // Stocker en string
            generatedPasswordForUser = null;

            document.getElementById('editUsername').value   = user.username;
            document.getElementById('editUserEmail').value  = user.email || '';
            document.getElementById('editUserRole').value   = user.role;

            const pwdField = document.getElementById('editUserPassword');
            pwdField.value           = '';
            pwdField.style.background = '';
            pwdField.style.border    = '';

            document.getElementById('newPasswordDisplay').style.display = 'none';
            document.getElementById('newPasswordValue').textContent     = '';

            openModal('editUserModal');
        }

        function generateNewPasswordForUser() {
            const pwd = Utils.generateSecurePassword(12);
            generatedPasswordForUser = pwd;

            const field = document.getElementById('editUserPassword');
            field.value            = pwd;
            field.type             = 'text';
            field.style.background = 'rgba(78,204,163,0.18)';
            field.style.border     = '2px solid #4ecca3';
            field.style.fontFamily = 'monospace';
            field.style.letterSpacing = '1px';

            document.getElementById('newPasswordValue').textContent     = pwd;
            document.getElementById('newPasswordDisplay').style.display = 'block';

            const btn = document.querySelector('[onclick="generateNewPasswordForUser()"]');
            if (btn) {
                const orig = btn.innerHTML;
                btn.innerHTML = '✅ Généré !';
                btn.style.background = '#4ecca3';
                setTimeout(() => { btn.innerHTML = orig; btn.style.background = ''; }, 2500);
            }

            try {
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(pwd).catch(() => {});
                } else {
                    const ta = document.createElement('textarea');
                    ta.value = pwd;
                    ta.style.position = 'fixed';
                    ta.style.opacity  = '0';
                    document.body.appendChild(ta);
                    ta.focus();
                    ta.select();
                    document.execCommand('copy');
                    document.body.removeChild(ta);
                }
            } catch(e) {}
        }

        async function saveEditUser() {
            if (!_editingUserId) return;

            const user = AppState.users.find(u => String(u.id) === _editingUserId);
            if (!user) {
                alert('❌ Erreur : utilisateur introuvable. Rechargez la page.');
                return;
            }

            user.username = document.getElementById('editUsername').value.trim();
            user.email    = document.getElementById('editUserEmail').value.trim();
            user.role     = document.getElementById('editUserRole').value;

            const fieldPwd = document.getElementById('editUserPassword').value.trim();
            const pwdToSave = fieldPwd || generatedPasswordForUser;
            if (pwdToSave) {
                user._plainPassword = pwdToSave;
                user.password = await hashPassword(pwdToSave);
            }

            try {
                await SupabaseDB.upsertUser(user);
                await broadcastUpdate('users');
                closeModal('editUserModal');
                _editingUserId = null;
                generatedPasswordForUser = null;
                loadUsers();
                const msg = pwdToSave
                    ? '✅ Utilisateur modifié.\n🔑 Nouveau mot de passe enregistré.'
                    : '✅ Utilisateur modifié.';
                alert(msg);
            } catch(err) {
                alert('❌ Erreur: ' + (err.message || err));
            }
        }

        function copyNewPassword() {
            const pwd = generatedPasswordForUser
                || document.getElementById('newPasswordValue').textContent;
            if (!pwd) return;

            try {
                if (navigator.clipboard && window.isSecureContext) {
                    navigator.clipboard.writeText(pwd).then(() => {
                        alert('✅ Mot de passe copié !');
                    }).catch(() => {
                        prompt('Copiez ce mot de passe :', pwd);
                    });
                } else {
                    prompt('Copiez ce mot de passe :', pwd);
                }
            } catch(e) {
                prompt('Copiez ce mot de passe :', pwd);
            }
        }

        function openChangePassword(userId) {
            const users = AppState.users.slice();
            const user = users.find(u => u.id === userId);
            
            if (!user) return;
            
            document.getElementById('changePasswordUserId').value = user.id;
            document.getElementById('changePasswordUsername').value = user.username;
            document.getElementById('newPasswordInput').value = '';
            document.getElementById('confirmPasswordInput').value = '';
            openModal('changePasswordModal');
        }

        document.getElementById('changePasswordForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const newPassword     = document.getElementById('newPasswordInput').value;
            const confirmPassword = document.getElementById('confirmPasswordInput').value;
            
            if (newPassword !== confirmPassword) {
                alert('Les mots de passe ne correspondent pas !');
                return;
            }
            if (newPassword.length < 4) {
                alert('Le mot de passe doit contenir au moins 4 caractères !');
                return;
            }
            
            const userId = parseInt(document.getElementById('changePasswordUserId').value);
            const user   = AppState.users.find(u => u.id === userId);
            if (!user) return;

            try {
                if (currentUser && userId === currentUser.id) {
                    const db = getSupabase();
                    const { error } = await db.auth.updateUser({ password: newPassword });
                    if (error) throw error;
                    user.password = await hashPassword(newPassword);
                    await SupabaseDB.upsertUser(user);
                } else {
                    await SupabaseDB.sendPasswordResetEmail(user.email);
                    user.password = await hashPassword(newPassword);
                    await SupabaseDB.upsertUser(user);
                    alert(`✅ Un email de réinitialisation a été envoyé à ${user.email}\n\nL'utilisateur devra cliquer sur le lien pour activer son nouveau mot de passe.`);
                }
                await broadcastUpdate('users');
                closeModal('changePasswordModal');
                if (!user.email || userId === currentUser.id) alert('Mot de passe modifié avec succès !');
            } catch(err) {
                alert('❌ Erreur : ' + (err.message || err));
            }
        });

        function openAdminQuickAbsence(comedianId) {
            const comedian = AppState.comedians.find(c => c.id === comedianId);
            if (!comedian) return;
            document.getElementById('adminAbsenceComedianId').value = comedian.id;
            document.getElementById('adminAbsenceComedianName').value = comedian.name;
            document.getElementById('adminAbsenceComedianName').disabled = true;
            document.getElementById('adminAbsenceComedianName').style.opacity = '0.6';
            document.getElementById('absenceComedianDropdown').style.display = 'none';
            document.getElementById('adminQuickAbsenceStart').value = '';
            document.getElementById('adminQuickAbsenceEnd').value = '';
            document.getElementById('adminQuickAbsenceStartTime').value = '09:00';
            document.getElementById('adminQuickAbsenceEndTime').value = '18:00';
            document.getElementById('adminQuickAbsenceComment').value = '';
            openModal('adminQuickAbsenceModal');
        }

        function openAdminAddAbsenceModal() {
            document.getElementById('adminAbsenceComedianId').value = '';
            document.getElementById('adminAbsenceComedianName').value = '';
            document.getElementById('adminAbsenceComedianName').disabled = false;
            document.getElementById('adminAbsenceComedianName').style.opacity = '1';
            document.getElementById('absenceComedianDropdown').style.display = 'none';
            document.getElementById('adminQuickAbsenceStart').value = '';
            document.getElementById('adminQuickAbsenceEnd').value = '';
            document.getElementById('adminQuickAbsenceStartTime').value = '09:00';
            document.getElementById('adminQuickAbsenceEndTime').value = '18:00';
            document.getElementById('adminQuickAbsenceComment').value = '';
            openModal('adminQuickAbsenceModal');
            setTimeout(() => document.getElementById('adminAbsenceComedianName').focus(), 200);
        }

        function filterAbsenceComedianSearch(query) {
            const dropdown = document.getElementById('absenceComedianDropdown');
            const input = document.getElementById('adminAbsenceComedianName');
            if (input.disabled) { dropdown.style.display = 'none'; return; }

            const q = query.trim().toLowerCase();
            const comedians = AppState.comedians.filter(c => c.active);
            const matches = q.length === 0
                ? comedians.slice(0, 8)
                : comedians.filter(c => c.name.toLowerCase().includes(q)).slice(0, 8);

            if (matches.length === 0) {
                dropdown.style.display = 'none';
                return;
            }

            dropdown.innerHTML = matches.map(c => `
                <div onclick="selectAbsenceComedian(${c.id}, '${c.name.replace(/'/g, "\'")}')"
                     style="padding: 10px 14px; cursor: pointer; border-bottom: 1px solid var(--border);
                            transition: background 0.15s;"
                     onmouseover="this.style.background='rgba(78,204,163,0.12)'"
                     onmouseout="this.style.background='transparent'">
                    <strong>${c.name}</strong>
                    <small style="color: var(--text-muted); margin-left: 8px;">${c.sexe || ''}</small>
                </div>
            `).join('');
            dropdown.style.display = 'block';
        }

        function selectAbsenceComedian(id, name) {
            document.getElementById('adminAbsenceComedianId').value = id;
            document.getElementById('adminAbsenceComedianName').value = name;
            document.getElementById('absenceComedianDropdown').style.display = 'none';
        }

        document.addEventListener('click', function(e) {
            const dropdown = document.getElementById('absenceComedianDropdown');
            const input = document.getElementById('adminAbsenceComedianName');
            if (dropdown && !dropdown.contains(e.target) && e.target !== input) {
                dropdown.style.display = 'none';
            }
        });

        document.getElementById('adminQuickAbsenceForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const comedianId = parseInt(document.getElementById('adminAbsenceComedianId').value);
            if (!comedianId) {
                document.getElementById('adminAbsenceComedianName').style.border = '1px solid #c0392b';
                document.getElementById('adminAbsenceComedianName').placeholder = 'Veuillez sélectionner un comédien';
                document.getElementById('adminAbsenceComedianName').focus();
                return;
            }
            document.getElementById('adminAbsenceComedianName').style.border = '';
            const start = document.getElementById('adminQuickAbsenceStart').value;
            const startTime = document.getElementById('adminQuickAbsenceStartTime').value;
            const end = document.getElementById('adminQuickAbsenceEnd').value;
            const endTime = document.getElementById('adminQuickAbsenceEndTime').value;
            const comment = document.getElementById('adminQuickAbsenceComment').value;
            if (!start || !end) { alert('Veuillez sélectionner les dates'); return; }
            try {
                await SupabaseDB.insertAbsenceDirect(comedianId, { id: Date.now(), start, startTime, end, endTime, comment });
                refreshCurrentView();
                closeModal('adminQuickAbsenceModal');
                this.reset();
                showToast('✅ Absence enregistrée');
            } catch(err) {
                alert('Erreur enregistrement: ' + (err.message || err));
            }
        });
        function openManagerQuickAbsence(comedianId) {
            const comedians = AppState.comedians.slice();
            const comedian = comedians.find(c => c.id === comedianId);
            
            if (!comedian) return;
            
            document.getElementById('managerAbsenceComedianId').value = comedian.id;
            document.getElementById('managerAbsenceComedianName').value = comedian.name;
            document.getElementById('managerQuickAbsenceStart').value = '';
            document.getElementById('managerQuickAbsenceEnd').value = '';
            document.getElementById('managerQuickAbsenceStartTime').value = '09:00';
            document.getElementById('managerQuickAbsenceEndTime').value = '18:00';
            document.getElementById('managerQuickAbsenceComment').value = '';
            openModal('managerQuickAbsenceModal');
        }

        document.getElementById('managerQuickAbsenceForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const comedianId = parseInt(document.getElementById('managerAbsenceComedianId').value);
            if (!comedianId) return;
            
            const start = document.getElementById('managerQuickAbsenceStart').value;
            const startTime = document.getElementById('managerQuickAbsenceStartTime').value;
            const end = document.getElementById('managerQuickAbsenceEnd').value;
            const endTime = document.getElementById('managerQuickAbsenceEndTime').value;
            const comment = document.getElementById('managerQuickAbsenceComment').value;
            if (!start || !end) { alert('Veuillez sélectionner les dates'); return; }
            
            try {
                await SupabaseDB.insertAbsenceDirect(comedianId, { id: Date.now(), start, startTime, end, endTime, comment });
                refreshCurrentView();
                loadAbsences();
                closeModal('managerQuickAbsenceModal');
                this.reset();
                showToast('✅ Absence enregistrée');
            } catch(err) {
                alert('Erreur enregistrement: ' + (err.message || err));
            }
        });

        document.getElementById('createUserForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const pwdField = document.getElementById('newPassword');
            const plainPwd = (pwdField && pwdField.value.trim()) ? pwdField.value.trim() : _generatedPassword;
            
            if (!plainPwd) {
                alert('⚠️ Veuillez saisir ou générer un mot de passe.');
                return;
            }
            
            const hash = await hashPassword(plainPwd);
            const newUser = {
                id: Date.now(),
                username: document.getElementById('newUsername').value.trim(),
                email: document.getElementById('newUserEmail') ? document.getElementById('newUserEmail').value.trim() : '',
                password: hash,
                _plainPassword: plainPwd,
                role: document.getElementById('newUserRole').value,
                comedianId: null,
                active: true
            };
            
            if (newUser.role === 'comedian') {
                newUser.comedianId = parseInt(document.getElementById('newUserComedianId').value);
            }
            
            try {
                await SupabaseDB.upsertUser(newUser);
                addLog('admin', 'admin', `Utilisateur créé: ${newUser.username}`);
                await broadcastUpdate('users');
                closeModal('createUserModal');
                loadUsers();
                _generatedPassword = '';
                this.reset();
            } catch(err) {
                alert('❌ Erreur lors de la création: ' + (err.message || err));
            }
        });

        document.getElementById('newUserRole').addEventListener('change', function() {
            const group = document.getElementById('comedianSelectGroup');
            if (this.value === 'comedian') {
                group.style.display = 'block';
                loadComedianOptions();
            } else {
                group.style.display = 'none';
            }
        });

        function loadComedianOptions() {
            const comedians = AppState.comedians.slice();
            const select = document.getElementById('newUserComedianId');
            select.innerHTML = '<option value="">Nouveau comédien</option>';
            comedians.forEach(c => {
                select.innerHTML += `<option value="${c.id}">${c.name}</option>`;
            });
        }

        document.getElementById('createComedianForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const comedians = AppState.comedians.slice();
            const email = document.getElementById('comedianEmail').value;
            
            const newComedian = {
                id: Date.now(),
                name: document.getElementById('comedianName').value,
                email: email,
                sexe: document.getElementById('comedianSexe').value,
                phone: document.getElementById('comedianPhone').value,
                classement: document.getElementById('comedianClassement') ? document.getElementById('comedianClassement').value : '',
                voixUrgente: document.getElementById('comedianVoixUrgente') ? document.getElementById('comedianVoixUrgente').checked : false,
                commentaireInterne: document.getElementById('comedianCommentaire') ? document.getElementById('comedianCommentaire').value : '',
                username: email.split('@')[0],
                password: Utils.generateSecurePassword(12),
                identifiantsSent: false,
                seances_dirigees: document.getElementById('comedianSeances').checked,
                voix_off: document.getElementById('comedianVoixOff').checked,
                voix_jouee: document.getElementById('comedianVoixJouee').checked,
                voix_enfant: document.getElementById('comedianVoixEnfant').checked,
                chant: document.getElementById('comedianChant').checked,
                voix_jeune: document.getElementById('comedianVoixJeune') ? document.getElementById('comedianVoixJeune').checked : false,
                voix_adulte: document.getElementById('comedianVoixAdulte') ? document.getElementById('comedianVoixAdulte').checked : false,
                voix_mature: document.getElementById('comedianVoixMature') ? document.getElementById('comedianVoixMature').checked : false,
                voix_accent: document.getElementById('comedianVoixAccent') ? document.getElementById('comedianVoixAccent').checked : false,
                timbre_grave: document.getElementById('comedianTimbreGrave') ? document.getElementById('comedianTimbreGrave').checked : false,
                timbre_medium: document.getElementById('comedianTimbreMedium') ? document.getElementById('comedianTimbreMedium').checked : false,
                timbre_aigu: document.getElementById('comedianTimbreAigu') ? document.getElementById('comedianTimbreAigu').checked : false,
                timbre_texture: document.getElementById('comedianTimbreTexture') ? document.getElementById('comedianTimbreTexture').checked : false,
                style_dynamique: document.getElementById('comedianStyleDynamique') ? document.getElementById('comedianStyleDynamique').checked : false,
                style_pose: document.getElementById('comedianStylePose') ? document.getElementById('comedianStylePose').checked : false,
                style_naturel: document.getElementById('comedianStyleNaturel') ? document.getElementById('comedianStyleNaturel').checked : false,
                style_institutionnel: document.getElementById('comedianStyleInstitutionnel') ? document.getElementById('comedianStyleInstitutionnel').checked : false,
                active: true,
                profilePic: null,
                audioDemo: null,
                presentation: '',
                absences: [],
                createdAt: new Date().toISOString()
            };
            
            try {
                const plainPwd = newComedian.password;
                newComedian.password = await hashPassword(plainPwd);

                await SupabaseDB.upsertComedian(newComedian);
                const realComedianId = newComedian.id;

                const baseUsername = email.split('@')[0].toLowerCase().replace(/[^a-z0-9._-]/g, '');
                const existingUsernames = AppState.users.map(u => u.username.toLowerCase());
                let username = baseUsername;
                let counter = 2;
                while (existingUsernames.includes(username.toLowerCase())) {
                    username = baseUsername + counter++;
                }

                const newUserComedian = {
                    username,
                    email,
                    password:       newComedian.password,
                    _plainPassword: plainPwd,
                    role:           'comedian',
                    comedianId:     realComedianId,
                    active:         true,
                    createdAt:      new Date().toISOString()
                };
                await SupabaseDB.upsertUser(newUserComedian);

                addLog(CONFIG.LOG_TYPES.CREATION, `Comédien créé: ${newComedian.name}`, 'comedian', realComedianId);
                await broadcastUpdate('comedians');
                closeModal('createComedianModal');
                loadComediansForAdmin();
                this.reset();
                alert(`Comedien cree !\n\nIDENTIFIANTS :\nIdentifiant : ${username}\nMot de passe : ${plainPwd}\n\nTransmettez ces informations au comedien.`);
            } catch(err) {
                alert('Erreur creation comedien: ' + (err.message || err));
            }
        });

        function loadComediansForAdmin() {
            const comedians = AppState.comedians.slice();
            displayComediansAdminList(comedians);
        }

        function displayComediansAdminList(comedians) {
            const container = document.getElementById('comediansListView');
            if (!container) return;
            container.innerHTML = '';
            
            if (comedians.length === 0) {
                container.innerHTML = '<div class="empty-state"><div class="icon">🎭</div><h3>Aucun comédien</h3><p>Créez votre première fiche comédien</p></div>';
                return;
            }
            
            comedians.forEach(comedian => {
                const item = document.createElement('div');
                item.className = 'list-item';
                item.onclick = () => showComedianDetail(comedian.id);
                
                let tags = '';
                if (comedian.seances_dirigees) tags += '<span class="tag">Séances dirigées</span>';
                if (comedian.voix_off) tags += '<span class="tag">Voix off</span>';
                if (comedian.voix_jouee) tags += '<span class="tag">Voix jouée</span>';
                if (comedian.voix_enfant) tags += '<span class="tag">Voix enfant</span>';
                if (comedian.chant) tags += '<span class="tag">Chant</span>';
                
                const classementBadge = comedian.classement
                    ? `<span class="tag" style="background:${comedian.classement === 'interne' ? 'rgba(233,69,96,0.15);color:var(--accent)' : 'rgba(78,204,163,0.15);color:var(--teal)'}; font-size:0.75em;">
                        ${comedian.classement === 'interne' ? '🏠 Interne' : '🌐 Externe'}
                       </span>`
                    : '';

                item.innerHTML = `
                    <div class="list-item-info">
                        <h4>${comedian.name} ${classementBadge}</h4>
                        <p>${comedian.sexe} - ${comedian.email}</p>
                        <div>${tags}</div>
                    </div>
                    <span class="tag ${comedian.active ? 'status-active' : 'status-inactive'}">${comedian.active ? 'Actif' : 'Inactif'}</span>
                `;
                
                container.appendChild(item);
            });
        }

        function filterAdminComedians(debounced) {
            if (debounced) {
                clearTimeout(_appFilterDebounceTimer);
                _appFilterDebounceTimer = setTimeout(function() { filterAdminComedians(false); }, 150);
                return;
            }
            const searchName     = document.getElementById('adminSearchName').value.toLowerCase();
            const filterInterne  = document.getElementById('adminFilterInterne')?.checked;
            const filterExterne  = document.getElementById('adminFilterExterne')?.checked;
            const filterInactif  = document.getElementById('adminFilterInactif')?.checked;

            let comedians = AppState.comedians.slice();

            if (searchName) {
                comedians = comedians.filter(c => c.name.toLowerCase().includes(searchName));
            }

            if (filterInterne || filterExterne) {
                comedians = comedians.filter(c => {
                    if (filterInterne && c.classement === 'interne') return true;
                    if (filterExterne && c.classement === 'externe') return true;
                    return false;
                });
            }

            if (!filterInactif) {
            }

            displayComediansAdminList(comedians);
        }

        function showComedianDetail(comedianId) {
            const comedians = AppState.comedians.slice();
            const comedian = comedians.find(c => c.id === comedianId);
            if (!comedian) return;
            
            let tags = '';
            if (comedian.seances_dirigees) tags += '<span class="tag">Séances dirigées</span>';
            if (comedian.voix_off) tags += '<span class="tag">Voix off</span>';
            if (comedian.voix_jouee) tags += '<span class="tag">Voix jouée</span>';
            if (comedian.voix_enfant) tags += '<span class="tag">Voix enfant</span>';
            if (comedian.chant) tags += '<span class="tag">Chant</span>';
            
            const profilePicAdmin = comedian.profilePic || `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100'%3E%3Crect fill='%2316213e' width='100' height='100'/%3E%3Ctext x='50%25' y='50%25' font-size='40' text-anchor='middle' dy='.3em' fill='%23e94560'%3E${encodeURIComponent(comedian.name.charAt(0))}%3C/text%3E%3C/svg%3E`;

            const content = `
                <div style="padding: 20px;">
                    <!-- En-tête : photo + infos + statut -->
                    <div style="display:flex; align-items:center; gap:18px; margin-bottom:24px; flex-wrap:wrap;">
                        <img src="${profilePicAdmin}" alt="${comedian.name}"
                             style="width:90px; height:90px; border-radius:50%; object-fit:cover;
                                    border:3px solid var(--border); flex-shrink:0;">
                        <div style="min-width:0; flex:1;">
                            <div style="display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin-bottom:6px;">
                                <h2 style="margin:0; font-size:1.3em;">${comedian.name}</h2>
                                ${comedian.voixUrgente ? '<span class="badge-urgent">🔥 Voix urgente</span>' : ''}
                                <span class="tag ${comedian.active ? 'status-active' : 'status-inactive'}" style="margin-left:auto;">${comedian.active ? 'Actif' : 'Inactif'}</span>
                            </div>
                            <p style="color:var(--text-muted); margin:0;">${comedian.sexe}</p>
                            <p style="color:var(--text-muted); font-size:0.88em; margin-top:4px;">✉️ ${comedian.email}</p>
                            ${comedian.phone ? `<p style="color:var(--text-muted); font-size:0.88em; margin-top:2px;">📞 ${comedian.phone}</p>` : ''}
                        </div>
                    </div>
                    
                    <div style="margin: 20px 0;">
                        <h3 style="color: var(--accent-light); margin-bottom: 10px;">Compétences</h3>
                        <div>${tags || '<p style="color: var(--text-muted);">Aucune compétence renseignée</p>'}</div>
                    </div>
                    
                    ${comedian.presentation ? `
                        <div style="margin: 20px 0;">
                            <h3 style="color: var(--accent-light); margin-bottom: 10px;">Présentation</h3>
                            <p>${comedian.presentation}</p>
                        </div>
                    ` : ''}
                    
                    <div style="margin-top: 30px; display: flex; gap: 10px;">
                        <button class="btn btn-small" onclick="openEditComedianAdmin(${comedian.id}); closeModal('comedianDetailModal');">✏️ Modifier</button>
                        <button class="btn btn-small" onclick="toggleComedianStatus(${comedian.id}); closeModal('comedianDetailModal');">${comedian.active ? 'Désactiver' : 'Activer'}</button>
                        <button class="btn btn-small" style="background: #c0392b;" onclick="deleteComedian(${comedian.id})">🗑️ Supprimer</button>
                    </div>
                </div>
            `;
            
            document.getElementById('comedianDetailContent').innerHTML = content;
            openModal('comedianDetailModal');
        }

        async function deleteComedian(comedianId) {
            if (confirm('Supprimer ce comedien ? Cette action est irreversible.')) {
                await SupabaseDB.deleteComedian(comedianId);
                await broadcastUpdate('comedians');
                closeModal('comedianDetailModal');
                loadComediansForAdmin();
                alert('Comedien supprime.');
            }
        }

        function applyAdminFilters() {
            filterAdminComedians();
        }

        function loadComediansForStudio() {
            document.getElementById('comediansGrid').innerHTML = '';
            document.getElementById('emptyState').style.display = 'block';
            loadAbsences();
        }

        function displayComedians(comedians) {
            const grid = document.getElementById('comediansGrid');
            const emptyState = document.getElementById('emptyState');
            
            grid.querySelectorAll('audio').forEach(function(a) {
                a.pause();
                a.src = '';
                a.load(); // force le navigateur à libérer le flux
            });
            grid.innerHTML = '';
            
            if (comedians.length === 0) {
                emptyState.style.display = 'block';
                emptyState.innerHTML = `
                    <div class="icon">😕</div>
                    <h3>Aucun résultat</h3>
                    <p>Aucun comédien ne correspond à votre recherche</p>
                `;
            } else {
                emptyState.style.display = 'none';
                comedians.forEach(comedian => {
                    const card = createComedianCard(comedian, false);
                    grid.appendChild(card);
                });
            }
        }

        function createComedianCard(comedian, isAdmin) {
            const card = document.createElement('div');
            card.className = 'card';
            card.style.position = 'relative';
            
            if (!isAdmin) {
                card.style.cursor = 'pointer';
                card.onclick = function(e) {
                    if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'AUDIO'
                        && e.target.tagName !== 'INPUT' && e.target.tagName !== 'LABEL'
                        && e.target.tagName !== 'SPAN' && !e.target.closest('audio')
                        && !e.target.closest('label')) {
                        showComedianDetailStudio(comedian.id);
                    }
                };
            }
            
            const tags = [];
            if (comedian.seances_dirigees) tags.push('Séances dirigées');
            if (comedian.voix_off) tags.push('Voix off');
            if (comedian.voix_jouee) tags.push('Voix jouée');
            if (comedian.voix_enfant) tags.push('Voix enfant');
            if (comedian.chant) tags.push('Chant');
            
            const tagsHTML = tags.map(tag => `<span class="tag">${tag}</span>`).join('');
            
            let actionsHTML = '';
            if (isAdmin) {
                actionsHTML = `
                    <div class="card-actions">
                        <button class="btn-icon" onclick="openEditComedianAdmin(${comedian.id})">✏️ Modifier</button>
                        <button class="btn-icon" onclick="openAdminQuickAbsence(${comedian.id})">📅 Absence</button>
                        <button class="btn-icon" onclick="toggleComedianStatus(${comedian.id})">${comedian.active ? 'Désactiver' : 'Activer'}</button>
                    </div>`;
            } else {
                const isManager = currentUser && currentUser.role === 'manager';
                actionsHTML = `
                    <div class="card-actions">
                        <button class="btn-icon" onclick="event.stopPropagation(); window.location.href='mailto:${comedian.email}'">✉️ Email</button>
                        ${isManager ? `<button class="btn-icon" onclick="event.stopPropagation(); openManagerQuickAbsence(${comedian.id})">📅 Absence</button>` : ''}
                    </div>`;
            }

            // ── Audio présentation ──
            const presData = getAudioData(comedian.audioPresentation);
            const audioPresentationHTML = presData ? `
                <div class="audio-block" onclick="event.stopPropagation()">
                    <span class="audio-label">🎤 Présentation</span>
                    <audio controls class="audio-player">
                        <source src="${presData}" type="audio/mpeg">
                    </audio>
                </div>` : '';

            // ── Audio démo ──
            const demoData = getAudioData(comedian.audioDemo);
            const audioDemoHTML = demoData ? `
                <div class="audio-block" onclick="event.stopPropagation()">
                    <span class="audio-label">🎵 Démo</span>
                    <audio controls class="audio-player">
                        <source src="${demoData}" type="audio/mpeg">
                    </audio>
                </div>` : '';

            // ── 3 nouvelles démos ──
            const demoPromoData  = getAudioData(comedian.audioDemoPromo);
            const demoJoueData   = getAudioData(comedian.audioDemoJoue);
            const demoInstitData = getAudioData(comedian.audioDemoInstit);
            const demosBlockHTML = (demoPromoData || demoJoueData || demoInstitData) ? `
                <div class="audio-block" onclick="event.stopPropagation()" style="border-top:1px solid var(--border);padding-top:10px;margin-top:6px;">
                    <span class="audio-label" style="display:block;margin-bottom:8px;">🎙️ Démos</span>
                    ${demoPromoData  ? `<span style="font-size:0.78em;color:var(--text-muted);display:block;margin:0 0 2px;">📣 Promo</span><audio controls class="audio-player"><source src="${demoPromoData}" type="audio/mpeg"></audio>` : ''}
                    ${demoJoueData   ? `<span style="font-size:0.78em;color:var(--text-muted);display:block;margin:8px 0 2px;">🎭 Jouée</span><audio controls class="audio-player"><source src="${demoJoueData}" type="audio/mpeg"></audio>` : ''}
                    ${demoInstitData ? `<span style="font-size:0.78em;color:var(--text-muted);display:block;margin:8px 0 2px;">🏛️ Institutionnelle</span><audio controls class="audio-player"><source src="${demoInstitData}" type="audio/mpeg"></audio>` : ''}
                </div>` : '';

            // ── Checkbox sélection (studio/manager uniquement) ──
            const isStudioRole = !isAdmin && currentUser && (currentUser.role === 'studio' || currentUser.role === 'manager');
            const selectionCheckboxHTML = isStudioRole ? `
                <div class="selection-btn-wrapper" onclick="event.stopPropagation()">
                    <label class="selection-btn-label" data-comedian-id="${comedian.id}">
                        <input type="checkbox" class="comedian-checkbox-studio" data-comedian-id="${comedian.id}" style="display:none;">
                        <span class="selection-btn-icon">＋</span>
                        <span class="selection-btn-text">Ajouter à ma sélection</span>
                    </label>
                </div>` : '';
            
            card.innerHTML = `
                <div class="card-header">
                    <img src="${comedian.profilePic || `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100'%3E%3Crect fill='%2316213e' width='100' height='100'/%3E%3Ctext x='50%25' y='50%25' font-size='40' text-anchor='middle' dy='.3em' fill='%23e94560'%3E${comedian.name.charAt(0)}%3C/text%3E%3C/svg%3E`}" 
                         alt="${comedian.name}" class="profile-pic">
                    <div class="card-info">
                        <div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin-bottom:4px;">
                            <h3 style="margin:0;">${comedian.name}</h3>
                            ${comedian.voixUrgente ? '<span class="badge-urgent">🔥 Voix urgente</span>' : ''}
                        </div>
                        <div class="card-meta">${comedian.sexe}</div>
                        ${isAdmin ? `
                            <div class="card-meta">${comedian.email}</div>
                            ${comedian.phone ? `<div class="card-meta">📞 ${comedian.phone}</div>` : ''}
                        ` : ''}
                    </div>
                </div>
                ${comedian.presentation ? `<div class="card-body">${comedian.presentation}</div>` : ''}
                <div class="card-tags">${tagsHTML}</div>
                ${audioPresentationHTML}
                ${audioDemoHTML}
                ${demosBlockHTML}
                ${actionsHTML}
                ${selectionCheckboxHTML}
            `;
            
            if (isStudioRole) {
                const cb = card.querySelector('.comedian-checkbox-studio');
                const label = card.querySelector('.selection-btn-label');
                const icon = card.querySelector('.selection-btn-icon');
                const text = card.querySelector('.selection-btn-text');

                function updateSelectionUI(checked) {
                    if (checked) {
                        label.style.background = 'rgba(78,204,163,0.18)';
                        label.style.borderColor = '#4ecca3';
                        label.style.color = '#4ecca3';
                        icon.textContent = '✓';
                        text.textContent = 'Dans ma sélection';
                    } else {
                        label.style.background = '';
                        label.style.borderColor = '';
                        label.style.color = '';
                        icon.textContent = '＋';
                        text.textContent = 'Ajouter à ma sélection';
                    }
                }

                if (cb) {
                    cb.addEventListener('change', function() {
                        toggleStudioSelection(comedian.id, this);
                        updateSelectionUI(this.checked);
                    });
                    if (studioSelection.includes(comedian.id)) {
                        cb.checked = true;
                        updateSelectionUI(true);
                    }
                }

                if (label) {
                    label.addEventListener('click', function(e) {
                        e.preventDefault();
                        cb.checked = !cb.checked;
                        cb.dispatchEvent(new Event('change'));
                    });
                }
            }
            
            return card;
        }

        function showComedianDetailStudio(comedianId) {
            const comedians = AppState.comedians.slice();
            const comedian = comedians.find(c => c.id === comedianId);
            if (!comedian) return;
            
            let tags = '';
            if (comedian.seances_dirigees) tags += '<span class="tag">Séances dirigées</span>';
            if (comedian.voix_off) tags += '<span class="tag">Voix off</span>';
            if (comedian.voix_jouee) tags += '<span class="tag">Voix jouée</span>';
            if (comedian.voix_enfant) tags += '<span class="tag">Voix enfant</span>';
            if (comedian.chant) tags += '<span class="tag">Chant</span>';
            
            let absencesHTML = '';
            if (comedian.absences && comedian.absences.length > 0) {
                const futureAbsences = comedian.absences.filter(a => isAbsenceActive(a));
                if (futureAbsences.length > 0) {
                    absencesHTML = '<div style="margin: 20px 0;"><h3 style="color: var(--warning); margin-bottom: 10px;">📅 Absences à venir</h3>';
                    futureAbsences.forEach(absence => {
                        const startTime = absence.startTime ? ` à ${absence.startTime}` : '';
                        const endTime = absence.endTime ? ` à ${absence.endTime}` : '';
                        const comment = absence.comment ? `<br><small style="color: var(--text-muted); font-style: italic;">${absence.comment}</small>` : '';
                        absencesHTML += `
                            <div class="card-absence-item">
                                <strong>Du ${formatDate(absence.start)}${startTime}</strong>
                                <strong>au ${formatDate(absence.end)}${endTime}</strong>
                                ${comment}
                            </div>
                        `;
                    });
                    absencesHTML += '</div>';
                }
            }
            
            const audioPresentationData = getAudioData(comedian.audioPresentation);
            const audioDemoData         = getAudioData(comedian.audioDemo);
            const audioDemoPromoData    = getAudioData(comedian.audioDemoPromo);
            const audioDemoJoueData     = getAudioData(comedian.audioDemoJoue);
            const audioDemoInstitData   = getAudioData(comedian.audioDemoInstit);

            const audioPresentationHTML = audioPresentationData
                ? `<audio controls class="audio-player"><source src="${audioPresentationData}" type="audio/mpeg"></audio>`
                : '<p style="color: var(--text-muted);">Aucune présentation audio</p>';

            const audioDemoHTML = audioDemoData
                ? `<audio controls class="audio-player"><source src="${audioDemoData}" type="audio/mpeg"></audio>`
                : '<p style="color: var(--text-muted);">Aucune démo audio</p>';

            function buildDemoBlock(label, icon, data) {
                if (!data) return '';
                return `<div style="margin-bottom:14px;">
                    <p style="font-size:0.82em;color:var(--text-muted);font-weight:600;margin-bottom:4px;">${icon} ${label}</p>
                    <audio controls class="audio-player"><source src="${data}" type="audio/mpeg"></audio>
                </div>`;
            }

            const demosHTML = (audioDemoPromoData || audioDemoJoueData || audioDemoInstitData)
                ? `<div style="margin:20px 0;">
                    <h3 style="color:var(--accent-light);margin-bottom:12px;">🎙️ Démos audio</h3>
                    ${buildDemoBlock('Démo promo', '📣', audioDemoPromoData)}
                    ${buildDemoBlock('Démo jouée', '🎭', audioDemoJoueData)}
                    ${buildDemoBlock('Démo institutionnelle', '🏛️', audioDemoInstitData)}
                   </div>`
                : ''
            
            const isManager = currentUser && currentUser.role === 'manager';
            
            const profilePicSrc = comedian.profilePic || `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100'%3E%3Crect fill='%2316213e' width='100' height='100'/%3E%3Ctext x='50%25' y='50%25' font-size='40' text-anchor='middle' dy='.3em' fill='%23e94560'%3E${encodeURIComponent(comedian.name.charAt(0))}%3C/text%3E%3C/svg%3E`;

            const content = `
                <div style="padding: 20px;">
                    <!-- En-tête : photo + infos -->
                    <div style="display:flex; align-items:center; gap:18px; margin-bottom:24px; flex-wrap:wrap;">
                        <img src="${profilePicSrc}" alt="${comedian.name}"
                             style="width:90px; height:90px; border-radius:50%; object-fit:cover;
                                    border:3px solid var(--border); flex-shrink:0;">
                        <div style="min-width:0;">
                            <div style="display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin-bottom:6px;">
                                <h2 style="margin:0; font-size:1.3em;">${comedian.name}</h2>
                                ${comedian.voixUrgente ? '<span class="badge-urgent">🔥 Voix urgente</span>' : ''}
                            </div>
                            <p style="color:var(--text-muted); margin:0;">${comedian.sexe}</p>
                            <p style="color:var(--text-muted); font-size:0.88em; margin-top:4px;">✉️ ${comedian.email}</p>
                            ${comedian.phone ? `<p style="color:var(--text-muted); font-size:0.88em; margin-top:2px;">📞 ${comedian.phone}</p>` : ''}
                        </div>
                    </div>
                    
                    <div style="margin: 20px 0;">
                        <h3 style="color: var(--accent-light); margin-bottom: 10px;">Compétences</h3>
                        <div>${tags || '<p style="color: var(--text-muted);">Aucune compétence renseignée</p>'}</div>
                    </div>
                    
                    ${comedian.presentation ? `
                        <div style="margin: 20px 0;">
                            <h3 style="color: var(--accent-light); margin-bottom: 10px;">Présentation</h3>
                            <p>${comedian.presentation}</p>
                        </div>
                    ` : ''}
                    
                    <div style="margin: 20px 0;">
                        <h3 style="color: var(--accent-light); margin-bottom: 10px;">🎤 Présentation audio</h3>
                        ${audioPresentationHTML}
                    </div>

                    <div style="margin: 20px 0;">
                        <h3 style="color: var(--accent-light); margin-bottom: 10px;">🎵 Démo audio</h3>
                        ${audioDemoHTML}
                    </div>

                    ${demosHTML}
                    
                    ${absencesHTML}
                    
                    ${(currentUser.role === 'admin' || currentUser.role === 'manager' || currentUser.role === 'studio') && comedian.commentaireInterne ? `
                        <div style="margin: 20px 0; padding: 15px; background: rgba(78, 204, 163, 0.1); border-radius: 8px; border-left: 4px solid var(--success);">
                            <h3 style="color: var(--success); margin-bottom: 10px;">💬 Commentaire interne</h3>
                            <p style="white-space: pre-wrap;">${comedian.commentaireInterne}</p>
                        </div>
                    ` : ''}
                    

                    
                    <div style="margin-top: 30px; display: flex; gap: 10px; flex-wrap: wrap;">
                        <button class="btn btn-small" onclick="window.location.href='mailto:${comedian.email}'">✉️ Envoyer un email</button>
                        ${isManager ? `<button class="btn btn-small" onclick="closeModal('comedianDetailModal'); openManagerQuickAbsence(${comedian.id});">📅 Ajouter une absence</button>` : ''}
                        ${currentUser.role === 'admin' ? `<button class="btn btn-small" onclick="closeModal('comedianDetailModal'); sendCredentials(${comedian.id});" ${comedian.identifiantsSent ? 'disabled title="Déjà envoyés"' : ''}>${comedian.identifiantsSent ? '✅ Identifiants envoyés' : '📧 Envoyer identifiants'}</button>` : ''}
                        <button class="btn btn-small" style="background: #ff6b6b;" onclick="closeModal('comedianDetailModal'); openUrgentRequestModal(${comedian.id});">🚨 Demande voix urgente</button>
                    </div>
                </div>
            `;
            
            document.getElementById('comedianDetailContent').innerHTML = content;
            openModal('comedianDetailModal');
        }

        async function toggleComedianStatus(comedianId) {
            const comedians = AppState.comedians.slice();
            const comedian = comedians.find(c => c.id === comedianId);
            
            if (!comedian) return;
            
            const action = comedian.active ? 'désactiver' : 'activer';
            const actionCapital = comedian.active ? 'Désactiver' : 'Activer';
            
            const confirmation = confirm(`${actionCapital} le comédien ${comedian.name} ?\n\n${comedian.active ? '⚠️ Le comédien ne sera plus visible dans le catalogue.' : '✅ Le comédien sera visible dans le catalogue.'}`);
            
            if (!confirmation) return;
            
            comedian.active = !comedian.active;
            await SupabaseDB.upsertComedian(comedian);
            await broadcastUpdate('comedians');
            
            addLog(
                comedian.active ? CONFIG.LOG_TYPES.ACTIVATION : CONFIG.LOG_TYPES.DESACTIVATION,
                `Comédien ${comedian.active ? 'activé' : 'désactivé'}: ${comedian.name}`,
                'comedian',
                comedianId
            );
            
            alert(`✅ ${comedian.name} a été ${comedian.active ? 'activé' : 'désactivé'} avec succès !`);
            
            loadComediansForAdmin();
        }

        function loadComedianProfile() {
            const users = AppState.users.slice();
            const currentUserData = users.find(u => u.username === currentUser.username);
            
            if (!currentUserData || !currentUserData.comedianId) {
                document.getElementById('comedianProfile').innerHTML = `
                    <div class="card">
                        <p>Aucun profil comédien associé à ce compte.</p>
                        <p style="color: var(--text-muted); margin-top: 10px;">Veuillez contacter un administrateur.</p>
                    </div>
                `;
                return;
            }
            
            const comedians = AppState.comedians.slice();
            const comedian = comedians.find(c => String(c.id) === String(currentUserData.comedianId));
            
            if (!comedian) {
                document.getElementById('comedianProfile').innerHTML = `<div class="card"><p>Profil non trouvé.</p></div>`;
                return;
            }

            function buildAudioBlock(label, icon, type, path) {
                const data = getAudioData(path);
                const filename = path ? path.split('/').pop() : '';
                if (data) {
                    return `
                        <div style="margin-top:15px; padding:15px; background:rgba(78,204,163,0.07); border:1px solid rgba(78,204,163,0.3); border-radius:10px;">
                            <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:8px;">
                                <strong style="color:var(--accent-light);">${icon} ${label}</strong>
                                <button onclick="deleteAudio(${comedian.id},'${type}')" style="background:transparent; border:1px solid rgba(192,57,43,0.5); color:#c0392b; border-radius:5px; padding:2px 7px; font-size:0.72em; cursor:pointer; line-height:1.4;">🗑</button>
                            </div>
                            <audio controls style="width:100%;">
                                <source src="${data}" type="audio/mpeg">
                            </audio>
                            <p style="color:var(--text-muted); font-size:0.8em; margin-top:5px;">📁 ${filename}</p>
                        </div>`;
                } else {
                    return `
                        <div style="margin-top:15px; padding:12px; background:rgba(255,255,255,0.03); border:1px dashed var(--border); border-radius:10px; color:var(--text-muted); font-style:italic;">
                            ${icon} Aucune ${label.toLowerCase()} — utilisez le bouton ci-dessus pour en ajouter une.
                        </div>`;
                }
            }

            const futureAbsences = (comedian.absences || []).filter(a => isAbsenceActive(a));
            let absencesHTML = '';
            if (futureAbsences.length > 0) {
                absencesHTML = '<h3 style="margin-top:25px; color:var(--accent-light);">📅 Mes absences</h3>';
                futureAbsences.forEach(absence => {
                    const startTime = absence.startTime ? ` à ${absence.startTime}` : '';
                    const endTime   = absence.endTime   ? ` à ${absence.endTime}`   : '';
                    const comment   = absence.comment   ? `<br><small style="color:var(--text-muted);">${absence.comment}</small>` : '';
                    absencesHTML += `
                        <div class="absence-item" style="display:flex; justify-content:space-between; align-items:center; gap:12px;">
                            <div>
                                <strong>Du ${formatDate(absence.start)}${startTime} au ${formatDate(absence.end)}${endTime}</strong>
                                ${comment}
                            </div>
                            <button onclick="deleteComedianAbsence(${absence.id})" style="flex-shrink:0; background:transparent; border:1px solid rgba(232,68,90,0.4); color:var(--accent); border-radius:5px; padding:2px 7px; font-size:0.72em; cursor:pointer; line-height:1.4;">🗑</button>
                        </div>`;
                });
            } else {
                absencesHTML = '<h3 style="margin-top:25px; color:var(--accent-light);">📅 Mes absences</h3><p style="color:var(--text-muted);">Aucune absence à venir</p>';
            }

            document.getElementById('comedianProfile').innerHTML = `
                <div class="card">
                    <div class="card-header">
                        <img src="${comedian.profilePic || `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='100' height='100'%3E%3Crect fill='%2316213e' width='100' height='100'/%3E%3Ctext x='50%25' y='50%25' font-size='40' text-anchor='middle' dy='.3em' fill='%23e94560'%3E${comedian.name.charAt(0)}%3C/text%3E%3C/svg%3E`}"
                             alt="${comedian.name}" class="profile-pic">
                        <div class="card-info">
                            <h3>${comedian.name}</h3>
                            <div class="card-meta">${comedian.sexe}</div>
                            <div class="card-meta">✉️ ${comedian.email}</div>
                            ${comedian.phone ? `<div class="card-meta">📞 ${comedian.phone}</div>` : ''}
                        </div>
                    </div>
                    
                    <h3 style="margin-top:20px; color:var(--accent-light);">✍️ Présentation</h3>
                    ${comedian.presentation ? `<div class="card-body">${comedian.presentation}</div>` : '<p style="color:var(--text-muted);">Aucune présentation renseignée</p>'}
                    
                    <h3 style="margin-top:25px; color:var(--accent-light);">🎤 Présentation audio</h3>
                    ${buildAudioBlock('Présentation audio', '🎤', 'presentation', comedian.audioPresentation)}
                    
                    <h3 style="margin-top:25px; color:var(--accent-light);">🎵 Démo audio</h3>
                    ${buildAudioBlock('Démo audio (ancienne)', '🎵', 'demo', comedian.audioDemo)}

                    <h3 style="margin-top:30px; color:var(--accent-light);">🎙️ Mes démos</h3>
                    <p style="color:var(--text-muted); font-size:0.85em; margin-bottom:12px;">Format MP3 · Maximum 1 minute · Utilisez les boutons en haut pour ajouter ou remplacer</p>
                    ${buildAudioBlock('Démo promo', '📣', 'demo_promo', comedian.audioDemoPromo)}
                    ${buildAudioBlock('Démo jouée', '🎭', 'demo_joue', comedian.audioDemoJoue)}
                    ${buildAudioBlock('Démo institutionnelle', '🏛️', 'demo_instit', comedian.audioDemoInstit)}

                    ${absencesHTML}
                </div>
            `;
        }
        
        async function deleteComedianAbsence(absenceId) {
            if (!confirm('Supprimer cette absence ?')) return;
            const currentUserData = AppState.users.find(u => u.username === currentUser.username);
            if (!currentUserData || !currentUserData.comedianId) return;
            try {
                await SupabaseDB.deleteAbsenceDirect(currentUserData.comedianId, absenceId);
                loadComedianProfile();
                showToast('✅ Absence supprimée');
            } catch(err) {
                alert('Erreur: ' + (err.message || err));
            }
        }

        function openMFTDelivery() {
            openModal('mftDeliveryModal');
        }

        function requestMFTAccess() {
            const admin = AppState.users.find(u => u.role === 'admin' && u.email);
            const adminEmail = admin ? admin.email : '';

            if (!adminEmail) {
                alert('Aucun email administrateur trouvé. Contactez directement votre studio.');
                return;
            }

            const comedianName = currentUser ? currentUser.username : 'Un comédien';
            const subject = encodeURIComponent('Demande d\'identifiants — Plateforme de livraison NRJ');
            const body    = encodeURIComponent(
                'Bonjour,\n\n' +
                'Je souhaite accéder à la plateforme de livraison des enregistrements (https://mft.nrjgroup.fr/login) ' +
                'mais mes identifiants sont perdus ou je n\'ai pas encore accès.\n\n' +
                'Merci de me les communiquer.\n\n' +
                'Comédien : ' + comedianName + '\n\n' +
                'Cordialement'
            );

            const link = document.createElement('a');
            link.href = 'mailto:' + adminEmail + '?subject=' + subject + '&body=' + body;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            setTimeout(() => document.body.removeChild(link), 200);

            showToast('📧 Email préparé pour ' + adminEmail);
        }

        function openEditComedianProfile() {
            const users = AppState.users.slice();
            const currentUserData = users.find(u => u.username === currentUser.username);
            
            if (currentUserData.comedianId) {
                openEditComedian(currentUserData.comedianId);
            }
        }

        function openQuickAbsence() {
            openModal('quickAbsenceModal');
        }

        document.getElementById('quickAbsenceForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const users = AppState.users.slice();
            const currentUserData = users.find(u => u.username === currentUser.username);
            
            if (!currentUserData || !currentUserData.comedianId) return;
            
            const comedianId = currentUserData.comedianId;
            const comedian = AppState.comedians.find(c => String(c.id) === String(comedianId));
            if (!comedian) return;
            
            const start = document.getElementById('quickAbsenceStart').value;
            const startTime = document.getElementById('quickAbsenceStartTime').value;
            const end = document.getElementById('quickAbsenceEnd').value;
            const endTime = document.getElementById('quickAbsenceEndTime').value;
            const comment = document.getElementById('quickAbsenceComment').value;
            if (!start || !end) { alert('Veuillez sélectionner les dates'); return; }
            
            try {
                await SupabaseDB.insertAbsenceDirect(comedianId, { id: Date.now(), start, startTime, end, endTime, comment });
                closeModal('quickAbsenceModal');
                this.reset();
                document.getElementById('quickAbsenceStartTime').value = '09:00';
                document.getElementById('quickAbsenceEndTime').value = '18:00';
                loadComedianProfile();
                showToast('✅ Absence enregistrée');
            } catch(err) {
                alert('Erreur enregistrement: ' + (err.message || err));
            }
        });

        let _adminEditingComedianId = null;

        function openEditComedianAdmin(comedianId) {
            const comedians = AppState.comedians.slice();
            const comedian = comedians.find(c => c.id === comedianId);
            
            if (!comedian) return;

            _adminEditingComedianId = comedianId;
            
            document.getElementById('editAdminComedianId').value = comedian.id;
            document.getElementById('editAdminName').value = comedian.name;
            document.getElementById('editAdminEmail').value = comedian.email;
            document.getElementById('editAdminSexe').value = comedian.sexe;
            document.getElementById('editAdminPhone').value = comedian.phone || '';
            document.getElementById('editAdminClassement').value = comedian.classement || '';
            
            document.getElementById('editAdminSeances').checked = comedian.seances_dirigees || false;
            document.getElementById('editAdminVoixOff').checked = comedian.voix_off || false;
            document.getElementById('editAdminVoixJouee').checked = comedian.voix_jouee || false;
            document.getElementById('editAdminVoixEnfant').checked = comedian.voix_enfant || false;
            document.getElementById('editAdminChant').checked = comedian.chant || false;
            
            document.getElementById('editAdminVoixJeune').checked = comedian.voix_jeune || false;
            document.getElementById('editAdminVoixAdulte').checked = comedian.voix_adulte || false;
            document.getElementById('editAdminVoixMature').checked = comedian.voix_mature || false;
            document.getElementById('editAdminVoixAccent').checked = comedian.voix_accent || false;
            
            document.getElementById('editAdminTimbreGrave').checked = comedian.timbre_grave || false;
            document.getElementById('editAdminTimbreMedium').checked = comedian.timbre_medium || false;
            document.getElementById('editAdminTimbreAigu').checked = comedian.timbre_aigu || false;
            document.getElementById('editAdminTimbreTexture').checked = comedian.timbre_texture || false;
            
            document.getElementById('editAdminStyleDynamique').checked = comedian.style_dynamique || false;
            document.getElementById('editAdminStylePose').checked = comedian.style_pose || false;
            document.getElementById('editAdminStyleNaturel').checked = comedian.style_naturel || false;
            document.getElementById('editAdminStyleInstitutionnel').checked = comedian.style_institutionnel || false;
            
            document.getElementById('editAdminVoixUrgente').checked = comedian.voixUrgente || false;
            document.getElementById('editAdminCommentaire').value = comedian.commentaireInterne || '';
            document.getElementById('editAdminPresentation').value = comedian.presentation || '';
            
            if (comedian.profilePic) {
                document.getElementById('editAdminProfilePreview').src = comedian.profilePic;
                document.getElementById('editAdminProfilePreview').style.display = 'block';
            } else {
                document.getElementById('editAdminProfilePreview').style.display = 'none';
            }
            
            const presData = getAudioData(comedian.audioPresentation);
            const presPreview = document.getElementById('adminAudioPresPreview');
            const presStatus  = document.getElementById('adminAudioPresStatus');
            if (presData) {
                presPreview.src = presData;
                presPreview.style.display = 'block';
                presStatus.textContent = '✅ ' + (comedian.audioPresentation || '').split('/').pop();
                presStatus.style.color = '#2ecc71';
            } else {
                presPreview.style.display = 'none';
                presPreview.src = '';
                presStatus.textContent = 'Aucune présentation audio';
                presStatus.style.color = '';
            }

            const demoData = getAudioData(comedian.audioDemo);
            const demoPreview = document.getElementById('adminAudioDemoPreview');
            const demoStatus  = document.getElementById('adminAudioDemoStatus');
            if (demoData) {
                demoPreview.src = demoData;
                demoPreview.style.display = 'block';
                demoStatus.textContent = '✅ ' + (comedian.audioDemo || '').split('/').pop();
                demoStatus.style.color = '#2ecc71';
            } else {
                demoPreview.style.display = 'none';
                demoPreview.src = '';
                demoStatus.textContent = 'Aucune démo audio';
                demoStatus.style.color = '';
            }

            [
                { type: 'demo_promo',  field: 'audioDemoPromo' },
                { type: 'demo_joue',   field: 'audioDemoJoue'  },
                { type: 'demo_instit', field: 'audioDemoInstit'},
            ].forEach(({ type, field }) => {
                const meta = getAudioMeta(type);
                const dom  = AUDIO_ADMIN_DOM[type];
                const data = getAudioData(comedian[field]);
                const prev = document.getElementById(dom.previewId);
                const stat = document.getElementById(dom.statusId);
                if (!prev || !stat) return;
                if (data) {
                    prev.src = data;
                    prev.style.display = 'block';
                    stat.textContent = '✅ ' + (comedian[field] || '').split('/').pop();
                    stat.style.color = '#2ecc71';
                } else {
                    prev.style.display = 'none';
                    prev.src = '';
                    stat.textContent = 'Aucune ' + meta.label.toLowerCase();
                    stat.style.color = '';
                }
            });

            displayAbsencesEditAdmin(comedian.absences || []);
            openModal('editComedianAdminModal');
        }

        document.getElementById('editAdminProfilePic').addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = function(event) {
                    document.getElementById('editAdminProfilePreview').src = event.target.result;
                    document.getElementById('editAdminProfilePreview').style.display = 'block';
                };
                reader.readAsDataURL(file);
            }
        });

        document.getElementById('editComedianAdminForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const comedianId = parseInt(document.getElementById('editAdminComedianId').value);
            await SupabaseDB.reloadComedians();
            const comedian = AppState.comedians.find(c => c.id === comedianId);
            
            if (!comedian) return;
            
            const oldClassement = comedian.classement;
            
            comedian.name = document.getElementById('editAdminName').value;
            comedian.email = document.getElementById('editAdminEmail').value;
            comedian.sexe = document.getElementById('editAdminSexe').value;
            comedian.phone = document.getElementById('editAdminPhone').value;
            comedian.classement = document.getElementById('editAdminClassement').value;
            
            comedian.seances_dirigees = document.getElementById('editAdminSeances').checked;
            comedian.voix_off = document.getElementById('editAdminVoixOff').checked;
            comedian.voix_jouee = document.getElementById('editAdminVoixJouee').checked;
            comedian.voix_enfant = document.getElementById('editAdminVoixEnfant').checked;
            comedian.chant = document.getElementById('editAdminChant').checked;
            
            comedian.voix_jeune = document.getElementById('editAdminVoixJeune').checked;
            comedian.voix_adulte = document.getElementById('editAdminVoixAdulte').checked;
            comedian.voix_mature = document.getElementById('editAdminVoixMature').checked;
            comedian.voix_accent = document.getElementById('editAdminVoixAccent').checked;
            
            comedian.timbre_grave = document.getElementById('editAdminTimbreGrave').checked;
            comedian.timbre_medium = document.getElementById('editAdminTimbreMedium').checked;
            comedian.timbre_aigu = document.getElementById('editAdminTimbreAigu').checked;
            comedian.timbre_texture = document.getElementById('editAdminTimbreTexture').checked;
            
            comedian.style_dynamique = document.getElementById('editAdminStyleDynamique').checked;
            comedian.style_pose = document.getElementById('editAdminStylePose').checked;
            comedian.style_naturel = document.getElementById('editAdminStyleNaturel').checked;
            comedian.style_institutionnel = document.getElementById('editAdminStyleInstitutionnel').checked;
            
            comedian.voixUrgente = document.getElementById('editAdminVoixUrgente').checked;
            comedian.commentaireInterne = document.getElementById('editAdminCommentaire').value;
            comedian.presentation = document.getElementById('editAdminPresentation').value;
            
            const profilePic = document.getElementById('editAdminProfilePreview');
            if (profilePic.style.display !== 'none') {
                comedian.profilePic = profilePic.src;
            }
            
            
            if (oldClassement !== comedian.classement) {
                const oldLabel = oldClassement === 'interne' ? 'Interne' : oldClassement === 'externe' ? 'Externe' : 'Aucun';
                const newLabel = comedian.classement === 'interne' ? 'Interne' : comedian.classement === 'externe' ? 'Externe' : 'Aucun';
                addLog(CONFIG.LOG_TYPES.MODIFICATION, `Classement modifié pour ${comedian.name}: ${oldLabel} → ${newLabel}`, 'comedian', comedianId);
            }
            
            try {
                await SupabaseDB.upsertComedian(comedian);
                await broadcastUpdate('comedians');
                closeModal('editComedianAdminModal');
                loadComediansForAdmin();
            } catch(err) {
                alert('❌ Erreur: ' + (err.message || err));
            }
        });

        function displayAbsencesEditAdmin(absences) {
            const container = document.getElementById('absencesListEditAdmin');
            container.innerHTML = '';
            
            if (!absences || absences.length === 0) {
                container.innerHTML = '<p style="color: var(--text-muted);">Aucune absence enregistrée</p>';
                return;
            }

            absences.forEach(absence => {
                const isPast = !isAbsenceActive(absence);
                const div = document.createElement('div');
                div.className = 'absence-item';
                div.style.opacity = isPast ? '0.5' : '1';
                const startTime = absence.startTime ? ` à ${absence.startTime}` : '';
                const endTime = absence.endTime ? ` à ${absence.endTime}` : '';
                const comment = absence.comment ? `<br><small style="color: var(--text-muted); font-style: italic;">${absence.comment}</small>` : '';
                const pastLabel = isPast ? '<br><small style="color:var(--text-muted);">✓ Terminée</small>' : '';
                div.innerHTML = `
                    <strong>Du ${formatDate(absence.start)}${startTime} au ${formatDate(absence.end)}${endTime}</strong>
                    ${comment}${pastLabel}
                    <button class="btn-icon btn-small" style="float: right;" onclick="removeAbsenceAdmin(${absence.id})">Supprimer</button>
                `;
                container.appendChild(div);
            });
        }

        async function addAbsenceAdmin() {
            const start = document.getElementById('editAdminAbsenceStart').value;
            const end = document.getElementById('editAdminAbsenceEnd').value;
            if (!start || !end) { alert('Veuillez sélectionner les dates de début et fin'); return; }
            const comedianId = parseInt(document.getElementById('editAdminComedianId').value);
            try {
                await SupabaseDB.insertAbsenceDirect(comedianId, { id: Date.now(), start, end });
                const comedian = AppState.comedians.find(c => c.id === comedianId);
                if (comedian) displayAbsencesEditAdmin(comedian.absences);
                document.getElementById('editAdminAbsenceStart').value = '';
                document.getElementById('editAdminAbsenceEnd').value = '';
                showToast('✅ Absence enregistrée');
            } catch(err) {
                alert('Erreur: ' + (err.message || err));
            }
        }

        async function removeAbsenceAdmin(absenceId) {
            const comedianId = parseInt(document.getElementById('editAdminComedianId').value);
            try {
                await SupabaseDB.deleteAbsenceDirect(comedianId, absenceId);
                const comedian = AppState.comedians.find(c => c.id === comedianId);
                if (comedian) displayAbsencesEditAdmin(comedian.absences);
            } catch(err) {
                alert('Erreur: ' + (err.message || err));
            }
        }

        function openEditComedian(comedianId) {
            const comedians = AppState.comedians.slice();
            const comedian = comedians.find(c => c.id === comedianId);
            if (!comedian) return;

            document.getElementById('editComedianId').value = comedian.id;
            document.getElementById('editPresentation').value = comedian.presentation || '';

            const preview = document.getElementById('editProfilePreview');
            if (comedian.profilePic) {
                preview.src = comedian.profilePic;
                preview.style.display = 'block';
            } else {
                preview.style.display = 'none';
                preview.src = '';
            }
            openModal('editComedianModal');
        }

        document.getElementById('editProfilePic').addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = function(ev) {
                const preview = document.getElementById('editProfilePreview');
                preview.src = ev.target.result;
                preview.style.display = 'block';
            };
            reader.readAsDataURL(file);
        });

        async function saveComedianProfile(e) {
            if (e) e.preventDefault();
            const comedianId = parseInt(document.getElementById('editComedianId').value);
            await SupabaseDB.reloadComedians();
            const comedian = AppState.comedians.find(c => c.id === comedianId);
            if (!comedian) return;

            comedian.presentation = document.getElementById('editPresentation').value;

            const profilePic = document.getElementById('editProfilePreview');
            if (profilePic.style.display !== 'none' && profilePic.src && profilePic.src.startsWith('data:')) {
                try {
                    const ext = profilePic.src.includes('image/png') ? 'png' : 'jpg';
                    const filename = `comedian_${comedianId}_${Date.now()}.${ext}`;
                    const url = await SupabaseDB.uploadImage(profilePic.src, filename);
                    comedian.profilePic = url;
                } catch(err) { console.warn('Photo upload failed:', err); }
            } else if (profilePic.style.display !== 'none' && profilePic.src && profilePic.src.startsWith('http')) {
                comedian.profilePic = profilePic.src;
            }

            await SupabaseDB.upsertComedian(comedian);
            await broadcastUpdate('comedians');
            closeModal('editComedianModal');
            if (currentUser && currentUser.role === 'comedian') loadComedianProfile();
        }

        const AUDIO_MAX_DURATION = 60; // 1 minute max pour les démos
        const AUDIO_MAX_DURATION_PRES = 90; // 1 min 30 pour la présentation
        let _audioUploadType    = null; // 'presentation'|'demo'|'demo_promo'|'demo_joue'|'demo_instit'
        let _audioUploadData    = null; // base64 data URL
        let _audioUploadName    = null; // nom canonique du fichier
        let _audioComedianId    = null;

        const AUDIO_TYPE_META = {
            presentation: { field: 'audioPresentation', label: 'Présentation audio',       icon: '🎤', suffix: 'pres',        maxDur: 90 },
            demo:         { field: 'audioDemo',         label: 'Démo audio',               icon: '🎵', suffix: 'demo',        maxDur: 60 },
            demo_promo:   { field: 'audioDemoPromo',    label: 'Démo promo',               icon: '📣', suffix: 'demopromo',   maxDur: 60 },
            demo_joue:    { field: 'audioDemoJoue',     label: 'Démo jouée',               icon: '🎭', suffix: 'demojoue',    maxDur: 60 },
            demo_instit:  { field: 'audioDemoInstit',   label: 'Démo institutionnelle',    icon: '🏛️', suffix: 'demoinstit',  maxDur: 60 },
        };

        function getAudioMeta(type) {
            return AUDIO_TYPE_META[type] || AUDIO_TYPE_META['demo'];
        }

        function buildAudioFilename(comedianName, type) {
            const base = comedianName
                .toLowerCase()
                .normalize('NFD').replace(/[\u0300-\u036f]/g, '')
                .replace(/[^a-z0-9]/g, '');
            const suffix = getAudioMeta(type).suffix;
            return `/app/audio/${base}${suffix}.mp3`;
        }

        function openAudioUpload(type) {
            const users = AppState.users.slice();
            const currentUserData = users.find(u => u.username === currentUser.username);
            if (!currentUserData || !currentUserData.comedianId) return;

            const meta = getAudioMeta(type);
            _audioUploadType  = type;
            _audioComedianId  = currentUserData.comedianId;
            _audioUploadData  = null;
            _audioUploadName  = null;

            document.getElementById('audioUploadTitle').textContent =
                meta.icon + ' Ajouter : ' + meta.label;
            const limitLabel = meta.maxDur === 60 ? '1 min max' : '1 min 30 max';
            const limitShort = meta.maxDur === 60 ? 'Max 1:00' : 'Max 1:30';
            document.getElementById('audioUploadHint').textContent =
                'Format MP3 uniquement — durée maximale : ' + limitLabel;
            const dropHint = document.getElementById('audioDropHint');
            if (dropHint) dropHint.textContent = 'Format MP3 uniquement · ' + limitShort;
            document.getElementById('audioValidationMsg').style.display = 'none';
            document.getElementById('audioPreviewSection').style.display = 'none';
            document.getElementById('audioConfirmBtn').disabled = true;
            document.getElementById('audioFileInput').value = '';
            const preview = document.getElementById('audioUploadPreview');
            preview.pause();
            preview.src = '';

            openModal('audioUploadModal');
        }

        function openAudioUploadAdmin(type) {
            if (!_adminEditingComedianId) return;
            const meta = getAudioMeta(type);
            _audioUploadType  = type;
            _audioComedianId  = _adminEditingComedianId;
            _audioUploadData  = null;
            _audioUploadName  = null;

            document.getElementById('audioUploadTitle').textContent =
                meta.icon + ' Ajouter : ' + meta.label;
            const limitLabel = meta.maxDur === 60 ? '1 min max' : '1 min 30 max';
            const limitShort = meta.maxDur === 60 ? 'Max 1:00' : 'Max 1:30';
            document.getElementById('audioUploadHint').textContent =
                'Format MP3 uniquement — durée maximale : ' + limitLabel;
            const dropHint2 = document.getElementById('audioDropHint');
            if (dropHint2) dropHint2.textContent = 'Format MP3 uniquement · ' + limitShort;
            document.getElementById('audioValidationMsg').style.display = 'none';
            document.getElementById('audioPreviewSection').style.display = 'none';
            document.getElementById('audioConfirmBtn').disabled = true;
            document.getElementById('audioFileInput').value = '';
            const preview = document.getElementById('audioUploadPreview');
            preview.pause();
            preview.src = '';

            openModal('audioUploadModal');
        }

        const AUDIO_ADMIN_DOM = {
            presentation: { previewId: 'adminAudioPresPreview',      statusId: 'adminAudioPresStatus' },
            demo:         { previewId: 'adminAudioDemoPreview',      statusId: 'adminAudioDemoStatus' },
            demo_promo:   { previewId: 'adminAudioDemoPromoPreview', statusId: 'adminAudioDemoPromoStatus' },
            demo_joue:    { previewId: 'adminAudioDemoJouePreview',  statusId: 'adminAudioDemoJoueStatus' },
            demo_instit:  { previewId: 'adminAudioDemoInstitPreview',statusId: 'adminAudioDemoInstitStatus' },
        };

        async function deleteAudioAdmin(type) {
            if (!_adminEditingComedianId) return;
            const meta = getAudioMeta(type);
            if (!confirm('Supprimer la ' + meta.label + ' ?')) return;
            await SupabaseDB.reloadComedians();
            const comedian = AppState.comedians.find(c => c.id === _adminEditingComedianId);
            if (!comedian) return;
            const NEW_DEMO_COLS = {
                audioDemoPromo:  'audio_demo_promo_url',
                audioDemoJoue:   'audio_demo_joue_url',
                audioDemoInstit: 'audio_demo_instit_url',
            };
            if (NEW_DEMO_COLS[meta.field]) {
                await SupabaseDB.updateAudioField(comedian.id, NEW_DEMO_COLS[meta.field], null);
                comedian[meta.field] = null;
            } else {
                comedian[meta.field] = null;
                await SupabaseDB.upsertComedian(comedian);
            }
            await broadcastUpdate('comedians');
            const dom = AUDIO_ADMIN_DOM[type] || AUDIO_ADMIN_DOM['demo'];
            const preview = document.getElementById(dom.previewId);
            const status  = document.getElementById(dom.statusId);
            if (preview) { preview.src = ''; preview.style.display = 'none'; }
            if (status)  { status.textContent = 'Aucune ' + meta.label.toLowerCase(); status.style.color = ''; }
        }

        function showAudioMsg(text, type) {
            const el = document.getElementById('audioValidationMsg');
            el.textContent = text;
            el.style.display = 'block';
            if (type === 'error') {
                el.style.background = 'rgba(231,76,60,0.15)';
                el.style.border     = '1px solid #e74c3c';
                el.style.color      = '#e74c3c';
            } else {
                el.style.background = 'rgba(46,204,113,0.15)';
                el.style.border     = '1px solid #2ecc71';
                el.style.color      = '#2ecc71';
            }
        }

        document.getElementById('audioFileInput').addEventListener('change', function(e) {
            const file = e.target.files[0];
            document.getElementById('audioPreviewSection').style.display = 'none';
            document.getElementById('audioConfirmBtn').disabled = true;
            _audioUploadData = null;
            _audioUploadName = null;

            if (!file) return;

            const isMp3 = file.type === 'audio/mp3'
                       || file.type === 'audio/mpeg'
                       || file.name.toLowerCase().endsWith('.mp3');
            if (!isMp3) {
                showAudioMsg('❌ Format invalide. Seuls les fichiers MP3 sont acceptés.', 'error');
                return;
            }

            const tempAudio = document.createElement('audio');
            const objectUrl = URL.createObjectURL(file);
            tempAudio.src   = objectUrl;

            tempAudio.addEventListener('loadedmetadata', function() {
                URL.revokeObjectURL(objectUrl);
                const duration = tempAudio.duration;

                if (!isFinite(duration) || isNaN(duration)) {
                    showAudioMsg('⚠️ Impossible de lire la durée. Vérifiez que le fichier MP3 est valide.', 'error');
                    return;
                }

                const maxDur = getAudioMeta(_audioUploadType).maxDur;
                if (duration > maxDur) {
                    const mins = Math.floor(duration / 60);
                    const secs = Math.round(duration % 60);
                    const maxLabel = maxDur === 60 ? '1 min' : '1 min 30';
                    showAudioMsg(
                        `❌ Durée trop longue : ${mins}m${secs < 10 ? '0' : ''}${secs}s. Maximum autorisé : ${maxLabel}.`,
                        'error'
                    );
                    return;
                }

                const reader = new FileReader();
                reader.onload = function(ev) {
                    _audioUploadData = ev.target.result;

                    const comedians = AppState.comedians.slice();
                    const comedian  = comedians.find(c => c.id === _audioComedianId);
                    const name = comedian ? comedian.name : 'comedien';
                    _audioUploadName = buildAudioFilename(name, _audioUploadType);

                    const mins = Math.floor(duration / 60);
                    const secs = Math.round(duration % 60);
                    showAudioMsg(
                        `✅ Fichier valide — Durée : ${mins}m${secs < 10 ? '0' : ''}${secs}s`,
                        'success'
                    );

                    const preview = document.getElementById('audioUploadPreview');
                    preview.src   = _audioUploadData;
                    document.getElementById('audioFilename').textContent =
                        '📁 Sera enregistré sous : ' + _audioUploadName;
                    document.getElementById('audioPreviewSection').style.display = 'block';
                    document.getElementById('audioConfirmBtn').disabled = false;
                };
                reader.readAsDataURL(file);
            });

            tempAudio.addEventListener('error', function() {
                URL.revokeObjectURL(objectUrl);
                showAudioMsg('❌ Fichier MP3 illisible ou corrompu.', 'error');
            });
        });

        async function confirmAudioUpload() {
            if (!_audioUploadData || !_audioComedianId) return;

            await SupabaseDB.reloadComedians();
            const comedian = AppState.comedians.find(c => String(c.id) === String(_audioComedianId));
            if (!comedian) return;

            const confirmBtn = document.getElementById('audioConfirmBtn');
            if (confirmBtn) { confirmBtn.disabled = true; confirmBtn.textContent = 'Upload en cours…'; }

            try {
                const normalizeCheck = document.getElementById('audioNormalizeCheck');
                const shouldNormalize = normalizeCheck && normalizeCheck.checked;
                let _dataToUpload = _audioUploadData;
                _audioUploadData = null;
                if (shouldNormalize) {
                    const normBtn = document.getElementById('audioConfirmBtn');
                    if (normBtn) normBtn.textContent = 'Normalisation…';
                    try { _dataToUpload = await normalizeAudio(_dataToUpload); }
                    catch(ne) { showAudioMsg('⚠️ Normalisation échouée, upload sans normalisation.', 'warning'); }
                }
                const filename = _audioUploadName.split('/').pop();
                const publicUrl = await SupabaseDB.uploadAudio(_dataToUpload, filename);

                const meta = getAudioMeta(_audioUploadType);

                const NEW_DEMO_COLUMNS = {
                    audioDemoPromo:  'audio_demo_promo_url',
                    audioDemoJoue:   'audio_demo_joue_url',
                    audioDemoInstit: 'audio_demo_instit_url',
                };
                if (NEW_DEMO_COLUMNS[meta.field]) {
                    await SupabaseDB.updateAudioField(comedian.id, NEW_DEMO_COLUMNS[meta.field], publicUrl);
                    comedian[meta.field] = publicUrl;
                } else {
                    comedian[meta.field] = publicUrl;
                    await SupabaseDB.upsertComedian(comedian);
                }
                await broadcastUpdate('comedians');
                closeModal('audioUploadModal');

            const meta2 = getAudioMeta(_audioUploadType);

            if (currentUser && currentUser.role === 'comedian') {
                loadComedianProfile();
            } else if (currentUser && (currentUser.role === 'admin' || currentUser.role === 'studio' || currentUser.role === 'manager')) {
                const dom = AUDIO_ADMIN_DOM[_audioUploadType] || AUDIO_ADMIN_DOM['demo'];
                const preview = document.getElementById(dom.previewId);
                const status  = document.getElementById(dom.statusId);
                if (preview && status) {
                    preview.src = _dataToUpload || '';
                    preview.style.display = 'block';
                    status.textContent = '✅ ' + filename;
                    status.style.color = '#2ecc71';
                }
            }

            showToast('✅ ' + meta2.label + ' enregistrée !');
            } catch(err) {
                alert('❌ Erreur upload: ' + (err.message || err));
            } finally {
                if (confirmBtn) { confirmBtn.disabled = false; confirmBtn.textContent = '✅ Confirmer'; }
            }
        }

        async function deleteAudio(comedianId, type) {
            const meta = getAudioMeta(type);
            if (!confirm('Supprimer : ' + meta.label + ' ?')) return;
            await SupabaseDB.reloadComedians();
            const comedian = AppState.comedians.find(c => String(c.id) === String(comedianId));
            if (!comedian) return;
            const NEW_DEMO_COLUMNS = {
                audioDemoPromo:  'audio_demo_promo_url',
                audioDemoJoue:   'audio_demo_joue_url',
                audioDemoInstit: 'audio_demo_instit_url',
            };
            if (NEW_DEMO_COLUMNS[meta.field]) {
                await SupabaseDB.updateAudioField(comedian.id, NEW_DEMO_COLUMNS[meta.field], null);
                comedian[meta.field] = null;
            } else {
                comedian[meta.field] = null;
                await SupabaseDB.upsertComedian(comedian);
            }
            await broadcastUpdate('comedians');
            if (currentUser && currentUser.role === 'comedian') loadComedianProfile();
        }

        function loadAbsences() {
            const container = document.getElementById('absencesList') || document.getElementById('absencesModalContent');
            if (!container) return;

            const comedians = AppState.comedians.slice().filter(c => c.active);
            const absencesHTML = [];

            comedians.forEach(comedian => {
                if (comedian.absences && comedian.absences.length > 0) {
                    comedian.absences.forEach(absence => {
                        if (isAbsenceActive(absence)) {
                            const startTime = absence.startTime ? ` \u00e0 ${absence.startTime}` : '';
                            const endTime = absence.endTime ? ` \u00e0 ${absence.endTime}` : '';
                            const comment = absence.comment ? `<br><small style="color: var(--text-muted); font-style: italic;">${absence.comment}</small>` : '';
                            absencesHTML.push({
                                date: new Date(absence.start),
                                html: `<div class="absence-item">
                                    <strong>${comedian.name}</strong><br>
                                    Du ${formatDate(absence.start)}${startTime} au ${formatDate(absence.end)}${endTime}
                                    ${comment}
                                </div>`
                            });
                        }
                    });
                }
            });

            if (absencesHTML.length === 0) {
                container.innerHTML = '<p style="color: var(--text-muted); text-align:center; padding:20px;">Aucune absence pr\u00e9vue</p>';
            } else {
                absencesHTML.sort((a, b) => a.date - b.date);
                container.innerHTML = absencesHTML.map(a => a.html).join('');
            }
        }

        function formatDate(dateStr) {
            const date = new Date(dateStr);
            return date.toLocaleDateString('fr-FR', { day: 'numeric', month: 'long', year: 'numeric' });
        }

        function applyFilters() {
            applyFiltersStudio();
        }

        function applyFiltersStudio(debounced) {
            if (debounced) {
                clearTimeout(_appFilterDebounceTimer);
                _appFilterDebounceTimer = setTimeout(function() { applyFiltersStudio(false); }, 150);
                return;
            }
            const searchName = document.getElementById('searchName').value.toLowerCase();
            const filterFemme = document.getElementById('filterFemme').checked;
            const filterHomme = document.getElementById('filterHomme').checked;
            const filterSeances = document.getElementById('filterSeances').checked;
            const filterVoixOff = document.getElementById('filterVoixOff').checked;
            const filterVoixJouee = document.getElementById('filterVoixJouee').checked;
            const filterVoixEnfant = document.getElementById('filterVoixEnfant').checked;
            const filterChant = document.getElementById('filterChant').checked;
            const filterInterne = document.getElementById('filterInterne') ? document.getElementById('filterInterne').checked : false;
            const filterExterne = document.getElementById('filterExterne') ? document.getElementById('filterExterne').checked : false;
            const filterVoixUrgente = document.getElementById('filterVoixUrgente') ? document.getElementById('filterVoixUrgente').checked : false;
            const filterDispo = document.getElementById('filterDisponibilite').checked;
            
            const filterVoixJeune = document.getElementById('filterVoixJeune') ? document.getElementById('filterVoixJeune').checked : false;
            const filterVoixAdulte = document.getElementById('filterVoixAdulte') ? document.getElementById('filterVoixAdulte').checked : false;
            const filterVoixMature = document.getElementById('filterVoixMature') ? document.getElementById('filterVoixMature').checked : false;
            const filterVoixAccent = document.getElementById('filterVoixAccent') ? document.getElementById('filterVoixAccent').checked : false;
            const filterTimbreGrave = document.getElementById('filterTimbreGrave') ? document.getElementById('filterTimbreGrave').checked : false;
            const filterTimbreMedium = document.getElementById('filterTimbreMedium') ? document.getElementById('filterTimbreMedium').checked : false;
            const filterTimbreAigu = document.getElementById('filterTimbreAigu') ? document.getElementById('filterTimbreAigu').checked : false;
            const filterTimbreTexture = document.getElementById('filterTimbreTexture') ? document.getElementById('filterTimbreTexture').checked : false;
            const filterStyleDynamique = document.getElementById('filterStyleDynamique') ? document.getElementById('filterStyleDynamique').checked : false;
            const filterStylePose = document.getElementById('filterStylePose') ? document.getElementById('filterStylePose').checked : false;
            const filterStyleNaturel = document.getElementById('filterStyleNaturel') ? document.getElementById('filterStyleNaturel').checked : false;
            const filterStyleInstitutionnel = document.getElementById('filterStyleInstitutionnel') ? document.getElementById('filterStyleInstitutionnel').checked : false;
            
            let comedians = AppState.comedians.slice()
                .filter(c => c.active);
            
            if (searchName) {
                comedians = comedians.filter(c => c.name.toLowerCase().includes(searchName));
            }
            
            if (filterFemme || filterHomme) {
                comedians = comedians.filter(c => 
                    (filterFemme && c.sexe === 'Femme') || (filterHomme && c.sexe === 'Homme')
                );
            }
            
            const hasCheckboxFilters = filterFemme || filterHomme || filterSeances || 
                                       filterVoixOff || filterVoixJouee || filterVoixEnfant || filterChant ||
                                       filterInterne || filterExterne || filterVoixUrgente ||
                                       filterVoixJeune || filterVoixAdulte || filterVoixMature || filterVoixAccent ||
                                       filterTimbreGrave || filterTimbreMedium || filterTimbreAigu || filterTimbreTexture ||
                                       filterStyleDynamique || filterStylePose || filterStyleNaturel || filterStyleInstitutionnel;
            
            if (filterSeances) {
                comedians = comedians.filter(c => c.seances_dirigees);
            }
            if (filterVoixOff) {
                comedians = comedians.filter(c => c.voix_off);
            }
            if (filterVoixJouee) {
                comedians = comedians.filter(c => c.voix_jouee);
            }
            if (filterVoixEnfant) {
                comedians = comedians.filter(c => c.voix_enfant);
            }
            if (filterChant) {
                comedians = comedians.filter(c => c.chant);
            }
            
            if (filterVoixJeune) {
                comedians = comedians.filter(c => c.voix_jeune);
            }
            if (filterVoixAdulte) {
                comedians = comedians.filter(c => c.voix_adulte);
            }
            if (filterVoixMature) {
                comedians = comedians.filter(c => c.voix_mature);
            }
            if (filterVoixAccent) {
                comedians = comedians.filter(c => c.voix_accent);
            }
            
            if (filterTimbreGrave) {
                comedians = comedians.filter(c => c.timbre_grave);
            }
            if (filterTimbreMedium) {
                comedians = comedians.filter(c => c.timbre_medium);
            }
            if (filterTimbreAigu) {
                comedians = comedians.filter(c => c.timbre_aigu);
            }
            if (filterTimbreTexture) {
                comedians = comedians.filter(c => c.timbre_texture);
            }
            
            if (filterStyleDynamique) {
                comedians = comedians.filter(c => c.style_dynamique);
            }
            if (filterStylePose) {
                comedians = comedians.filter(c => c.style_pose);
            }
            if (filterStyleNaturel) {
                comedians = comedians.filter(c => c.style_naturel);
            }
            if (filterStyleInstitutionnel) {
                comedians = comedians.filter(c => c.style_institutionnel);
            }
            
            if (filterInterne || filterExterne) {
                comedians = comedians.filter(c => {
                    if (filterInterne && c.classement === 'interne') return true;
                    if (filterExterne && c.classement === 'externe') return true;
                    return false;
                });
            }
            
            if (filterVoixUrgente) {
                comedians = comedians.filter(c => c.voixUrgente);
            }
            
            if (filterDispo) {
                const dateStart = document.getElementById('dispoDateStart').value;
                const dateEnd = document.getElementById('dispoDateEnd').value;
                
                if (dateStart && dateEnd) {
                    comedians = comedians.filter(c => isComedianAvailable(c, dateStart, dateEnd));
                }
            }
            
            if (hasCheckboxFilters && !searchName) {
                comedians = shuffleArray(comedians);
            }
            
            displayComedians(comedians);
        }

        function isComedianAvailable(comedian, startDate, endDate) {
            if (!comedian.absences || comedian.absences.length === 0) {
                return true;
            }
            
            const start = new Date(startDate);
            const end = new Date(endDate);
            
            return !comedian.absences.some(absence => {
                const absStart = new Date(absence.start);
                const absEnd = new Date(absence.end);
                
                return absStart <= end && absEnd >= start;
            });
        }

        function shuffleArray(array) {
            const shuffled = [...array];
            for (let i = shuffled.length - 1; i > 0; i--) {
                const j = Math.floor(Math.random() * (i + 1));
                [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
            }
            return shuffled;
        }

        function toggleDisponibiliteFilter() {
            const checkbox = document.getElementById('filterDisponibilite');
            const selector = document.getElementById('disponibiliteSelector');
            
            if (checkbox.checked) {
                selector.classList.remove('hidden');
            } else {
                selector.classList.add('hidden');
                document.getElementById('dispoDateStart').value = '';
                document.getElementById('dispoDateEnd').value = '';
            }
            applyFiltersStudio();
        }

        function loadAbsencesModal() {
            const comedians = AppState.comedians.slice()
                .filter(c => c.active);
            const container = document.getElementById('absencesModalContent');
            container.innerHTML = '';
            
            let hasAbsences = false;
            const absencesHTML = [];
            
            comedians.forEach(comedian => {
                if (comedian.absences && comedian.absences.length > 0) {
                    comedian.absences.forEach(absence => {
                        if (isAbsenceActive(absence)) {
                            hasAbsences = true;
                            const startTime = absence.startTime ? ` à ${absence.startTime}` : '';
                            const endTime = absence.endTime ? ` à ${absence.endTime}` : '';
                            const comment = absence.comment ? `<br><small style="color: var(--text-muted); font-style: italic;">${absence.comment}</small>` : '';
                            
                            absencesHTML.push({
                                date: new Date(absence.start),
                                html: `
                                    <div class="card-absence-item" style="margin: 10px 0;">
                                        <strong style="color: var(--accent-light);">${comedian.name}</strong><br>
                                        Du ${formatDate(absence.start)}${startTime} au ${formatDate(absence.end)}${endTime}
                                        ${comment}
                                    </div>
                                `
                            });
                        }
                    });
                }
            });
            
            if (!hasAbsences) {
                container.innerHTML = '<p style="text-align: center; color: var(--text-muted); padding: 40px;">Aucune absence prévue</p>';
            } else {
                absencesHTML.sort((a, b) => a.date - b.date);
                container.innerHTML = absencesHTML.map(a => a.html).join('');
            }
        }

        function loadAdminAbsences() {
            const comedians = AppState.comedians.slice();
            const container = document.getElementById('adminAbsencesList');
            const showPast = document.getElementById('adminShowPastAbsences').checked;
            container.innerHTML = '';
            
            let hasAbsences = false;
            const absencesByComedian = [];
            
            comedians.forEach(comedian => {
                if (comedian.absences && comedian.absences.length > 0) {
                    const absences = comedian.absences.filter(absence => {
                        if (showPast) return true;
                        return isAbsenceActive(absence);
                    });
                    
                    if (absences.length > 0) {
                        hasAbsences = true;
                        absencesByComedian.push({
                            comedian: comedian,
                            absences: absences
                        });
                    }
                }
            });
            
            if (!hasAbsences) {
                container.innerHTML = '<div class="empty-state"><div class="icon">📅</div><h3>Aucune absence</h3><p>' + 
                    (showPast ? 'Aucune absence enregistrée' : 'Aucune absence prévue') + '</p></div>';
                return;
            }
            
            absencesByComedian.forEach(item => {
                const section = document.createElement('div');
                section.className = 'role-section';
                section.style.borderLeftColor = item.comedian.active ? 'var(--success)' : 'var(--text-muted)';
                
                const statusBadge = item.comedian.active ? 
                    '<span class="tag status-active">Actif</span>' : 
                    '<span class="tag status-inactive">Inactif</span>';
                
                let absencesHTML = '';
                item.absences.forEach(absence => {
                    const isPast = !isAbsenceActive(absence);
                    const startTime = absence.startTime ? ` à ${absence.startTime}` : '';
                    const endTime = absence.endTime ? ` à ${absence.endTime}` : '';
                    const comment = absence.comment ? `<br><small style="color: var(--text-muted); font-style: italic;">${absence.comment}</small>` : '';
                    const pastStyle = isPast ? 'opacity: 0.5;' : '';
                    
                    absencesHTML += `
                        <div class="card-absence-item" style="${pastStyle}">
                            <div style="display: flex; justify-content: space-between; align-items: start;">
                                <div style="flex: 1;">
                                    <strong>Du ${formatDate(absence.start)}${startTime}</strong><br>
                                    <strong>au ${formatDate(absence.end)}${endTime}</strong>
                                    ${comment}
                                    ${isPast ? '<br><small style="color: var(--text-muted);">✓ Terminée</small>' : ''}
                                </div>
                                <button class="btn-icon btn-small" onclick="deleteAbsence(${item.comedian.id}, ${absence.id})" 
                                        style="background: #c0392b; margin-left: 10px;">
                                    🗑️
                                </button>
                            </div>
                        </div>
                    `;
                });
                
                section.innerHTML = `
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                        <h3>${item.comedian.name} ${statusBadge}</h3>
                        <button class="btn-icon btn-small" onclick="openAdminQuickAbsence(${item.comedian.id})">
                            ➕ Ajouter une absence
                        </button>
                    </div>
                    ${absencesHTML}
                `;
                
                container.appendChild(section);
            });
        }

        async function deleteAbsence(comedianId, absenceId) {
            if (confirm('Supprimer cette absence ?')) {
                try {
                    await SupabaseDB.deleteAbsenceDirect(comedianId, absenceId);
                    loadAdminAbsences();
                    showToast('✅ Absence supprimée');
                } catch(err) {
                    alert('Erreur: ' + (err.message || err));
                }
            }
        }

        function loadLogs() {
            const logs = AppState.logs.slice();
            const tbody = document.querySelector('#logsTable tbody');
            tbody.innerHTML = '';
            
            if (logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">Aucun historique</td></tr>';
                return;
            }
            
            logs.forEach(log => {
                const tr = document.createElement('tr');
                const date = new Date(log.timestamp);
                tr.innerHTML = `
                    <td>${date.toLocaleString('fr-FR')}</td>
                    <td>${log.username}</td>
                    <td>${getRoleLabel(log.role)}</td>
                    <td>${log.action}</td>
                `;
                tbody.appendChild(tr);
            });
        }

        async function clearLogs() {
            if (confirm('Supprimer tout l\'historique ?')) {
                await SupabaseDB.clearLogs();
                loadLogs();
                showToast('✓ Historique supprimé');
            }
        }

        async function sendUserCredentials(userId) {
            const user = AppState.users.find(u => u.id === userId);
            if (!user) { alert('Utilisateur non trouvé'); return; }
            if (!user.email) { alert('❌ Cet utilisateur n\'a pas d\'email renseigné.\nModifiez-le d\'abord pour ajouter son adresse email.'); return; }

            let plainPwd;
            if (!user.password) {
                plainPwd            = Utils.generateSecurePassword(12);
                user.password       = await hashPassword(plainPwd);
                user._plainPassword = plainPwd;
                await SupabaseDB.upsertUser(user);
                await broadcastUpdate('users');
            } else if (user._plainPassword) {
                plainPwd = user._plainPassword;
            } else {
                alert('⚠️ Cet utilisateur a déjà un mot de passe.\n\nLe mot de passe en clair n\'est plus disponible car la page a été rechargée.\n\nPour renvoyer les identifiants, modifiez l\'utilisateur et définissez un nouveau mot de passe manuellement.');
                return;
            }

            const studioName = AppState.settings.studioName || 'Catalogue Comédiens';
            const template   = getTemplate('identifiants');
            const subject    = Utils.replaceEmailVariables(template.subject, { studio: studioName });
            const body       = Utils.replaceEmailVariables(template.body, {
                prenom:   user.username,
                username: user.username,
                password: plainPwd,
                lien:     window.location.origin,
                studio:   studioName,
                role:     CONFIG.ROLE_LABELS[user.role] || user.role
            });

            Utils.simulateEmail(user.email, subject, body);

            addLog(CONFIG.LOG_TYPES.EMAIL_SENT, `Identifiants envoyés à ${user.username} (${user.email})`, 'user', userId);
            alert(`✅ Email préparé pour ${user.email}\n\nIdentifiant : ${user.username}\nMot de passe : ${plainPwd}\n\nVotre client mail s\'est ouvert.\n⚠️ Notez ce mot de passe, il ne sera plus affiché après rechargement.`);
        }

        async function sendCredentials(comedianId) {
            const comedians = AppState.comedians.slice();
            const comedian = comedians.find(c => c.id === comedianId);
            
            if (!comedian) {
                alert('Comédien non trouvé');
                return;
            }

            let plainPwd = null;
            if (!comedian.username) {
                comedian.username = comedian.email.split('@')[0];
            }
            if (!comedian.password) {
                plainPwd = Utils.generateSecurePassword(12);
                comedian.password = await hashPassword(plainPwd);
                comedian._plainPassword = plainPwd;
            } else {
                plainPwd = comedian._plainPassword || null;
                if (!plainPwd) {
                    alert('⚠️ Les identifiants de ce comédien existent déjà en base.\n\nLe mot de passe en clair n\'est plus disponible car la page a été rechargée.\n\nPour renvoyer les identifiants, modifiez le comédien et définissez un nouveau mot de passe.');
                    return;
                }
            }

            const existingUser = AppState.users.find(u => u.comedianId === comedian.id);
            if (existingUser) {
                existingUser.password = comedian.password;
                await SupabaseDB.upsertUser(existingUser);
            } else {
                const newUser = {
                    username:   comedian.username,
                    email:      comedian.email,
                    password:   comedian.password,
                    role:       'comedian',
                    comedianId: comedian.id,
                    active:     true
                };
                await SupabaseDB.upsertUser(newUser);
            }
            
            const template   = getTemplate('identifiants');
            const studioName = AppState.settings.studioName || 'Catalogue Comédiens';
            const emailBody  = Utils.replaceEmailVariables(template.body, {
                prenom:   comedian.name.split(' ')[0],
                username: comedian.username,
                password: plainPwd,
                lien:     window.location.origin,
                studio:   studioName
            });
            const subject = Utils.replaceEmailVariables(template.subject, { studio: studioName });
            
            Utils.simulateEmail(comedian.email, subject, emailBody);
            
            comedian.identifiantsSent = true;
            await SupabaseDB.upsertComedian(comedian);
            await broadcastUpdate('comedians');
            await broadcastUpdate('users');
            
            addLog(CONFIG.LOG_TYPES.EMAIL_SENT, `Identifiants envoyés à ${comedian.name}`, 'comedian', comedianId);
            
            alert(`✅ Email préparé pour ${comedian.email}\n\nIdentifiant : ${comedian.username}\nMot de passe : ${plainPwd}\n\n⚠️ Notez ce mot de passe, il ne sera plus affiché après rechargement de la page.`);
            
            if (typeof loadComediansForAdmin === 'function') {
                loadComediansForAdmin();
            }
        }

        function openUrgentRequestModal(comedianId) {
            document.getElementById('urgentComedianId').value = comedianId;
            openModal('urgentRequestModal');
        }

        function sendUrgentRequest() {
            try {
            const comedianId = parseInt(document.getElementById('urgentComedianId').value);
            const comedians = AppState.comedians.slice();
            const comedian = comedians.find(c => c.id === comedianId);
            if (!comedian) return;

            const deliveryTime  = document.getElementById('urgentDeliveryTime').value;
            const texte         = document.getElementById('urgentInfos').value.trim();
            const odp           = document.getElementById('urgentOdp')     ? document.getElementById('urgentOdp').value.trim()     : '';
            const clientName    = document.getElementById('urgentClient')  ? document.getElementById('urgentClient').value.trim()  : '';

            if (!deliveryTime) {
                alert('Veuillez renseigner l\'heure de livraison souhaitée.');
                return;
            }

            const prenom      = comedian.name.split(' ')[0];
            const studioName  = AppState.settings.studioName || 'Catalogue Comediens';
            const expediteur  = currentUser ? currentUser.username : studioName;

            const odp_subject  = odp ? ` [ODP ${odp}]` : '';
            const odp_line     = odp ? `📋 ODP : ${odp}\n` : '';
            const client_line  = clientName ? `👤 CLIENT : ${clientName}\n` : '';

            const tpl = getTemplate('commande_urgente');
            const vars = { prenom, nom: comedian.name, email: comedian.email,
                mission: '', heure_livraison: deliveryTime, texte: texte || '',
                studio: studioName, expediteur, client: clientName, odp,
                odp_subject, odp_line, client_line,
                date_livraison: '', nb_comediens: '', liste_comediens: '', lien_selection: '', message: '', role: '' };

            function applyVars(str) {
                let r = str;
                Object.entries(vars).forEach(([k,v]) => { r = r.replace(new RegExp('{{' + k + '}}', 'g'), v); });
                return r;
            }

            const subject = tpl ? applyVars(tpl.subject) : 'Demande de voix urgente';
            const body    = tpl ? applyVars(tpl.body) : ('Bonjour ' + prenom + ',\n\nCordialement,\n' + studioName);

            const mailto = 'mailto:' + encodeURIComponent(comedian.email)
                + '?subject=' + encodeURIComponent(subject)
                + '&body=' + encodeURIComponent(body);

            const link = document.createElement('a');
            link.href = mailto;
            link.click();

            addLog(CONFIG.LOG_TYPES.EMAIL_SENT, `Demande urgente pour ${comedian.name}`, 'comedian', comedianId);
            closeModal('urgentRequestModal');
            document.getElementById('urgentDeliveryTime').value = '';
            document.getElementById('urgentInfos').value = '';
            if (document.getElementById('urgentOdp'))    document.getElementById('urgentOdp').value = '';
            if (document.getElementById('urgentClient')) document.getElementById('urgentClient').value = '';
            } catch(err) {
                console.error('sendUrgentRequest:', err);
                alert("Erreur lors de l'envoi de la demande.");
            }
        }

        // ── Un seul audio à la fois ─────────────────────────────
        document.addEventListener('play', function(e) {
            if (e.target.tagName !== 'AUDIO') return;
            document.querySelectorAll('audio').forEach(function(a) {
                if (a !== e.target) { a.pause(); }
            });
        }, true); // capture phase pour intercepter avant l'élément

        (function() { var _run2 = function() {
            const searchName = document.getElementById('searchName');
            if (searchName) {
                searchName.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        applyFiltersStudio();
                    }
                });
            }
            
            const dbSearch = document.getElementById('databaseSearch');
            if (dbSearch) {
                dbSearch.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        filterDatabase();
                    }
                });
            }
        }; if (document.readyState === 'loading') { document.addEventListener('DOMContentLoaded', _run2); } else { _run2(); } })();

        function openModal(modalId) {
            if (modalId === 'absencesModal') {
                loadAbsencesModal();
            }
            const el = document.getElementById(modalId);
            if (!el) return;
            const activeModals = document.querySelectorAll('.modal.active');
            let maxZ = 1000;
            activeModals.forEach(m => {
                const z = parseInt(m.style.zIndex || getComputedStyle(m).zIndex) || 1000;
                if (z > maxZ) maxZ = z;
            });
            el.style.zIndex = String(maxZ + 10);
            el.classList.add('active');
        }

        function resetModalZIndex(modalId) {
            const el = document.getElementById(modalId);
            if (el) el.style.zIndex = '';
        }

        function closeModal(modalId) {
            const el = document.getElementById(modalId);
            if (!el) return;
            el.classList.remove('active');
            el.style.zIndex = ''; // reset z-index pour la prochaine ouverture
        }

        let studioSelection     = [];
        let selectionPanelOpen  = false;   // ouvert/fermé

        function toggleSelectionPanel() {
            selectionPanelOpen = !selectionPanelOpen;
            const body    = document.getElementById('selectionPanelBody');
            const chevron = document.getElementById('selectionPanelChevron');
            if (!body) return;
            body.style.display    = selectionPanelOpen ? 'block' : 'none';
            if (chevron) chevron.style.transform = selectionPanelOpen ? 'rotate(180deg)' : '';
        }

        function toggleStudioSelection(comedianId, checkbox) {
            const wasEmpty = studioSelection.length === 0;
            if (checkbox.checked) {
                if (!studioSelection.includes(comedianId)) studioSelection.push(comedianId);
                if (wasEmpty && !selectionPanelOpen) toggleSelectionPanel();
            } else {
                studioSelection = studioSelection.filter(id => id !== comedianId);
            }
            updateSelectionPanel();
        }

        function removeFromStudioSelection(comedianId) {
            studioSelection = studioSelection.filter(id => id !== comedianId);
            const cb = document.querySelector(`.comedian-checkbox-studio[data-comedian-id="${comedianId}"]`);
            if (cb) cb.checked = false;
            updateSelectionPanel();
        }

        function clearStudioSelection() {
            studioSelection = [];
            document.querySelectorAll('.comedian-checkbox-studio').forEach(cb => { cb.checked = false; });
            updateSelectionPanel();
            if (selectionPanelOpen) toggleSelectionPanel();
        }

        function updateSelectionPanel() {
            const n = studioSelection.length;

            const badge = document.getElementById('selectionPanelBadge');
            if (badge) {
                badge.textContent = n;
                badge.style.background = n > 0 ? 'var(--accent)' : '#555';
            }

            const status = document.getElementById('selectionPanelStatus');
            if (status) {
                status.textContent = n === 0 ? 'Aucun comédien sélectionné'
                    : n === 1 ? '1 comédien — cliquez pour vérifier'
                    : `${n} comédiens — cliquez pour vérifier`;
            }

            const sendBtn  = document.getElementById('selectionSendBtn');
            const clearBtn = document.getElementById('selectionClearBtn');
            if (sendBtn)  sendBtn.style.display  = n > 0 ? 'inline-block' : 'none';
            if (clearBtn) clearBtn.style.display = n > 0 ? 'inline-block' : 'none';

            if (selectionPanelOpen) renderSelectionPanelList();

            const panel = document.getElementById('studioSelectionPanel');
            if (panel) {
                panel.style.borderColor = n > 0 ? 'var(--accent)' : 'var(--border)';
            }
        }

        function renderSelectionPanelList() {
            const empty  = document.getElementById('selectionPanelEmpty');
            const list   = document.getElementById('selectionPanelList');
            if (!empty || !list) return;

            if (studioSelection.length === 0) {
                empty.style.display = 'block';
                list.style.display  = 'none';
                list.innerHTML = '';
                return;
            }

            empty.style.display = 'none';
            list.style.display  = 'block';

            const comedians = AppState.comedians.slice();
            const selected  = studioSelection
                .map(id => comedians.find(c => c.id === id))
                .filter(Boolean);

            list.innerHTML = '';

            selected.forEach((comedian, idx) => {
                const presData = getAudioData(comedian.audioPresentation);
                const demoData = getAudioData(comedian.audioDemo);

                const audioPres = presData ? `
                    <div class="audio-block" style="margin-top:8px;">
                        <span class="audio-label">🎤 Présentation</span>
                        <audio controls class="audio-player" style="margin:4px 0 0;">
                            <source src="${presData}" type="audio/mpeg">
                        </audio>
                    </div>` : '';

                const audioDemo = demoData ? `
                    <div class="audio-block" style="margin-top:8px;">
                        <span class="audio-label">🎵 Démo</span>
                        <audio controls class="audio-player" style="margin:4px 0 0;">
                            <source src="${demoData}" type="audio/mpeg">
                        </audio>
                    </div>` : '';

                const tags = [];
                if (comedian.voix_off)    tags.push('Voix off');
                if (comedian.voix_jouee)  tags.push('Voix jouée');
                if (comedian.voix_enfant) tags.push('Voix enfant');
                if (comedian.chant)       tags.push('Chant');
                if (comedian.voix_jeune)  tags.push('Voix jeune');
                if (comedian.voix_adulte) tags.push('Voix adulte');
                if (comedian.voix_mature) tags.push('Voix mature');
                const tagsHTML = tags.map(t => `<span class="tag" style="font-size:0.75em; padding:3px 8px;">${t}</span>`).join('');

                const row = document.createElement('div');
                row.style.cssText = `
                    display: grid;
                    grid-template-columns: 32px 64px 1fr auto;
                    gap: 14px;
                    align-items: start;
                    padding: 14px 0;
                    border-top: 1px solid var(--border);
                `;
                const numEl = document.createElement('div');
                numEl.style.cssText = 'width:32px;height:32px;border-radius:50%;background:var(--accent);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:0.9em;flex-shrink:0;margin-top:4px;';
                numEl.textContent = idx + 1;

                const photoEl = document.createElement('img');
                photoEl.src = comedian.profilePic || `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='64' height='64'%3E%3Crect fill='%230f0f18' width='64' height='64'/%3E%3Ctext x='50%25' y='50%25' font-size='28' text-anchor='middle' dy='.3em' fill='%23e8445a'%3E${comedian.name.charAt(0)}%3C/text%3E%3C/svg%3E`;
                photoEl.alt = comedian.name;
                photoEl.style.cssText = 'width:64px;height:64px;border-radius:10px;object-fit:cover;border:2px solid var(--border);';

                const infoEl = document.createElement('div');
                infoEl.innerHTML = `
                    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px;">
                        <strong style="color:var(--text);font-size:1em;">${comedian.name}</strong>
                        ${comedian.voixUrgente ? '<span style="background:rgba(232,68,90,0.2);color:var(--accent);font-size:0.7em;padding:2px 6px;border-radius:10px;border:1px solid rgba(232,68,90,0.4);">🔥 Urgent</span>' : ''}
                        <span style="color:var(--text-muted);font-size:0.85em;">${comedian.sexe}</span>
                    </div>
                    <div style="display:flex;gap:5px;flex-wrap:wrap;margin-bottom:6px;">${tagsHTML}</div>
                    ${audioPres}
                    ${audioDemo}
                    ${(!presData && !demoData) ? '<p style="color:var(--text-muted);font-size:0.82em;font-style:italic;">Aucun fichier audio</p>' : ''}
                `;

                const removeBtn = document.createElement('button');
                removeBtn.textContent = '✕';
                removeBtn.title = 'Retirer de la sélection';
                removeBtn.style.cssText = 'background:rgba(232,68,90,0.1);color:var(--accent);border:1px solid rgba(232,68,90,0.3);border-radius:8px;padding:7px 11px;cursor:pointer;font-size:0.9em;flex-shrink:0;transition:all 0.2s;margin-top:4px;';
                removeBtn.onclick = () => removeFromStudioSelection(comedian.id);

                row.appendChild(numEl);
                row.appendChild(photoEl);
                row.appendChild(infoEl);
                row.appendChild(removeBtn);
                list.appendChild(row);
            });

            const footer = document.createElement('div');
            footer.style.cssText = 'border-top:1px solid var(--border); padding-top:14px; margin-top:4px; display:flex; gap:10px; justify-content:flex-end; flex-wrap:wrap;';
            footer.innerHTML = `
                <span style="flex:1; color:var(--text-muted); font-size:0.9em; align-self:center; min-width:120px;">
                    ${selected.length} comédien${selected.length > 1 ? 's' : ''} dans la sélection
                </span>
                <button onclick="openOrderModal()"
                        style="background:var(--teal); color:var(--bg); border:none;
                               padding:8px 18px; border-radius:8px; cursor:pointer; font-size:0.9em; font-weight:700;">
                    🛒 Passer commande
                </button>
                <button onclick="openSendSelectionModal()"
                        style="background:var(--accent); color:#fff; border:none;
                               padding:8px 18px; border-radius:8px; cursor:pointer; font-size:0.9em; font-weight:700;">
                    📧 Envoyer au client
                </button>
            `;
            list.appendChild(footer);
        }

        function openOrderModal() {
            if (studioSelection.length === 0) {
                alert('❌ Sélectionnez au moins un comédien.');
                return;
            }
            const comedians = AppState.comedians.slice();
            const selected  = studioSelection.map(id => comedians.find(c => c.id === id)).filter(Boolean);
            const recap = document.getElementById('orderModalRecap');
            if (recap) {
                recap.innerHTML = selected.map((c, i) => `
                    <div style="display:flex;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid var(--border);">
                        <span style="width:22px;height:22px;border-radius:50%;background:var(--teal);color:var(--bg);
                                     font-size:.72em;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;">${i + 1}</span>
                        <strong style="color:var(--text);font-size:.9em;">${c.name}</strong>
                        <span style="color:var(--text-muted);font-size:.8em;margin-left:auto;">${c.sexe}</span>
                        ${!c.email ? '<span style="color:var(--warning);font-size:.75em;">⚠️ pas d\'email</span>' : ''}
                    </div>`).join('');
            }
            ['orderODP','orderClient','orderDeliveryDate','orderDeliveryTime','orderText'].forEach(id => {
                const el = document.getElementById(id);
                if (el) el.value = '';
            });
            openModal('orderModal');
        }

        function sendOrderRequest() {
            const odp          = document.getElementById('orderODP').value.trim();
            const clientName   = document.getElementById('orderClient').value.trim();
            const deliveryDate = document.getElementById('orderDeliveryDate').value;
            const deliveryTime = document.getElementById('orderDeliveryTime').value;
            const text         = document.getElementById('orderText').value.trim();

            if (!odp || !clientName || !deliveryDate || !deliveryTime) {
                alert('❌ Veuillez remplir tous les champs obligatoires (ODP, client, date et heure de livraison).');
                return;
            }

            const comedians = AppState.comedians.slice();
            const selected  = studioSelection.map(id => comedians.find(c => c.id === id)).filter(Boolean);
            const withEmail = selected.filter(c => c.email);

            if (withEmail.length === 0) {
                alert("❌ Aucun comédien sélectionné n'a d'adresse email renseignée.");
                return;
            }

            const studioUser = currentUser ? currentUser.username : 'Studio';
            const studioName = AppState.settings.studioName || 'Le Studio';

            const dateObj = new Date(deliveryDate + 'T' + deliveryTime);
            const dateStr = dateObj.toLocaleDateString('fr-FR', { weekday:'long', day:'numeric', month:'long', year:'numeric' });

            const tplOdp = getTemplate('commande_odp');
            const varsOdp = { prenom: '', nom: '', email: '',
                odp, client: clientName, date_livraison: dateStr, heure_livraison: deliveryTime,
                texte: text || '', studio: studioName, expediteur: studioUser,
                mission: '', nb_comediens: '', liste_comediens: '', lien_selection: '', message: '', role: '' };

            function applyVarsOdp(str) {
                let r = str;
                Object.entries(varsOdp).forEach(([k,v]) => { r = r.replace(new RegExp('{{' + k + '}}', 'g'), v); });
                return r;
            }

            const subject = tplOdp ? applyVarsOdp(tplOdp.subject) : ('[ODP ' + odp + '] Commande enregistrement — ' + clientName);
            let body      = tplOdp ? applyVarsOdp(tplOdp.body)    : ('Commande ODP ' + odp + ' — ' + clientName);
            const bccList  = withEmail.map(c => c.email).join(',');

            const mailtoLink = 'mailto:'
                + '?bcc='     + encodeURIComponent(bccList)
                + '&subject=' + encodeURIComponent(subject)
                + '&body='    + encodeURIComponent(body);

            const link = document.createElement('a');
            link.href = mailtoLink;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            setTimeout(() => document.body.removeChild(link), 200);

            try {
                addLog(CONFIG.LOG_TYPES.EMAIL_SENT,
                    'Commande ODP ' + odp + ' envoyée à ' + withEmail.length + ' comédien(s) — Client : ' + clientName,
                    'studio', null);
            } catch(e) {}

            closeModal('orderModal');

            const noEmail = selected.filter(c => !c.email);
            if (noEmail.length > 0) {
                alert('✅ Email de commande préparé pour ' + withEmail.length + ' comédien(s).\n\n⚠️ ' + noEmail.length + ' comédien(s) sans email ignoré(s) :\n' + noEmail.map(c => '• ' + c.name).join('\n'));
            }
        }

        function openSendSelectionModal() {
            if (studioSelection.length === 0) {
                alert('❌ Sélectionnez au moins un comédien.');
                return;
            }
            document.getElementById('sendSelectionEmail').value = '';
            document.getElementById('sendSelectionMessage').value = '';
            document.getElementById('sendSelectionLinkSection').style.display = 'none';
            document.getElementById('generatedShareLink').textContent = '';

            const comedians = AppState.comedians.slice();
            const selected  = studioSelection.map(id => comedians.find(c => c.id === id)).filter(Boolean);
            const recap     = document.getElementById('sendModalSelectionRecap');
            if (recap) {
                recap.innerHTML = selected.map((c, i) => `
                    <div style="display:flex; align-items:center; gap:10px; padding:6px 0;
                                border-bottom:1px solid rgba(255,255,255,0.06);">
                        <span style="width:22px; height:22px; border-radius:50%; background:var(--accent);
                                     color:#fff; font-size:0.75em; font-weight:700; display:flex;
                                     align-items:center; justify-content:center; flex-shrink:0;">${i + 1}</span>
                        <img src="${c.profilePic || `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='32' height='32'%3E%3Crect fill='%2316213e' width='32' height='32'/%3E%3Ctext x='50%25' y='50%25' font-size='16' text-anchor='middle' dy='.3em' fill='%23e94560'%3E${c.name.charAt(0)}%3C/text%3E%3C/svg%3E`}"
                             style="width:32px; height:32px; border-radius:6px; object-fit:cover; flex-shrink:0;">
                        <div>
                            <strong style="color:var(--accent-light); font-size:0.9em;">${c.name}</strong>
                            <span style="color:var(--text-muted); font-size:0.8em; margin-left:6px;">${c.sexe}</span>
                        </div>
                    </div>`).join('');
            }

            openModal('sendSelectionModal');
        }

        function generateShareToken() {
            return 'share_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 9);
        }

        async function sendStudioSelection() {
            const email   = document.getElementById('sendSelectionEmail').value.trim();
            const message = document.getElementById('sendSelectionMessage').value.trim();

            if (!email) {
                alert('❌ Veuillez saisir une adresse email.');
                return;
            }

            const comedians = AppState.comedians.slice();
            const selected  = comedians.filter(c => studioSelection.includes(c.id));

            if (selected.length === 0) {
                alert('❌ Erreur : aucun comédien trouvé dans la sélection.');
                return;
            }

            const token = generateShareToken();
            const selData = {
                comedianIds:    studioSelection.slice(),
                createdBy:      currentUser ? currentUser.username : 'studio',
                recipientEmail: email
            };
            await SupabaseDB.saveSharedSelection(token, selData);

            const baseUrl   = window.location.href.split('?')[0].split('#')[0];
            const shareUrl  = baseUrl + '?share=' + token;

            const msgPart   = message ? '\n\n' + message + '\n\n' : '\n\n';
            const namesList = selected.map((c, i) => {
                const dn = getClientDisplayName(c, selected);
                return (i + 1) + '. ' + dn + ' — ' + c.sexe;
            }).join('\n');

            const tplSel = getTemplate('envoi_selection_client');
            const expedSel = currentUser ? currentUser.username : 'Studio';
            const studioSel = AppState.settings.studioName || 'Studio';
            const varsSel = { prenom: '', nb_comediens: String(selected.length),
                liste_comediens: namesList, lien_selection: shareUrl,
                message: message || '', studio: studioSel, expediteur: expedSel,
                odp:'', client:'', date_livraison:'', heure_livraison:'',
                texte:'', mission:'', role:'' };
            function applyVarsSel(str) {
                let r = str;
                Object.entries(varsSel).forEach(([k,v]) => { r = r.replace(new RegExp('{{' + k + '}}', 'g'), v); });
                return r;
            }
            const subject   = tplSel ? applyVarsSel(tplSel.subject) : ('Sélection de ' + selected.length + ' comédien(s)');
            const emailBody = tplSel ? applyVarsSel(tplSel.body)    :
                ('Bonjour,\n\nVoici une sélection pour vous :\n\n' + namesList + '\n\n▶ ' + shareUrl + '\n\nCordialement,\n' + expedSel);
            const mailto    = 'mailto:' + encodeURIComponent(email)
                            + '?subject=' + encodeURIComponent(subject)
                            + '&body=' + encodeURIComponent(emailBody);

            const link = document.createElement('a');
            link.href = mailto;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            setTimeout(() => document.body.removeChild(link), 200);

            document.getElementById('generatedShareLink').textContent = shareUrl;
            document.getElementById('sendSelectionLinkSection').style.display = 'block';

            try {
                addLog(CONFIG.LOG_TYPES.EMAIL_SENT,
                    'Sélection de ' + selected.length + ' comédiens envoyée à ' + email + ' (token: ' + token + ')',
                    'studio', null);
            } catch(e) {}
        }

        function copyShareLink() {
            const link = document.getElementById('generatedShareLink').textContent;
            if (!link) return;
            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(link).then(() => alert('✅ Lien copié !')).catch(() => prompt('Copiez ce lien :', link));
            } else {
                prompt('Copiez ce lien :', link);
            }
        }

        
        let clientSelection      = [];
        let clientPanelOpen      = false;

        function loadClientContent() {
            clientSelection = [];
            updateClientSelectionPanel();
            applyFiltersClient();
        }

        function toggleClientSelectionPanel() {
            clientPanelOpen = !clientPanelOpen;
            const body    = document.getElementById('clientSelectionBody');
            const chevron = document.getElementById('clientSelectionChevron');
            if (!body) return;
            body.style.display    = clientPanelOpen ? 'block' : 'none';
            if (chevron) chevron.style.transform = clientPanelOpen ? 'rotate(180deg)' : '';
            if (clientPanelOpen) renderClientSelectionList();
        }

        function toggleComedianSelection(comedianId, checkbox) {
            const wasEmpty = clientSelection.length === 0;
            if (checkbox.checked) {
                if (!clientSelection.includes(comedianId)) clientSelection.push(comedianId);
                if (wasEmpty && !clientPanelOpen) toggleClientSelectionPanel();
            } else {
                clientSelection = clientSelection.filter(id => id !== comedianId);
            }
            updateClientSelectionPanel();
        }

        function removeFromClientSelection(comedianId) {
            clientSelection = clientSelection.filter(id => id !== comedianId);
            const cb = document.querySelector(`.comedian-checkbox-client[data-comedian-id="${comedianId}"]`);
            if (cb) cb.checked = false;
            updateClientSelectionPanel();
        }

        function removeFromSelection(comedianId) { removeFromClientSelection(comedianId); }

        function clearClientSelection() {
            clientSelection = [];
            document.querySelectorAll('.comedian-checkbox-client').forEach(cb => { cb.checked = false; });
            updateClientSelectionPanel();
            if (clientPanelOpen) toggleClientSelectionPanel();
        }

        function updateClientSelectionPanel() {
            const n = clientSelection.length;

            const badge = document.getElementById('clientSelectionBadge');
            if (badge) {
                badge.textContent       = n;
                badge.style.background  = n > 0 ? 'var(--accent)' : '#555';
            }

            const status = document.getElementById('clientSelectionStatus');
            if (status) {
                status.textContent = n === 0 ? 'Aucun comédien sélectionné'
                    : n === 1 ? '1 comédien — cliquez pour vérifier'
                    : `${n} comédiens — cliquez pour vérifier`;
            }

            const sendBtn  = document.getElementById('clientSendBtn');
            const clearBtn = document.getElementById('clientClearBtn');
            if (sendBtn)  sendBtn.style.display  = n > 0 ? 'inline-block' : 'none';
            if (clearBtn) clearBtn.style.display = n > 0 ? 'inline-block' : 'none';

            const panel = document.getElementById('clientSelectionPanel');
            if (panel) panel.style.borderColor = n > 0 ? 'var(--accent)' : 'var(--border)';

            if (clientPanelOpen) renderClientSelectionList();
        }

        function renderClientSelectionList() {
            const empty = document.getElementById('clientSelectionEmpty');
            const list  = document.getElementById('clientSelectionList');
            if (!empty || !list) return;

            if (clientSelection.length === 0) {
                empty.style.display = 'block';
                list.style.display  = 'none';
                list.innerHTML = '';
                return;
            }

            empty.style.display = 'none';
            list.style.display  = 'block';

            const comedians = AppState.comedians.slice();
            const selected  = clientSelection
                .map(id => comedians.find(c => c.id === id))
                .filter(Boolean);

            list.innerHTML = '';

            selected.forEach((comedian, idx) => {
                const displayName = getClientDisplayName(comedian, selected);

                const presData = getAudioData(comedian.audioPresentation);
                const demoData = getAudioData(comedian.audioDemo);

                const audioPres = presData ? `
                    <div class="audio-block" style="margin-top:8px;">
                        <span class="audio-label">🎤 Présentation</span>
                        <audio controls controlsList="nodownload" oncontextmenu="return false" class="audio-player" style="margin:4px 0 0;">
                            <source src="${presData}" type="audio/mpeg">
                        </audio>
                    </div>` : '';

                const audioDemo = demoData ? `
                    <div class="audio-block" style="margin-top:8px;">
                        <span class="audio-label">🎵 Démo</span>
                        <audio controls controlsList="nodownload" oncontextmenu="return false" class="audio-player" style="margin:4px 0 0;">
                            <source src="${demoData}" type="audio/mpeg">
                        </audio>
                    </div>` : '';

                const tags = [];
                if (comedian.voix_off)    tags.push('Voix off');
                if (comedian.voix_jouee)  tags.push('Voix jouée');
                if (comedian.voix_enfant) tags.push('Voix enfant');
                if (comedian.chant)       tags.push('Chant');
                const tagsHTML = tags.map(t => `<span class="tag" style="font-size:0.75em; padding:3px 8px;">${t}</span>`).join('');

                const row = document.createElement('div');
                row.style.cssText = `
                    display: grid;
                    grid-template-columns: 32px 56px 1fr auto;
                    gap: 12px;
                    align-items: start;
                    padding: 14px 0;
                    border-top: 1px solid var(--border);
                `;
                row.innerHTML = `
                    <div style="width:32px; height:32px; border-radius:50%; background:var(--accent);
                                color:#fff; display:flex; align-items:center; justify-content:center;
                                font-weight:700; font-size:0.9em; flex-shrink:0; margin-top:4px;">
                        ${idx + 1}
                    </div>
                    <img src="${comedian.profilePic || `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='56' height='56'%3E%3Crect fill='%2316213e' width='56' height='56'/%3E%3Ctext x='50%25' y='50%25' font-size='24' text-anchor='middle' dy='.3em' fill='%23e94560'%3E${comedian.name.charAt(0)}%3C/text%3E%3C/svg%3E`}"
                         style="width:56px; height:56px; border-radius:8px; object-fit:cover; border:2px solid var(--border);">
                    <div>
                        <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px; flex-wrap:wrap;">
                            <strong style="color:var(--accent-light); font-size:1em;">${displayName}</strong>
                            <span style="color:var(--text-muted); font-size:0.85em;">${comedian.sexe}</span>
                        </div>
                        <div style="display:flex; gap:4px; flex-wrap:wrap; margin-bottom:4px;">${tagsHTML}</div>
                        ${audioPres}
                        ${audioDemo}
                        ${(!presData && !demoData) ? '<p style="color:var(--text-muted); font-size:0.82em; font-style:italic; margin-top:4px;">Aucun fichier audio</p>' : ''}
                    </div>
                    <button onclick="removeFromClientSelection(${comedian.id})"
                            title="Retirer"
                            style="background:rgba(255,107,107,0.12); color:#ff6b6b; border:1px solid rgba(255,107,107,0.35);
                                   border-radius:8px; padding:7px 11px; cursor:pointer; font-size:0.9em; flex-shrink:0; margin-top:4px;"
                            onmouseover="this.style.background='rgba(255,107,107,0.28)'"
                            onmouseout="this.style.background='rgba(255,107,107,0.12)'">
                        ✕
                    </button>
                `;
                list.appendChild(row);
            });

            const footer = document.createElement('div');
            footer.style.cssText = 'border-top:1px solid var(--border); padding-top:14px; margin-top:4px; display:flex; gap:10px; justify-content:flex-end; flex-wrap:wrap;';
            footer.innerHTML = `
                <span style="flex:1; color:var(--text-muted); font-size:0.9em; align-self:center; min-width:120px;">
                    ${selected.length} comédien${selected.length > 1 ? 's' : ''} sélectionné${selected.length > 1 ? 's' : ''}
                </span>

            `;
            list.appendChild(footer);
        }

        function openClientBasketSend() {
            if (clientSelection.length === 0) {
                alert('❌ Sélectionnez au moins un comédien.');
                return;
            }

            const emailInput = document.getElementById('clientStudioSelectedEmail');
            const nameInput  = document.getElementById('clientStudioSelectedName');
            if (emailInput) emailInput.value = '';
            if (nameInput)  nameInput.value  = '';

            const comedians = AppState.comedians.slice();
            const selected  = clientSelection.map(id => comedians.find(c => c.id === id)).filter(Boolean);
            const recap = document.getElementById('clientBasketRecap');
            if (recap) {
                recap.innerHTML = selected.map((c, i) => {
                    const dn = getClientDisplayName(c, selected);
                    return `<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:1px solid var(--border);">
                        <span style="width:22px;height:22px;border-radius:50%;background:var(--accent);color:#fff;font-size:0.72em;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;">${i + 1}</span>
                        <strong style="color:var(--text);font-size:0.9em;">${dn}</strong>
                        <span style="color:var(--text-muted);font-size:0.82em;margin-left:auto;">${c.sexe}</span>
                    </div>`;
                }).join('');
            }

            const users = AppState.users.slice();
            const studioMembers = users.filter(u => (u.role === 'studio' || u.role === 'manager') && u.active && u.email);
            const listEl = document.getElementById('clientStudioList');
            if (listEl) {
                if (studioMembers.length === 0) {
                    listEl.innerHTML = `<p style="color:var(--text-muted);font-size:.88em;padding:var(--s3);">Aucun membre studio disponible.</p>`;
                } else {
                    listEl.innerHTML = '';
                    studioMembers.forEach(member => {
                        const roleLabel = member.role === 'manager' ? 'Manager' : 'Équipe Studio';
                        const card = document.createElement('div');
                        card.dataset.email = member.email;
                        card.dataset.name  = member.username;
                        card.style.cssText = `
                            display:flex;align-items:center;gap:var(--s4);
                            padding:var(--s3) var(--s4);
                            background:var(--surface-2);border:2px solid var(--border);
                            border-radius:var(--r2);cursor:pointer;transition:all .2s;
                        `;
                        card.innerHTML = `
                            <div style="width:38px;height:38px;border-radius:50%;background:var(--accent-dim);
                                        border:2px solid rgba(232,68,90,0.3);display:flex;align-items:center;
                                        justify-content:center;font-weight:700;font-size:1em;color:var(--accent);flex-shrink:0;">
                                ${member.username.charAt(0).toUpperCase()}
                            </div>
                            <div style="min-width:0;">
                                <div style="font-weight:600;color:var(--text);font-size:.92em;">${member.username}</div>
                                <div style="color:var(--text-muted);font-size:.78em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${member.email}</div>
                            </div>
                            <span style="margin-left:auto;font-size:.72em;font-weight:700;text-transform:uppercase;
                                         letter-spacing:.05em;color:var(--teal);background:var(--teal-dim);
                                         border:1px solid rgba(62,207,168,.2);padding:2px 8px;border-radius:20px;flex-shrink:0;">
                                ${roleLabel}
                            </span>
                            <span class="check-icon" style="font-size:1.2em;flex-shrink:0;opacity:0;">✓</span>
                        `;
                        card.addEventListener('click', () => selectStudioMember(card, member.email, member.username, listEl));
                        listEl.appendChild(card);
                    });
                }
            }

            const msgInput = document.getElementById('clientBasketMessage');
            if (msgInput) msgInput.value = '';

            openModal('clientBasketModal');
        }

        function selectStudioMember(card, email, name, listEl) {
            listEl.querySelectorAll('div[data-email]').forEach(c => {
                c.style.borderColor     = 'var(--border)';
                c.style.background      = 'var(--surface-2)';
                c.querySelector('.check-icon').style.opacity = '0';
            });
            card.style.borderColor = 'var(--accent)';
            card.style.background  = 'var(--accent-dim)';
            card.querySelector('.check-icon').style.opacity = '1';
            card.querySelector('.check-icon').style.color   = 'var(--accent)';
            document.getElementById('clientStudioSelectedEmail').value = email;
            document.getElementById('clientStudioSelectedName').value  = name;
        }

        function sendClientSelectionToStudio() {
            const studioEmail = document.getElementById('clientStudioSelectedEmail')?.value || '';
            const studioName  = document.getElementById('clientStudioSelectedName')?.value  || '';

            if (!studioEmail) {
                alert('❌ Veuillez sélectionner un contact studio.');
                return;
            }

            const comedians = AppState.comedians.slice();
            const selected  = clientSelection.map(id => comedians.find(c => c.id === id)).filter(Boolean);

            if (selected.length === 0) {
                alert('❌ Aucun comédien dans la sélection.');
                return;
            }

            const clientName = currentUser ? currentUser.username : 'Client';
            const namesList  = selected.map((c, i) => {
                const dn = getClientDisplayName(c, selected);
                return (i + 1) + '. ' + dn + ' — ' + c.sexe;
            }).join('\n');

            const msgInput = document.getElementById('clientBasketMessage');
            const message  = msgInput ? msgInput.value.trim() : '';
            const msgPart  = message ? '\n\nMessage du client :\n' + message + '\n\n' : '\n\n';

            const studioAppName = AppState.settings.studioName || 'le studio';

            const tplCtoS = getTemplate('selection_vers_studio');
            const varsCtoS = { prenom: studioName, nb_comediens: String(selected.length),
                liste_comediens: namesList, message: message || '',
                expediteur: clientName, studio: studioAppName,
                odp:'', client:'', date_livraison:'', heure_livraison:'',
                texte:'', mission:'', lien_selection:'', role:'' };
            function applyVarsCtoS(str) {
                let r = str;
                Object.entries(varsCtoS).forEach(([k,v]) => { r = r.replace(new RegExp('{{' + k + '}}', 'g'), v); });
                return r;
            }
            const subject    = tplCtoS ? applyVarsCtoS(tplCtoS.subject) : ('Sélection de ' + selected.length + ' comédien(s) — ' + clientName);
            let emailBody    = tplCtoS ? applyVarsCtoS(tplCtoS.body)    :
                ('Bonjour ' + studioName + ',\n\n' + clientName + ' vous envoie une sélection :\n\n' + namesList + '\n\nCordialement,\n' + clientName);
            const mailtoLink = 'mailto:' + encodeURIComponent(studioEmail)
                             + '?subject=' + encodeURIComponent(subject)
                             + '&body='    + encodeURIComponent(emailBody);

            const link = document.createElement('a');
            link.href = mailtoLink;
            link.style.display = 'none';
            document.body.appendChild(link);
            link.click();
            setTimeout(() => document.body.removeChild(link), 200);

            try {
                addLog(CONFIG.LOG_TYPES.EMAIL_SENT,
                    'Client ' + clientName + ' a envoyé une sélection de ' + selected.length + ' comédien(s) à ' + studioName,
                    'client', null);
            } catch(e) {}

            closeModal('clientBasketModal');
        }

        function updateSelectionBar() { updateClientSelectionPanel(); }
        function openBasketModal()    { if (clientPanelOpen) renderClientSelectionList(); else toggleClientSelectionPanel(); }
        function loadStudioMembers()  {  }
        function sendSelectionToStudio() { openClientBasketSend(); }
        
        function applyFiltersClient(debounced) {
            if (debounced) {
                clearTimeout(_appFilterDebounceTimer);
                _appFilterDebounceTimer = setTimeout(function() { applyFiltersClient(false); }, 150);
                return;
            }
            let comedians = AppState.comedians.slice();
            
            comedians = comedians.filter(c => c.active);
            
            const searchName = document.getElementById('searchNameClient').value.toLowerCase();
            if (searchName) {
                comedians = comedians.filter(c => {
                    const firstName = c.name.split(' ')[0].toLowerCase();
                    return firstName.includes(searchName);
                });
            }
            
            const filterFemme = document.getElementById('filterFemmeClient').checked;
            const filterHomme = document.getElementById('filterHommeClient').checked;
            
            if (filterFemme || filterHomme) {
                comedians = comedians.filter(c => {
                    if (filterFemme && c.sexe === 'Femme') return true;
                    if (filterHomme && c.sexe === 'Homme') return true;
                    return false;
                });
            }
            
            const filterVoixOff = document.getElementById('filterVoixOffClient').checked;
            const filterVoixJouee = document.getElementById('filterVoixJoueeClient').checked;
            const filterVoixEnfant = document.getElementById('filterVoixEnfantClient').checked;
            const filterChant = document.getElementById('filterChantClient').checked;
            
            if (filterVoixOff) comedians = comedians.filter(c => c.voix_off);
            if (filterVoixJouee) comedians = comedians.filter(c => c.voix_jouee);
            if (filterVoixEnfant) comedians = comedians.filter(c => c.voix_enfant);
            if (filterChant) comedians = comedians.filter(c => c.chant);
            
            const filterVoixJeune = document.getElementById('filterVoixJeuneClient') && document.getElementById('filterVoixJeuneClient').checked;
            const filterVoixAdulte = document.getElementById('filterVoixAdulteClient') && document.getElementById('filterVoixAdulteClient').checked;
            const filterVoixMature = document.getElementById('filterVoixMatureClient') && document.getElementById('filterVoixMatureClient').checked;
            const filterVoixAccent = document.getElementById('filterVoixAccentClient') && document.getElementById('filterVoixAccentClient').checked;
            
            if (filterVoixJeune) comedians = comedians.filter(c => c.voix_jeune);
            if (filterVoixAdulte) comedians = comedians.filter(c => c.voix_adulte);
            if (filterVoixMature) comedians = comedians.filter(c => c.voix_mature);
            if (filterVoixAccent) comedians = comedians.filter(c => c.voix_accent);
            
            const filterTimbreGrave = document.getElementById('filterTimbreGraveClient') && document.getElementById('filterTimbreGraveClient').checked;
            const filterTimbreMedium = document.getElementById('filterTimbreMediumClient') && document.getElementById('filterTimbreMediumClient').checked;
            const filterTimbreAigu = document.getElementById('filterTimbreAiguClient') && document.getElementById('filterTimbreAiguClient').checked;
            const filterTimbreTexture = document.getElementById('filterTimbreTextureClient') && document.getElementById('filterTimbreTextureClient').checked;
            
            if (filterTimbreGrave) comedians = comedians.filter(c => c.timbre_grave);
            if (filterTimbreMedium) comedians = comedians.filter(c => c.timbre_medium);
            if (filterTimbreAigu) comedians = comedians.filter(c => c.timbre_aigu);
            if (filterTimbreTexture) comedians = comedians.filter(c => c.timbre_texture);
            
            const filterStyleDynamique = document.getElementById('filterStyleDynamiqueClient') && document.getElementById('filterStyleDynamiqueClient').checked;
            const filterStylePose = document.getElementById('filterStylePoseClient') && document.getElementById('filterStylePoseClient').checked;
            const filterStyleNaturel = document.getElementById('filterStyleNaturelClient') && document.getElementById('filterStyleNaturelClient').checked;
            const filterStyleInstitutionnel = document.getElementById('filterStyleInstitutionnelClient') && document.getElementById('filterStyleInstitutionnelClient').checked;
            
            if (filterStyleDynamique) comedians = comedians.filter(c => c.style_dynamique);
            if (filterStylePose) comedians = comedians.filter(c => c.style_pose);
            if (filterStyleNaturel) comedians = comedians.filter(c => c.style_naturel);
            if (filterStyleInstitutionnel) comedians = comedians.filter(c => c.style_institutionnel);
            
            displayComediansClient(comedians);
        }
        
        function displayComediansClient(comedians) {
            const grid = document.getElementById('comediansGridClient');
            const emptyState = document.getElementById('emptyStateClient');
            
            if (!grid || !emptyState) return;
            
            if (comedians.length === 0) {
                grid.innerHTML = '';
                emptyState.style.display = 'block';
                return;
            }
            
            emptyState.style.display = 'none';
            grid.innerHTML = '';
            
            comedians.forEach(comedian => {
                const card = createComedianCardClient(comedian);
                grid.appendChild(card);
            });
        }
        
        function createComedianCardClient(comedian) {
            const card = document.createElement('div');
            card.className = 'card';
            card.style.position = 'relative';
            
            const nameParts = comedian.name.split(' ');
            const firstName = nameParts[0];
            const lastInitial = nameParts.length > 1 ? nameParts[nameParts.length - 1].charAt(0) + '.' : '';
            const displayName = `${firstName} ${lastInitial}`;
            
            const competences = [];
            if (comedian.seances_dirigees) competences.push('Séances dirigées');
            if (comedian.voix_off) competences.push('Voix off');
            if (comedian.voix_jouee) competences.push('Voix jouée');
            if (comedian.voix_enfant) competences.push('Voix enfant');
            if (comedian.chant) competences.push('Chant');
            
            const competencesHTML = competences.length > 0 
                ? `<div class="tags">${competences.map(c => `<span class="tag">${c}</span>`).join('')}</div>`
                : '';
            
            const photoHTML = comedian.profilePic 
                ? `<img src="${comedian.profilePic}" alt="${displayName}" style="width: 100%; height: 200px; object-fit: cover; border-radius: 10px 10px 0 0;">`
                : '';
            
            const clientAudioPresData = getAudioData(comedian.audioPresentation);
            const clientAudioDemoData = getAudioData(comedian.audioDemo);

            const clientAudioPresHTML = clientAudioPresData
                ? `<div style="margin: 10px 0;">
                     <p style="font-size:0.85em; color:var(--text-muted); margin-bottom:4px;">🎤 Présentation audio</p>
                     <audio controls controlsList="nodownload" oncontextmenu="return false" style="width:100%;">
                       <source src="${clientAudioPresData}" type="audio/mpeg">
                     </audio>
                   </div>`
                : '';
            const clientAudioDemoHTML = clientAudioDemoData
                ? `<div style="margin: 10px 0;">
                     <p style="font-size:0.85em; color:var(--text-muted); margin-bottom:4px;">🎵 Démo audio</p>
                     <audio controls controlsList="nodownload" oncontextmenu="return false" style="width:100%;">
                       <source src="${clientAudioDemoData}" type="audio/mpeg">
                     </audio>
                   </div>`
                : '';
            
            const presentationHTML = comedian.presentation
                ? `<p style="color: var(--text-muted); font-size: 0.9em; margin-top: 10px;">${comedian.presentation}</p>`
                : '';
            
            card.innerHTML = `
                <div style="position: absolute; top: 10px; right: 10px; z-index: 10;">
                    <label style="display: flex; align-items: center; gap: 5px; background: white; padding: 8px 12px; border-radius: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.2); cursor: pointer;">
                        <input type="checkbox" class="comedian-checkbox-client" data-comedian-id="${comedian.id}" style="width: 18px; height: 18px; cursor: pointer;">
                        <span style="font-size: 0.9em; font-weight: 600;">Sélectionner</span>
                    </label>
                </div>
                ${photoHTML}
                <div style="padding: 20px;">
                    <h3>${displayName}</h3>
                    <p style="color: var(--text-muted);">${comedian.sexe}</p>
                    ${competencesHTML}
                    ${presentationHTML}
                    ${clientAudioPresHTML}
                    ${clientAudioDemoHTML}
                </div>
            `;
            
            const checkbox = card.querySelector('.comedian-checkbox-client');
            checkbox.addEventListener('change', function() {
                toggleComedianSelection(comedian.id, this);
            });
            
            if (clientSelection.includes(comedian.id)) {
                checkbox.checked = true;
            }
            
            return card;
        }
