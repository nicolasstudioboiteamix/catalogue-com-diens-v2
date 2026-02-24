

let currentDatabaseType = 'tous';

function showDatabaseType(type) {
    currentDatabaseType = type;
    document.querySelectorAll('#adminDatabaseSection .nav-tab').forEach(t => t.classList.remove('active'));
    const tab = document.getElementById(`dbTab${type.charAt(0).toUpperCase() + type.slice(1)}`);
    if (tab) tab.classList.add('active');
    loadDatabaseTable();
    updateDatabaseStats();
}

async function deleteDatabaseByType() {
    const type = currentDatabaseType;

    if (type === 'tous') {
        const confirmation = prompt('⚠️ DANGER ! Supprimer TOUTE la base de données ?\n\nTapez "SUPPRIMER" pour confirmer :');
        if (confirmation !== 'SUPPRIMER') {
            if (confirmation !== null) alert('Suppression annulée : texte incorrect.');
            return;
        }
        if (!confirm('Dernière confirmation : Êtes-vous ABSOLUMENT sûr ?\n\nUn backup sera automatiquement téléchargé.')) return;

        exportDatabase('json');
        try {
            await SupabaseDB.deleteAllComedians();
            addLog(CONFIG.LOG_TYPES.SUPPRESSION, 'Base de données complète supprimée', 'database', null);
            alert('✅ Base de données supprimée.\nBackup JSON téléchargé.');
            loadDatabaseView();
        } catch(err) {
            alert('❌ Erreur: ' + (err.message || err));
        }

    } else {
        const typeLabel = type === 'interne' ? 'Interne' : 'Externe';
        const toDelete  = AppState.comedians.filter(c => c.classement === type);

        if (toDelete.length === 0) {
            alert(`Aucun comédien dans la base ${typeLabel}.`);
            return;
        }

        if (!confirm(`⚠️ Supprimer TOUTE la base ${typeLabel} ?\n\n${toDelete.length} comédiens seront supprimés.\n\nCette action est IRRÉVERSIBLE !`)) return;

        try {
            await SupabaseDB.deleteComediansByClassement(type);
            addLog(CONFIG.LOG_TYPES.SUPPRESSION, `Base ${typeLabel} supprimée (${toDelete.length} comédiens)`, 'database', null);
            alert(`✅ Base ${typeLabel} supprimée.\n${toDelete.length} comédiens supprimés.`);
            loadDatabaseView();
        } catch(err) {
            alert('❌ Erreur: ' + (err.message || err));
        }
    }
}

function loadDatabaseView() {
    loadDatabaseTable();
    updateDatabaseStats();
}

function updateDatabaseStats() {
    const comedians = AppState.comedians;
    const total    = comedians.length;
    const active   = comedians.filter(c => c.active).length;
    const inactive = total - active;
    const interne  = comedians.filter(c => c.classement === 'interne').length;
    const externe  = comedians.filter(c => c.classement === 'externe').length;

    const el = id => document.getElementById(id);
    if (el('totalComedians'))   el('totalComedians').textContent   = total;
    if (el('activeComedians'))  el('activeComedians').textContent  = active;
    if (el('inactiveComedians'))el('inactiveComedians').textContent= inactive;
    if (el('interneComedians')) el('interneComedians').textContent = interne;
    if (el('externeComedians')) el('externeComedians').textContent = externe;
    if (el('countTous'))    el('countTous').textContent    = total;
    if (el('countInterne')) el('countInterne').textContent = interne;
    if (el('countExterne')) el('countExterne').textContent = externe;
}

function loadDatabaseTable() {
    let comedians = AppState.comedians.slice();
    if (currentDatabaseType === 'interne') comedians = comedians.filter(c => c.classement === 'interne');
    else if (currentDatabaseType === 'externe') comedians = comedians.filter(c => c.classement === 'externe');
    displayDatabaseTable(comedians);
}

function displayDatabaseTable(comedians) {
    const tbody = document.getElementById('databaseTableBody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (comedians.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;padding:40px;color:var(--text-muted);">Aucun comédien dans la base</td></tr>';
        return;
    }

    comedians.forEach(comedian => {
        const competences = [];
        if (comedian.seances_dirigees) competences.push('Séances');
        if (comedian.voix_off)         competences.push('Voix off');
        if (comedian.voix_jouee)       competences.push('Voix jouée');
        if (comedian.voix_enfant)      competences.push('Voix enfant');
        if (comedian.chant)            competences.push('Chant');

        const classementBadge = comedian.classement
            ? `<span class="tag" style="background:rgba(233,69,96,0.2);">${comedian.classement}</span>`
            : '<span style="color:var(--text-muted);">-</span>';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${comedian.name}</strong></td>
            <td>${comedian.sexe}</td>
            <td>${comedian.email}</td>
            <td>${comedian.phone || '-'}</td>
            <td>${classementBadge}</td>
            <td><small>${competences.join(', ') || '-'}</small></td>
            <td><span class="tag ${comedian.active ? 'status-active' : 'status-inactive'}">${comedian.active ? 'Actif' : 'Inactif'}</span></td>
            <td>
                <button class="btn-icon btn-small" onclick="showComedianDetail(${comedian.id})" title="Voir">👁️</button>
                <button class="btn-icon btn-small" onclick="toggleComedianStatus(${comedian.id}).then(() => loadDatabaseView())" title="Activer/Désactiver">🔄</button>
                <button class="btn-icon btn-small" style="background:#c0392b;" onclick="deleteComedianFromDB(${comedian.id})" title="Supprimer">🗑️</button>
            </td>`;
        tbody.appendChild(tr);
    });
}

let _filterDebounceTimer = null;

function filterDatabase(debounced) {
    if (debounced) {
        clearTimeout(_filterDebounceTimer);
        _filterDebounceTimer = setTimeout(function() { filterDatabase(false); }, 150);
        return;
    }
    const search        = document.getElementById('databaseSearch').value.toLowerCase();
    const filterActifs  = document.getElementById('dbFilterActifs').checked;
    const filterInterne = document.getElementById('dbFilterInterne').checked;
    const filterExterne = document.getElementById('dbFilterExterne').checked;

    let comedians = AppState.comedians.slice();
    if (search)       comedians = comedians.filter(c => c.name.toLowerCase().includes(search) || c.email.toLowerCase().includes(search));
    if (filterActifs) comedians = comedians.filter(c => c.active);
    if (filterInterne || filterExterne) {
        comedians = comedians.filter(c => {
            if (filterInterne && c.classement === 'interne') return true;
            if (filterExterne && c.classement === 'externe') return true;
            return false;
        });
    }
    displayDatabaseTable(comedians);
}

function exportDatabase(format) {
    const comedians = AppState.comedians;
    if (comedians.length === 0) { alert('Aucune donnée à exporter'); return; }
    if (format === 'csv')  exportCSV(comedians);
    else if (format === 'json') exportJSON(comedians);
}

function exportCSV(comedians) {
    let csv = 'Nom,Prénom,Sexe,Email,Téléphone,Classement,Séances dirigées,Voix off,Voix jouée,Voix enfant,Chant,';
    csv += 'Voix jeune,Voix adulte,Voix mature,Voix avec accent,';
    csv += 'Timbre grave,Timbre médium,Timbre aigu,Voix texturée,';
    csv += 'Style dynamique,Style posé,Style naturel,Style institutionnel,Actif\n';

    comedians.forEach(c => {
        const nameParts = c.name.split(' ');
        const prenom = nameParts[0];
        const nom    = nameParts.slice(1).join(' ') || nameParts[0];
        const b = v => v ? 'oui' : 'non';
        csv += `"${nom}","${prenom}","${c.sexe}","${c.email}","${c.phone||''}","${c.classement||''}",`;
        csv += `"${b(c.seances_dirigees)}","${b(c.voix_off)}","${b(c.voix_jouee)}","${b(c.voix_enfant)}","${b(c.chant)}",`;
        csv += `"${b(c.voix_jeune)}","${b(c.voix_adulte)}","${b(c.voix_mature)}","${b(c.voix_accent)}",`;
        csv += `"${b(c.timbre_grave)}","${b(c.timbre_medium)}","${b(c.timbre_aigu)}","${b(c.timbre_texture)}",`;
        csv += `"${b(c.style_dynamique)}","${b(c.style_pose)}","${b(c.style_naturel)}","${b(c.style_institutionnel)}",`;
        csv += `"${b(c.active)}"\n`;
    });

    downloadFile(csv, 'catalogue-comediens.csv', 'text/csv');
}

function exportJSON(comedians) {
    const data = { version: '2.0', exportDate: new Date().toISOString(), comedians };
    downloadFile(JSON.stringify(data, null, 2), 'catalogue-comediens.json', 'application/json');
}

// ── Import JSON ──────────────────────────────────────────────
async function importJSON(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async function(e) {
        let parsed;
        try {
            parsed = JSON.parse(e.target.result);
        } catch(err) {
            alert('❌ Fichier JSON invalide : ' + err.message);
            if (event.target) event.target.value = '';
            return;
        }

        const raw = Array.isArray(parsed) ? parsed
                  : Array.isArray(parsed.comedians) ? parsed.comedians
                  : null;

        if (!raw || raw.length === 0) {
            alert('❌ Aucun comédien trouvé dans le fichier JSON.\nFormat attendu : { "comedians": [ ... ] } ou [ ... ]');
            if (event.target) event.target.value = '';
            return;
        }

        const existingEmails = AppState.comedians.map(c => c.email.toLowerCase());
        const newComedians   = [];
        let   skipped        = 0;

        for (const raw_c of raw) {
            const email = (raw_c.email || '').trim().toLowerCase();
            if (!email || !raw_c.name) { skipped++; continue; }
            if (existingEmails.includes(email)) { skipped++; continue; }

            const password = Utils.generateSecurePassword(12);
            const comedian = {
                id:                  Date.now() + Math.floor(Math.random() * 999999),
                name:                raw_c.name,
                email,
                phone:               raw_c.phone               || null,
                sexe:                raw_c.sexe                || 'Homme',
                classement:          raw_c.classement          || '',
                seances_dirigees:    !!raw_c.seances_dirigees,
                voix_off:            !!raw_c.voix_off,
                voix_jouee:          !!raw_c.voix_jouee,
                voix_enfant:         !!raw_c.voix_enfant,
                chant:               !!raw_c.chant,
                voix_jeune:          !!raw_c.voix_jeune,
                voix_adulte:         !!raw_c.voix_adulte,
                voix_mature:         !!raw_c.voix_mature,
                voix_accent:         !!raw_c.voix_accent,
                timbre_grave:        !!raw_c.timbre_grave,
                timbre_medium:       !!raw_c.timbre_medium,
                timbre_aigu:         !!raw_c.timbre_aigu,
                timbre_texture:      !!raw_c.timbre_texture,
                style_dynamique:     !!raw_c.style_dynamique,
                style_pose:          !!raw_c.style_pose,
                style_naturel:       !!raw_c.style_naturel,
                style_institutionnel:!!raw_c.style_institutionnel,
                voixUrgente:         !!raw_c.voixUrgente,
                commentaireInterne:  raw_c.commentaireInterne  || '',
                presentation:        raw_c.presentation        || '',
                username:            email.split('@')[0].toLowerCase().replace(/[^a-z0-9._-]/g, ''),
                password,
                identifiantsSent:    false,
                active:              raw_c.active !== false,
                profilePic:          null,
                audioPresentation:   null,
                audioDemo:           null,
                absences:            [],
                createdAt:           new Date().toISOString(),
            };
            newComedians.push(comedian);
            existingEmails.push(email);
        }

        if (newComedians.length === 0) {
            alert('Aucun comédien importé. ' + skipped + ' doublon(s) ou enregistrement(s) invalide(s) ignoré(s).');
            if (event.target) event.target.value = '';
            return;
        }

        if (!confirm(
            newComedians.length + ' nouveau(x) comédien(s) trouvé(s).' +
            (skipped > 0 ? '\n' + skipped + ' ignoré(s) (doublons / données manquantes).' : '') +
            '\n\nImporter maintenant ?'
        )) {
            if (event.target) event.target.value = '';
            return;
        }

        const plainPwds = {};
        for (const c of newComedians) plainPwds[c.email] = c.password;

        for (const c of newComedians) c.password = await hashPassword(c.password);

        try {
            const insertedRows = await SupabaseDB.bulkInsertComedians(newComedians);

            const existingUsernames = AppState.users.map(u => u.username.toLowerCase());
            const newUsers = [];

            for (const comedian of newComedians) {
                const insertedRow = insertedRows ? insertedRows.find(r => r.email === comedian.email) : null;
                const comedianId  = insertedRow ? insertedRow.id : null;
                if (!comedianId) continue;

                let uname   = comedian.username;
                let counter = 2;
                while (existingUsernames.includes(uname.toLowerCase())) uname = comedian.username + counter++;
                existingUsernames.push(uname.toLowerCase());

                newUsers.push({
                    username:   uname,
                    email:      comedian.email,
                    password:   comedian.password,
                    role:       'comedian',
                    comedianId,
                    active:     true,
                    createdAt:  new Date().toISOString()
                });
            }

            if (newUsers.length > 0) await SupabaseDB.bulkInsertUsers(newUsers);

            await SupabaseDB.reloadComedians();
            await SupabaseDB.reloadUsers();
            if (window.broadcastUpdate) {
                await window.broadcastUpdate('comedians');
                await window.broadcastUpdate('users');
            }

            addLog(CONFIG.LOG_TYPES.CREATION, 'Import JSON: ' + newComedians.length + ' comédiens, ' + newUsers.length + ' utilisateurs', 'database', null);

            let credList = '';
            for (const u of newUsers) {
                credList += '\n  • ' + u.username + ' / ' + (plainPwds[u.email] || '(n/a)');
            }

            alert('✅ Import JSON terminé !\n\n📊 Comédiens importés : ' + newComedians.length +
                  '\n👥 Utilisateurs créés : ' + newUsers.length +
                  (skipped > 0 ? '\n⚠️ Ignorés : ' + skipped : '') +
                  (credList ? '\n\n🔑 IDENTIFIANTS :\n' + credList : ''));

            loadDatabaseView();
        } catch(err) {
            alert('❌ Erreur import JSON : ' + (err.message || err));
        }

        if (event.target) event.target.value = '';
    };
    reader.readAsText(file, 'utf-8');
}

function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a); URL.revokeObjectURL(url);
}

async function importCSV(event) {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = e => parseCSV(e.target.result);
    reader.readAsText(file);
}

async function parseCSV(csv) {
    const lines     = csv.split('\n').map(l => l.trim()).filter(l => l.length > 0);
    const separator = lines[0].includes(';') ? ';' : ',';

    let headerLineIndex = 0;
    for (let i = 0; i < Math.min(5, lines.length); i++) {
        if (lines[i].toLowerCase().includes('nom') && lines[i].toLowerCase().includes('email')) {
            headerLineIndex = i; break;
        }
    }

    const existingEmails = AppState.comedians.map(c => c.email.toLowerCase());
    const newComedians   = [];
    let skipped = 0;

    for (let i = headerLineIndex + 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        const values = line.split(separator).map(v => v.trim().replace(/^"|"$/g, ''));
        if (values.length < 7) continue;

        const nom    = values[0].trim().toUpperCase();
        const prenom = Utils.capitalize(values[1].trim());
        const sexe   = values[2].trim();
        const email  = values[3].trim().toLowerCase();
        const tel    = values[4].trim();

        const classementRaw = values[5] ? values[5].trim().toLowerCase() : '';
        const classement    = classementRaw === 'interne' ? 'interne' : classementRaw === 'externe' ? 'externe' : '';

        const yesNo = v => !!(v && (v.trim().toLowerCase().includes('oui') || v.trim().toLowerCase() === 'yes'));

        if (!email || existingEmails.includes(email)) { skipped++; continue; }

        const password = Utils.generateSecurePassword(12);
        const newComedian = {
            id: Date.now() + i + Math.floor(Math.random() * 1000),
            name: `${prenom} ${nom}`,
            email, phone: tel, sexe, classement,
            seances_dirigees: yesNo(values[6]), voix_off: yesNo(values[7]),
            voix_jouee: yesNo(values[8]), voix_enfant: yesNo(values[9]), chant: yesNo(values[10]),
            voix_jeune: yesNo(values[11]), voix_adulte: yesNo(values[12]),
            voix_mature: yesNo(values[13]), voix_accent: yesNo(values[14]),
            timbre_grave: yesNo(values[15]), timbre_medium: yesNo(values[16]),
            timbre_aigu: yesNo(values[17]), timbre_texture: yesNo(values[18]),
            style_dynamique: yesNo(values[19]), style_pose: yesNo(values[20]),
            style_naturel: yesNo(values[21]), style_institutionnel: yesNo(values[22]),
            voixUrgente: false, commentaireInterne: '', presentation: '',
            username: email.split('@')[0], password,
            identifiantsSent: false, active: !values[23] || !values[23].trim() ? true : yesNo(values[23]),
            profilePic: null, audioPresentation: null, audioDemo: null,
            absences: [], createdAt: new Date().toISOString()
        };
        newComedians.push(newComedian);
        existingEmails.push(email);
    }

    if (newComedians.length === 0) {
        alert(`Aucun comédien importé. ${skipped} doublon(s) ignoré(s).`);
        return;
    }

    const plainPasswords = {};
    for (const c of newComedians) {
        plainPasswords[c.email] = c.password;
    }

    for (const c of newComedians) {
        c.password = await hashPassword(c.password);
    }

    try {
        const insertedRows = await SupabaseDB.bulkInsertComedians(newComedians);

        const existingUsernames = AppState.users.map(u => u.username.toLowerCase());
        const newUsers = [];

        for (const comedian of newComedians) {
            const insertedRow = insertedRows ? insertedRows.find(r => r.email === comedian.email) : null;
            const comedianId  = insertedRow ? insertedRow.id : null;
            if (!comedianId) continue;

            let uname = comedian.username;
            let counter = 2;
            while (existingUsernames.includes(uname.toLowerCase())) {
                uname = comedian.username + counter++;
            }
            existingUsernames.push(uname.toLowerCase());

            newUsers.push({
                username:   uname,
                email:      comedian.email,
                password:   comedian.password, // déjà haché SHA-256
                role:       'comedian',
                comedianId: comedianId,
                active:     true,
                createdAt:  new Date().toISOString()
            });
        }

        if (newUsers.length > 0) await SupabaseDB.bulkInsertUsers(newUsers);

        await SupabaseDB.reloadComedians();
        await SupabaseDB.reloadUsers();

        if (window.broadcastUpdate) {
            await window.broadcastUpdate('comedians');
            await window.broadcastUpdate('users');
        }

        addLog(CONFIG.LOG_TYPES.CREATION, `Import CSV: ${newComedians.length} comediens, ${newUsers.length} utilisateurs`, 'database', null);

        let credentialsList = '';
        for (const u of newUsers) {
            const plain = plainPasswords[u.email] || '(non disponible)';
            credentialsList += `\n  • ${u.username} / ${plain}`;
        }

        alert(`✅ Import terminé !\n\n📊 Comédiens importés : ${newComedians.length}\n👥 Utilisateurs créés : ${newUsers.length}\n⚠️ Ignorés (doublons) : ${skipped}\n\n🔑 IDENTIFIANTS CRÉÉS (notez-les) :${credentialsList}\n\nVous pouvez aussi envoyer les identifiants via le bouton 📧 dans la liste des utilisateurs.`);
        loadDatabaseView();
    } catch(err) {
        alert('❌ Erreur import: ' + (err.message || err));
    }

    if (event && event.target) event.target.value = '';
}

async function deleteComedianFromDB(comedianId) {
    if (confirm('Supprimer ce comedien ? Cette action est irreversible !')) {
        const comedian = AppState.comedians.find(c => c.id === comedianId);
        await SupabaseDB.deleteComedian(comedianId);
        if (window.broadcastUpdate) await window.broadcastUpdate('comedians');
        loadDatabaseView();
        if (comedian) alert(comedian.name + ' supprime.');
    }
}
