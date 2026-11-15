// ================= ASSET MANAGER MODULE =================

function getAssetLabelBadgeClass(label) {
    const lbl = (label || '').toLowerCase().trim();
    if (lbl === 'firewall' || lbl === 'router' || lbl === 'network') {
        return 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30';
    }
    if (lbl === 'linux') {
        return 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/30';
    }
    if (lbl === 'windows') {
        return 'bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30';
    }
    if (lbl === 'máy trạm' || lbl === 'endpoint') {
        return 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30';
    }
    if (lbl === 'server' || lbl === 'siem' || lbl === 'soc' || lbl === 'web' || lbl === 'gpu-host' || lbl === 'ai-core') {
        return 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30';
    }
    return 'bg-muted text-muted-foreground border-border';
}

function syncAssetFilterOptions(assets) {
    const selectEl = document.getElementById('asset-filter-label');
    if (!selectEl) return;
    const currentVal = selectEl.value;
    const knownOptions = new Set(Array.from(selectEl.options).map(o => o.value));
    assets.forEach(a => {
        (a.labels || []).forEach(lbl => {
            const clean = (lbl || '').trim().toLowerCase();
            if (clean && !knownOptions.has(clean)) {
                knownOptions.add(clean);
                const opt = document.createElement('option');
                opt.value = clean;
                opt.textContent = clean;
                selectEl.appendChild(opt);
            }
        });
    });
    selectEl.value = currentVal;
}

function renderAssetsFromCache(force = false) {
    const assets = cachedAssetsData || [];
    syncAssetFilterOptions(assets);

    const searchEl = document.getElementById('asset-search');
    const labelEl = document.getElementById('asset-filter-label');
    const searchQuery = searchEl ? searchEl.value.trim().toLowerCase() : '';
    const labelFilter = labelEl ? labelEl.value.trim().toLowerCase() : '';

    const signature = JSON.stringify(assets) + '|' + searchQuery + '|' + labelFilter;
    if (!force && signature === lastAssetsRenderSignature) return;
    lastAssetsRenderSignature = signature;

    const totalCasesLinked = assets.reduce((acc, a) => acc + (a.case_count || 0), 0);
    const summaryEl = document.getElementById('asset-summary-count');
    if (summaryEl) {
        summaryEl.innerText = `(${assets.length} Thiết bị | ${totalCasesLinked} lượt Case ghi nhận)`;
    }

    const filtered = assets.filter(a => {
        if (labelFilter && !(a.labels || []).some(l => (l || '').toLowerCase() === labelFilter)) return false;
        if (searchQuery) {
            const hay = [a.id, a.name, a.ip, ...(a.extra_ips || []), a.agent_id, ...(a.labels || []), a.owner, ...(a.case_ids || [])].join(' ').toLowerCase();
            if (!hay.includes(searchQuery)) return false;
        }
        return true;
    });

    const tbody = document.getElementById('asset-table-body');
    if (!tbody) return;
    if (filtered.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="p-6 text-center text-muted-foreground">Không tìm thấy thiết bị nào khớp bộ lọc.</td></tr>';
        return;
    }

    tbody.innerHTML = filtered.map((a, idx) => {
        const labelsHtml = (a.labels && a.labels.length > 0)
            ? a.labels.map(lbl => `<span class="inline-block px-2 py-0.5 rounded-full text-[10px] font-mono border ${getAssetLabelBadgeClass(lbl)}">${escapeHtml(lbl)}</span>`).join(' ')
            : '<span class="text-muted-foreground text-[11px]">Chưa gắn nhãn</span>';

        const ipsList = (a.all_ips && a.all_ips.length > 0) ? a.all_ips.join(', ') : (a.ip || 'N/A');
        const agentText = a.agent_id ? `<div class="text-[10px] text-purple-600 dark:text-purple-300 font-mono mt-0.5">Wazuh Agent: #${escapeHtml(a.agent_id)}</div>` : '';
        const containmentBadge = a.containment_status
            ? `<div class="mt-1 inline-block px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">🛡️ ${escapeHtml(a.containment_status)}</div>`
            : '';

        const caseCount = Number(a.case_count || 0);
        const openCount = Number(a.open_case_count || 0);
        const caseCountColor = caseCount === 0
            ? 'bg-muted text-muted-foreground border-border'
            : (openCount > 0 ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30 font-bold' : 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/30 font-bold');

        const caseLinksHtml = (a.case_ids && a.case_ids.length > 0)
            ? '<div class="flex flex-wrap gap-1 mt-1.5">' + a.case_ids.slice(0, 4).map(cid =>
                `<button onclick="openCaseFromAsset('${escapeHtml(cid)}')" class="px-1.5 py-0.5 rounded bg-card hover:bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-border hover:border-cyan-500/40 font-mono text-[10px] transition">${escapeHtml(cid)}</button>`
              ).join('') + (a.case_ids.length > 4 ? `<span class="text-[10px] text-muted-foreground">+${a.case_ids.length - 4}</span>` : '') + '</div>'
            : '';

        const zebraCls = idx % 2 === 0 ? 'bg-card' : 'bg-muted/25';
        return `
            <tr class="${zebraCls} hover:bg-muted/60 align-top transition-colors">
                <td class="p-3">
                    <div class="font-bold text-foreground">${escapeHtml(a.name)}</div>
                    <div class="text-[10px] font-mono text-emerald-600 dark:text-emerald-400">${escapeHtml(a.id)}</div>
                    ${containmentBadge}
                </td>
                <td class="p-3 font-mono text-foreground">
                    <div>${escapeHtml(ipsList)}</div>
                    ${agentText}
                </td>
                <td class="p-3"><div class="flex flex-wrap gap-1">${labelsHtml}</div></td>
                <td class="p-3 text-foreground font-medium">${escapeHtml(a.owner || 'Unassigned')}</td>
                <td class="p-3">
                    <div class="flex items-center gap-1.5">
                        <span class="px-2 py-0.5 rounded-full text-[11px] font-mono border ${caseCountColor}">${caseCount} Case</span>
                        ${openCount > 0 ? `<span class="px-1.5 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">${openCount} đang mở</span>` : ''}
                    </div>
                    ${caseLinksHtml}
                </td>
                <td class="p-3 text-right whitespace-nowrap space-x-1">
                    <button onclick="editAssetItem('${escapeHtml(a.id)}')" class="px-2.5 py-1 rounded-lg bg-card hover:bg-muted text-cyan-700 dark:text-cyan-300 border border-border text-[11px]">✏️ Sửa</button>
                    <button onclick="deleteAssetItem('${escapeHtml(a.id)}', '${escapeHtml(a.name)}')" class="px-2.5 py-1 rounded-lg bg-rose-500/10 hover:bg-rose-500/20 text-rose-700 dark:text-rose-300 border border-rose-500/30 text-[11px]">🗑️ Xóa</button>
                </td>
            </tr>
        `;
    }).join('');
}

function editAssetItem(assetId) {
    const asset = (cachedAssetsData || []).find(a => a.id === assetId);
    if (!asset) return;
    document.getElementById('asset-edit-id').value = asset.id || '';
    document.getElementById('asset-name').value = asset.name || '';
    document.getElementById('asset-ip').value = asset.ip || '';
    document.getElementById('asset-agent-id').value = asset.agent_id || '';
    document.getElementById('asset-labels').value = (asset.labels || []).join(', ');
    document.getElementById('asset-owner').value = asset.owner || '';
    document.getElementById('btn-asset-submit').innerText = '💾 Lưu';
    document.getElementById('btn-asset-cancel-edit').classList.remove('hidden');
    document.getElementById('asset-name').focus();
}

function resetAssetForm() {
    document.getElementById('asset-edit-id').value = '';
    document.getElementById('asset-name').value = '';
    document.getElementById('asset-ip').value = '';
    document.getElementById('asset-agent-id').value = '';
    document.getElementById('asset-labels').value = '';
    document.getElementById('asset-owner').value = '';
    document.getElementById('btn-asset-submit').innerText = '+ Lưu';
    document.getElementById('btn-asset-cancel-edit').classList.add('hidden');
}

async function saveAssetForm(e) {
    e.preventDefault();
    const id = document.getElementById('asset-edit-id').value.trim();
    const name = document.getElementById('asset-name').value.trim();
    const ip = document.getElementById('asset-ip').value.trim();
    const agent_id = document.getElementById('asset-agent-id').value.trim();
    const labels = document.getElementById('asset-labels').value.trim();
    const owner = document.getElementById('asset-owner').value.trim();
    try {
        const res = await fetch('/api/assets', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: id || undefined, name, ip, agent_id, labels, owner })
        });
        const data = await res.json();
        if (data.success) {
            cachedAssetsData = data.assets || cachedAssetsData;
            const badge = document.getElementById('btn-asset-count');
            if (badge) badge.innerText = cachedAssetsData.length;
            resetAssetForm();
            renderAssetsFromCache(true);
        } else {
            alert('❌ ' + (data.message || 'Không thể lưu thiết bị.'));
        }
    } catch (err) {
        alert('❌ Lỗi kết nối server: ' + err);
    }
}

async function deleteAssetItem(assetId, assetName) {
    if (!confirm(`Bạn có chắc muốn xóa thiết bị ${assetId} (${assetName}) khỏi Asset Manager?`)) return;
    try {
        const res = await fetch(`/api/assets/${encodeURIComponent(assetId)}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            cachedAssetsData = data.assets || [];
            const badge = document.getElementById('btn-asset-count');
            if (badge) badge.innerText = cachedAssetsData.length;
            if (document.getElementById('asset-edit-id').value === assetId) resetAssetForm();
            renderAssetsFromCache(true);
        } else {
            alert('❌ ' + (data.message || 'Không thể xóa thiết bị.'));
        }
    } catch (err) {
        alert('❌ Lỗi xóa thiết bị: ' + err);
    }
}

function openCaseFromAsset(caseId) {
    switchView('cases');
    const domainEl = document.getElementById('case-filter-domain');
    const statusEl = document.getElementById('case-filter-status');
    const cSearch = document.getElementById('case-search');
    if (domainEl) domainEl.value = '';
    if (statusEl) statusEl.value = '';
    if (cSearch) cSearch.value = '';
    expandedCaseIds.add(caseId);
    renderCasesFromCache(true);
    setTimeout(() => {
        document.getElementById(`case-card-${caseId}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 60);
}
