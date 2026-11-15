// ================= MISP IOC VAULT MODULE =================

function onMispSearchInput() {
    if (mispSearchTimeout) clearTimeout(mispSearchTimeout);
    mispSearchTimeout = setTimeout(() => { loadMispIocs(); }, 300);
}

async function loadMispIocs() {
    try {
        const searchEl = document.getElementById('misp-search');
        const searchVal = searchEl ? searchEl.value.trim() : '';
        const url = searchVal ? `/api/misp?search=${encodeURIComponent(searchVal)}&limit=100` : '/api/misp?limit=100';
        const res = await fetch(url);
        const data = await res.json();

        const total = data.total !== undefined ? data.total : (Array.isArray(data) ? data.length : 0);
        const iocs = data.iocs || (Array.isArray(data) ? data : []);

        const cntEl = document.getElementById('misp-count');
        if (cntEl) cntEl.innerText = `(${total.toLocaleString()} IOCs trong Vault)`;
        const tbody = document.getElementById('misp-table-body');
        if (!tbody) return;
        if (iocs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="p-6 text-center text-muted-foreground font-sans">Không tìm thấy IOC nào trong kho dữ liệu.</td></tr>';
            return;
        }
        tbody.innerHTML = iocs.map((ioc, idx) => {
            let badgeColor = 'bg-muted text-muted-foreground border-border';
            const lvl = (ioc.threat_level || ioc.confidence || '').toLowerCase();
            if (lvl === 'critical') badgeColor = 'bg-rose-500/15 text-rose-700 dark:text-rose-400 border-rose-500/30';
            else if (lvl === 'high') badgeColor = 'bg-amber-500/15 text-amber-700 dark:text-amber-400 border-amber-500/30';
            else if (lvl === 'medium') badgeColor = 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-400 border-yellow-500/30';
            else if (lvl === 'low') badgeColor = 'bg-blue-500/15 text-blue-700 dark:text-blue-400 border-blue-500/30';

            let sourceBadge = 'bg-muted text-muted-foreground border-border';
            const src = ioc.source || '';
            if (src.includes('Lab')) sourceBadge = 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-400 border-emerald-500/30';
            else if (src.includes('Feodo')) sourceBadge = 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-400 border-cyan-500/30';
            else if (src.includes('URLhaus')) sourceBadge = 'bg-purple-500/15 text-purple-700 dark:text-purple-400 border-purple-500/30';
            else if (src.includes('Ipsum')) sourceBadge = 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-400 border-indigo-500/30';

            const zebraCls = idx % 2 === 0 ? 'bg-card' : 'bg-muted/25';
            return `
                <tr class="${zebraCls} hover:bg-muted/60 transition-colors">
                    <td class="p-2.5 text-muted-foreground">${escapeHtml(ioc.id)}</td>
                    <td class="p-2.5 text-cyan-700 dark:text-cyan-300 font-mono text-[11px]">${escapeHtml(ioc.type)}</td>
                    <td class="p-2.5 text-foreground font-bold select-all">${escapeHtml(ioc.value)}</td>
                    <td class="p-2.5"><span class="px-2 py-0.5 rounded-full text-[10px] border ${badgeColor}">${escapeHtml(ioc.threat_level || ioc.confidence || 'Medium')}</span></td>
                    <td class="p-2.5"><span class="px-2 py-0.5 rounded-full text-[10px] font-sans border ${sourceBadge}">${escapeHtml(ioc.source || 'OSINT')}</span></td>
                    <td class="p-2.5 text-foreground/85 font-sans text-xs max-w-xs truncate" title="${escapeHtml(ioc.comment || ioc.threat_name || '')}">${escapeHtml(ioc.comment || ioc.threat_name || '')}</td>
                    <td class="p-2.5 text-muted-foreground text-[11px] whitespace-nowrap">${escapeHtml(ioc.date || ioc.updated_at || '')}</td>
                </tr>
            `;
        }).join('');
    } catch (e) {
        console.error("Lỗi tải MISP IOCs:", e);
    }
}

async function syncMispFeeds() {
    const btn = document.getElementById('btn-sync-osint');
    const originalHtml = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `${renderIcon('loader-2', 'w-3.5 h-3.5 animate-spin')}<span>Đang tải Feeds từ OSINT...</span>`;
    btn.classList.add('opacity-75', 'cursor-not-allowed');
    try {
        const res = await fetch('/api/misp/sync', { method: 'POST' });
        const data = await res.json();
        if (data.success) {
            alert(`✅ ${data.message}`);
            loadMispIocs();
        } else {
            alert(`❌ Lỗi cập nhật: ${data.message}`);
        }
    } catch (e) {
        alert(`❌ Lỗi kết nối tới server: ${e}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalHtml;
        btn.classList.remove('opacity-75', 'cursor-not-allowed');
    }
}

async function addMispIoc(e) {
    e.preventDefault();
    const type = document.getElementById('ioc-type').value;
    const value = document.getElementById('ioc-value').value;
    const threat_level = document.getElementById('ioc-threat').value;
    const comment = document.getElementById('ioc-comment').value;
    try {
        const res = await fetch('/api/misp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type, value, threat_level, comment })
        });
        const data = await res.json();
        if (data.success) {
            document.getElementById('ioc-value').value = '';
            document.getElementById('ioc-comment').value = '';
            loadMispIocs();
        } else {
            alert('Lỗi: ' + data.message);
        }
    } catch (err) {
        alert('Lỗi gửi request: ' + err);
    }
}
