// ================= CASE MANAGEMENT & KILL-CHAIN GRAPH MODULE =================

function toggleCaseDetails(caseId) {
    if (expandedCaseIds.has(caseId)) expandedCaseIds.delete(caseId);
    else expandedCaseIds.add(caseId);
    renderCasesFromCache(true);
}

function toggleSavedGraph(caseId) {
    if (openGraphCaseIds.has(caseId)) openGraphCaseIds.delete(caseId);
    else openGraphCaseIds.add(caseId);
    renderCasesFromCache(true);
}

async function generateCaseGraph(caseId) {
    try {
        const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/graph`, { method: 'POST' });
        const data = await res.json();
        if (!data.success || !data.graph) {
            alert('❌ ' + (data.message || 'Không thể dựng sơ đồ tấn công'));
            return;
        }
        const target = (cachedCasesData.cases || []).find(item => item.id === caseId);
        if (target) target.attack_graph = data.graph;
        openGraphCaseIds.add(caseId);
        renderCasesFromCache(true);
    } catch (e) {
        alert('❌ Lỗi kết nối khi dựng Sơ đồ: ' + e);
    }
}

function renderAttackGraphSvg(graph) {
    const nodes = graph.nodes || [];
    const edges = graph.edges || [];
    if (nodes.length === 0) {
        return '<div class="text-xs text-slate-400 p-3">Chưa đủ thực thể để dựng sơ đồ.</div>';
    }

    const presentCols = [...new Set(nodes.map(n => Number(n.col || 0)))].sort((a, b) => a - b);
    const colToIdx = {};
    presentCols.forEach((col, i) => { colToIdx[col] = i; });

    const nodesByCol = {};
    presentCols.forEach(col => { nodesByCol[col] = []; });
    nodes.forEach(n => { nodesByCol[Number(n.col || 0)].push(n); });

    const maxRows = Math.max(1, ...presentCols.map(c => nodesByCol[c].length));
    const nodeW = 176;
    const nodeH = 54;
    const colGap = 68;
    const rowGap = 24;
    const padX = 18;
    const padY = 24;

    const svgW = Math.max(760, padX * 2 + presentCols.length * nodeW + Math.max(0, presentCols.length - 1) * colGap);
    const svgH = Math.max(200, padY * 2 + maxRows * nodeH + Math.max(0, maxRows - 1) * rowGap);

    const pos = {};
    presentCols.forEach(col => {
        const colNodes = nodesByCol[col];
        const colIdx = colToIdx[col];
        const x = padX + colIdx * (nodeW + colGap);
        const totalColH = colNodes.length * nodeH + Math.max(0, colNodes.length - 1) * rowGap;
        const startY = (svgH - totalColH) / 2;
        colNodes.forEach((n, rIdx) => {
            const y = startY + rIdx * (nodeH + rowGap);
            pos[n.id] = { x, y, cx: x + nodeW / 2, cy: y + nodeH / 2 };
        });
    });

    const styleByType = {
        attacker: { stroke: '#f43f5e', fill: '#4c0519', tag: '#fda4af', badge: 'ATTACKER' },
        trigger: { stroke: '#a855f7', fill: '#3b0764', tag: '#d8b4fe', badge: 'TRIGGER' },
        vector: { stroke: '#8b5cf6', fill: '#2e1065', tag: '#c4b5fd', badge: 'TECHNIQUE' },
        target: { stroke: '#f59e0b', fill: '#451a03', tag: '#fcd34d', badge: 'TARGET' },
        related_case: { stroke: '#ec4899', fill: '#500724', tag: '#f9a8d4', badge: 'LINKED' },
        artifact_file: { stroke: '#06b6d4', fill: '#083344', tag: '#67e8f9', badge: 'FILE' },
        artifact_hash: { stroke: '#0ea5e9', fill: '#0c4a6e', tag: '#7dd3fc', badge: 'HASH / TI' },
        artifact_proc: { stroke: '#22d3ee', fill: '#164e63', tag: '#a5f3fc', badge: 'PROCESS' },
        soar_action: { stroke: '#10b981', fill: '#022c22', tag: '#6ee7b7', badge: 'SOAR DEFENSE' },
    };

    const markerId = `arrow-${escapeHtml(graph.case_id || 'case')}`.replace(/[^a-zA-Z0-9_-]/g, '');

    const edgesSvg = edges.map(e => {
        const s = pos[e.source];
        const t = pos[e.target];
        if (!s || !t) return '';
        const x1 = s.x + nodeW;
        const y1 = s.cy;
        const x2 = t.x;
        const y2 = t.cy;
        const dx = Math.max(30, Math.abs(x2 - x1) * 0.45);
        const d = (x2 >= x1)
            ? `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2 - 4} ${y2}`
            : `M ${s.cx} ${s.y} Q ${(s.cx + t.cx) / 2} ${Math.min(s.y, t.y) - 36}, ${t.cx} ${t.y}`;
        const mx = (x1 + x2) / 2;
        const my = (y1 + y2) / 2 - 6;
        const lbl = escapeHtml(e.label || '');
        const lblSvg = lbl ? `
            <rect x="${mx - Math.min(54, lbl.length * 3.2 + 6)}" y="${my - 9}" width="${Math.min(108, lbl.length * 6.4 + 12)}" height="14" rx="4" fill="#0f172a" stroke="#334155" stroke-width="0.8"/>
            <text x="${mx}" y="${my + 1}" text-anchor="middle" fill="#cbd5e1" font-size="9" font-family="monospace">${lbl}</text>
        ` : '';
        return `<path d="${d}" fill="none" stroke="#64748b" stroke-width="1.6" marker-end="url(#${markerId})" opacity="0.9"/>${lblSvg}`;
    }).join('');

    const nodesSvg = nodes.map(n => {
        const p = pos[n.id];
        if (!p) return '';
        const st = styleByType[n.type] || { stroke: '#64748b', fill: '#1e293b', tag: '#cbd5e1', badge: 'ENTITY' };
        const titleTxt = (n.label || '').length > 23 ? (n.label.slice(0, 22) + '…') : (n.label || '');
        const subTxt = (n.sublabel || '').length > 26 ? (n.sublabel.slice(0, 25) + '…') : (n.sublabel || '');
        return `
            <g transform="translate(${p.x}, ${p.y})">
                <rect width="${nodeW}" height="${nodeH}" rx="8" fill="${st.fill}" stroke="${st.stroke}" stroke-width="1.5"/>
                <text x="10" y="15" fill="${st.tag}" font-size="8.5" font-weight="bold" font-family="monospace">${escapeHtml(st.badge)}</text>
                <text x="10" y="31" fill="#f8fafc" font-size="11" font-weight="bold" font-family="sans-serif">${escapeHtml(titleTxt)}</text>
                <text x="10" y="45" fill="#94a3b8" font-size="9.5" font-family="monospace">${escapeHtml(subTxt)}</text>
            </g>
        `;
    }).join('');

    return `
        <div class="overflow-x-auto bg-slate-950 border border-slate-800 rounded-lg p-2">
            <svg width="${svgW}" height="${svgH}" viewBox="0 0 ${svgW} ${svgH}" class="mx-auto block">
                <defs>
                    <marker id="${markerId}" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
                        <polygon points="0 0, 8 3, 0 6" fill="#94a3b8"/>
                    </marker>
                </defs>
                ${edgesSvg}
                ${nodesSvg}
            </svg>
        </div>
    `;
}

async function changeCaseStatus(caseId, newStatus) {
    try {
        const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/status`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus, reason: newStatus === 'CLOSED' ? 'Đóng từ Web UI SOC' : 'Mở lại từ Web UI SOC' })
        });
        const data = await res.json();
        if (!data.success) alert('❌ ' + (data.message || 'Lỗi cập nhật trạng thái Case'));
        await refresh();
    } catch (e) {
        alert('❌ Lỗi kết nối: ' + e);
    }
}

async function replayCase(caseId) {
    try {
        const res = await fetch(`/api/cases/${encodeURIComponent(caseId)}/replay`, { method: 'POST' });
        const data = await res.json();
        if (data.success) alert(`🔄 ${data.message}`);
        else alert(`❌ ${data.message}`);
        await refresh();
    } catch (e) {
        alert('❌ Lỗi Replay Case: ' + e);
    }
}

function renderCasesFromCache(force = false) {
    const cases = cachedCasesData.cases || [];
    const parentIncidents = cachedCasesData.parent_incidents || [];
    const domainFilter = (document.getElementById('case-filter-domain')?.value || '').toUpperCase();
    const statusFilter = (document.getElementById('case-filter-status')?.value || '').toUpperCase();
    const searchQuery = (document.getElementById('case-search')?.value || '').trim().toLowerCase();

    const signature = JSON.stringify({
        df: domainFilter,
        sf: statusFilter,
        sq: searchQuery,
        exp: [...expandedCaseIds].sort(),
        grp: [...openGraphCaseIds].sort(),
        pis: parentIncidents.map(p => `${p.id}:${p.updated_at}:${p.severity}:${(p.combined_timeline || []).length}`),
        cs: cases.map(c => `${c.id}:${c.status}:${c.verdict}:${c.severity}:${c.alert_count}:${c.slm_calls}:${c.updated_at}:${(c.related_case_ids || []).join(',')}:${c.attack_graph ? c.attack_graph.generated_at : ''}`)
    });
    if (!force && signature === lastCasesRenderSignature) return;
    lastCasesRenderSignature = signature;

    const summaryEl = document.getElementById('case-summary-count');
    if (summaryEl) summaryEl.innerText = `(${cases.length} Cases | ${parentIncidents.length} Parent Incidents)`;

    const parentSection = document.getElementById('parent-incidents-section');
    const parentList = document.getElementById('parent-incidents-list');
    if (parentSection && parentList) {
        if (parentIncidents.length === 0) {
            parentSection.classList.add('hidden');
            parentList.innerHTML = '';
        } else {
            parentSection.classList.remove('hidden');
            parentList.innerHTML = parentIncidents.map(inc => {
                const timelineHtml = (inc.combined_timeline || []).slice(-6).map(t =>
                    `<div class="text-[11px] font-mono text-foreground/80 border-l-2 border-rose-500 pl-2 py-0.5">
                        [${escapeHtml(t.time)}] <span class="text-cyan-600 dark:text-cyan-300 font-semibold">${escapeHtml(t.case_id)}</span> (${escapeHtml(t.domain)}) — ${escapeHtml(t.title)}
                    </div>`
                ).join('');
                return `
                    <div class="p-3.5 rounded-xl bg-rose-500/5 border border-rose-500/30 space-y-1.5">
                        <div class="flex justify-between items-center gap-2">
                            <div class="font-bold text-rose-700 dark:text-rose-300 text-xs inline-flex items-center gap-1.5">${renderIcon('link-2', 'w-3.5 h-3.5')}<span>${escapeHtml(inc.id)}: ${escapeHtml(inc.title)}</span></div>
                            <span class="px-2 py-0.5 rounded-full text-[10px] font-bold bg-rose-500/15 text-rose-700 dark:text-rose-200 border border-rose-500/30">${escapeHtml(inc.severity)}</span>
                        </div>
                        <div class="text-[11px] font-mono text-foreground/80">
                            Kill-Chain: ${escapeHtml(inc.kill_chain_summary)} | Child Cases: <span class="text-amber-600 dark:text-amber-300 font-semibold">${escapeHtml((inc.child_case_ids || []).join(', '))}</span>
                        </div>
                        <div class="text-[11px] text-muted-foreground">${escapeHtml((inc.escalation_reasons || []).join(' | '))}</div>
                        <div class="space-y-0.5 pt-1">${timelineHtml}</div>
                    </div>
                `;
            }).join('');
        }
    }

    const filtered = cases.filter(c => {
        if (domainFilter && c.domain !== domainFilter) return false;
        if (statusFilter && c.status !== statusFilter) return false;
        if (searchQuery) {
            const hay = [c.id, c.title, c.src_ip, c.agent_id, ...(c.victim_ips || []), c.verdict].join(' ').toLowerCase();
            if (!hay.includes(searchQuery)) return false;
        }
        return true;
    });

    const listEl = document.getElementById('cases-list');
    if (!listEl) return;
    if (filtered.length === 0) {
        listEl.innerHTML = '<div class="p-6 text-center text-muted-foreground border border-dashed border-border rounded-xl">Chưa có hồ sơ Case nào khớp bộ lọc.</div>';
        return;
    }

    listEl.innerHTML = filtered.map(c => {
        const isExpanded = expandedCaseIds.has(c.id);
        const sevColors = {
            'CRITICAL': 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30',
            'HIGH': 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30',
            'MEDIUM': 'bg-yellow-500/15 text-yellow-700 dark:text-yellow-300 border-yellow-500/30',
            'LOW': 'bg-muted text-muted-foreground border-border'
        };
        const sevClass = sevColors[c.severity] || sevColors['LOW'];
        const verdictColors = {
            'TRUE POSITIVE': 'bg-rose-600/15 text-rose-700 dark:text-rose-200 border-rose-500/30',
            'SUSPICIOUS': 'bg-amber-500/15 text-amber-700 dark:text-amber-200 border-amber-500/30',
            'FALSE POSITIVE': 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-200 border-emerald-500/30',
            'UNKNOWN': 'bg-muted text-muted-foreground border-border'
        };
        const vClass = verdictColors[c.verdict] || verdictColors['UNKNOWN'];
        const statusBadge = c.status === 'CLOSED'
            ? '<span class="px-2 py-0.5 rounded-full text-[10px] font-mono bg-muted text-muted-foreground border border-border">CLOSED</span>'
            : '<span class="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">OPEN</span>';
        const domainBadge = c.domain === 'NETWORK'
            ? '<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/25">NETWORK</span>'
            : '<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/25">ENDPOINT</span>';

        const targetDisplay = c.domain === 'NETWORK'
            ? `Attacker: <span class="text-rose-600 dark:text-rose-300 font-bold">${escapeHtml(c.src_ip)}</span> → Victims: <span class="text-amber-600 dark:text-amber-300 font-semibold">${escapeHtml((c.victim_ips || []).join(', ') || 'N/A')}</span>`
            : `Agent: <span class="text-purple-600 dark:text-purple-300 font-bold">${escapeHtml(c.agent_id)}</span> (${escapeHtml((c.victim_ips || []).join(', ') || 'N/A')})`;

        const relatedHtml = (c.related_case_ids && c.related_case_ids.length > 0)
            ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-500/10 text-rose-700 dark:text-rose-300 border border-rose-500/30 font-mono text-[10px]">${renderIcon('link-2', 'w-3 h-3')}<span>Related: ${escapeHtml(c.related_case_ids.join(', '))} ${c.parent_incident_id ? '(' + escapeHtml(c.parent_incident_id) + ')' : ''}</span></span>`
            : '';

        const toggleActionStatus = c.status === 'CLOSED'
            ? `<button onclick="changeCaseStatus('${escapeHtml(c.id)}', 'OPEN')" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-700 dark:text-emerald-200 border border-emerald-500/30 text-[11px] font-medium">${renderIcon('unlock', 'w-3 h-3')}<span>Mở lại</span></button>`
            : `<button onclick="changeCaseStatus('${escapeHtml(c.id)}', 'CLOSED')" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-muted hover:bg-muted/80 text-foreground border border-border text-[11px] font-medium">${renderIcon('lock', 'w-3 h-3')}<span>Đóng Case</span></button>`;

        const hasGraph = Boolean(c.attack_graph);
        const isGraphOpen = hasGraph && openGraphCaseIds.has(c.id);
        const isGraphStale = hasGraph && (c.alert_count > (c.attack_graph.generated_at_alert_count || 0));
        const graphBtnHtml = !hasGraph
            ? `<button onclick="generateCaseGraph('${escapeHtml(c.id)}')" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 text-indigo-700 dark:text-indigo-200 border border-indigo-500/30 text-[11px] font-medium">${renderIcon('waypoints', 'w-3 h-3')}<span>Vẽ Sơ Đồ</span></button>`
            : `<button onclick="toggleSavedGraph('${escapeHtml(c.id)}')" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 text-indigo-700 dark:text-indigo-200 border border-indigo-500/30 text-[11px] font-medium">${renderIcon('waypoints', 'w-3 h-3')}<span>${isGraphOpen ? 'Ẩn Sơ Đồ' : 'Xem Sơ Đồ'}</span></button>` +
              ((isGraphOpen || isGraphStale) ? `<button onclick="generateCaseGraph('${escapeHtml(c.id)}')" title="Cập nhật lại sơ đồ theo dữ liệu mới nhất" class="inline-flex items-center gap-1 px-2 py-1 rounded-lg bg-muted hover:bg-muted/80 text-indigo-600 dark:text-indigo-300 border border-border text-[11px]">${renderIcon('refresh-cw', 'w-3 h-3')}<span>${isGraphStale ? 'Cập Nhật' : 'Vẽ Lại'}</span></button>` : '');

        let graphContainerHtml = '';
        if (isGraphOpen) {
            const g = c.attack_graph;
            graphContainerHtml = `
                <div class="mt-2.5 pt-2.5 border-t border-indigo-500/25 space-y-2 iris-subcard p-3">
                    <div class="flex flex-wrap justify-between items-center gap-2 text-[11px]">
                        <span class="font-bold text-indigo-700 dark:text-indigo-300 inline-flex items-center gap-1.5">${renderIcon('waypoints', 'w-3.5 h-3.5')}<span>SƠ ĐỒ MỐI LIÊN HỆ TRỰC QUAN (${escapeHtml(c.id)}) — Đã lưu lúc ${escapeHtml(g.generated_at)} (${g.generated_at_alert_count} alerts)</span></span>
                        <span class="text-muted-foreground font-mono inline-flex flex-wrap items-center gap-2.5">
                            <span class="inline-flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-rose-500"></span>Attacker</span>
                            <span class="inline-flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-purple-500"></span>Kỹ thuật</span>
                            <span class="inline-flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-amber-500"></span>Mục tiêu</span>
                            <span class="inline-flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-sky-500"></span>File/Hash/Proc</span>
                            <span class="inline-flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-emerald-500"></span>SOAR Defense</span>
                        </span>
                    </div>
                    ${renderAttackGraphSvg(g)}
                    <div class="text-[11px] font-mono text-indigo-700 dark:text-indigo-200 bg-indigo-500/10 border border-indigo-500/25 px-2.5 py-1.5 rounded-lg">
                        <b>Đường đi tấn công:</b> ${escapeHtml(g.attack_path_summary || '')}
                    </div>
                </div>
            `;
        }

        let detailsHtml = '';
        if (isExpanded) {
            const alertsRows = (c.incident_alerts || []).slice().reverse().map((a, idx) =>
                `<div class="border-b border-border/70 py-1.5 font-mono text-[11px] flex justify-between gap-2">
                    <span class="text-foreground/90">#${(c.incident_alerts.length - idx)} [${escapeHtml(a.captured_at || '')}] Rule ${escapeHtml(a.rule_id || '?')} (Lv.${escapeHtml(a.level || 0)}) — ${escapeHtml(a.title || '')}</span>
                    <span class="text-muted-foreground shrink-0">${escapeHtml(a.src_ip !== 'unknown' ? (a.src_ip + ' → ' + a.victim_ip) : (a.file_path || a.victim_ip))}</span>
                </div>`
            ).join('');
            const escHtml = (c.escalation_reasons && c.escalation_reasons.length > 0)
                ? `<div class="text-[11px] text-amber-700 dark:text-amber-300 bg-amber-500/10 border border-amber-500/30 p-2.5 rounded-lg"><b>Lý do nâng mức / Vòng đời:</b><br>${c.escalation_reasons.map(r => '• ' + escapeHtml(r)).join('<br>')}</div>`
                : '';
            detailsHtml = `
                <div class="mt-2.5 pt-2.5 border-t border-border space-y-2 iris-subcard p-3">
                    ${escHtml}
                    <div class="text-[11px] font-semibold text-cyan-600 dark:text-cyan-300 inline-flex items-center gap-1.5">${renderIcon('scroll-text', 'w-3.5 h-3.5')}<span>Danh sách Alert gốc đã gom (${(c.incident_alerts || []).length} alerts lưu kiểm toán):</span></div>
                    <div class="max-h-44 overflow-y-auto pr-1">${alertsRows || '<div class="text-muted-foreground">Không có dữ liệu alert</div>'}</div>
                </div>
            `;
        }

        return `
            <div id="case-card-${escapeHtml(c.id)}" class="p-3.5 iris-subcard space-y-2">
                <div class="flex flex-wrap justify-between items-center gap-2">
                    <div class="flex flex-wrap items-center gap-1.5">
                        <span class="font-mono font-bold text-foreground">${escapeHtml(c.id)}</span>
                        ${domainBadge}
                        ${statusBadge}
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${sevClass}">${escapeHtml(c.severity)}</span>
                        <span class="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold border ${vClass}">${escapeHtml(c.verdict)}</span>
                        ${relatedHtml}
                    </div>
                    <div class="flex flex-wrap items-center gap-1.5">
                        <span class="text-[11px] font-mono text-cyan-700 dark:text-cyan-300 bg-card px-2 py-0.5 rounded-lg border border-border">Alerts: <b>${c.alert_count}</b> | SLM: <b>${c.slm_calls}</b></span>
                        <button onclick="toggleCaseDetails('${escapeHtml(c.id)}')" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-700 dark:text-cyan-200 border border-cyan-500/30 text-[11px] font-medium">${renderIcon(isExpanded ? 'chevron-up' : 'chevron-down', 'w-3 h-3')}<span>${isExpanded ? 'Thu gọn' : 'Chi tiết'}</span></button>
                        ${graphBtnHtml}
                        <button onclick="replayCase('${escapeHtml(c.id)}')" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-purple-500/15 hover:bg-purple-500/25 text-purple-700 dark:text-purple-200 border border-purple-500/30 text-[11px] font-medium">${renderIcon('refresh-cw', 'w-3 h-3')}<span>Replay</span></button>
                        <button onclick="sendCaseToCurrentRoom('${escapeHtml(c.id)}')" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-amber-500/15 hover:bg-amber-500/25 text-amber-700 dark:text-amber-200 border border-amber-500/30 text-[11px] font-medium">${renderIcon('siren', 'w-3 h-3')}<span>Đưa vào Room</span></button>
                        ${toggleActionStatus}
                    </div>
                </div>
                <div class="text-xs text-foreground font-semibold">${escapeHtml(c.title)}</div>
                <div class="text-[11px] font-mono text-muted-foreground">
                    ${targetDisplay} | Tạo lúc: ${escapeHtml(c.created_at)} | Cập nhật: ${escapeHtml(c.updated_at)}
                    ${c.close_reason ? ` | Đóng: <span class="text-foreground/80">${escapeHtml(c.close_reason)}</span>` : ''}
                </div>
                ${graphContainerHtml}
                ${detailsHtml}
            </div>
        `;
    }).join('');
}
