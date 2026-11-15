// ================= DASHBOARD MODULE (KPI, WAVE, LIVE STREAM & VERDICTS) =================

async function triggerSim() {
    const btn = document.getElementById('btn-sim');
    btn.disabled = true;
    btn.innerHTML = '<span>⏳ Đang gửi...</span>';
    try {
        await fetch('/api/simulate', { method: 'POST' });
    } catch (e) {
        console.error(e);
    }
    setTimeout(() => {
        btn.disabled = false;
        btn.innerHTML = '<span>⚡ Giả Lập Alert</span>';
    }, 5000);
}

async function clearBlocklist() {
    if (!confirm('Bạn có chắc muốn xóa sạch toàn bộ IP trong Alias SOC_BLOCKLIST trên pfSense?')) return;
    const btn = document.getElementById('btn-clear');
    btn.disabled = true;
    btn.innerText = 'Đang xóa...';
    try {
        await fetch('/api/clear-blocklist', { method: 'POST' });
    } catch (e) {
        console.error(e);
    }
    btn.disabled = false;
    btn.innerText = '🧹 Xóa Blocklist';
    refresh();
}

function renderDashboardWave(data) {
    const areaEl = document.getElementById('dashboard-wave-area');
    const lineEl = document.getElementById('dashboard-wave-line');
    if (!areaEl || !lineEl) return;

    const cases = data.cases || [];
    const stream = data.reasoning_stream || [];
    const buckets = new Array(12).fill(4);

    cases.forEach((c, i) => {
        const idx = i % 12;
        buckets[idx] += Math.min(38, Number(c.alert_count || 1) * 4);
    });
    stream.forEach((s, i) => {
        const idx = (i + 3) % 12;
        buckets[idx] += (s.type === 'VERDICT' || s.type === 'ALERT') ? 10 : 3;
    });

    const maxVal = Math.max(20, ...buckets);
    const pts = buckets.map((v, i) => {
        const x = Math.round((i / (buckets.length - 1)) * 1000);
        const y = Math.round(64 - (v / maxVal) * 48);
        return [x, y];
    });

    let dLine = `M ${pts[0][0]} ${pts[0][1]}`;
    for (let i = 1; i < pts.length; i++) {
        const [x0, y0] = pts[i - 1];
        const [x1, y1] = pts[i];
        const cx = Math.round((x0 + x1) / 2);
        dLine += ` C ${cx} ${y0}, ${cx} ${y1}, ${x1} ${y1}`;
    }
    const dArea = `${dLine} L 1000 72 L 0 72 Z`;
    lineEl.setAttribute('d', dLine);
    areaEl.setAttribute('d', dArea);
}

function renderDashboardStreamAndVerdicts(data) {
    document.getElementById('st-total').innerText = data.stats.total_alerts;
    document.getElementById('st-tp').innerText = data.stats.true_positives;
    document.getElementById('st-fp').innerText = data.stats.false_positives;

    const blockedIps = (data.stats.blocked_ips && data.stats.blocked_ips.length > 0) ? data.stats.blocked_ips : [];
    const epActions = (data.stats.endpoint_actions && data.stats.endpoint_actions.length > 0) ? data.stats.endpoint_actions : [];
    const combinedActions = [...blockedIps.map(ip => `🔥 pfSense: ${ip}`), ...epActions.map(a => `🛡️ ${a}`)];
    document.getElementById('st-blocked').innerText = combinedActions.length > 0 ? combinedActions.join(' | ') : 'Chưa có';

    const streamBox = document.getElementById('stream-box');
    if (!data.reasoning_stream || data.reasoning_stream.length === 0) {
        streamBox.innerHTML = '<div class="h-full flex items-center justify-center text-muted-foreground font-mono text-xs">[Hệ thống sẵn sàng. Đang lắng nghe sự kiện từ pfSense, Wazuh & Threat Intel...]</div>';
    } else {
        streamBox.innerHTML = data.reasoning_stream.map(s => {
            let tagColor = 'text-cyan-700 dark:text-cyan-300';
            if (s.type === 'ALERT') tagColor = 'text-amber-600 dark:text-yellow-400 font-bold';
            else if (s.type === 'CASE') tagColor = 'text-amber-700 dark:text-amber-300 font-semibold';
            else if (s.type === 'THOUGHT') tagColor = 'text-purple-700 dark:text-purple-400';
            else if (s.type === 'TOOL') tagColor = 'text-indigo-700 dark:text-indigo-400 font-semibold';
            else if (s.type === 'VERDICT') tagColor = 'text-rose-700 dark:text-rose-400 font-bold';
            else if (s.type === 'ERROR') tagColor = 'text-red-600 dark:text-red-400 font-bold';

            return `<div class="border-b border-border/60 pb-1 leading-relaxed text-foreground/90">
                <span class="text-muted-foreground">[${escapeHtml(s.time)}]</span>
                <span class="${tagColor}">[${escapeHtml(s.type)}]</span>
                ${escapeHtml(s.message)}
            </div>`;
        }).join('');
    }

    const decisionBox = document.getElementById('decision-box');
    if (!data.decisions || data.decisions.length === 0) {
        decisionBox.innerHTML = `
            <div class="h-full flex flex-col items-center justify-center text-center p-6 text-muted-foreground border border-dashed border-border rounded-xl">
                <div class="text-3xl mb-2">🛡️</div>
                <div class="font-semibold text-foreground/80">Chưa có phán quyết nào</div>
                <div class="text-xs text-muted-foreground mt-1">Hệ thống đang trực chiến. Bấm nút <b>"Giả Lập Alert"</b> trên thanh công cụ để kiểm tra phản ứng Qwen AI &amp; Threat Intel.</div>
            </div>`;
    } else {
        decisionBox.innerHTML = data.decisions.map(d => {
            let borderClass = 'border-l-slate-400';
            let verdictBadge = '<span class="text-[11px] px-2.5 py-0.5 rounded-full font-mono font-bold bg-muted text-muted-foreground border border-border">UNKNOWN</span>';

            if (d.verdict === 'TRUE POSITIVE') {
                borderClass = 'border-l-rose-500';
                verdictBadge = '<span class="text-[11px] px-2.5 py-0.5 rounded-full font-mono font-bold bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30">TRUE POSITIVE</span>';
            } else if (d.verdict === 'FALSE POSITIVE') {
                borderClass = 'border-l-emerald-500';
                verdictBadge = '<span class="text-[11px] px-2.5 py-0.5 rounded-full font-mono font-bold bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">FALSE POSITIVE</span>';
            } else if (d.verdict === 'SUSPICIOUS') {
                borderClass = 'border-l-amber-500';
                verdictBadge = '<span class="text-[11px] px-2.5 py-0.5 rounded-full font-mono font-bold bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">SUSPICIOUS</span>';
            }

            let ipInfoHtml = '';
            if (d.src_ip && d.src_ip !== 'unknown') {
                ipInfoHtml = `SRC: <span class="text-cyan-700 dark:text-cyan-300 font-bold">${escapeHtml(d.src_ip)}</span>`;
                if (d.victim_ip && d.victim_ip !== 'unknown') {
                    ipInfoHtml += ` | Target: <span class="text-amber-700 dark:text-amber-300">${escapeHtml(d.victim_ip)}</span>`;
                }
            } else {
                const endpointHost = (d.victim_ip && d.victim_ip !== 'unknown') ? d.victim_ip : (d.agent_ip && d.agent_ip !== 'unknown' ? d.agent_ip : 'Internal Host');
                ipInfoHtml = `Host: <span class="text-amber-700 dark:text-amber-300 font-bold">${escapeHtml(endpointHost)}</span>`;
            }
            if (d.file_path) {
                ipInfoHtml += ` | File: <span class="text-purple-700 dark:text-purple-300 font-mono">${escapeHtml(d.file_path)}</span>`;
            }

            let mitreHtml = '';
            if (d.mitre && d.mitre.length > 0) {
                mitreHtml = '<div class="flex flex-wrap gap-1 mt-1.5">' + d.mitre.map(m =>
                    `<span class="inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-mono bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30">
                        🛡️ MITRE: ${escapeHtml(m)}
                    </span>`
                ).join('') + '</div>';
            }

            let tiHtml = '';
            if (d.ti_summary) {
                tiHtml = `<div class="mt-1.5 text-[11px] font-mono text-cyan-800 dark:text-cyan-300 bg-cyan-500/10 border border-cyan-500/25 px-2.5 py-1 rounded-lg">
                    🌐 <b>Threat Intel:</b> ${escapeHtml(d.ti_summary)}
                </div>`;
            }

            let arHtml = '';
            if (d.endpoint_response) {
                const isLocked = d.endpoint_response.includes('Giữ khóa cô lập');
                const arStyle = isLocked
                    ? 'text-amber-700 dark:text-amber-300 bg-amber-500/10 border-amber-500/30'
                    : 'text-emerald-700 dark:text-emerald-300 bg-emerald-500/10 border-emerald-500/30';
                arHtml = `<div class="mt-1.5 text-[11px] font-mono ${arStyle} border px-2.5 py-1 rounded-lg">
                    🛡️ <b>Wazuh Active Response (:55000):</b> ${escapeHtml(d.endpoint_response)}
                </div>`;
            }

            return `
                <div class="p-3.5 iris-subcard border-l-4 ${borderClass}">
                    <div class="flex justify-between items-start gap-2 mb-1">
                        <div class="min-w-0">
                            <div class="font-bold text-foreground text-xs sm:text-sm">${d.case_id ? `<span class="text-cyan-700 dark:text-cyan-400 font-mono text-xs mr-1">[${escapeHtml(d.case_id)}]</span>` : ''}${escapeHtml(d.title)}</div>
                            <div class="text-[11px] font-mono text-muted-foreground mt-0.5">
                                ${ipInfoHtml} |
                                Thời gian: <span class="text-foreground/80">${escapeHtml(d.time)}</span> |
                                Nguồn: <span class="text-foreground/80">${escapeHtml(d.source)}</span>
                            </div>
                        </div>
                        <div class="shrink-0">${verdictBadge}</div>
                    </div>
                    ${mitreHtml}
                    ${tiHtml}
                    ${arHtml}
                    <div class="text-foreground/90 mt-2 whitespace-pre-line text-xs font-sans leading-relaxed border-t border-border/70 pt-2">
                        ${escapeHtml(d.summary)}
                    </div>
                </div>
            `;
        }).join('');
    }
}
