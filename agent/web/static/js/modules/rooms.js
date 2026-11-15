// ================= CONTINGENCY ROOM MODULE (WAR ROOM + STREAM + DECISIONS) =================

let highlightedDecisionId = '';
let pendingRevertDecisionId = '';

function openDecisionInRoom(decisionId, roomId = '', caseId = '') {
    const rooms = cachedRoomsData || [];
    let targetRoom = roomId ? rooms.find(r => r.id === roomId) : null;
    if (!targetRoom) {
        targetRoom = rooms.find(r => (r.room_decisions || []).some(d => d.id === decisionId));
    }
    if (!targetRoom && caseId) {
        targetRoom = rooms.find(r => (r.case_ids || []).includes(caseId));
    }
    if (targetRoom) selectedRoomId = targetRoom.id;
    highlightedDecisionId = decisionId || '';
    switchView('rooms');
    setRoomSubTab('decisions');
    renderContingencyRoomsFromCache(true);
    setTimeout(() => {
        const el = document.getElementById(`decision-card-${decisionId}`);
        if (el) {
            el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }, 80);
}

function setRoomSubTab(tab) {
    if (!['all', 'board', 'stream', 'decisions', 'cases'].includes(tab)) tab = 'all';
    activeRoomSubTab = tab;
    try { localStorage.setItem('soc_room_subtab', tab); } catch (e) {}

    document.querySelectorAll('.room-subtab').forEach(btn => {
        const isAct = btn.id === `room-subtab-${tab}`;
        btn.classList.toggle('text-foreground', isAct);
        btn.classList.toggle('font-semibold', isAct);
        btn.classList.toggle('text-muted-foreground', !isAct);
        const bar = btn.querySelector('.room-subtab-bar');
        if (bar) {
            bar.classList.toggle('bg-primary', isAct);
            bar.classList.toggle('bg-transparent', !isAct);
        }
    });

    const secBoard = document.getElementById('room-sec-board');
    const secCases = document.getElementById('room-sec-cases');
    const secStream = document.getElementById('room-sec-stream');
    const secDecisions = document.getElementById('room-sec-decisions');
    const execGrid = document.getElementById('room-exec-grid');

    if (secBoard) secBoard.classList.toggle('hidden', !(tab === 'all' || tab === 'board'));
    if (secCases) secCases.classList.toggle('hidden', !(tab === 'all' || tab === 'cases'));
    if (secStream) {
        const showS = (tab === 'all' || tab === 'stream');
        secStream.classList.toggle('hidden', !showS);
        secStream.classList.toggle('xl:col-span-12', tab === 'stream');
        secStream.classList.toggle('xl:col-span-6', tab !== 'stream');
    }
    if (secDecisions) {
        const showD = (tab === 'all' || tab === 'decisions');
        secDecisions.classList.toggle('hidden', !showD);
        secDecisions.classList.toggle('xl:col-span-12', tab === 'decisions');
        secDecisions.classList.toggle('xl:col-span-6', tab !== 'decisions');
    }
    if (execGrid) {
        execGrid.classList.toggle('hidden', !(tab === 'all' || tab === 'stream' || tab === 'decisions'));
    }
}

function toggleRoomStreamLane(lane) {
    const cb = document.getElementById(`lane-${lane}`);
    roomStreamLanes[lane] = cb ? cb.checked : !roomStreamLanes[lane];
    renderContingencyRoomsFromCache(true);
}

function clearRoomStreamFilters() {
    roomStreamSearch = '';
    const srch = document.getElementById('room-stream-search');
    if (srch) srch.value = '';
    ['COMMANDER', 'AI_AGENT', 'SYSTEM'].forEach(lane => {
        roomStreamLanes[lane] = true;
        const cb = document.getElementById(`lane-${lane}`);
        if (cb) cb.checked = true;
    });
    renderContingencyRoomsFromCache(true);
}

function onRoomStreamSearch() {
    roomStreamSearch = (document.getElementById('room-stream-search')?.value || '').trim().toLowerCase();
    renderContingencyRoomsFromCache(true);
}

function toggleCreateRoomForm(forceState = null) {
    const form = document.getElementById('form-create-room');
    if (!form) return;
    if (forceState === true) form.classList.remove('hidden');
    else if (forceState === false) form.classList.add('hidden');
    else form.classList.toggle('hidden');
    if (!form.classList.contains('hidden')) document.getElementById('new-room-name')?.focus();
}

function toggleAssetsFlagView() {
    document.getElementById('room-assets-flag-bar')?.classList.toggle('hidden');
}

function selectRoom(roomId) {
    selectedRoomId = roomId;
    renderContingencyRoomsFromCache(true);
}

async function submitCreateRoom(e) {
    e.preventDefault();
    const name = (document.getElementById('new-room-name')?.value || '').trim();
    const stage = document.getElementById('new-room-stage')?.value || 'Containment';
    const priority = document.getElementById('new-room-priority')?.value || 'HIGH';
    if (!name) return;
    try {
        const res = await fetch('/api/rooms', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, stage, priority })
        });
        const data = await res.json();
        if (data.success && data.room) {
            cachedRoomsData = data.rooms || cachedRoomsData;
            cachedTacticalDecisions = data.decisions || cachedTacticalDecisions;
            selectedRoomId = data.room.id;
            document.getElementById('new-room-name').value = '';
            toggleCreateRoomForm(false);
            renderContingencyRoomsFromCache(true);
            await refresh();
        } else {
            alert('❌ ' + (data.message || 'Không thể tạo Room mới.'));
        }
    } catch (err) {
        alert('❌ Lỗi tạo Room: ' + err);
    }
}

async function changeCurrentRoomStage(newStage) {
    if (!selectedRoomId || !newStage) return;
    try {
        const res = await fetch(`/api/rooms/${encodeURIComponent(selectedRoomId)}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ stage: newStage })
        });
        const data = await res.json();
        if (data.success) {
            cachedRoomsData = data.rooms || cachedRoomsData;
            renderContingencyRoomsFromCache(true);
        } else {
            alert('❌ ' + (data.message || 'Không thể đổi giai đoạn Room.'));
        }
    } catch (err) {
        alert('❌ Lỗi cập nhật Room: ' + err);
    }
}

async function deleteCurrentRoom() {
    if (!selectedRoomId) return;
    if (!confirm(`Bạn có chắc muốn xóa phòng tác chiến ${selectedRoomId}?`)) return;
    try {
        const res = await fetch(`/api/rooms/${encodeURIComponent(selectedRoomId)}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            cachedRoomsData = data.rooms || [];
            selectedRoomId = cachedRoomsData[0]?.id || '';
            renderContingencyRoomsFromCache(true);
            await refresh();
        } else {
            alert('❌ ' + (data.message || 'Không thể xóa Room.'));
        }
    } catch (err) {
        alert('❌ Lỗi xóa Room: ' + err);
    }
}

function onDragCaseStart(ev, caseId) {
    draggedCaseId = caseId;
    if (ev.dataTransfer) {
        ev.dataTransfer.setData('text/plain', caseId);
        ev.dataTransfer.effectAllowed = 'move';
    }
}

function onRoomDragOver(ev) {
    ev.preventDefault();
    if (ev.dataTransfer) ev.dataTransfer.dropEffect = 'move';
    document.getElementById('room-cases-dropzone')?.classList.add('border-amber-500', 'bg-amber-500/10');
}

function onRoomDragLeave() {
    document.getElementById('room-cases-dropzone')?.classList.remove('border-amber-500', 'bg-amber-500/10');
}

async function onDropCaseToRoom(ev) {
    ev.preventDefault();
    onRoomDragLeave();
    const caseId = (ev.dataTransfer && ev.dataTransfer.getData('text/plain')) || draggedCaseId;
    draggedCaseId = '';
    if (caseId && selectedRoomId) await attachCaseToRoom(selectedRoomId, caseId);
}

async function attachCaseToRoom(roomId, caseId) {
    try {
        const res = await fetch(`/api/rooms/${encodeURIComponent(roomId)}/cases`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_id: caseId })
        });
        const data = await res.json();
        if (data.success) {
            cachedRoomsData = data.rooms || cachedRoomsData;
            cachedTacticalDecisions = data.decisions || cachedTacticalDecisions;
            renderContingencyRoomsFromCache(true);
        } else {
            alert('❌ ' + (data.message || 'Không thể kéo Case vào Room.'));
        }
    } catch (err) {
        alert('❌ Lỗi kéo Case vào Room: ' + err);
    }
}

async function detachCaseFromRoom(roomId, caseId) {
    try {
        const res = await fetch(`/api/rooms/${encodeURIComponent(roomId)}/cases/${encodeURIComponent(caseId)}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.success) {
            cachedRoomsData = data.rooms || cachedRoomsData;
            cachedTacticalDecisions = data.decisions || cachedTacticalDecisions;
            renderContingencyRoomsFromCache(true);
        } else {
            alert('❌ ' + (data.message || 'Không thể gỡ Case khỏi Room.'));
        }
    } catch (err) {
        alert('❌ Lỗi gỡ Case: ' + err);
    }
}

async function sendCaseToCurrentRoom(caseId) {
    if (!cachedRoomsData || cachedRoomsData.length === 0) {
        try {
            const res = await fetch('/api/rooms');
            const data = await res.json();
            cachedRoomsData = data.rooms || [];
        } catch (e) {}
    }
    const targetRoomId = selectedRoomId || (cachedRoomsData[0] && cachedRoomsData[0].id);
    if (!targetRoomId) {
        alert('❌ Chưa có phòng tác chiến nào.');
        return;
    }
    selectedRoomId = targetRoomId;
    await attachCaseToRoom(targetRoomId, caseId);
    switchView('rooms');
}

async function submitRoomMessage(e) {
    e.preventDefault();
    if (!selectedRoomId) return;
    const inputEl = document.getElementById('room-chat-input');
    const caseEl = document.getElementById('room-chat-case');
    const askAiCheckbox = document.getElementById('room-chat-ask-ai');
    const text = (inputEl?.value || '').trim();
    if (!text) return;
    const askAi = askAiCheckbox ? askAiCheckbox.checked : true;

    try {
        const res = await fetch(`/api/rooms/${encodeURIComponent(selectedRoomId)}/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sender: 'SOC Commander',
                case_id: caseEl?.value || '',
                text,
                ask_ai: askAi,
                async_ai: true
            })
        });
        const data = await res.json();
        if (data.success) {
            inputEl.value = '';
            cachedRoomsData = data.rooms || cachedRoomsData;
            renderContingencyRoomsFromCache(true);
        } else {
            alert('❌ ' + (data.message || 'Không gửi được tin nhắn.'));
        }
    } catch (err) {
        alert('❌ Lỗi gửi tin nhắn: ' + err);
    }
}

async function askAiInRoom() {
    if (!selectedRoomId) return;
    const caseEl = document.getElementById('room-chat-case');
    try {
        const res = await fetch(`/api/rooms/${encodeURIComponent(selectedRoomId)}/messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sender: 'SOC Commander',
                case_id: caseEl?.value || '',
                text: 'Tóm tắt tình hình tác chiến hiện tại trên Board và đề xuất hành động ưu tiên.',
                ask_ai: true,
                async_ai: true
            })
        });
        const data = await res.json();
        if (data.success) {
            cachedRoomsData = data.rooms || cachedRoomsData;
            renderContingencyRoomsFromCache(true);
        } else {
            alert('❌ ' + (data.message || 'Không gọi được Qwen AI.'));
        }
    } catch (err) {
        alert('❌ Lỗi gọi AI Advisor: ' + err);
    }
}

function prefillDecisionTarget() {
    const caseId = document.getElementById('dec-case-id')?.value || '';
    const actionType = document.getElementById('dec-action-type')?.value || 'BLOCK_IP';
    const targetEl = document.getElementById('dec-target');
    if (!targetEl) return;

    const cObj = (cachedCasesData.cases || []).find(c => c.id === caseId);
    if (actionType === 'CLOSE_CASE') {
        targetEl.value = caseId || '';
        return;
    }
    if (actionType === 'BLOCK_IP') {
        targetEl.value = (cObj && cObj.src_ip && cObj.src_ip !== 'unknown') ? cObj.src_ip : '';
        return;
    }
    if (actionType === 'ISOLATE_ENDPOINT' || actionType === 'RELEASE_ENDPOINT') {
        targetEl.value = (cObj && cObj.agent_id && cObj.agent_id !== '000') ? cObj.agent_id : '';
        return;
    }
    if (actionType === 'FLAG_ASSET') {
        const activeRoom = (cachedRoomsData || []).find(r => r.id === selectedRoomId);
        const firstAsset = (cachedAssetsData || []).find(a =>
            !cObj || (a.case_ids || []).includes(cObj.id) || (cObj.victim_ips || []).includes(a.ip)
        ) || (cachedAssetsData || [])[0];
        targetEl.value = (firstAsset && firstAsset.id) || (activeRoom?.board?.room_assets_flags?.[0]?.id) || 'ASSET-0003';
    }
}

async function submitNewDecision(e) {
    e.preventDefault();
    if (!selectedRoomId) return;
    const case_id = document.getElementById('dec-case-id')?.value || '';
    const action_type = document.getElementById('dec-action-type')?.value || 'BLOCK_IP';
    const target = (document.getElementById('dec-target')?.value || '').trim();
    const reason = (document.getElementById('dec-reason')?.value || '').trim();
    const ttlEl = document.getElementById('dec-ttl-seconds');
    const ttl_seconds = ttlEl ? Number(ttlEl.value) : 3600;
    if (!target) {
        alert('Vui lòng nhập mục tiêu thực thi.');
        return;
    }
    try {
        const res = await fetch(`/api/rooms/${encodeURIComponent(selectedRoomId)}/decisions`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ case_id, action_type, target, reason, ttl_seconds })
        });
        const data = await res.json();
        if (data.success) {
            cachedRoomsData = data.rooms || cachedRoomsData;
            cachedTacticalDecisions = data.decisions || cachedTacticalDecisions;
            document.getElementById('dec-reason').value = '';
            renderContingencyRoomsFromCache(true);
            await refresh();
        } else {
            alert('❌ ' + (data.message || 'Không thể thực thi quyết định.'));
        }
    } catch (err) {
        alert('❌ Lỗi thực thi Decision: ' + err);
    }
}

function _findDecisionInCache(decisionId) {
    const activeRoom = (cachedRoomsData || []).find(r => r.id === selectedRoomId);
    const inRoom = (activeRoom?.room_decisions || []).find(d => d.id === decisionId);
    if (inRoom) return inRoom;
    return (cachedTacticalDecisions || []).find(d => d.id === decisionId) || null;
}

function revertDecisionItem(decisionId, prefillReason = '') {
    const dec = _findDecisionInCache(decisionId);
    const modal = document.getElementById('modal-confirm-revert');
    if (!modal || !dec) {
        alert('❌ Không tìm thấy thông tin Decision để xác nhận.');
        return;
    }
    pendingRevertDecisionId = decisionId;
    document.getElementById('revert-modal-decision-id').value = decisionId;

    const metaEl = document.getElementById('revert-modal-header-meta');
    if (metaEl) {
        metaEl.textContent = `${dec.id} · ${dec.control_key || dec.action_type} · Mục tiêu: ${dec.target}`;
    }

    const originEl = document.getElementById('revert-modal-origin');
    if (originEl) {
        const srcText = dec.source_label || (dec.source_case_id ? `Khởi phát từ ${dec.source_case_id}` : 'Không xác định');
        originEl.innerHTML = `<div class="font-semibold text-foreground mb-0.5">Nguồn gốc Control:</div>`
            + `<div class="font-mono text-[11px] ${dec.is_orphan ? 'text-rose-600 dark:text-rose-300 font-semibold' : 'text-cyan-700 dark:text-cyan-300'}">${escapeHtml(srcText)}</div>`;
    }

    const impactEl = document.getElementById('revert-modal-impact-banner');
    if (impactEl) {
        const details = dec.control_cases_detail || [];
        const rawIds = dec.control_cases || (dec.case_id ? [dec.case_id] : []);
        const count = details.length || rawIds.length;
        let warnIcon = 'triangle-alert';
        let warnTitle = 'Kiểm tra tác động trước khi mở khóa / gỡ chặn:';
        if (count > 1) {
            warnIcon = 'siren';
            warnTitle = `CẢNH BÁO ĐA CASE (${count} CASES): Gỡ bỏ control này sẽ ảnh hưởng đồng thời tới nhiều hồ sơ đang liên kết!`;
        } else if (dec.is_orphan) {
            warnTitle = 'CẢNH BÁO ORPHAN CONTROL: Control này có nguồn khởi phát không xác định. Hãy chắc chắn bạn hiểu tác động thực tế trước khi gỡ.';
        }
        const chipsHtml = details.length > 0
            ? details.map(c => `<div class="flex items-center justify-between gap-2 px-2 py-1 rounded bg-card/80 border border-border text-[11px] font-mono">
                <span><b class="text-cyan-700 dark:text-cyan-300">${escapeHtml(c.case_id)}</b> <span class="text-[10px] px-1 rounded ${c.role === 'SOURCE' ? 'bg-amber-500/20 text-amber-700 dark:text-amber-300' : 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300'}">${escapeHtml(c.role)}</span> · ${escapeHtml(c.title || '')}</span>
                <span class="shrink-0 text-[10px] text-muted-foreground">${escapeHtml(c.status)} / ${escapeHtml(c.verdict)}</span>
            </div>`).join('')
            : (rawIds.length > 0
                ? `<div class="font-mono text-[11px]">${rawIds.map(escapeHtml).join(', ')}</div>`
                : '<div class="text-[11px] text-muted-foreground">Không có Case nào được liên kết trực tiếp.</div>');
        impactEl.innerHTML = `<div class="font-bold text-amber-700 dark:text-amber-300 inline-flex items-start gap-1.5">${renderIcon(warnIcon, 'w-3.5 h-3.5 mt-0.5')}<span>${escapeHtml(warnTitle)}</span></div>${chipsHtml}`;
    }

    const reasonInput = document.getElementById('revert-confirm-reason');
    const errEl = document.getElementById('revert-confirm-error');
    if (errEl) {
        errEl.classList.add('hidden');
        errEl.textContent = '';
    }
    if (reasonInput) {
        reasonInput.value = prefillReason || (dec.pending_revert_proposal?.reason || '');
    }
    modal.classList.remove('hidden');
    setTimeout(() => reasonInput?.focus(), 40);
}

function closeRevertConfirmModal() {
    const modal = document.getElementById('modal-confirm-revert');
    if (modal) modal.classList.add('hidden');
    pendingRevertDecisionId = '';
}

async function confirmRevertModalSubmit(e) {
    e.preventDefault();
    const decisionId = document.getElementById('revert-modal-decision-id')?.value || pendingRevertDecisionId;
    const reason = (document.getElementById('revert-confirm-reason')?.value || '').trim();
    const errEl = document.getElementById('revert-confirm-error');
    if (!reason) {
        if (errEl) {
            errEl.textContent = 'Vui lòng nhập lý do đảo ngược (bắt buộc để ghi Audit Log).';
            errEl.classList.remove('hidden');
        }
        return;
    }
    const submitBtn = document.getElementById('btn-confirm-revert-submit');
    if (submitBtn) submitBtn.disabled = true;
    try {
        const res = await fetch(`/api/decisions/${encodeURIComponent(decisionId)}/revert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason, actor: 'SOC Commander' })
        });
        const data = await res.json();
        if (data.success) {
            closeRevertConfirmModal();
            cachedRoomsData = data.rooms || cachedRoomsData;
            cachedTacticalDecisions = data.decisions || cachedTacticalDecisions;
            renderContingencyRoomsFromCache(true);
            await refresh();
        } else {
            if (errEl) {
                errEl.innerHTML = `<span class="inline-flex items-center gap-1">${renderIcon('triangle-alert', 'w-3.5 h-3.5 shrink-0')}<span>${escapeHtml(data.message || 'Không thể đảo ngược quyết định.')}</span></span>`;
                errEl.classList.remove('hidden');
            } else {
                alert('❌ ' + (data.message || 'Không thể đảo ngược quyết định.'));
            }
        }
    } catch (err) {
        if (errEl) {
            errEl.innerHTML = `<span class="inline-flex items-center gap-1">${renderIcon('triangle-alert', 'w-3.5 h-3.5 shrink-0')}<span>${escapeHtml('Lỗi đảo ngược Decision: ' + err)}</span></span>`;
            errEl.classList.remove('hidden');
        } else {
            alert('❌ Lỗi đảo ngược Decision: ' + err);
        }
    } finally {
        if (submitBtn) submitBtn.disabled = false;
    }
}

async function rejectRevertProposal(decisionId) {
    try {
        const res = await fetch(`/api/decisions/${encodeURIComponent(decisionId)}/reject-proposal`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ reason: 'Người vận hành giữ nguyên Active Control', actor: 'SOC Commander' })
        });
        const data = await res.json();
        if (data.success) {
            cachedRoomsData = data.rooms || cachedRoomsData;
            cachedTacticalDecisions = data.decisions || cachedTacticalDecisions;
            renderContingencyRoomsFromCache(true);
            await refresh();
        } else {
            alert('❌ ' + (data.message || 'Không thể từ chối đề xuất.'));
        }
    } catch (err) {
        alert('❌ Lỗi từ chối đề xuất: ' + err);
    }
}

async function reapplyDecisionItem(decisionId) {
    try {
        const res = await fetch(`/api/decisions/${encodeURIComponent(decisionId)}/reapply`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({})
        });
        const data = await res.json();
        if (data.success) {
            cachedRoomsData = data.rooms || cachedRoomsData;
            cachedTacticalDecisions = data.decisions || cachedTacticalDecisions;
            renderContingencyRoomsFromCache(true);
            await refresh();
        } else {
            alert('❌ ' + (data.message || 'Không thể thực thi lại quyết định.'));
        }
    } catch (err) {
        alert('❌ Lỗi thực thi lại Decision: ' + err);
    }
}

function renderContingencyRoomsFromCache(force = false) {
    const rooms = cachedRoomsData || [];
    if (rooms.length > 0 && !rooms.some(r => r.id === selectedRoomId)) {
        selectedRoomId = rooms[0].id;
    } else if (rooms.length === 0) {
        selectedRoomId = '';
    }

    const activeRoom = rooms.find(r => r.id === selectedRoomId) || null;
    const allCases = cachedCasesData.cases || [];

    const sig = JSON.stringify({
        sel: selectedRoomId,
        hl: highlightedDecisionId,
        sq: roomStreamSearch,
        lanes: roomStreamLanes,
        rooms: rooms.map(r => ({
            id: r.id,
            name: r.name,
            stage: r.stage,
            priority: r.priority,
            updated_at: r.updated_at,
            ai: Boolean(r.ai_thinking),
            cids: r.case_ids,
            mcnt: (r.messages || []).length,
            board: r.board,
            decs: (r.room_decisions || []).map(d => `${d.id}:${d.status}:${d.reverted_at}:${(d.control_cases || []).join(',')}:${d.expires_at || ''}:${d.pending_revert_proposal ? 'P' : ''}`),
        })),
        cases: allCases.map(c => `${c.id}:${c.status}:${c.verdict}:${c.alert_count}:${c.severity}`)
    });
    if (!force && sig === lastRoomsRenderSignature) return;
    lastRoomsRenderSignature = sig;

    // 1. Room Switcher Pills
    const tabsEl = document.getElementById('room-tabs');
    if (tabsEl) {
        tabsEl.innerHTML = rooms.map(r => {
            const isAct = r.id === selectedRoomId;
            const cls = isAct
                ? 'bg-slate-900 text-white border-slate-900 dark:bg-amber-600 dark:border-amber-500 font-semibold shadow-sm'
                : 'bg-card text-muted-foreground border-border hover:text-foreground hover:border-amber-500/40';
            const cCnt = (r.case_ids || []).length;
            return `<button onclick="selectRoom('${escapeHtml(r.id)}')" class="px-2.5 py-1 rounded-full border text-xs transition flex items-center gap-1.5 ${cls}">
                <span class="font-mono text-[11px]">${escapeHtml(r.id)}</span>
                <span class="max-w-[160px] truncate">${escapeHtml(r.name)}</span>
                <span class="px-1.5 py-0.2 rounded-full bg-black/15 dark:bg-black/30 font-mono text-[10px]">${cCnt}</span>
            </button>`;
        }).join('') || '<span class="text-xs text-muted-foreground">Chưa có Room nào — bấm + Tạo Room</span>';
    }

    const stageSel = document.getElementById('room-stage-select');
    if (stageSel && activeRoom) stageSel.value = activeRoom.stage || 'Containment';

    const headerName = document.getElementById('room-header-name');
    const titleBadge = document.getElementById('room-board-title-badge');
    const subtitleEl = document.getElementById('room-board-subtitle');
    const kpisEl = document.getElementById('room-board-kpis');
    const flagBarEl = document.getElementById('room-assets-flag-bar');
    const availEl = document.getElementById('room-available-cases');
    const availCntEl = document.getElementById('room-available-count');
    const boardCasesEl = document.getElementById('room-board-cases-list');
    const boardCasesCntEl = document.getElementById('room-cases-count');
    const chatEl = document.getElementById('room-chat-messages');
    const decsEl = document.getElementById('room-decisions-list');
    const decSummaryEl = document.getElementById('room-decisions-summary');

    if (!activeRoom) {
        if (headerName) headerName.innerText = 'Contingency War Room';
        if (titleBadge) titleBadge.innerText = 'NO ROOM';
        if (subtitleEl) subtitleEl.innerText = 'Tạo phòng tác chiến mới để bắt đầu.';
        if (kpisEl) kpisEl.innerHTML = '';
        if (boardCasesEl) boardCasesEl.innerHTML = '';
        if (chatEl) chatEl.innerHTML = '';
        if (decsEl) decsEl.innerHTML = '';
        return;
    }

    const board = activeRoom.board || {};
    if (headerName) headerName.innerText = activeRoom.name || activeRoom.id;
    if (titleBadge) titleBadge.innerText = `${activeRoom.id} · ${activeRoom.stage || 'Containment'} · ${activeRoom.priority || 'HIGH'}`;
    if (subtitleEl) {
        subtitleEl.innerText = `${board.case_count || 0} case${(board.case_count || 0) === 1 ? '' : 's'} · updated ${board.refreshed_at || activeRoom.updated_at || '--:--:--'} · refreshes automatically`;
    }

    // 2. Render 8 KPI Cards (2 rows x 4 cols)
    if (kpisEl) {
        const compCnt = Number(board.compromised_assets_count || 0);
        const openDecs = Number(board.open_decisions_count || 0);
        const revDecs = Number(board.exceptions_reverted_count || 0);
        const openTasks = Number(board.open_tasks_count || 0);
        const openAlerts = Number(board.open_vulnerabilities_alerts_count || 0);
        const expOpen = Number(board.exploited_open_count || 0);
        const containedCnt = Number(board.contained_targets_count || 0);
        const mitreCnt = Number(board.mitre_techniques_count || 0);

        const kpiCards = [
            { label: 'Compromised', icon: 'unplug', value: compCnt, valCls: compCnt > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-foreground', sub: `${board.unflagged_assets_count || 0} assets without a flag` },
            { label: 'Open decisions', icon: 'scale', value: openDecs, valCls: openDecs > 0 ? 'text-amber-600 dark:text-amber-300' : 'text-foreground', sub: `${board.reversible_decisions_count || 0} reversible (có thể đảo ngược)` },
            { label: 'Exceptions (Reverted)', icon: 'undo-2', value: revDecs, valCls: revDecs > 0 ? 'text-cyan-600 dark:text-cyan-300' : 'text-foreground', sub: revDecs === 0 ? 'None' : `${revDecs} hành động đã hoàn tác` },
            { label: 'Open tasks / Actions', icon: 'clipboard-list', value: openTasks, valCls: 'text-foreground', sub: `${board.in_progress_cases_count || 0} cases in progress` },
            { label: 'Open alerts on assets', icon: 'shield-alert', value: openAlerts, valCls: openAlerts > 0 ? 'text-amber-600 dark:text-amber-200' : 'text-foreground', sub: 'Open findings on room case assets' },
            { label: 'Exploited & open', icon: 'flame', value: expOpen, valCls: expOpen > 0 ? 'text-rose-600 dark:text-rose-400' : 'text-foreground', sub: expOpen > 0 ? `${expOpen} TRUE POSITIVE open` : 'No exploited case left open' },
            { label: 'Active Containment', icon: 'ban', value: containedCnt, valCls: containedCnt > 0 ? 'text-emerald-600 dark:text-emerald-400' : 'text-foreground', sub: 'Blocked IPs & Isolated hosts' },
            { label: 'MITRE Techniques', icon: 'crosshair', value: mitreCnt, valCls: mitreCnt > 0 ? 'text-purple-600 dark:text-purple-300' : 'text-foreground', sub: (board.mitre_techniques && board.mitre_techniques.length > 0) ? board.mitre_techniques.slice(0, 3).join(', ') : 'No techniques mapped' },
        ];

        kpisEl.innerHTML = kpiCards.map(k => `
            <div class="iris-panel p-3.5 flex flex-col justify-between">
                <div class="flex justify-between items-center text-xs text-muted-foreground font-medium">
                    <span>${escapeHtml(k.label)}</span>
                    <span class="text-muted-foreground">${renderIcon(k.icon, 'w-4 h-4')}</span>
                </div>
                <div class="text-2xl font-bold font-mono mt-1.5 ${k.valCls}">${k.value}</div>
                <div class="text-[11px] text-muted-foreground mt-1 truncate" title="${escapeHtml(k.sub)}">${escapeHtml(k.sub)}</div>
            </div>
        `).join('');
    }

    // 3. Assets by Flag
    if (flagBarEl) {
        const flags = board.room_assets_flags || [];
        flagBarEl.innerHTML = flags.map(f => {
            const cls = f.flag === 'COMPROMISED'
                ? 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30'
                : (f.flag === 'CONTAINED' ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30' : 'bg-card text-foreground border-border');
            return `<span class="px-2.5 py-1 rounded-full border font-mono text-[11px] ${cls}">${escapeHtml(f.name)} (${escapeHtml(f.ip || 'N/A')}): <b>${escapeHtml(f.flag)}</b></span>`;
        }).join('') || '<span class="text-muted-foreground">Chưa có thiết bị.</span>';
    }

    // 4. Available Cases (Draggable)
    const inRoomIds = new Set(activeRoom.case_ids || []);
    const availableCases = allCases.filter(c => !inRoomIds.has(c.id));
    if (availCntEl) availCntEl.innerText = `${availableCases.length} khả dụng`;
    if (availEl) {
        availEl.innerHTML = availableCases.length === 0
            ? '<div class="text-muted-foreground text-center py-5">Tất cả Case hiện có đã được đưa vào Room này.</div>'
            : availableCases.map(c => `
                <div draggable="true" ondragstart="onDragCaseStart(event, '${escapeHtml(c.id)}')" class="p-2.5 iris-panel hover:border-cyan-500/50 cursor-grab active:cursor-grabbing flex justify-between items-center gap-2 transition">
                    <div class="min-w-0">
                        <div class="font-mono font-bold text-cyan-700 dark:text-cyan-300">${escapeHtml(c.id)} <span class="text-[10px] text-amber-600 dark:text-amber-300">[${escapeHtml(c.verdict || 'UNKNOWN')}]</span></div>
                        <div class="text-[11px] text-foreground truncate">${escapeHtml(c.title || '')}</div>
                        <div class="text-[10px] font-mono text-muted-foreground">${escapeHtml(c.src_ip !== 'unknown' ? c.src_ip : (c.agent_id || ''))} · ${c.alert_count || 0} alerts</div>
                    </div>
                    <button onclick="attachCaseToRoom('${escapeHtml(activeRoom.id)}', '${escapeHtml(c.id)}')" class="shrink-0 px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-700 dark:text-cyan-200 border border-cyan-500/30 text-[10px] font-semibold transition">+ Kéo vào</button>
                </div>
            `).join('');
    }

    // 5. Cases Attached to Board
    const roomCases = board.room_cases_enriched || [];
    if (boardCasesCntEl) boardCasesCntEl.innerText = `${roomCases.length} Cases`;
    if (boardCasesEl) {
        boardCasesEl.innerHTML = roomCases.length === 0
            ? '<div class="col-span-2 text-center py-8 text-muted-foreground text-xs">Kéo một Case từ cột bên trái thả vào đây (hoặc bấm + Kéo vào) để đưa Case vào tác chiến.</div>'
            : roomCases.map(rc => {
                const stageBadgeCls = rc.status === 'CLOSED'
                    ? 'bg-muted text-muted-foreground border-border'
                    : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30';
                const sevTxtCls = rc.severity === 'CRITICAL' ? 'text-rose-600 dark:text-rose-400' : (rc.severity === 'HIGH' ? 'text-amber-600 dark:text-amber-300' : 'text-muted-foreground');
                const assetsTxt = (rc.matched_assets && rc.matched_assets.length > 0) ? rc.matched_assets.join(', ') : (rc.src_ip || 'N/A');
                return `
                    <div class="p-3 iris-panel space-y-2">
                        <div class="flex justify-between items-start gap-2">
                            <div class="min-w-0">
                                <div class="font-bold text-foreground text-xs truncate">
                                    <span class="text-muted-foreground font-mono">#${escapeHtml(rc.id)}</span> ${escapeHtml(rc.title)}
                                </div>
                                <div class="text-[11px] text-muted-foreground mt-0.5 truncate flex items-center gap-1.5">${renderIcon('building-2', 'w-3 h-3')}<span class="truncate">${escapeHtml(assetsTxt)}</span><span>·</span>${renderIcon('user', 'w-3 h-3')}<span>${escapeHtml(rc.commander || 'SOC Commander')}</span></div>
                            </div>
                            <div class="flex items-center gap-1 shrink-0">
                                <span class="px-2 py-0.5 rounded-full text-[10px] border ${stageBadgeCls}">${escapeHtml(rc.stage_label || activeRoom.stage)}</span>
                                <span class="text-[10px] font-bold ${sevTxtCls}">${escapeHtml(rc.severity)}</span>
                            </div>
                        </div>
                        <div class="w-full h-1.5 bg-muted rounded-full overflow-hidden">
                            <div class="h-full bg-blue-500 transition-all" style="width: ${rc.progress_pct}%"></div>
                        </div>
                        <div class="flex justify-between items-center text-[11px] font-mono text-foreground/85">
                            <span><b>${rc.decisions_active}/${rc.decisions_total}</b> active decisions</span>
                            <span class="${rc.compromised_count > 0 ? 'text-rose-600 dark:text-rose-400 font-bold' : 'text-muted-foreground'}">${rc.compromised_count} compromised</span>
                        </div>
                        <div class="flex justify-between items-center pt-1.5 border-t border-border text-[10px] font-mono text-muted-foreground">
                            <span class="inline-flex items-center gap-1">${renderIcon('file-text', 'w-3 h-3')}<span>${rc.alert_count} alerts</span><span>·</span>${renderIcon('scale', 'w-3 h-3')}<span>${rc.decisions_reverted} reverted · ${escapeHtml(rc.verdict)}</span></span>
                            <button onclick="detachCaseFromRoom('${escapeHtml(activeRoom.id)}', '${escapeHtml(rc.id)}')" class="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400 hover:underline px-1.5 py-0.5 rounded bg-rose-500/10 border border-rose-500/25">${renderIcon('x', 'w-3 h-3')}<span>Gỡ</span></button>
                        </div>
                    </div>
                `;
            }).join('');
    }

    // Update Case dropdowns when room cases change
    const selectSig = `${activeRoom.id}|${(activeRoom.case_ids || []).join(',')}`;
    if (selectSig !== lastRoomSelectSignature) {
        lastRoomSelectSignature = selectSig;
        const optsHtml = `<option value="">Chung Room</option>` +
            roomCases.map(rc => `<option value="${escapeHtml(rc.id)}">${escapeHtml(rc.id)} (${escapeHtml(rc.src_ip !== 'unknown' ? rc.src_ip : rc.agent_id)})</option>`).join('');
        const chatCaseEl = document.getElementById('room-chat-case');
        const decCaseEl = document.getElementById('dec-case-id');
        if (chatCaseEl) chatCaseEl.innerHTML = optsHtml;
        if (decCaseEl) {
            decCaseEl.innerHTML = optsHtml;
            if (roomCases.length > 0) decCaseEl.value = roomCases[0].id;
            prefillDecisionTarget();
        }
    }

    // 6. War Room Stream & AI Chat (IRIS Stream Styling)
    const askAiBtn = document.getElementById('btn-ask-ai-room');
    const isAiThinking = Boolean(activeRoom.ai_thinking);
    if (askAiBtn) {
        askAiBtn.disabled = isAiThinking;
        askAiBtn.innerHTML = isAiThinking
            ? `${renderIcon('loader-2', 'w-3.5 h-3.5 animate-spin')}<span>GPU đang suy luận...</span>`
            : `${renderIcon('bot', 'w-3.5 h-3.5')}<span>AI Tóm Tắt Tác Chiến</span>`;
    }
    if (chatEl) {
        const rawMsgs = activeRoom.messages || [];
        const msgs = rawMsgs.filter(m => {
            const r = m.role || 'COMMANDER';
            if (roomStreamLanes[r] === false) return false;
            if (roomStreamSearch) {
                const txt = `${m.sender || ''} ${m.text || ''} ${m.case_id || ''}`.toLowerCase();
                if (!txt.includes(roomStreamSearch)) return false;
            }
            return true;
        });
        const wasAtBottom = (chatEl.scrollHeight - chatEl.scrollTop - chatEl.clientHeight) < 40;
        let chatHtml = msgs.length === 0
            ? '<div class="text-muted-foreground text-center py-8">Chưa có tin nhắn nào khớp bộ lọc.</div>'
            : msgs.map(m => {
                let avatarCls = 'bg-blue-600 text-white';
                let initials = 'CM';
                let senderCls = 'text-foreground';
                if (m.role === 'SYSTEM') {
                    avatarCls = 'bg-amber-500 text-white';
                    initials = 'SY';
                    senderCls = 'text-amber-700 dark:text-amber-300';
                } else if (m.role === 'AI_AGENT') {
                    avatarCls = 'bg-purple-600 text-white';
                    initials = 'AI';
                    senderCls = 'text-purple-700 dark:text-purple-300';
                }
                const cTag = m.case_id ? `<span class="px-1.5 py-0.2 rounded-full bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border border-indigo-500/25 font-mono text-[10px]">${escapeHtml(m.case_id)}</span>` : '';
                const isDecisionMention = (m.text || '').includes('DEC-') || (m.text || '').toLowerCase().includes('/decision');
                const bodyCls = isDecisionMention
                    ? 'mt-1 p-2 rounded-lg border border-indigo-500/30 bg-indigo-500/10 text-foreground'
                    : 'mt-0.5 text-foreground/90';

                return `
                    <div class="flex items-start gap-2.5 p-2 rounded-lg hover:bg-muted/40 transition-colors">
                        <div class="flex h-7 w-7 shrink-0 items-center justify-center rounded-full text-[10px] font-bold ${avatarCls}">
                            ${initials}
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center justify-between gap-2">
                                <div class="flex items-center gap-1.5 min-w-0">
                                    <span class="font-semibold text-xs ${senderCls} truncate">${escapeHtml(m.sender)}</span>
                                    ${cTag}
                                </div>
                                <span class="text-[10px] font-mono text-muted-foreground shrink-0">${escapeHtml(m.time || '')}</span>
                            </div>
                            <div class="whitespace-pre-line leading-relaxed text-xs ${bodyCls}">${escapeHtml(m.text || '')}</div>
                        </div>
                    </div>
                `;
            }).join('');
        if (isAiThinking) {
            chatHtml += `
                <div class="p-2.5 rounded-lg border border-purple-500/40 bg-purple-500/10 text-purple-700 dark:text-purple-200 animate-pulse flex items-center gap-2 text-xs">
                    ${renderIcon('cpu', 'w-4 h-4')}
                    <span class="font-semibold">Qwen AI Agent (GPU) đang suy luận &amp; tra cứu công cụ...</span>
                </div>
            `;
        }
        chatEl.innerHTML = chatHtml;
        if (wasAtBottom || isAiThinking) {
            chatEl.scrollTop = chatEl.scrollHeight;
        }
    }

    // 7. Reversible Decisions List
    const roomDecs = activeRoom.room_decisions || [];
    if (decSummaryEl) {
        const actCnt = roomDecs.filter(d => d.status === 'ACTIVE').length;
        const revCnt = roomDecs.filter(d => d.status === 'REVERTED').length;
        const propCnt = roomDecs.filter(d => d.status === 'ACTIVE' && d.pending_revert_proposal).length;
        decSummaryEl.innerText = propCnt > 0
            ? `${actCnt} Active | ${propCnt} Chờ duyệt | ${revCnt} Reverted`
            : `${actCnt} Active | ${revCnt} Reverted`;
    }
    if (decsEl) {
        decsEl.innerHTML = roomDecs.length === 0
            ? '<div class="text-muted-foreground text-center py-8 border border-dashed border-border rounded-xl">Chưa có Decision nào trong Room này. Các hành động SOAR hoặc quyết định thủ công sẽ hiện tại đây kèm nút Đảo ngược.</div>'
            : roomDecs.map(d => {
                const isReverted = d.status === 'REVERTED';
                const isHighlighted = highlightedDecisionId && d.id === highlightedDecisionId;
                const cardCls = isHighlighted
                    ? 'iris-panel border-2 border-cyan-500 ring-2 ring-cyan-500/30'
                    : (isReverted ? 'iris-panel opacity-75' : 'iris-panel border-amber-500/40');
                const statusBadge = isReverted
                    ? (d.expired
                        ? `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">${renderIcon('clock', 'w-3 h-3')}<span>EXPIRED -> REVERTED</span></span>`
                        : '<span class="px-2 py-0.5 rounded-full text-[10px] font-mono bg-muted text-muted-foreground border border-border">REVERTED</span>')
                    : '<span class="px-2 py-0.5 rounded-full text-[10px] font-mono bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border border-emerald-500/30">ACTIVE</span>';
                let srcBadge = `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border border-cyan-500/30">${renderIcon('shield', 'w-3 h-3')}<span>Commander</span></span>`;
                if (d.source === 'AI_SOAR') {
                    srcBadge = `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-purple-500/15 text-purple-700 dark:text-purple-300 border border-purple-500/30">${renderIcon('bot', 'w-3 h-3')}<span>AI SOAR</span></span>`;
                } else if (d.source === 'RECONCILER') {
                    srcBadge = `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-mono bg-amber-500/15 text-amber-700 dark:text-amber-300 border border-amber-500/30">${renderIcon('refresh-cw', 'w-3 h-3')}<span>Reconciler</span></span>`;
                }
                const orphanBadge = d.is_orphan
                    ? `<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-rose-500/15 text-rose-700 dark:text-rose-300 border border-rose-500/30">${renderIcon('triangle-alert', 'w-3 h-3')}<span>Nguồn không xác định</span></span>`
                    : '';
                const ckeyBadge = d.control_key
                    ? `<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-muted/70 text-foreground/80 border border-border">${escapeHtml(d.control_key)}</span>`
                    : '';
                const ttlBadge = (!isReverted && d.expires_at)
                    ? `<span class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-500/10 text-sky-700 dark:text-sky-300 border border-sky-500/25">${renderIcon('clock', 'w-3 h-3')}<span>TTL tới ${escapeHtml(d.expires_at)}</span></span>`
                    : '';

                const details = d.control_cases_detail || [];
                const refCases = details.length > 0
                    ? details
                    : (d.control_cases || (d.case_id ? [d.case_id] : [])).map(cid => ({ case_id: cid, role: cid === d.source_case_id ? 'SOURCE' : 'REFERENCING' }));
                const caseChipsHtml = refCases.length > 0
                    ? `<div class="flex flex-wrap items-center gap-1 pt-0.5">
                        <span class="text-[10px] text-muted-foreground font-mono">Cases liên quan:</span>
                        ${refCases.map(c => {
                            const roleCls = c.role === 'SOURCE'
                                ? 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/30'
                                : 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30';
                            const roleTag = c.role === 'SOURCE' ? 'gốc' : 'tham chiếu';
                            return `<button type="button" onclick="openCaseFromAsset('${escapeHtml(c.case_id)}')" class="px-1.5 py-0.5 rounded text-[10px] font-mono border ${roleCls} hover:opacity-80 transition">${escapeHtml(c.case_id)} (${roleTag})</button>`;
                        }).join('')}
                       </div>`
                    : '';

                const prop = (!isReverted && d.pending_revert_proposal) ? d.pending_revert_proposal : null;
                const proposalBannerHtml = prop
                    ? `<div class="mt-1.5 p-2 rounded-lg border border-amber-500/50 bg-amber-500/10 space-y-1.5">
                        <div class="flex flex-wrap justify-between items-center gap-1 text-[11px]">
                            <span class="inline-flex items-center gap-1 font-bold text-amber-700 dark:text-amber-300">${renderIcon('hourglass', 'w-3 h-3')}<span>Đề xuất đảo ngược từ ${escapeHtml(prop.proposed_by || 'AI_SOAR')} (${escapeHtml(prop.proposed_at || '')})</span></span>
                        </div>
                        <div class="text-[11px] text-foreground/90">${escapeHtml(prop.reason || '')}</div>
                        <div class="flex flex-wrap gap-1.5 pt-1">
                            <button type="button" onclick="revertDecisionItem('${escapeHtml(d.id)}')" class="inline-flex items-center gap-1 px-2 py-1 rounded bg-rose-600 hover:bg-rose-500 text-white text-[10px] font-bold transition">${renderIcon('check', 'w-3 h-3')}<span>Xác nhận Đảo ngược</span></button>
                            <button type="button" onclick="rejectRevertProposal('${escapeHtml(d.id)}')" class="inline-flex items-center gap-1 px-2 py-1 rounded bg-card hover:bg-muted text-foreground border border-border text-[10px] font-medium transition">${renderIcon('x', 'w-3 h-3')}<span>Từ chối đề xuất</span></button>
                        </div>
                       </div>`
                    : '';

                const actionBtn = isReverted
                    ? `<button onclick="reapplyDecisionItem('${escapeHtml(d.id)}')" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-700 dark:text-cyan-200 border border-cyan-500/30 text-[11px] font-semibold">${renderIcon('rotate-ccw', 'w-3 h-3')}<span>Thực thi lại</span></button>`
                    : `<button onclick="revertDecisionItem('${escapeHtml(d.id)}')" class="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-700 dark:text-rose-200 border border-rose-500/40 text-[11px] font-bold">${renderIcon('undo-2', 'w-3 h-3')}<span>Đảo ngược</span></button>`;

                return `
                    <div id="decision-card-${escapeHtml(d.id)}" class="p-3 ${cardCls} space-y-1.5">
                        <div class="flex justify-between items-center gap-2">
                            <div class="flex flex-wrap items-center gap-1.5">
                                <span class="font-mono font-bold text-amber-700 dark:text-amber-300">${escapeHtml(d.id)}</span>
                                ${statusBadge}
                                ${srcBadge}
                                ${ckeyBadge}
                                ${orphanBadge}
                                ${ttlBadge}
                            </div>
                            <div class="shrink-0">${actionBtn}</div>
                        </div>
                        <div class="font-semibold ${isReverted ? 'line-through text-muted-foreground' : 'text-foreground'}">${escapeHtml(d.title || d.action_type)}</div>
                        <div class="text-[11px] font-mono text-muted-foreground">
                            Mục tiêu: <span class="text-cyan-700 dark:text-cyan-300 font-semibold">${escapeHtml(d.target)}</span> | Tạo: ${escapeHtml(d.created_at || '')}
                            ${isReverted && d.reverted_at ? ` | Đảo ngược lúc: <span class="text-amber-600 dark:text-amber-300">${escapeHtml(d.reverted_at)}</span>` : ''}
                        </div>
                        ${d.source_label ? `<div class="text-[11px] font-mono ${d.is_orphan ? 'text-rose-600 dark:text-rose-300' : 'text-cyan-700 dark:text-cyan-300'}">${escapeHtml(d.source_label)}</div>` : ''}
                        ${caseChipsHtml}
                        ${d.reason ? `<div class="text-[11px] text-foreground/85">Lý do: ${escapeHtml(d.reason)}</div>` : ''}
                        ${proposalBannerHtml}
                        ${isReverted && d.revert_reason ? `<div class="text-[11px] font-mono text-foreground/85">Lý do đảo ngược (${escapeHtml(d.reverted_by || 'SOC')}): ${escapeHtml(d.revert_reason)}</div>` : ''}
                        ${isReverted && d.revert_result ? `<div class="flex items-start gap-1.5 text-[11px] font-mono text-amber-700 dark:text-amber-300 bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 rounded-lg">${renderIcon('undo-2', 'w-3 h-3 mt-0.5')}<span>${escapeHtml(d.revert_result)}</span></div>` : ''}
                    </div>
                `;
            }).join('');
    }
}
