// ================= MAIN ENTRY POINT & LIVE POLLING =================

async function refresh() {
    try {
        const res = await fetch('/api/state');
        const data = await res.json();

        cachedCasesData = {
            cases: data.cases || [],
            parent_incidents: data.parent_incidents || []
        };
        const openCaseCount = (data.cases || []).filter(c => c.status !== 'CLOSED').length;
        const caseCountBadge = document.getElementById('btn-case-count');
        if (caseCountBadge) caseCountBadge.innerText = openCaseCount;
        renderCasesFromCache();

        cachedAssetsData = data.assets || [];
        const assetCountBadge = document.getElementById('btn-asset-count');
        if (assetCountBadge) assetCountBadge.innerText = cachedAssetsData.length;
        renderAssetsFromCache();

        cachedRoomsData = data.contingency_rooms || [];
        cachedTacticalDecisions = data.tactical_decisions || [];
        const roomCountBadge = document.getElementById('btn-room-count');
        if (roomCountBadge) roomCountBadge.innerText = cachedRoomsData.length;
        renderContingencyRoomsFromCache();

        renderDashboardWave(data);
        renderDashboardStreamAndVerdicts(data);
    } catch (err) {
        console.error("Lỗi cập nhật trạng thái:", err);
    }
}

(function initAppShell() {
    updateThemeButton();
    updateSidebarClock();
    setInterval(updateSidebarClock, 1000);

    try {
        if (localStorage.getItem('soc_sidebar_collapsed') === '1') {
            sidebarCollapsed = true;
            document.getElementById('app-sidebar')?.classList.add('sidebar-collapsed');
        }
        const savedSubTab = localStorage.getItem('soc_room_subtab');
        if (savedSubTab) activeRoomSubTab = savedSubTab;
        const savedView = localStorage.getItem('soc_active_view');
        if (savedView && VIEW_META[savedView]) activeView = savedView;
    } catch (e) {}

    setRoomSubTab(activeRoomSubTab);
    switchView(activeView);
    refresh();
    setInterval(refresh, 1500);
})();
