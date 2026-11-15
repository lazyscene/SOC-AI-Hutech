// ================= APP SHELL: THEME, SIDEBAR & NAVIGATION =================

function updateThemeButton() {
    const isDark = document.documentElement.classList.contains('dark');
    const iconEl = document.getElementById('theme-toggle-icon');
    const lblEl = document.getElementById('theme-toggle-label');
    if (iconEl) iconEl.innerHTML = renderIcon(isDark ? 'moon' : 'sun', 'w-3.5 h-3.5');
    if (lblEl) lblEl.textContent = isDark ? 'Dark' : 'Light';
}

function toggleTheme() {
    const root = document.documentElement;
    const willDark = !root.classList.contains('dark');
    root.classList.toggle('dark', willDark);
    try {
        localStorage.setItem('soc_theme', willDark ? 'dark' : 'light');
    } catch (e) {}
    updateThemeButton();
}

function toggleSidebarCollapse() {
    sidebarCollapsed = !sidebarCollapsed;
    const sb = document.getElementById('app-sidebar');
    if (sb) {
        sb.classList.toggle('sidebar-collapsed', sidebarCollapsed);
    }
    try {
        localStorage.setItem('soc_sidebar_collapsed', sidebarCollapsed ? '1' : '0');
    } catch (e) {}
}

function toggleMobileSidebar(forceOpen) {
    const sb = document.getElementById('app-sidebar');
    const bd = document.getElementById('mobile-sidebar-backdrop');
    if (!sb || !bd) return;
    const open = (typeof forceOpen === 'boolean') ? forceOpen : sb.classList.contains('-translate-x-full');
    sb.classList.toggle('-translate-x-full', !open);
    bd.classList.toggle('hidden', !open);
}

function switchView(viewName) {
    if (!VIEW_META[viewName]) viewName = 'dashboard';
    activeView = viewName;
    try {
        localStorage.setItem('soc_active_view', viewName);
    } catch (e) {}

    Object.keys(VIEW_META).forEach(k => {
        const sec = document.getElementById(VIEW_META[k].sectionId);
        if (sec) sec.classList.toggle('hidden', k !== viewName);
    });

    document.querySelectorAll('.sidebar-nav-btn').forEach(btn => {
        const isAct = btn.getAttribute('data-view') === viewName;
        btn.classList.toggle('bg-slate-900', isAct);
        btn.classList.toggle('text-white', isAct);
        btn.classList.toggle('dark:bg-blue-600/20', isAct);
        btn.classList.toggle('dark:text-blue-400', isAct);
        btn.classList.toggle('shadow-sm', isAct);
        btn.classList.toggle('text-sidebar-foreground', !isAct);
        btn.classList.toggle('hover:bg-sidebar-hover', !isAct);
        btn.classList.toggle('hover:text-foreground', !isAct);
    });

    const topTitle = document.getElementById('topbar-view-title');
    if (topTitle) topTitle.textContent = VIEW_META[viewName].title;

    if (viewName === 'cases') renderCasesFromCache(true);
    else if (viewName === 'assets') renderAssetsFromCache(true);
    else if (viewName === 'rooms') renderContingencyRoomsFromCache(true);
    else if (viewName === 'misp') loadMispIocs();

    toggleMobileSidebar(false);
}

function toggleMispPanel() { switchView('misp'); }
function toggleCasePanel() { switchView('cases'); }
function toggleAssetPanel() { switchView('assets'); }
function toggleRoomPanel(forceOpen = null) {
    if (forceOpen === false) switchView('dashboard');
    else switchView('rooms');
}

function updateSidebarClock() {
    const el = document.getElementById('sidebar-clock');
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleDateString('vi-VN') + ' · ' + now.toLocaleTimeString('vi-VN', { hour12: false });
}

function onGlobalSearchInput() {
    const val = (document.getElementById('global-search-input')?.value || '').trim();
    if (activeView === 'cases') {
        const cSearch = document.getElementById('case-search');
        if (cSearch) cSearch.value = val;
        renderCasesFromCache(true);
    } else if (activeView === 'assets') {
        const aSearch = document.getElementById('asset-search');
        if (aSearch) aSearch.value = val;
        renderAssetsFromCache(true);
    } else if (activeView === 'misp') {
        const mSearch = document.getElementById('misp-search');
        if (mSearch) mSearch.value = val;
        onMispSearchInput();
    } else if (activeView === 'rooms') {
        const rSearch = document.getElementById('room-stream-search');
        if (rSearch) rSearch.value = val;
        onRoomStreamSearch();
    }
}

function onGlobalSearchKeydown(e) {
    if (e.key === 'Enter' && activeView === 'dashboard') {
        const val = (document.getElementById('global-search-input')?.value || '').trim();
        const cSearch = document.getElementById('case-search');
        if (cSearch) cSearch.value = val;
        switchView('cases');
    }
}

document.addEventListener('keydown', function (e) {
    if ((e.ctrlKey || e.metaKey) && e.key === '/') {
        e.preventDefault();
        document.getElementById('global-search-input')?.focus();
    }
});
