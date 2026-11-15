// ================= CENTRAL FRONTEND STORE & CACHES =================

let activeView = 'dashboard';
let sidebarCollapsed = false;

const VIEW_META = {
    dashboard: { title: 'Dashboard', sectionId: 'view-dashboard' },
    cases: { title: 'Alerts & Cases', sectionId: 'view-cases' },
    rooms: { title: 'Contingency Rooms', sectionId: 'view-rooms' },
    assets: { title: 'Asset Manager', sectionId: 'view-assets' },
    misp: { title: 'MISP Threat Vault', sectionId: 'view-misp' },
};

// Cases cache
let cachedCasesData = { cases: [], parent_incidents: [] };
const expandedCaseIds = new Set();
const openGraphCaseIds = new Set();
let lastCasesRenderSignature = '';

// MISP state
let mispSearchTimeout = null;

// Assets cache
let cachedAssetsData = [];
let lastAssetsRenderSignature = '';

// Contingency Rooms cache
let cachedRoomsData = [];
let cachedTacticalDecisions = [];
let selectedRoomId = '';
let draggedCaseId = '';
let lastRoomsRenderSignature = '';
let lastRoomSelectSignature = '';
let activeRoomSubTab = 'all';
let roomStreamSearch = '';
const roomStreamLanes = { COMMANDER: true, AI_AGENT: true, SYSTEM: true };
