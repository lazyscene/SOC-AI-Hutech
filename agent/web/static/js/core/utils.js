// ================= SHARED UTILITIES =================

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}

function _toLucidePascalName(name) {
    if (!name) return '';
    return String(name).replace(/(^|[-_])([a-z0-9])/gi, (_, __, ch) => ch.toUpperCase());
}

/**
 * Render a Lucide icon synchronously as an inline SVG string using the bundled
 * `window.lucide.icons` registry, avoiding repeated full-DOM scans on polling ticks.
 */
function renderIcon(name, cls = 'w-3.5 h-3.5', extraAttrs = '') {
    const icons = typeof window !== 'undefined' && window.lucide && window.lucide.icons;
    const key = _toLucidePascalName(name);
    const nodes = icons && icons[key];
    if (!Array.isArray(nodes)) {
        return `<span class="inline-block ${escapeHtml(cls)}" aria-hidden="true"></span>`;
    }
    const inner = nodes.map(([tag, attrs]) => {
        const attrStr = Object.entries(attrs || {})
            .map(([k, v]) => `${escapeHtml(k)}="${escapeHtml(v)}"`)
            .join(' ');
        return `<${escapeHtml(tag)} ${attrStr}></${escapeHtml(tag)}>`;
    }).join('');
    const classAttr = escapeHtml(`lucide lucide-${name} shrink-0 ${cls}`.trim());
    const extra = extraAttrs ? ` ${extraAttrs}` : '';
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="${classAttr}"${extra}>${inner}</svg>`;
}

function initLucideStaticIcons(root) {
    if (typeof window !== 'undefined' && window.lucide && typeof window.lucide.createIcons === 'function') {
        window.lucide.createIcons(root ? { root } : undefined);
    }
}
