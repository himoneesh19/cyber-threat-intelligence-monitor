/**
 * Global Cyber Threat Intelligence Portal Client Logic
 * Handles real-time search, category/technology filtering, and audit status persistence.
 */

(function () {
    'use strict';

    // State
    let allThreats = [];
    let filteredThreats = [];
    let currentPage = 1;
    const pageSize = 25;

    let activeCategory = 'ALL';
    let activeTech = null;
    let activeSeverity = 'ALL';
    let activeAuditStatus = 'ALL';
    let searchQuery = '';

    // Local Storage for Audit Status
    const AUDIT_STORAGE_KEY = 'gsm_audited_threats';
    let auditedMap = {};
    try {
        auditedMap = JSON.parse(localStorage.getItem(AUDIT_STORAGE_KEY) || '{}');
    } catch (e) {
        auditedMap = {};
    }

    // DOM Elements
    const searchInput = document.getElementById('searchInput');
    const clearSearchBtn = document.getElementById('clearSearchBtn');
    const severitySelect = document.getElementById('severitySelect');
    const auditFilterSelect = document.getElementById('auditFilterSelect');
    const categoryTabs = document.getElementById('categoryTabs');
    const techChipsContainer = document.getElementById('techChipsContainer');
    const threatCardsContainer = document.getElementById('threatCardsContainer');
    const resultsCount = document.getElementById('resultsCount');
    const lastUpdatedText = document.getElementById('lastUpdatedText');
    const exportJsonBtn = document.getElementById('exportJsonBtn');

    // KPI Elements
    const kpiKevCount = document.getElementById('kpiKevCount');
    const kpiCriticalCount = document.getElementById('kpiCriticalCount');
    const kpiHighCount = document.getElementById('kpiHighCount');
    const kpiTotalCount = document.getElementById('kpiTotalCount');

    // Pagination Elements
    const paginationWrapper = document.getElementById('paginationWrapper');
    const prevPageBtn = document.getElementById('prevPageBtn');
    const nextPageBtn = document.getElementById('nextPageBtn');
    const pageIndicator = document.getElementById('pageIndicator');

    // Initialization
    async function init() {
        setupEventListeners();
        await loadThreatData();
    }

    async function loadThreatData() {
        try {
            // First attempt to fetch data/threats.json relative to portal
            const response = await fetch('data/threats.json');
            if (!response.ok) {
                throw new Error(`HTTP error ${response.status}`);
            }
            const data = await response.json();
            allThreats = data.threats || [];
            if (data.generated_at) {
                const date = new Date(data.generated_at);
                lastUpdatedText.textContent = `Updated: ${date.toLocaleDateString()} ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
            } else {
                lastUpdatedText.textContent = 'Telemetry Connected';
            }
        } catch (err) {
            console.warn('Could not load data/threats.json, checking for fallback:', err);
            lastUpdatedText.textContent = 'Using Live Baseline Telemetry';
            // Fallback sample data if opened locally before first build
            allThreats = window.INITIAL_THREATS || [];
        }

        updateKpis(allThreats);
        applyFilters();
    }

    function updateKpis(threats) {
        const kevCount = threats.filter(t => t.is_cisa_kev).length;
        const criticalCount = threats.filter(t => t.severity === 'CRITICAL').length;
        const highCount = threats.filter(t => t.severity === 'HIGH').length;

        kpiKevCount.textContent = kevCount.toLocaleString();
        kpiCriticalCount.textContent = criticalCount.toLocaleString();
        kpiHighCount.textContent = highCount.toLocaleString();
        kpiTotalCount.textContent = threats.length.toLocaleString();
    }

    function applyFilters() {
        filteredThreats = allThreats.filter(threat => {
            // 1. Search Query
            if (searchQuery) {
                const q = searchQuery.toLowerCase();
                const corpus = [
                    threat.cve_id,
                    threat.title,
                    threat.summary,
                    threat.category,
                    ...(threat.technologies || [])
                ].join(' ').toLowerCase();

                if (!corpus.includes(q)) return false;
            }

            // 2. Category Tab
            if (activeCategory !== 'ALL' && threat.category !== activeCategory) {
                return false;
            }

            // 3. Technology Chip
            if (activeTech) {
                const techs = threat.technologies || [];
                const hasTech = techs.some(t => t.toLowerCase() === activeTech.toLowerCase());
                if (!hasTech) return false;
            }

            // 4. Severity Select
            if (activeSeverity === 'KEV') {
                if (!threat.is_cisa_kev) return false;
            } else if (activeSeverity !== 'ALL') {
                if ((threat.severity || '').toUpperCase() !== activeSeverity) return false;
            }

            // 5. Audit Status
            const isAudited = !!auditedMap[threat.cve_id];
            if (activeAuditStatus === 'AUDITED' && !isAudited) return false;
            if (activeAuditStatus === 'UNAUDITED' && isAudited) return false;

            return true;
        });

        currentPage = 1;
        renderThreats();
    }

    function renderThreats() {
        resultsCount.textContent = `Showing ${filteredThreats.length.toLocaleString()} threat${filteredThreats.length === 1 ? '' : 's'}`;

        if (filteredThreats.length === 0) {
            threatCardsContainer.innerHTML = `
                <div style="text-align:center;padding:48px 20px;background:var(--bg-surface);border:1px solid var(--border-color);border-radius:10px;color:var(--text-secondary);">
                    <div style="font-size:32px;margin-bottom:12px;">🔍</div>
                    <div style="font-size:16px;font-weight:700;color:var(--text-primary);margin-bottom:6px;">No matching security threats found</div>
                    <div style="font-size:13px;">Try relaxing your search terms or clearing category filters.</div>
                </div>
            `;
            paginationWrapper.style.display = 'none';
            return;
        }

        const totalPages = Math.ceil(filteredThreats.length / pageSize);
        const startIndex = (currentPage - 1) * pageSize;
        const pageItems = filteredThreats.slice(startIndex, startIndex + pageSize);

        let html = '';
        for (const threat of pageItems) {
            html += renderThreatCard(threat);
        }
        threatCardsContainer.innerHTML = html;

        // Pagination controls
        if (totalPages > 1) {
            paginationWrapper.style.display = 'flex';
            pageIndicator.textContent = `Page ${currentPage} of ${totalPages}`;
            prevPageBtn.disabled = currentPage === 1;
            nextPageBtn.disabled = currentPage === totalPages;
        } else {
            paginationWrapper.style.display = 'none';
        }

        // Attach audit checkbox handlers
        threatCardsContainer.querySelectorAll('.audit-checkbox').forEach(cb => {
            cb.addEventListener('change', (e) => {
                const cveId = e.target.dataset.cve;
                if (e.target.checked) {
                    auditedMap[cveId] = true;
                } else {
                    delete auditedMap[cveId];
                }
                localStorage.setItem(AUDIT_STORAGE_KEY, JSON.stringify(auditedMap));
                const card = document.getElementById(`card-${cveId}`);
                if (card) {
                    card.classList.toggle('is-audited', e.target.checked);
                }
            });
        });
    }

    function renderThreatCard(t) {
        const cveId = escapeHtml(t.cve_id);
        const title = escapeHtml(t.title || 'Security Advisory');
        const summary = escapeHtml((t.summary || '').slice(0, 500));
        const action = escapeHtml(t.cisa_required_action || 'Review vendor security notes and apply patches.');
        const severity = (t.severity || 'UNKNOWN').toUpperCase();
        const sevClass = `sev-${severity.toLowerCase()}`;
        const isAudited = !!auditedMap[t.cve_id];

        // Badges
        const kevBadge = t.is_cisa_kev
            ? `<span class="badge-kev">🔥 CISA KEV (ACTIVE EXPLOIT)</span>`
            : '';

        const cvssBadge = t.cvss_score !== null && t.cvss_score !== undefined
            ? `<span class="badge-cvss">CVSS ${t.cvss_score}</span>`
            : '';

        const epssBadge = t.epss_score !== null && t.epss_score !== undefined && t.epss_score >= 0.10
            ? `<span class="badge-epss">EPSS ${(t.epss_score * 100).toFixed(1)}%</span>`
            : '';

        // Tech Tags
        const techTags = (t.technologies || []).map(tech =>
            `<span class="card-tech-tag">${escapeHtml(tech)}</span>`
        ).join('');

        // Due Date
        const dueHtml = t.cisa_due_date
            ? `<div class="cisa-due-notice">⏱️ CISA Federal Due Date: ${escapeHtml(t.cisa_due_date)}</div>`
            : '';

        // Sources
        const sourcesHtml = (t.sources || []).map(s =>
            `<a href="${escapeHtml(s.url || '#')}" target="_blank" rel="noopener noreferrer" class="source-link">↗ ${escapeHtml(s.name || 'Advisory')}</a>`
        ).join('');

        return `
            <div class="threat-card ${t.is_cisa_kev ? 'is-kev' : ''} ${isAudited ? 'is-audited' : ''}" id="card-${cveId}">
                <div class="card-top">
                    <div class="badges-row">
                        <span class="badge-sev ${sevClass}">${severity}</span>
                        ${cvssBadge}
                        ${kevBadge}
                        ${epssBadge}
                    </div>
                    <label class="audit-checkbox-label" title="Mark this threat as audited/mitigated in your environment">
                        <input type="checkbox" class="audit-checkbox" data-cve="${cveId}" ${isAudited ? 'checked' : ''}>
                        <span>Audited</span>
                    </label>
                </div>
                <div class="card-title">${cveId}: ${title}</div>
                ${techTags ? `<div class="card-tech-row">${techTags}</div>` : ''}
                <div class="card-summary">${summary}</div>
                <div class="card-action-box">
                    <div class="action-title">Recommended Action:</div>
                    <div>${action}</div>
                    ${dueHtml}
                </div>
                <div class="card-footer">
                    <div class="source-links">${sourcesHtml}</div>
                    <div style="font-size:11px;color:var(--text-muted);">${escapeHtml(t.category || 'General')}</div>
                </div>
            </div>
        `;
    }

    function setupEventListeners() {
        // Search Input with debounce
        let searchTimeout;
        searchInput.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                searchQuery = e.target.value.trim();
                clearSearchBtn.style.display = searchQuery ? 'block' : 'none';
                applyFilters();
            }, 200);
        });

        clearSearchBtn.addEventListener('click', () => {
            searchInput.value = '';
            searchQuery = '';
            clearSearchBtn.style.display = 'none';
            applyFilters();
            searchInput.focus();
        });

        // Severity Select
        severitySelect.addEventListener('change', (e) => {
            activeSeverity = e.target.value;
            applyFilters();
        });

        // Audit Filter Select
        auditFilterSelect.addEventListener('change', (e) => {
            activeAuditStatus = e.target.value;
            applyFilters();
        });

        // Category Tabs
        categoryTabs.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                categoryTabs.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                activeCategory = btn.dataset.category;
                applyFilters();
            });
        });

        // Tech Chips
        techChipsContainer.querySelectorAll('.tech-chip').forEach(chip => {
            chip.addEventListener('click', () => {
                if (chip.classList.contains('active')) {
                    chip.classList.remove('active');
                    activeTech = null;
                } else {
                    techChipsContainer.querySelectorAll('.tech-chip').forEach(c => c.classList.remove('active'));
                    chip.classList.add('active');
                    activeTech = chip.dataset.tech;
                }
                applyFilters();
            });
        });

        // Pagination
        prevPageBtn.addEventListener('click', () => {
            if (currentPage > 1) {
                currentPage--;
                renderThreats();
                window.scrollTo({ top: 300, behavior: 'smooth' });
            }
        });

        nextPageBtn.addEventListener('click', () => {
            const totalPages = Math.ceil(filteredThreats.length / pageSize);
            if (currentPage < totalPages) {
                currentPage++;
                renderThreats();
                window.scrollTo({ top: 300, behavior: 'smooth' });
            }
        });

        // Export JSON
        exportJsonBtn.addEventListener('click', () => {
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredThreats, null, 2));
            const dlAnchor = document.createElement('a');
            dlAnchor.setAttribute("href", dataStr);
            dlAnchor.setAttribute("download", `threat_intelligence_${new Date().toISOString().slice(0, 10)}.json`);
            document.body.appendChild(dlAnchor);
            dlAnchor.click();
            dlAnchor.remove();
        });
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }

    // Run
    init();
})();
