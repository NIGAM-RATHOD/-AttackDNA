/**
 * AttackDNA — Core Application Logic
 * Interactive CVE Attack Chain Visualizer with D3.js
 */

(() => {
  'use strict';

  // ---------------------------------------------------------------------------
  // Phase Color Palette
  // ---------------------------------------------------------------------------
  const PHASE_COLORS = {
    'Recon': '#38bdf8',
    'Resource Development': '#818cf8',
    'Initial Access': '#f43f5e',
    'Execution': '#fb923c',
    'Persistence': '#fbbf24',
    'Privilege Escalation': '#f59e0b',
    'Defense Evasion': '#e879f9',
    'Credential Access': '#c084fc',
    'Discovery': '#a78bfa',
    'Lateral Movement': '#ec4899',
    'Collection': '#2dd4bf',
    'Command and Control': '#06b6d4',
    'Exfiltration': '#14b8a6',
    'Impact': '#ef4444',
  };

  const DEFAULT_PHASE_COLOR = '#22d3ee';

  const POPULAR_CVES = [
    { id: 'CVE-2024-3400', name: 'PAN-OS Command Injection' },
    { id: 'CVE-2021-44228', name: 'Log4Shell RCE' },
    { id: 'CVE-2023-34362', name: 'MOVEit SQLi' },
    { id: 'CVE-2024-21762', name: 'FortiOS Out-of-Bounds' },
    { id: 'CVE-2023-44228', name: 'ActiveMQ RCE' },
    { id: 'CVE-2024-1709', name: 'ScreenConnect Auth Bypass' },
  ];

  // ---------------------------------------------------------------------------
  // State
  // ---------------------------------------------------------------------------
  const state = {
    currentCve: null,
    attackChain: null,
    currentView: 'attacker', // 'attacker' | 'defender'
    selectedPhaseId: null,
    activeTab: 'overview',
    zoomBehavior: null,
    svgSelection: null,
    gSelection: null,
    nodesData: [],
    linksData: [],
  };

  // ---------------------------------------------------------------------------
  // DOM Elements
  // ---------------------------------------------------------------------------
  const dom = {
    bgCanvas: document.getElementById('bg-canvas'),
    brandLink: document.getElementById('brand-link'),
    statusPill: document.getElementById('status-pill'),
    hero: document.getElementById('hero'),
    heroSearch: document.getElementById('hero-search'),
    headerSearch: document.getElementById('header-search'),
    exampleChips: document.getElementById('example-chips'),
    dashboard: document.getElementById('dashboard'),
    summary: document.getElementById('summary'),
    tabPanels: document.getElementById('tab-panels'),
    tabButtons: document.querySelectorAll('.tabs .tab'),
    graphCard: document.getElementById('graph-card'),
    graphSvg: document.getElementById('graph-svg'),
    viewToggle: document.getElementById('view-toggle'),
    zoomIn: document.getElementById('zoom-in'),
    zoomOut: document.getElementById('zoom-out'),
    zoomFit: document.getElementById('zoom-fit'),
    exportPng: document.getElementById('export-png'),
    graphLegend: document.getElementById('graph-legend'),
    timeline: document.getElementById('timeline'),
    timelineCount: document.getElementById('timeline-count'),
    drawer: document.getElementById('drawer'),
    drawerBackdrop: document.getElementById('drawer-backdrop'),
    drawerClose: document.getElementById('drawer-close'),
    drawerBody: document.getElementById('drawer-body'),
    loader: document.getElementById('loader'),
    loaderTitle: document.getElementById('loader-title'),
    loaderSteps: document.querySelectorAll('#loader-steps li'),
    toasts: document.getElementById('toasts'),
  };

  // ---------------------------------------------------------------------------
  // Canvas Ambient Particle Background
  // ---------------------------------------------------------------------------
  function initBackgroundCanvas() {
    const canvas = dom.bgCanvas;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let width, height;
    let particles = [];
    const count = 35;

    function resize() {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    }
    window.addEventListener('resize', resize);
    resize();

    class Particle {
      constructor() {
        this.reset();
      }
      reset() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 0.4;
        this.vy = (Math.random() - 0.5) * 0.4;
        this.radius = Math.random() * 2 + 1;
        this.alpha = Math.random() * 0.4 + 0.1;
      }
      update() {
        this.x += this.vx;
        this.y += this.vy;
        if (this.x < 0 || this.x > width || this.y < 0 || this.y > height) {
          this.reset();
        }
      }
      draw() {
        ctx.beginPath();
        ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(34, 211, 238, ${this.alpha})`;
        ctx.fill();
      }
    }

    for (let i = 0; i < count; i++) {
      particles.push(new Particle());
    }

    function loop() {
      ctx.clearRect(0, 0, width, height);

      // Connect nearby particles
      for (let i = 0; i < particles.length; i++) {
        for (let j = i + 1; j < particles.length; j++) {
          const dx = particles[i].x - particles[j].x;
          const dy = particles[i].y - particles[j].y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 130) {
            ctx.beginPath();
            ctx.moveTo(particles[i].x, particles[i].y);
            ctx.lineTo(particles[j].x, particles[j].y);
            ctx.strokeStyle = `rgba(167, 139, 250, ${(1 - dist / 130) * 0.12})`;
            ctx.lineWidth = 1;
            ctx.stroke();
          }
        }
      }

      particles.forEach(p => {
        p.update();
        p.draw();
      });
      requestAnimationFrame(loop);
    }
    requestAnimationFrame(loop);
  }

  // ---------------------------------------------------------------------------
  // Status Pill & Health Check
  // ---------------------------------------------------------------------------
  async function checkHealth() {
    if (!dom.statusPill) return;
    try {
      const res = await fetch('/api/health');
      if (!res.ok) throw new Error('Health check non-200');
      const data = await res.json();
      dom.statusPill.className = 'status-pill is-ok';
      const statusText = dom.statusPill.querySelector('.status-pill__text');
      if (statusText) {
        statusText.textContent = data.claude_configured ? 'AI Ready' : 'Online (Fallback)';
      }
      dom.statusPill.title = `AttackDNA v${data.version || '1.1.0'} · ${data.claude_configured ? 'Claude AI Connected' : 'Offline Template Mode'}`;
    } catch {
      dom.statusPill.className = 'status-pill is-warn';
      const statusText = dom.statusPill.querySelector('.status-pill__text');
      if (statusText) statusText.textContent = 'Degraded';
    }
  }

  // ---------------------------------------------------------------------------
  // Toast Notifications
  // ---------------------------------------------------------------------------
  function showToast(message, type = 'info', duration = 4000) {
    if (!dom.toasts) return;
    const toast = document.createElement('div');
    toast.className = `toast toast--${type}`;
    toast.textContent = message;
    dom.toasts.appendChild(toast);

    setTimeout(() => {
      toast.classList.add('is-leaving');
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }

  // ---------------------------------------------------------------------------
  // Loading Simulation
  // ---------------------------------------------------------------------------
  let loaderStepInterval = null;

  function showLoader(title = 'Analyzing…') {
    if (!dom.loader) return;
    dom.loader.hidden = false;
    if (dom.loaderTitle) dom.loaderTitle.textContent = title;

    dom.loaderSteps.forEach((li, idx) => {
      li.className = idx === 0 ? 'is-active' : '';
    });

    let currentStep = 0;
    clearInterval(loaderStepInterval);
    loaderStepInterval = setInterval(() => {
      if (currentStep < dom.loaderSteps.length - 1) {
        dom.loaderSteps[currentStep].className = 'is-done';
        currentStep++;
        dom.loaderSteps[currentStep].className = 'is-active';
      }
    }, 1800);
  }

  function hideLoader() {
    if (!dom.loader) return;
    clearInterval(loaderStepInterval);
    dom.loaderSteps.forEach(li => (li.className = 'is-done'));
    setTimeout(() => {
      dom.loader.hidden = true;
    }, 200);
  }

  // ---------------------------------------------------------------------------
  // Autocomplete / Search Dropdown
  // ---------------------------------------------------------------------------
  function setupSearchForm(form) {
    if (!form) return;
    const input = form.querySelector('.search__input');
    const resultsBox = form.querySelector('.search__results');
    let debounceTimer = null;

    form.addEventListener('submit', e => {
      e.preventDefault();
      const query = input.value.trim();
      if (!query) return;
      resultsBox.hidden = true;
      loadCVE(query);
    });

    input.addEventListener('input', () => {
      const q = input.value.trim();
      clearTimeout(debounceTimer);
      if (!q || q.length < 2) {
        resultsBox.hidden = true;
        resultsBox.innerHTML = '';
        return;
      }

      debounceTimer = setTimeout(async () => {
        try {
          const res = await fetch(`/api/search?q=${encodeURIComponent(q)}`);
          if (!res.ok) return;
          const data = await res.json();
          renderSearchResults(data, resultsBox);
        } catch (err) {
          console.error('Search error:', err);
        }
      }, 300);
    });

    // Close on outside click
    document.addEventListener('click', e => {
      if (!form.contains(e.target)) {
        resultsBox.hidden = true;
      }
    });

    // Reopen if input focused and has text
    input.addEventListener('focus', () => {
      if (resultsBox.children.length > 0 && input.value.trim().length >= 2) {
        resultsBox.hidden = false;
      }
    });
  }

  function renderSearchResults(data, container) {
    container.innerHTML = '';
    if (!data.results || data.results.length === 0) {
      if (data.redirect_cve) {
        container.innerHTML = `<button type="button" class="result" data-id="${data.redirect_cve}"><div class="result__top"><span class="result__id">${data.redirect_cve}</span></div><div class="result__desc">Direct CVE lookup</div></button>`;
      } else {
        container.innerHTML = `<div class="result result--msg">No matching CVEs found.</div>`;
      }
      container.hidden = false;
      return;
    }

    data.results.forEach(item => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'result';
      btn.dataset.id = item.cve_id;
      const scoreBadge = item.cvss_score ? `<span class="badge badge--${(item.cvss_severity || 'none').toLowerCase()}">${item.cvss_score}</span>` : '';
      btn.innerHTML = `
        <div class="result__top">
          <span class="result__id">${item.cve_id}</span>
          ${scoreBadge}
        </div>
        <div class="result__desc">${escapeHtml(item.description || '')}</div>
      `;
      btn.addEventListener('click', () => {
        container.hidden = true;
        loadCVE(item.cve_id);
      });
      container.appendChild(btn);
    });

    container.hidden = false;
  }

  // ---------------------------------------------------------------------------
  // Load CVE Analysis
  // ---------------------------------------------------------------------------
  async function loadCVE(cveQuery) {
    const cveId = cveQuery.toUpperCase().trim();
    showLoader(`Analyzing ${cveId}…`);

    try {
      const res = await fetch(`/api/cve/${encodeURIComponent(cveId)}`);
      const data = await res.json();

      if (!res.ok || data.error) {
        throw new Error(data.message || `Failed to analyze ${cveId}`);
      }

      state.currentCve = data.cve;
      state.attackChain = data.attack_chain;
      if (data.ai_warning) {
        showToast(data.ai_warning, 'warn', 5000);
      }

      // Sync inputs
      if (dom.headerSearch) {
        const hi = dom.headerSearch.querySelector('.search__input');
        if (hi) hi.value = state.currentCve.cve_id;
      }
      if (dom.heroSearch) {
        const hsi = dom.heroSearch.querySelector('.search__input');
        if (hsi) hsi.value = state.currentCve.cve_id;
      }

      // Update URL hash without reload
      window.location.hash = state.currentCve.cve_id;

      // Render dashboard
      renderDashboard();
    } catch (err) {
      showToast(err.message || 'An error occurred during CVE lookup', 'error', 6000);
    } finally {
      hideLoader();
    }
  }

  // ---------------------------------------------------------------------------
  // Dashboard Rendering
  // ---------------------------------------------------------------------------
  function renderDashboard() {
    if (!state.currentCve || !state.attackChain) return;

    // Switch view from hero to dashboard
    if (dom.hero) dom.hero.hidden = true;
    if (dom.dashboard) dom.dashboard.hidden = false;
    document.querySelector('.topbar')?.classList.remove('is-landing');

    renderSummary();
    renderTabs();
    renderTimeline();
    renderGraph();
  }

  function getSeverityColor(sev, score) {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL' || score >= 9.0) return 'var(--sev-critical)';
    if (s === 'HIGH' || score >= 7.0) return 'var(--sev-high)';
    if (s === 'MEDIUM' || score >= 4.0) return 'var(--sev-medium)';
    if (s === 'LOW' || score > 0) return 'var(--sev-low)';
    return 'var(--sev-none)';
  }

  function renderSummary() {
    const cve = state.currentCve;
    const chain = state.attackChain;
    const score = Number(cve.cvss_score) || 0;
    const sev = (cve.cvss_severity || 'Unknown').toUpperCase();
    const sevColor = getSeverityColor(sev, score);

    // SVG Gauge calculation
    const radius = 38;
    const circumference = 2 * Math.PI * radius;
    const dashoffset = circumference - (score / 10) * circumference;

    dom.summary.style.setProperty('--sev-color', sevColor);
    dom.summary.innerHTML = `
      <div class="gauge">
        <svg viewBox="0 0 96 96">
          <circle class="gauge__track" cx="48" cy="48" r="${radius}"/>
          <circle class="gauge__value" cx="48" cy="48" r="${radius}"
            stroke="${sevColor}"
            stroke-dasharray="${circumference}"
            stroke-dashoffset="${dashoffset}"/>
        </svg>
        <div class="gauge__label">
          <span class="gauge__score">${score > 0 ? score.toFixed(1) : 'N/A'}</span>
          <span class="gauge__max">${sev}</span>
        </div>
      </div>

      <div class="summary__main">
        <div class="summary__row">
          <h1 class="summary__id">${cve.cve_id}</h1>
          <span class="badge" style="color: ${sevColor}">${sev}</span>
          ${cve.known_exploited ? '<span class="badge badge--kev">CISA KEV EXPLOITED</span>' : ''}
          ${chain._fallback ? '<span class="badge badge--tpl">TEMPLATE CHAIN</span>' : '<span class="badge badge--ai">CLAUDE AI VERIFIED</span>'}
        </div>
        <p class="summary__oneliner">${escapeHtml(chain.one_liner || cve.description || '')}</p>
        <div class="summary__meta">
          <span><b>Published:</b> ${formatDate(cve.published_date)}</span>
          ${cve.cvss_vector ? `<span><b>Vector:</b> <code class="mono">${cve.cvss_vector}</code></span>` : ''}
          ${cve.affected_products?.length ? `<span><b>Affected:</b> ${cve.affected_products.length} products</span>` : ''}
        </div>
      </div>

      <div class="summary__actions">
        <button class="btn btn--sm" id="btn-copy-json" title="Copy raw analysis JSON">
          <svg viewBox="0 0 24 24"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg>
          Copy JSON
        </button>
        <button class="btn btn--sm btn--primary" id="btn-share" title="Share link to this analysis">
          <svg viewBox="0 0 24 24"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" x2="15.42" y1="13.51" y2="17.49"/><line x1="15.41" x2="8.59" y1="6.51" y2="10.49"/></svg>
          Share
        </button>
      </div>
    `;

    document.getElementById('btn-copy-json')?.addEventListener('click', () => {
      navigator.clipboard.writeText(JSON.stringify({ cve, attack_chain: chain }, null, 2));
      showToast('Copied analysis JSON to clipboard', 'ok');
    });

    document.getElementById('btn-share')?.addEventListener('click', () => {
      navigator.clipboard.writeText(window.location.href);
      showToast('Analysis URL copied to clipboard', 'ok');
    });
  }

  // ---------------------------------------------------------------------------
  // Tabs Rendering (Overview / Narrative / References)
  // ---------------------------------------------------------------------------
  function renderTabs() {
    const cve = state.currentCve;
    const chain = state.attackChain;

    let overviewHtml = `
      <div class="panel ${state.activeTab === 'overview' ? 'is-active' : ''}" id="panel-overview">
        <div class="field">
          <span class="field__label">Vulnerability Summary</span>
          <p class="field__text">${escapeHtml(cve.description || 'No description available.')}</p>
        </div>

        ${chain.patch_action ? `
          <div class="field">
            <span class="field__label">Recommended Remediation</span>
            <div class="callout callout--patch">${escapeHtml(chain.patch_action)}</div>
          </div>
        ` : ''}

        ${cve.cwe_ids?.length ? `
          <div class="field">
            <span class="field__label">Weakness Types (CWE)</span>
            <div class="tags">
              ${cve.cwe_ids.map(cwe => `<span class="tag tag--cwe">${escapeHtml(cwe)}</span>`).join('')}
            </div>
          </div>
        ` : ''}

        ${chain.affected_industries?.length ? `
          <div class="field">
            <span class="field__label">Target Industries</span>
            <div class="tags">
              ${chain.affected_industries.map(ind => `<span class="tag tag--industry">${escapeHtml(ind)}</span>`).join('')}
            </div>
          </div>
        ` : ''}

        ${cve.affected_products?.length ? `
          <div class="field">
            <span class="field__label">Affected Software / Products</span>
            <div class="tags" style="max-height: 120px; overflow-y: auto;">
              ${cve.affected_products.slice(0, 15).map(prod => `<span class="tag tag--tool">${escapeHtml(prod)}</span>`).join('')}
              ${cve.affected_products.length > 15 ? `<span class="muted">+${cve.affected_products.length - 15} more</span>` : ''}
            </div>
          </div>
        ` : ''}
      </div>
    `;

    // Narrative panel
    const storyParagraphs = (chain.severity_story || '').split('\n\n').filter(Boolean);
    let narrativeHtml = `
      <div class="panel ${state.activeTab === 'narrative' ? 'is-active' : ''}" id="panel-narrative">
        <div class="story">
          ${storyParagraphs.map(p => `<p>${escapeHtml(p)}</p>`).join('')}
        </div>
      </div>
    `;

    // References panel
    const refs = cve.references || [];
    let refsHtml = `
      <div class="panel ${state.activeTab === 'refs' ? 'is-active' : ''}" id="panel-refs">
        ${refs.length ? `
          <ul class="ref-list">
            ${refs.map(r => {
              let host = '';
              try { host = new URL(r.url).hostname; } catch { host = 'Reference'; }
              return `
                <li>
                  <a href="${escapeHtml(r.url)}" target="_blank" rel="noopener noreferrer">
                    <div class="ref-host">${escapeHtml(host)}</div>
                    <div class="ref-url">${escapeHtml(r.url)}</div>
                    ${r.tags?.length ? `
                      <div class="ref-tags">
                        ${r.tags.map(t => `<span>${escapeHtml(t)}</span>`).join('')}
                      </div>
                    ` : ''}
                  </a>
                </li>
              `;
            }).join('')}
          </ul>
        ` : '<p class="muted">No external references cataloged for this CVE.</p>'}
      </div>
    `;

    dom.tabPanels.innerHTML = overviewHtml + narrativeHtml + refsHtml;
  }

  // ---------------------------------------------------------------------------
  // Timeline Track
  // ---------------------------------------------------------------------------
  function renderTimeline() {
    const phases = state.attackChain?.attack_phases || [];
    if (dom.timelineCount) dom.timelineCount.textContent = `${phases.length} phases`;
    if (!dom.timeline) return;

    dom.timeline.innerHTML = '';
    phases.forEach((phase, index) => {
      const color = PHASE_COLORS[phase.phase] || DEFAULT_PHASE_COLOR;
      const step = document.createElement('li');
      step.className = 'step';
      step.style.setProperty('--phase', color);
      step.style.animationDelay = `${index * 0.08}s`;
      step.innerHTML = `
        <span class="step__num">PHASE ${index + 1}</span>
        <div class="step__phase">${escapeHtml(phase.phase)}</div>
        <div class="step__name">${escapeHtml(phase.mitre_name || phase.phase)}</div>
        <div class="step__mitre">${escapeHtml(phase.mitre_id || '')}</div>
        <div class="step__detect">🛡️ ${escapeHtml(phase.detection_point || 'Monitor logs')}</div>
      `;
      step.addEventListener('click', () => {
        openPhaseDrawer(phase.id);
      });
      dom.timeline.appendChild(step);
    });
  }

  // ---------------------------------------------------------------------------
  // D3 Graph Visualization
  // ---------------------------------------------------------------------------
  function renderGraph() {
    const phases = state.attackChain?.attack_phases || [];
    const svg = d3.select(dom.graphSvg);
    svg.selectAll('*').remove();

    if (!phases.length) return;

    const width = dom.graphCard.clientWidth || 900;
    const height = dom.graphCard.clientHeight || 560;

    // Defs: Filters, Arrows, Gradients
    const defs = svg.append('defs');

    // Glow filter
    const filter = defs.append('filter')
      .attr('id', 'node-glow')
      .attr('x', '-30%').attr('y', '-30%')
      .attr('width', '160%').attr('height', '160%');
    filter.append('feGaussianBlur').attr('stdDeviation', '6').attr('result', 'blur');
    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'blur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Arrow markers
    defs.append('marker')
      .attr('id', 'arrow-attacker')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 18)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L8,0L0,4')
      .attr('fill', '#22d3ee');

    defs.append('marker')
      .attr('id', 'arrow-defender')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 18)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-4L8,0L0,4')
      .attr('fill', '#34d399');

    // Container with Zoom behavior
    const g = svg.append('g').attr('class', 'graph-container');
    state.gSelection = g;

    const zoom = d3.zoom()
      .scaleExtent([0.3, 2.5])
      .on('zoom', e => {
        g.attr('transform', e.transform);
      });
    svg.call(zoom).on('dblclick.zoom', null);
    state.zoomBehavior = zoom;
    state.svgSelection = svg;

    // Build Nodes & Links
    const nodeMap = new Map();
    state.nodesData = phases.map((p, idx) => {
      const node = {
        ...p,
        index: idx,
        color: PHASE_COLORS[p.phase] || DEFAULT_PHASE_COLOR,
      };
      nodeMap.set(p.id, node);
      return node;
    });

    state.linksData = [];
    phases.forEach((p, idx) => {
      if (p.connects_to && Array.isArray(p.connects_to) && p.connects_to.length > 0) {
        p.connects_to.forEach(targetId => {
          if (nodeMap.has(targetId)) {
            state.linksData.push({ source: p.id, target: targetId });
          }
        });
      } else if (idx < phases.length - 1) {
        // Fallback linear sequence if connects_to empty
        state.linksData.push({ source: p.id, target: phases[idx + 1].id });
      }
    });

    // Compute layout positions (horizontal flow with gentle stagger)
    const cardW = 190;
    const cardH = 96;
    const totalCols = state.nodesData.length;
    const colSpacing = Math.max(220, (width - 120) / Math.max(totalCols - 1, 1));
    const startX = 80;
    const centerY = height / 2;

    state.nodesData.forEach((node, idx) => {
      node.x = startX + idx * colSpacing;
      // Stagger slightly up and down for visual rhythm
      node.y = centerY + (idx % 2 === 0 ? -25 : 25);
    });

    // Links rendering
    const linkGroup = g.append('g').attr('class', 'links');
    const linkElements = linkGroup.selectAll('.link-group')
      .data(state.linksData)
      .enter()
      .append('g')
      .attr('class', 'link-group');

    linkElements.append('path')
      .attr('class', 'link__base')
      .attr('d', d => {
        const s = nodeMap.get(d.source);
        const t = nodeMap.get(d.target);
        return generateCurve(s.x + cardW / 2, s.y, t.x - cardW / 2, t.y);
      });

    linkElements.append('path')
      .attr('class', 'link__flow')
      .attr('stroke', state.currentView === 'defender' ? '#34d399' : '#22d3ee')
      .attr('marker-end', state.currentView === 'defender' ? 'url(#arrow-defender)' : 'url(#arrow-attacker)')
      .attr('d', d => {
        const s = nodeMap.get(d.source);
        const t = nodeMap.get(d.target);
        return generateCurve(s.x + cardW / 2, s.y, t.x - cardW / 2, t.y);
      });

    // Nodes rendering
    const nodeGroup = g.append('g').attr('class', 'nodes');
    const nodeElements = nodeGroup.selectAll('.node')
      .data(state.nodesData)
      .enter()
      .append('g')
      .attr('class', 'node')
      .attr('transform', d => `translate(${d.x - cardW / 2}, ${d.y - cardH / 2})`)
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended)
      )
      .on('click', (event, d) => {
        openPhaseDrawer(d.id);
      });

    // Card background
    nodeElements.append('rect')
      .attr('class', 'node__card')
      .attr('width', cardW)
      .attr('height', cardH)
      .attr('rx', 12)
      .attr('fill', '#0e1526')
      .attr('stroke', d => d.color)
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.85);

    // Top Phase Accent Bar
    nodeElements.append('path')
      .attr('d', `M 0,12 A 12,12 0 0,1 12,0 L ${cardW - 12},0 A 12,12 0 0,1 ${cardW},12 L ${cardW},16 L 0,16 Z`)
      .attr('fill', d => d.color);

    // Phase Name Pill Text
    nodeElements.append('text')
      .attr('x', 12)
      .attr('y', 32)
      .attr('fill', '#94a3b8')
      .attr('font-size', '10px')
      .attr('font-weight', '700')
      .attr('text-transform', 'uppercase')
      .attr('letter-spacing', '0.08em')
      .text(d => d.phase);

    // MITRE Technique ID
    nodeElements.append('text')
      .attr('x', cardW - 12)
      .attr('y', 32)
      .attr('text-anchor', 'end')
      .attr('fill', d => d.color)
      .attr('font-family', 'var(--font-mono)')
      .attr('font-size', '11px')
      .attr('font-weight', '700')
      .text(d => d.mitre_id || '');

    // Technique Name
    nodeElements.append('text')
      .attr('x', 12)
      .attr('y', 52)
      .attr('fill', '#f1f5f9')
      .attr('font-size', '12px')
      .attr('font-weight', '600')
      .text(d => truncate(d.mitre_name || d.phase, 22));

    // Tools preview tag / detection preview
    nodeElements.append('text')
      .attr('class', 'node__tools-preview')
      .attr('x', 12)
      .attr('y', 74)
      .attr('fill', '#64748b')
      .attr('font-size', '10px')
      .attr('font-family', 'var(--font-mono)')
      .text(d => d.tools?.length ? `🔨 ${truncate(d.tools.join(', '), 20)}` : '• Direct exploit');

    // Defender Badge / Shield (appears in Defender View)
    const defenderShield = nodeElements.append('g')
      .attr('class', 'node__detect')
      .attr('transform', `translate(12, 70)`);

    defenderShield.append('rect')
      .attr('width', cardW - 24)
      .attr('height', 18)
      .attr('rx', 4)
      .attr('fill', 'rgba(52, 211, 153, 0.15)')
      .attr('stroke', 'rgba(52, 211, 153, 0.4)')
      .attr('stroke-width', 1);

    defenderShield.append('text')
      .attr('x', 6)
      .attr('y', 13)
      .attr('fill', '#6ee7b7')
      .attr('font-size', '9.5px')
      .attr('font-weight', '600')
      .text(d => `🛡️ ${truncate(d.detection_point || 'Audit log', 22)}`);

    // Drag handlers
    function dragstarted(event, d) {
      d3.select(this).raise().classed('is-dragging', true);
    }

    function dragged(event, d) {
      d.x += event.dx;
      d.y += event.dy;
      d3.select(this).attr('transform', `translate(${d.x - cardW / 2}, ${d.y - cardH / 2})`);

      // Update link curves
      linkElements.selectAll('path').attr('d', l => {
        const s = nodeMap.get(l.source);
        const t = nodeMap.get(l.target);
        return generateCurve(s.x + cardW / 2, s.y, t.x - cardW / 2, t.y);
      });
    }

    function dragended() {
      d3.select(this).classed('is-dragging', false);
    }

    // Render Legend
    renderGraphLegend(phases);

    // Initial Zoom Fit
    zoomFit();
  }

  function generateCurve(x1, y1, x2, y2) {
    const dx = Math.abs(x2 - x1) * 0.5;
    return `M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`;
  }

  function renderGraphLegend(phases) {
    if (!dom.graphLegend) return;
    const uniquePhases = [...new Set(phases.map(p => p.phase))];
    dom.graphLegend.innerHTML = uniquePhases.map(ph => {
      const color = PHASE_COLORS[ph] || DEFAULT_PHASE_COLOR;
      return `
        <div class="legend-item">
          <span class="legend-dot" style="background: ${color}"></span>
          <span>${escapeHtml(ph)}</span>
        </div>
      `;
    }).join('');
  }

  function zoomFit() {
    if (!state.svgSelection || !state.gSelection || !state.nodesData.length) return;
    const svgEl = dom.graphSvg;
    const width = svgEl.clientWidth || 900;
    const height = svgEl.clientHeight || 560;

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    state.nodesData.forEach(n => {
      minX = Math.min(minX, n.x - 100);
      maxX = Math.max(maxX, n.x + 100);
      minY = Math.min(minY, n.y - 60);
      maxY = Math.max(maxY, n.y + 60);
    });

    const dx = maxX - minX;
    const dy = maxY - minY;
    if (dx <= 0 || dy <= 0) return;

    const scale = Math.min(1.2, Math.max(0.4, 0.85 / Math.max(dx / width, dy / height)));
    const translate = [width / 2 - scale * (minX + dx / 2), height / 2 - scale * (minY + dy / 2)];

    state.svgSelection.transition().duration(600).call(
      state.zoomBehavior.transform,
      d3.zoomIdentity.translate(translate[0], translate[1]).scale(scale)
    );
  }

  // ---------------------------------------------------------------------------
  // Perspective View Toggle (Attacker vs Defender)
  // ---------------------------------------------------------------------------
  function setPerspectiveView(view) {
    state.currentView = view;

    dom.viewToggle?.querySelectorAll('button').forEach(btn => {
      btn.classList.toggle('is-active', btn.dataset.view === view);
    });

    const isDef = view === 'defender';
    dom.graphCard?.classList.toggle('is-defender', isDef);
    dom.dashboard?.classList.toggle('is-defender', isDef);

    // Update D3 link colors and arrows
    if (dom.graphSvg) {
      d3.select(dom.graphSvg).selectAll('.link__flow')
        .attr('stroke', isDef ? '#34d399' : '#22d3ee')
        .attr('marker-end', isDef ? 'url(#arrow-defender)' : 'url(#arrow-attacker)');
    }
  }

  // ---------------------------------------------------------------------------
  // Phase Drawer Modal
  // ---------------------------------------------------------------------------
  function openPhaseDrawer(phaseId) {
    const phases = state.attackChain?.attack_phases || [];
    const index = phases.findIndex(p => p.id === phaseId);
    if (index === -1) return;

    const phase = phases[index];
    state.selectedPhaseId = phaseId;
    const color = PHASE_COLORS[phase.phase] || DEFAULT_PHASE_COLOR;

    // Highlight node in SVG
    if (dom.graphSvg) {
      d3.select(dom.graphSvg).selectAll('.node')
        .classed('is-selected', d => d.id === phaseId);
    }

    const prevPhase = index > 0 ? phases[index - 1] : null;
    const nextPhase = index < phases.length - 1 ? phases[index + 1] : null;

    dom.drawerBody.innerHTML = `
      <span class="drawer__step" style="color: ${color}">PHASE ${index + 1} OF ${phases.length}</span>
      <div><span class="drawer__phase" style="--phase: ${color}; color: ${color}; border-color: ${color}40; background: ${color}15;">${escapeHtml(phase.phase)}</span></div>
      <h2 id="drawer-title">${escapeHtml(phase.mitre_name || phase.phase)}</h2>
      
      ${phase.mitre_id ? `
        <a class="drawer__mitre" href="https://attack.mitre.org/techniques/${escapeHtml(phase.mitre_id)}/" target="_blank" rel="noopener noreferrer">
          ${escapeHtml(phase.mitre_id)}
          <svg viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6M15 3h6v6M10 14L21 3"/></svg>
        </a>
      ` : ''}

      <div class="field">
        <span class="field__label">Phase Description</span>
        <p class="field__text">${escapeHtml(phase.description || '')}</p>
      </div>

      <div class="field">
        <span class="field__label">Defender Detection Point</span>
        <div class="callout callout--patch">
          🛡️ <b>Detection Strategy:</b> ${escapeHtml(phase.detection_point || 'Audit logging and baseline monitoring')}
        </div>
      </div>

      ${phase.tools?.length ? `
        <div class="field">
          <span class="field__label">Known Attacker Tooling</span>
          <div class="tags">
            ${phase.tools.map(t => `<span class="tag tag--tool">${escapeHtml(t)}</span>`).join('')}
          </div>
        </div>
      ` : ''}

      <div class="drawer__nav">
        <button class="btn btn--sm" id="drawer-prev" ${!prevPhase ? 'disabled' : ''}>
          ← Previous
        </button>
        <button class="btn btn--sm" id="drawer-next" ${!nextPhase ? 'disabled' : ''}>
          Next →
        </button>
      </div>
    `;

    document.getElementById('drawer-prev')?.addEventListener('click', () => {
      if (prevPhase) openPhaseDrawer(prevPhase.id);
    });
    document.getElementById('drawer-next')?.addEventListener('click', () => {
      if (nextPhase) openPhaseDrawer(nextPhase.id);
    });

    dom.drawer.classList.add('is-open');
    dom.drawerBackdrop.hidden = false;
    dom.drawer.setAttribute('aria-hidden', 'false');
  }

  function closePhaseDrawer() {
    dom.drawer.classList.remove('is-open');
    dom.drawerBackdrop.hidden = true;
    dom.drawer.setAttribute('aria-hidden', 'true');
    state.selectedPhaseId = null;

    if (dom.graphSvg) {
      d3.select(dom.graphSvg).selectAll('.node').classed('is-selected', false);
    }
  }

  // ---------------------------------------------------------------------------
  // Export Graph to PNG
  // ---------------------------------------------------------------------------
  function exportGraphToPng() {
    const svgEl = dom.graphSvg;
    if (!svgEl) return;

    showToast('Rendering graph PNG…', 'info', 1500);

    const serializer = new XMLSerializer();
    let source = serializer.serializeToString(svgEl);

    // Add XML namespaces
    if (!source.match(/^<svg[^>]+xmlns="http:\/\/www\.w3\.org\/2000\/svg"/)) {
      source = source.replace(/^<svg/, '<svg xmlns="http://www.w3.org/2000/svg"');
    }

    const svgBlob = new Blob([source], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(svgBlob);
    const img = new Image();

    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = svgEl.clientWidth * 2;
      canvas.height = svgEl.clientHeight * 2;
      const ctx = canvas.getContext('2d');
      ctx.fillStyle = '#070a13';
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);

      URL.revokeObjectURL(url);
      const a = document.createElement('a');
      a.download = `AttackDNA-${state.currentCve?.cve_id || 'chain'}.png`;
      a.href = canvas.toDataURL('image/png');
      a.click();
      showToast('Graph exported as PNG', 'ok');
    };
    img.src = url;
  }

  // ---------------------------------------------------------------------------
  // Helper Utilities
  // ---------------------------------------------------------------------------
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function truncate(str, max) {
    if (!str) return '';
    return str.length > max ? str.slice(0, max - 1) + '…' : str;
  }

  function formatDate(isoStr) {
    if (!isoStr) return 'N/A';
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
    } catch {
      return isoStr.split('T')[0] || isoStr;
    }
  }

  // ---------------------------------------------------------------------------
  // Initialization
  // ---------------------------------------------------------------------------
  function init() {
    initBackgroundCanvas();
    checkHealth();

    // Setup forms
    setupSearchForm(dom.heroSearch);
    setupSearchForm(dom.headerSearch);

    // Keyboard shortcut "/" to focus search
    window.addEventListener('keydown', e => {
      if (e.key === '/' && !['INPUT', 'TEXTAREA'].includes(document.activeElement.tagName)) {
        e.preventDefault();
        const activeSearch = dom.dashboard && !dom.dashboard.hidden ? dom.headerSearch : dom.heroSearch;
        activeSearch?.querySelector('.search__input')?.focus();
      }
    });

    // Populate example chips in hero
    if (dom.exampleChips) {
      dom.exampleChips.innerHTML = POPULAR_CVES.map(item => `
        <button type="button" class="chip" data-id="${item.id}">
          <span class="chip__id">${item.id}</span>
          <span class="chip__name">${item.name}</span>
        </button>
      `).join('');

      dom.exampleChips.addEventListener('click', e => {
        const chip = e.target.closest('.chip');
        if (chip && chip.dataset.id) {
          loadCVE(chip.dataset.id);
        }
      });
    }

    // Brand link resets to landing
    dom.brandLink?.addEventListener('click', e => {
      e.preventDefault();
      if (dom.dashboard) dom.dashboard.hidden = true;
      if (dom.hero) dom.hero.hidden = false;
      document.querySelector('.topbar')?.classList.add('is-landing');
      window.location.hash = '';
    });

    // Tabs navigation
    dom.tabButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        dom.tabButtons.forEach(b => {
          b.classList.remove('is-active');
          b.setAttribute('aria-selected', 'false');
        });
        btn.classList.add('is-active');
        btn.setAttribute('aria-selected', 'true');
        state.activeTab = btn.dataset.tab;

        document.querySelectorAll('.tab-panels .panel').forEach(p => {
          p.classList.toggle('is-active', p.id === `panel-${state.activeTab}`);
        });
      });
    });

    // Graph toolbar
    dom.viewToggle?.addEventListener('click', e => {
      const btn = e.target.closest('button');
      if (btn && btn.dataset.view) {
        setPerspectiveView(btn.dataset.view);
      }
    });

    dom.zoomIn?.addEventListener('click', () => {
      if (state.svgSelection && state.zoomBehavior) {
        state.svgSelection.transition().duration(250).call(state.zoomBehavior.scaleBy, 1.3);
      }
    });

    dom.zoomOut?.addEventListener('click', () => {
      if (state.svgSelection && state.zoomBehavior) {
        state.svgSelection.transition().duration(250).call(state.zoomBehavior.scaleBy, 0.77);
      }
    });

    dom.zoomFit?.addEventListener('click', zoomFit);
    dom.exportPng?.addEventListener('click', exportGraphToPng);

    // Drawer close events
    dom.drawerClose?.addEventListener('click', closePhaseDrawer);
    dom.drawerBackdrop?.addEventListener('click', closePhaseDrawer);
    window.addEventListener('keydown', e => {
      if (e.key === 'Escape' && dom.drawer.classList.contains('is-open')) {
        closePhaseDrawer();
      }
    });

    // Deep linking via hash or URL param
    const hash = window.location.hash.replace('#', '').trim();
    const urlParams = new URLSearchParams(window.location.search);
    const paramCve = urlParams.get('cve') || urlParams.get('q');

    const initialCve = hash || paramCve;
    if (initialCve) {
      loadCVE(initialCve);
    } else {
      document.querySelector('.topbar')?.classList.add('is-landing');
    }
  }

  // Run on DOM ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
