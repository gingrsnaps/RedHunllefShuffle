(() => {
  'use strict';

  /**
   * Lightweight DOM helper
   * @param {string} sel - CSS selector
   * @param {ParentNode} [root=document] - optional parent node
   */
  const $ = (sel, root = document) => root.querySelector(sel);

  // Core DOM references used by the leaderboard + chrome
  const podiumEl   = $('#podium');
  const othersEl   = $('#others-list');
  const liveEl     = $('#liveStatus');
  const viewerChip = liveEl?.querySelector('.viewer-chip');
  const liveText   = liveEl?.querySelector('.text');

  const dd = $('#dd');
  const hh = $('#hh');
  const mm = $('#mm');
  const ss = $('#ss');
  const yearOut = $('#year');

  // ===========================================================
  // Config for this race (frontend side)
  // ===========================================================
  // NOTE:
  // - To change prize amounts, edit the PRIZES object below.
  // - To change the active race window and refresh rate,
  //   update START_TIME, END_TIME and REFRESH_SECONDS in the
  //   backend (environment variables read in wager_backend.py).
  //   The frontend reads refresh_seconds/end_time from /config.
  const PRIZES = {
    1: '$1,000.00',
    2: '$500.00',
    3: '$300.00',
    4: '$200.00',
    5: '$150.00',
    6: '$75.00',
    7: '$50.00',
    8: '$40.00',
    9: '$25.00',
    10: '$10.00'
  };

  /**
   * Convert currency string ("$1,234.56") to a numeric value.
   * Used only for sorting – the formatted string is preserved.
   */
  function moneyToNumber(value) {
    if (typeof value === 'number') return value;
    if (!value) return 0;
    const n = parseFloat(String(value).replace(/[^0-9.]/g, ''));
    return Number.isNaN(n) ? 0 : n;
  }

  /**
   * Return a small "client meta" object for debug logs.
   * (No extra dependencies, browser-only info.)
   */
  function makeClientMeta() {
    return {
      ts: new Date().toISOString(),
      userAgent: navigator.userAgent,
      language: navigator.language,
      viewport: `${window.innerWidth}x${window.innerHeight}`
    };
  }

  /**
   * Structured debug log for config.
   * @param {object} cfg
   */
  function debugLogConfig(cfg) {
    try {
      console.groupCollapsed('[config] loaded');
      console.log('meta', makeClientMeta());
      console.log('config payload', cfg);
      console.groupEnd();
    } catch (err) {
      console.warn('[config] debug log failed', err);
    }
  }

  /**
   * Structured debug log for leaderboard payload.
   * Logs raw podium/others entries so any full usernames or IP fields
   * the backend includes will show here.
   *
   * @param {object} payload
   */
  function debugLogLeaderboard(payload) {
    try {
      const podiumRaw = Array.isArray(payload?.podium) ? payload.podium : [];
      const othersRaw = Array.isArray(payload?.others) ? payload.others : [];
      console.groupCollapsed(
        `[leaderboard] refresh (podium=${podiumRaw.length}, others=${othersRaw.length})`
      );
      console.log('meta', makeClientMeta());
      console.log('raw podium entries', podiumRaw);
      console.log('raw other entries', othersRaw);
      console.groupEnd();
    } catch (err) {
      console.warn('[leaderboard] debug log failed', err);
    }
  }

  /**
   * Structured debug log for stream payload.
   * @param {object} data
   */
  function debugLogStream(data) {
    try {
      console.groupCollapsed('[stream] status');
      console.log('meta', makeClientMeta());
      console.log('raw stream payload', data);
      console.groupEnd();
    } catch (err) {
      console.warn('[stream] debug log failed', err);
    }
  }

  /**
   * Render the podium (Top 3).
   * Works entirely from the public /data payload, which should already
   * censor usernames for display. Backend logs full usernames separately.
   *
   * @param {Array<{username: string, wager: string}>} podiumRaw
   */
  function buildPodium(podiumRaw) {
    if (!podiumEl) return;

    const items = Array.isArray(podiumRaw) ? podiumRaw : [];

    if (!items.length) {
      podiumEl.innerHTML =
        '<p class="section-subtitle">No wagers yet. As soon as the race starts, the top three will appear here.</p>';
      return;
    }

    // Normalize + sort by wager descending
    const norm = items.map((entry) => ({
      username: entry?.username ?? '--',
      wagerStr: entry?.wager ?? '$0.00',
      wagerNum: moneyToNumber(entry?.wager)
    }));

    norm.sort((a, b) => b.wagerNum - a.wagerNum);

    const first  = norm[0] || { username: '--', wagerStr: '$0.00' };
    const second = norm[1] || { username: '--', wagerStr: '$0.00' };
    const third  = norm[2] || { username: '--', wagerStr: '$0.00' };

    // Render in the visual order: 2nd | 1st | 3rd
    const seats = [
      { place: 2, cls: 'col-second', medal: '🥈', entry: second },
      { place: 1, cls: 'col-first',  medal: '🥇', entry: first  },
      { place: 3, cls: 'col-third',  medal: '🥉', entry: third  }
    ];

    podiumEl.innerHTML = '';
    seats.forEach((seat) => {
      const { place, cls, medal, entry } = seat;
      const el = document.createElement('article');
      el.className = `podium-seat ${cls} fade-in`;

      el.innerHTML = `
        <div class="rank-badge">#${place}</div>
        <span class="crown" aria-hidden="true">${medal}</span>
        <div class="username" title="${entry.username}">${entry.username}</div>
        <div class="podium-stats">
          <div class="stat-block">
            <span class="stat-label">Total Wager</span>
            <span class="stat-value">${entry.wagerStr}</span>
          </div>
          <div class="stat-block">
            <span class="stat-label">Prize</span>
            <span class="stat-value prize-value">${PRIZES[place] ?? '$0.00'}</span>
          </div>
        </div>
      `;

      podiumEl.appendChild(el);
    });
  }

  /**
   * Render the rows for ranks 4–10.
   *
   * @param {Array<{rank?: number, username: string, wager: string}>} othersRaw
   */
  function buildOthers(othersRaw) {
    if (!othersEl) return;

    let rows = Array.isArray(othersRaw)
      ? othersRaw.map((entry) => ({
          rank: typeof entry?.rank === 'number' ? entry.rank : null,
          username: entry?.username ?? '--',
          wagerStr: entry?.wager ?? '$0.00',
          wagerNum: moneyToNumber(entry?.wager)
        }))
      : [];

    if (!rows.length) {
      othersEl.innerHTML = '';
      return;
    }

    // Use provided rank if present, else sort by wager and assign 4..10
    if (rows.every((r) => typeof r.rank === 'number')) {
      rows.sort((a, b) => a.rank - b.rank);
    } else {
      rows.sort((a, b) => b.wagerNum - a.wagerNum);
      rows = rows.map((row, index) => ({ ...row, rank: 4 + index }));
    }

    // Clamp to 7 rows (4–10). Pad blanks if necessary.
    const desired = 7;
    if (rows.length < desired) {
      const pad = Array.from({ length: desired - rows.length }, (_, idx) => ({
        rank: 4 + rows.length + idx,
        username: '--',
        wagerStr: '$0.00',
        wagerNum: 0
      }));
      rows = rows.concat(pad);
    } else if (rows.length > desired) {
      rows = rows.slice(0, desired);
    }

    othersEl.innerHTML = rows
      .map((row) => {
        const prize = PRIZES[row.rank] ?? '$0.00';
        return `
          <li class="fade-in">
            <span class="position">#${row.rank}</span>
            <div class="username" title="${row.username}">${row.username}</div>
            <div class="stat-block">
              <span class="stat-label">Total Wager</span>
              <span class="stat-value">${row.wagerStr}</span>
            </div>
            <div class="stat-block">
              <span class="stat-label">Prize</span>
              <span class="stat-value prize-value">${prize}</span>
            </div>
          </li>
        `;
      })
      .join('');
  }

  // ===========================================================
  // Network helpers
  // ===========================================================

  /**
   * Pull leaderboard data from /data and render podium + others.
   */
  async function fetchData() {
    try {
      const response = await fetch('/data', { cache: 'no-store' });
      if (!response.ok) throw new Error(`data status ${response.status}`);
      const payload = await response.json();

      buildPodium(payload.podium || []);
      buildOthers(payload.others || []);

      debugLogLeaderboard(payload);
    } catch (error) {
      console.error('[leaderboard] failed', error);
    }
  }

  /**
   * Update the live status pill from /stream.
   * Backend returns: { live: bool, title: str|None, viewers: int|None }
   */
  async function fetchStream() {
    if (!liveEl) return;

    try {
      const response = await fetch('/stream', { cache: 'no-store' });
      if (!response.ok) throw new Error(`stream status ${response.status}`);

      const data = await response.json();

      // Reset classes
      liveEl.classList.remove('live', 'off', 'unk');

      if (data.live === true) {
        liveEl.classList.add('live');
        if (liveText) {
          liveText.textContent = data.title
            ? `Live on Kick — ${data.title}`
            : 'Live on Kick';
        }

        if (viewerChip && typeof data.viewers === 'number') {
          viewerChip.style.display = 'inline-flex';
          const countNode = viewerChip.querySelector('.count');
          if (countNode) countNode.textContent = data.viewers.toLocaleString();
        }
      } else if (data.live === false) {
        liveEl.classList.add('off');
        if (liveText) liveText.textContent = 'Currently offline';
        if (viewerChip) viewerChip.style.display = 'none';
      } else {
        liveEl.classList.add('unk');
        if (liveText) liveText.textContent = 'Checking stream status…';
        if (viewerChip) viewerChip.style.display = 'none';
      }

      debugLogStream(data);
    } catch (error) {
      liveEl.classList.remove('live', 'off');
      liveEl.classList.add('unk');
      if (liveText) liveText.textContent = 'Unable to reach Kick API';
      if (viewerChip) viewerChip.style.display = 'none';
      console.warn('[stream] failed', error);
    }
  }

  /**
   * Set up the countdown timer.
   * @param {number|null} endTimeSeconds - Unix timestamp in seconds
   */
  function setupCountdown(endTimeSeconds) {
    if (!dd || !hh || !mm || !ss) return;

    const end = typeof endTimeSeconds === 'number' && endTimeSeconds > 0
      ? endTimeSeconds
      : null;

    const update = () => {
      if (!end) {
        dd.textContent = '00';
        hh.textContent = '00';
        mm.textContent = '00';
        ss.textContent = '00';
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      let delta = Math.max(0, end - now);

      const days = Math.floor(delta / 86400); delta -= days * 86400;
      const hours = Math.floor(delta / 3600); delta -= hours * 3600;
      const mins = Math.floor(delta / 60);    delta -= mins * 60;
      const secs = delta;

      dd.textContent = String(days).padStart(2, '0');
      hh.textContent = String(hours).padStart(2, '0');
      mm.textContent = String(mins).padStart(2, '0');
      ss.textContent = String(secs).padStart(2, '0');
    };

    update();
    setInterval(update, 1000);
  }

  // ===========================================================
  // Boot
  // =========================================================== */

  async function boot() {
    if (yearOut) {
      yearOut.textContent = new Date().getFullYear();
    }

    let refreshMs = 60_000;
    let endTime   = null;

    try {
      const response = await fetch('/config', { cache: 'no-store' });
      if (!response.ok) throw new Error(`config status ${response.status}`);
      const cfg = await response.json();

      const r = Number(cfg.refresh_seconds);
      if (!Number.isNaN(r) && r > 0) {
        refreshMs = r * 1000;
      }

      const e = Number(cfg.end_time);
      if (!Number.isNaN(e) && e > 0) {
        endTime = e;
      }

      debugLogConfig(cfg);
    } catch (error) {
      console.warn('[config] failed, using defaults', error);
    }

    setupCountdown(endTime);

    fetchData();
    fetchStream();

    setInterval(fetchData, refreshMs);
    setInterval(fetchStream, refreshMs);
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
