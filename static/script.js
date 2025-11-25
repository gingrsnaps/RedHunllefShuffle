(() => {
  const $ = (sel, root = document) => root.querySelector(sel);

  const podiumEl   = $('#podium');
  const othersEl   = $('#others-list');
  const liveEl     = $('#liveStatus');
  const viewerChip = liveEl?.querySelector('.viewer-chip');
  const text       = liveEl?.querySelector('.text');

  const dd = $('#dd'), hh = $('#hh'), mm = $('#mm'), ss = $('#ss');
  const yearOut = $('#year');

// Prize table

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



  /** Convert a currency string to a number */
  function moneyToNumber(s) {
    if (typeof s === 'number') return s;
    if (!s) return 0;
    const n = parseFloat(String(s).replace(/[^0-9.]/g, ''));
    return isNaN(n) ? 0 : n;
  }

  /** Format integer with commas */
  function fmtInt(n) {
    return (n ?? 0).toLocaleString();
  }

  /** Podium with 1st place in the MIDDLE (Olympics style) */
  function buildPodium(podiumRaw) {
    // Normalize and sort by wager descending
    const norm = (podiumRaw || []).map(e => ({
      username: e?.username ?? '--',
      wagerStr: e?.wager ?? '$0.00',
      wagerNum: moneyToNumber(e?.wager)
    }));
    norm.sort((a, b) => b.wagerNum - a.wagerNum);

    // Top 3 after sorting
    const first  = norm[0] || { username: '--', wagerStr: '$0.00' };
    const second = norm[1] || { username: '--', wagerStr: '$0.00' };
    const third  = norm[2] || { username: '--', wagerStr: '$0.00' };

    // Render order = [second, first, third] to place 1st at the center column
    const seats = [
      { place: 2, cls: 'col-second', medal: '🥈', entry: second },
      { place: 1, cls: 'col-first',  medal: '🥇', entry: first  },
      { place: 3, cls: 'col-third',  medal: '🥉', entry: third  },
    ];

    podiumEl.innerHTML = '';
    seats.forEach(s => {
      const el = document.createElement('article');
      el.className = `podium-seat ${s.cls} fade-in`;
      el.innerHTML = `
        <span class="rank-badge">${s.place}</span>
        <div class="crown">${s.medal}</div>
        <div class="user">${s.entry.username}</div>
        <div class="label">WAGERED</div>
        <div class="wager">${s.entry.wagerStr}</div>
        <div class="label">PRIZE</div>
        <div class="prize">${PRIZES[s.place]}</div>
      `;
      podiumEl.appendChild(el);
    });
  }

  /** Build placements 4–10. If absent, use wager DESC and assign ranks. */
  function buildOthers(othersRaw) {
    let others = (othersRaw || []).map(e => ({
      rank: typeof e?.rank === 'number' ? e.rank : null,
      username: e?.username ?? '--',
      wagerStr: e?.wager ?? '$0.00',
      wagerNum: moneyToNumber(e?.wager)
    }));

    if (others.length === 0) {
      othersEl.innerHTML = '';
      return;
    }

    // If rank is provided, sort ascending by rank; else sort by wager desc then rank 4..10
    if (others.every(o => typeof o.rank === 'number')) {
      others.sort((a, b) => a.rank - b.rank);
    } else {
      others.sort((a, b) => b.wagerNum - a.wagerNum);
      others = others.map((o, idx) => ({ ...o, rank: 4 + idx }));
    }

    // Ensure exactly 7 items (4..10)
    const desired = 7;
    if (others.length < desired) {
      const pad = Array.from({ length: desired - others.length }, (_, i) => ({
        rank: 4 + others.length + i,
        username: '--',
        wagerStr: '$0.00',
        wagerNum: 0
      }));
      others = others.concat(pad);
    } else if (others.length > desired) {
      others = others.slice(0, desired);
    }

    othersEl.innerHTML = others.map(o => `
      <li class="fade-in">
        <span class="position">#${o.rank}</span>
        <div class="username">${o.username}</div>
        <div class="label emphasized">WAGER</div>
        <div class="wager">${o.wagerStr}</div>
        <div class="prize">${PRIZES[o.rank] || '$0.00'}</div>
      </li>
    `).join('');
  }

  /** Pull leaderboard data and render */
  async function fetchData() {
    try {
      const r = await fetch('/data', { cache: 'no-store' });
      if (!r.ok) throw new Error(`data status ${r.status}`);
      const j = await r.json();
      buildPodium(j.podium || []);
      buildOthers(j.others || []);
      console.info('[leaderboard] updated', j);
    } catch (e) {
      console.error('[leaderboard] failed', e);
    }
  }

  /** Live badge + viewer count when available */
  async function fetchStream() {
    if (!liveEl) return;
    try {
      const r = await fetch('/stream', { cache: 'no-store' });
      if (!r.ok) throw new Error(`stream status ${r.status}`);
      const j = await r.json();
      const live = !!j.live;
      const viewers = j.viewers ?? null;

      liveEl.classList.remove('live', 'off', 'unk');
      if (live) {
        liveEl.classList.add('live');
        text.textContent = 'LIVE NOW!';
        if (typeof viewers === 'number') {
          viewerChip.style.display = 'inline-flex';
          viewerChip.textContent = `${fmtInt(viewers)} watching`;
        } else {
          viewerChip.style.display = 'none';
        }
      } else {
        liveEl.classList.add('off');
        text.textContent = 'Offline';
        viewerChip.style.display = 'none';
      }
      console.info('[stream] status', j);
    } catch (e) {
      liveEl.classList.remove('live', 'off');
      liveEl.classList.add('unk');
      text.textContent = 'Status unavailable';
      viewerChip.style.display = 'none';
      console.warn('[stream] failed', e);
    }
  }

  /** Countdown driven by /config (end_time epoch seconds) */
  async function initCountdown() {
    try {
      const r = await fetch('/config', { cache: 'no-store' });
      if (!r.ok) throw new Error(`config status ${r.status}`);
      const j = await r.json();
      const end = Number(j.end_time) || 0;

      function tick() {
        const now = Math.floor(Date.now() / 1000);
        let delta = Math.max(0, end - now);

        const d = Math.floor(delta / 86400); delta -= d * 86400;
        const h = Math.floor(delta / 3600);  delta -= h * 3600;
        const m = Math.floor(delta / 60);    delta -= m * 60;
        const s = delta;

        dd.textContent = String(d).padStart(2, '0');
        hh.textContent = String(h).padStart(2, '0');
        mm.textContent = String(m).padStart(2, '0');
        ss.textContent = String(s).padStart(2, '0');
      }

      tick();
      setInterval(tick, 1000);
    } catch (e) {
      console.warn('[countdown] failed', e);
    }
  }

  /** Boot */
  function boot() {
    if (yearOut) yearOut.textContent = new Date().getFullYear();

    fetchData();
    fetchStream();
    initCountdown();

    // refresh every 60s
    setInterval(fetchData, 60_000);
    setInterval(fetchStream, 60_000);
  }

  document.addEventListener('DOMContentLoaded', boot);
})();









