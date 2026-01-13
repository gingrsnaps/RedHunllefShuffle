(() => {
  // Shorthand query helper
  const $ = (sel, root = document) => root.querySelector(sel);

  const podiumEl   = $('#podium');
  const othersEl   = $('#others-list');
  const liveEl     = $('#liveStatus');
  const viewerChip = liveEl?.querySelector('.viewer-chip');
  const statusText = liveEl?.querySelector('.text');

  const dd = $('#dd'), hh = $('#hh'), mm = $('#mm'), ss = $('#ss');
  const yearOut = $('#year');

  // ------------------------------
  // Prize table – easy to tweak.
  // ------------------------------
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
    10: '$10.00',
    11: '$0.00'
  };

  function moneyToNumber(s) {
    if (typeof s === 'number') return s;
    if (!s) return 0;
    const n = parseFloat(String(s).replace(/[^0-9.]/g, ''));
    return Number.isNaN(n) ? 0 : n;
  }

  function fmtInt(n) {
    return (n ?? 0).toLocaleString();
  }

  // -----------------------------------------
  // Podium (1–3) – with new header layout
  // -----------------------------------------
  function buildPodium(podiumRaw) {
    const norm = (podiumRaw || []).map(e => ({
      username: e?.username ?? '--',
      wagerStr: e?.wager ?? '$0.00',
      wagerNum: moneyToNumber(e?.wager)
    }));

    // Sort defensively by wager amount
    norm.sort((a, b) => b.wagerNum - a.wagerNum);

    const first  = norm[0] || { username: '--', wagerStr: '$0.00' };
    const second = norm[1] || { username: '--', wagerStr: '$0.00' };
    const third  = norm[2] || { username: '--', wagerStr: '$0.00' };

    // Render as Olympic layout: 2 | 1 | 3
    const seats = [
      { place: 2, cls: 'col-second', medal: '🥈', entry: second },
      { place: 1, cls: 'col-first',  medal: '🥇', entry: first  },
      { place: 3, cls: 'col-third',  medal: '🥉', entry: third  }
    ];

    if (!podiumEl) return;
    podiumEl.innerHTML = '';

    seats.forEach(s => {
      const el = document.createElement('article');
      el.className = `podium-seat ${s.cls} fade-in`;

      // NOTE: new .podium-head row avoids overlap between the
      // numeric rank chip and the medal icon.
      el.innerHTML = `
        <div class="podium-head">
          <span class="rank-badge">#${s.place}</span>
          <span class="crown" aria-hidden="true">${s.medal}</span>
        </div>
        <div class="user">${s.entry.username}</div>
        <div class="label">TOTAL WAGER</div>
        <div class="wager">${s.entry.wagerStr}</div>
        <div class="label">PRIZE</div>
        <div class="prize">${PRIZES[s.place] || '$0.00'}</div>
      `;
      podiumEl.appendChild(el);
    });
  }

  // -----------------------------------------
  // Placements 4–11 grid
  // -----------------------------------------
  function buildOthers(othersRaw) {
    if (!othersEl) return;

    let others = (othersRaw || []).map(e => ({
      rank: (typeof e?.rank === 'number') ? e.rank : null,
      username: e?.username ?? '--',
      wagerStr: e?.wager ?? '$0.00',
      wagerNum: moneyToNumber(e?.wager)
    }));

    if (others.length === 0) {
      othersEl.innerHTML = '';
      return;
    }

    const hasRank = others.some(o => o.rank !== null);

    if (hasRank) {
      others.sort((a, b) => (a.rank ?? 999) - (b.rank ?? 999));
    } else {
      others.sort((a, b) => b.wagerNum - a.wagerNum);
      others = others.map((o, idx) => ({ ...o, rank: 4 + idx }));
    }

    // 8 cards for ranks 4–11 so desktop grid is 4x2.
    const desiredCards = 8;
    if (others.length < desiredCards) {
      const startRank = 4 + others.length;
      const pad = Array.from({ length: desiredCards - others.length }, (_, i) => ({
        rank: startRank + i,
        username: '--',
        wagerStr: '$0.00',
        wagerNum: 0
      }));
      others = others.concat(pad);
    } else if (others.length > desiredCards) {
      others = others.slice(0, desiredCards);
    }

    othersEl.innerHTML = others.map(o => `
      <li class="fade-in">
        <span class="position">#${o.rank}</span>
        <div class="username">${o.username}</div>
        <div class="label emphasized">TOTAL WAGER</div>
        <div class="wager">${o.wagerStr}</div>
        <div class="label">PRIZE</div>
        <div class="prize">${PRIZES[o.rank] || '$0.00'}</div>
      </li>
    `).join('');
  }

  // -----------------------------------------
  // Fetch leaderboard data and render
  // -----------------------------------------
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

  // -----------------------------------------
  // Live status badge + viewers
  // -----------------------------------------
  async function fetchStream() {
    if (!liveEl || !statusText || !viewerChip) return;

    try {
      const r = await fetch('/stream', { cache: 'no-store' });
      if (!r.ok) throw new Error(`stream status ${r.status}`);
      const j = await r.json();
      const live = !!j.live;
      const viewers = j.viewers ?? null;

      liveEl.classList.remove('live', 'off', 'unk');

      if (live) {
        liveEl.classList.add('live');
        statusText.textContent = 'Live on Kick';
        if (typeof viewers === 'number') {
          viewerChip.style.display = 'inline-flex';
          viewerChip.textContent = `${fmtInt(viewers)} watching`;
        } else {
          viewerChip.style.display = 'none';
        }
      } else {
        liveEl.classList.add('off');
        statusText.textContent = 'Currently offline';
        viewerChip.style.display = 'none';
      }

      console.info('[stream] status', j);
    } catch (e) {
      console.warn('[stream] failed', e);
      liveEl.classList.remove('live', 'off');
      liveEl.classList.add('unk');
      statusText.textContent = 'Status unavailable';
      viewerChip.style.display = 'none';
    }
  }

  // -----------------------------------------
  // Countdown timer (based on END_TIME)
  // -----------------------------------------
  async function initCountdown() {
    if (!dd || !hh || !mm || !ss) return;

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

  // -----------------------------------------
  // Boot
  // -----------------------------------------
  function boot() {
    if (yearOut) yearOut.textContent = new Date().getFullYear();
    fetchData();
    fetchStream();
    initCountdown();

    // Keep everything feeling live
    setInterval(fetchData, 60_000);
    setInterval(fetchStream, 60_000);
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
