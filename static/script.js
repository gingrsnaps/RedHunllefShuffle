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
    return Number.isFinite(n) ? n : 0;
  }

  function pad2(n) { return String(n).padStart(2, '0'); }

  // -----------------------------------------
  // Podium (1–3) – with new header layout
  // -----------------------------------------
  function buildPodium(podiumRaw) {
    const norm = (podiumRaw || []).map(e => ({
      rank: (typeof e?.rank === 'number') ? e.rank : null,
      username: e?.username ?? '--',
      wagerStr: e?.wager ?? '$0.00',
      wagerNum: moneyToNumber(e?.wager)
    }));

    // Sort defensively:
    // - If the backend provides explicit ranks, honor them (keeps forced placement stable).
    // - Otherwise fall back to sorting by wager amount (original behavior).
    const hasRank = norm.some(n => n.rank !== null);
    if (hasRank) {
      norm.sort((a, b) => (a.rank ?? 999) - (b.rank ?? 999));
    } else {
      norm.sort((a, b) => b.wagerNum - a.wagerNum);
    }

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
  // Ranks 4–11
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
  // Live status badge + viewers
  // -----------------------------------------
  async function fetchStream() {
    if (!liveEl || !statusText || !viewerChip) return;

    try {
      const r = await fetch('/stream', { cache: 'no-store' });
      if (!r.ok) throw new Error(`stream status ${r.status}`);
      const j = await r.json();
      const live = !!j.live;

      liveEl.classList.remove('unk', 'live', 'off');
      liveEl.classList.add(live ? 'live' : 'off');

      statusText.textContent = live ? 'LIVE on Kick' : 'Offline';
      if (j.viewers != null && live) {
        viewerChip.style.display = '';
        viewerChip.textContent = `${j.viewers.toLocaleString()} watching`;
      } else {
        viewerChip.style.display = 'none';
      }

      console.info('[stream] updated', j);
    } catch (e) {
      liveEl.classList.remove('live', 'off');
      liveEl.classList.add('unk');
      statusText.textContent = 'Checking stream status…';
      viewerChip.style.display = 'none';
      console.error('[stream] failed', e);
    }
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
  // Countdown timer from /config END_TIME
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

        dd.textContent = pad2(d);
        hh.textContent = pad2(h);
        mm.textContent = pad2(m);
        ss.textContent = pad2(s);
      }

      tick();
      setInterval(tick, 1000);
      console.info('[countdown] ready', j);
    } catch (e) {
      console.error('[countdown] failed', e);
    }
  }

  // -----------------------------------------
  // Boot
  // -----------------------------------------
  function init() {
    if (yearOut) yearOut.textContent = String(new Date().getFullYear());

    fetchData();
    fetchStream();
    initCountdown();

    // Always keep this at 60s visually/functionally unless you change backend cadence.
    setInterval(fetchData, 60_000);
    setInterval(fetchStream, 60_000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
