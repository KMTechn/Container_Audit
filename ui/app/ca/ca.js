// 이적(CA) 현장 앱 새 화면 — 주인 w9uiflow1014(APP-SCREENS-1013). 그리기 = render(state) 하나: 처리 층 state() 가 진실이고
// 화면은 수 · 남은 수 · 몫을 셈하지 않는다(work.remaining · list_count · today.total_trays · progress 줄 left · trays_left 를 그대로).
// 부르기 · push · 창 초점 · 관리자 ▾ · 판 · PIN · 스캔 받이 = ../frame.js(AppFrame.start) · ../sheet.js · ../scan.js — 이 파일에 KMShell · 키 사건 · 소리 0.
// 꼴 = contract.json, 상태마다 fixtures/<상태>.json. 설계 = w9uiflow1014 apps-mock/CA-STATE.md, 시안 = apps-mock/ca-work.html.
'use strict';
(() => {
  const { el, $, icon, code, drawResult } = window.AppFrame;
  const SVG = 'http://www.w3.org/2000/svg';
  const num = (n) => n.toLocaleString('ko-KR');

  // 판 — 글은 여기(현장 말), 사실 줄 · 결과 · 목록은 처리 층 state.admin_menu 에서 덮음(render). PIN 판은 admin(이름, {admin_id, pin})
  const PIN = { kind: 'pin', tag: '관리자' };
  const sheets = {
    quarantine_hold: { ...PIN, title: '보류 묶음 따로 두고 다른 작업 계속', go: '따로 두고 계속',
      lead: '현품표 확인 중에 보관한 묶음을 따로 두고 이 PC 에서 다른 현품표 작업을 계속합니다. 스캔한 기록은 지우지 않고 그대로 둡니다.' },
    pair_hold: { ...PIN, title: '보류하고 다음 작업', go: '함께 보류하고 계속',
      lead: '보류한 기록과 현재 트레이 기록이 달라 함께 보류했습니다\n다른 현품표 작업을 계속하세요' },
    preserve_check: { ...PIN, title: '현재 현품표 기록 다시 확인 · 다시 저장', go: '다시 저장',
      lead: '지금 현품표의 작업 기록이 이 PC 에 따로 저장됐는지 다시 확인하고, 안 됐으면 다시 저장합니다. 저장이 확인된 뒤에만 「보류하고 다른 현품표 계속」 을 할 수 있습니다.' },
    defer_unsettled: { ...PIN, title: '확정 안 된 묶음 보류하고 다른 작업 계속', go: '보류하고 계속',
      lead: '지금 묶음이 회사 서버에서 확정됐는지 아직 모릅니다. 보낸 요청과 스캔한 기록을 보류 목록에 그대로 두고 다른 현품표 작업을 계속합니다.' },
    resend_completion: { kind: 'confirm', tag: '관리자', title: '끝낸 트레이 회사 서버에 다시 보내기', go: '다시 보내기', command: 'resend_completion',
      lead: '관리자로 로그인한 상태에서만 됩니다. 끝낸 트레이를 회사 서버에 다시 보냅니다. 회사 서버가 받았는지 확인되지 않으면 관리자 확인 대기로 남습니다.' },
    recheck_review: { ...PIN, title: '관리자 확인 다시 조회', go: '다시 조회', lead: '회사 서버에 보낸 관리자 확인 요청이 승인됐는지 다시 묻습니다. 승인된 것은 그대로 이어서 처리합니다.' },
    check_unsettled: { kind: 'result', tag: '관리자', title: '보낸 요청 결과 다시 확인' },
    view_handoff: { kind: 'info', tag: '관리자', title: '관리자 인계 내용 보기', lead: '확정 안 된 작업 넘겨받기 — 스캔한 기록을 지우지 말고 이 내용대로 확인하세요.' },
    list_paired: { ...PIN, title: '함께 보류한 기록 목록', go: '목록 보기', lead: '두 기록을 함께 보류한 묶음과 따로 둔 기록을 봅니다. 목록 안에서 하는 일은 이 관리자 확인으로 합니다.' },
    view_sync: { kind: 'info', tag: '관리자', title: '전송 상태 상세' },
    // 리셋은 되돌릴 수 없다 — 마우스로만(처음 초점 = 그만두기), 처리 층은 id=confirmed 가 아니면 거절
    reset: { kind: 'confirm', tag: '확인', title: '현재 작업 취소', go: '현재 작업 취소', command: 'reset:confirmed',
      note: '현재 작업 취소는 마우스로만 할 수 있습니다\n빈 Enter나 스캔은 취소 확인 창을 닫습니다' },
    register: { kind: 'form', tag: '새 이름', title: '새 이름 등록', lead: '이름만 넣으면 명단에 바로 올라갑니다', go: '등록하고 시작',
      command: 'register_worker', fields: [{ name: 'name', label: '이름', placeholder: '이름' }] },
  };

  const menuSheets = Object.fromEntries(Object.entries(sheets).map(([name, sheet]) => [name, { ...sheet }]));

  // 남은 수 줄 — 어느 글인지는 처리 층 left_kind, 수는 처리 층 remaining
  const LEFT = {
    none: () => ['현품표를 스캔하면 나옵니다'],
    target_pending: () => ['목표 수 확인 중'],
    remaining: (n) => ['남은 ', el('b', '', `${n}개`)],
    remaining_total: (n) => ['전체 남은 ', el('b', '', `${n}개`)],
    short: (n) => ['부족 ', el('b', '', `${n}개`), '로 마감'],
    full: () => ['완료했습니다'],
    quota: (n) => ['끊김 — 혼자 더 넣을 수 ', el('b', '', `${n}개`)],
    closed_short: (n) => ['부분 제출 · 수량 부족 ', el('b', '', `${n}개`)],
  };
  const F8_STEPS = ['바꿀 현품표 스캔', '회사 서버 지시 확인', 'F8 — 새 현품표 인쇄', '새 현품표 붙이기'];

  function button(cls, text, go) {
    const node = el('button', cls, text);
    node.type = 'button';
    node.dataset.go = go;
    return node;
  }

  function renderTop(s) {
    const starting = s.view === 'start';
    const tag = $('[data-tag]');
    tag.replaceChildren();
    if (!starting) {
      if (s.work.tag) tag.append('현품표 ', el('b', '', s.work.tag));
      else tag.textContent = '현품표를 스캔하면 여기 나옵니다';
    }
    $('[data-legacy]').hidden = !s.legacy;
    $('[data-held]').textContent = `보류 ${s.held_count}건 · 오늘 현황`;
    for (const link of document.querySelectorAll('[data-nav] [data-go]')) link.hidden = starting;
    $('[data-change]').hidden = starting;
  }

  function renderAdmin(s) {
    for (const entry of document.querySelectorAll('[data-admin] [data-open]')) {
      const name = entry.dataset.open;
      const sheet = sheets[name];
      if (!sheet) continue;
      const item = (s.admin_menu || []).find((row) => row.name === name);
      const original = menuSheets[name];
      const worker = item && item.pin === false;
      sheet.kind = worker && original.kind === 'pin' ? 'confirm' : original.kind;
      sheet.tag = worker ? '작업' : original.tag;
      sheet.lead = worker && name === 'resend_completion' ? original.lead.replace('관리자로 로그인한 상태에서만 됩니다. ', '') : original.lead;
      sheet.command = item?.command || (worker && original.kind === 'pin' ? name : original.command);
      for (const key of ['facts', 'result', 'rows', 'actions']) sheet[key] = item && item[key];
      entry.disabled = !(item && item.enabled);
      if (sheet.kind === 'info' || sheet.kind === 'result') {
        sheet.load = item && item.load;
        sheet.command = item && item.command;
        entry.hidden = !(sheet.load || sheet.command) || !(sheet.facts && sheet.facts.length);
      }
    }
    const flags = (s.admin_menu || []).filter(i => typeof i.pin === 'boolean');
    AppFrame.menu($('[data-admin]'), flags.length ? Object.fromEntries(flags.map(i => [i.name, i.pin])) : null);
  }

  // A normal space may wrap before the separator; each following phrase stays whole.
  function itemDetails(parts, wholeFirst = false) {
    return parts.flatMap((text, i) => i
      ? [' ', el('span', 'ca-count__detail', `· ${text}`)]
      : [wholeFirst ? el('span', 'ca-count__detail', text) : text]);
  }

  function renderWork(s) {
    const w = s.work;
    const swapping = w.mode === 'swap1' || w.mode === 'swap2';
    $('[data-pane="work"] .next').classList.toggle('ca-next--done', w.mode === 'done');
    const label = $('[data-next-label]');
    label.classList.toggle('ca-next__label--swap', swapping);
    label.replaceChildren(...(swapping ? [icon('swap', 18), `제품 교환 중 · ${w.mode === 'swap1' ? 1 : 2} / 2`] : ['다음에 할 일']));
    $('[data-next]').textContent = w.next;
    $('[data-next-sub]').replaceChildren(...w.next_sub.map((p) => (p.on ? el('b', '', p.text) : p.off ? el('span', 'off', p.text) : p.text)));

    const card = $('[data-count-card]');
    card.classList.toggle('ca-count--done', w.mode === 'done');
    card.classList.toggle('ca-count--short', w.mode === 'short');
    card.classList.toggle('ca-count--none', !w.item);
    card.classList.toggle('ca-count--stale', !!(w.cofill && w.cofill.total_age_s > 5));
    const details = el('span', 'ca-count__meta');
    if (w.item) details.append(...itemDetails(['', w.item.spec, w.item.code]));
    $('[data-item]').replaceChildren(...(w.item ? [w.item.name, details] : ['품목 —']));
    renderCofill(w.cofill);
    $('[data-count]').replaceChildren(String(w.count), el('span', '', w.target ? `/ ${w.target}` : w.item ? '/ …' : '/ —'));
    $('[data-bar] i').style.width = w.target ? `${Math.min(100, (100 * w.count) / w.target)}%` : '0%'; // 막대 길이만(글 수는 처리 층 값)
    $('[data-left]').replaceChildren(...(LEFT[w.left_kind] || LEFT.none)(w.remaining));

    AppFrame.exchange($('[data-next]').parentElement, w.exchange && 'remove' in w.exchange && 'insert' in w.exchange ? { phase: w.exchange.phase, remove: w.exchange.remove.code, insert: w.exchange.insert.code, error: w.result.kind === 'bad' } : null);
    const result = $('[data-result]');
    result.classList.remove('ca-result--needs-room');
    drawResult(result, w.result, true);

    $('[data-list-title]').textContent = w.checking ? `보관한 제품 · ${w.list_count}개` : w.cofill ? `이 PC 가 넣은 · ${w.list_count}건` : `지금 트레이 · ${w.list_count}건`;
    $('[data-list]').replaceChildren(...(w.list.length ? w.list.map((row) => {
      const li = el('li', `ca-row ca-row--${row.st}`);
      li.append(el('span', 'ca-row__no', row.no), code(row.code, 'ca-row__code'), el('span', 'ca-row__tag', row.tag || ''), el('span', 'ca-row__at', row.at));
      return li;
    }) : [el('li', 'ca-list__empty', w.item ? '아직 스캔한 제품이 없습니다' : '현품표를 스캔하고 제품을 스캔하면 여기 쌓입니다')]));
    fitList();

    for (const node of document.querySelectorAll('[data-allow]')) {
      const key = node.dataset.allow;
      node.disabled = !s.allow[key];
      if (key === 'exchange') node.setAttribute('aria-pressed', String(swapping));
      if (key === 'undo') node.textContent = swapping ? '교환 취소' : '마지막 스캔 취소';
    }
    sheets.reset.lead = [`이 트레이에 스캔한 ${w.count}개를 지우고 현품표부터 다시 합니다. `, '되돌릴 수 없습니다.'];
  }

  // 같이 채우기 한 줄 — 「몇 대가 같이 · 내가 넣은 수」(3초: 몇 대가 채우고 전체 몇 개 남았나 = 이 줄 + 큰 수 + 「전체 남은」)
  function renderCofill(c) {
    const line = $('[data-cofill]');
    line.hidden = !c;
    if (!c) return;
    const slots = el('span', 'ca-cofill__pcs');
    for (let i = 0; i < c.max_participants; i += 1) slots.append(el('i', i < c.participants ? 'is-in' : ''));
    const text = c.mode === 'closed' ? '같이 채움 · 마감' : c.total_age_s > 5 ? '같이 채우는 중\n합계 확인 중' : '같이 채우는 중';
    line.replaceChildren(slots, `${text} · `, el('b', '', `${c.participants}대`), ' · 내가 넣은 ', el('b', '', `${c.mine_good}개`));
  }

  // 목록이 칸을 넘치면 넘친 줄을 숨기고 「그 앞 N건」(작업자는 굴리지 않는다 — 최신 몇 줄이면 됨)
  function fitList() {
    const list = $('[data-list]');
    const rows = [...list.querySelectorAll('.ca-row')];
    for (const li of rows) li.hidden = false;
    const more = $('[data-list-more]');
    if (innerWidth > 600 && innerWidth < 1366 && innerHeight >= 800) {
      // Measure the full list first; the old notice also occupied its grid gap.
      more.textContent = '';
      if (rows.some(li => li.getBoundingClientRect().bottom > list.getBoundingClientRect().bottom + .5)) more.textContent = '그 앞 1건';
    }
    const bottom = list.getBoundingClientRect().bottom + 0.5;
    let cut = 0;
    for (const li of rows) {
      if (li.getBoundingClientRect().bottom > bottom) {
        li.hidden = true;
        cut += 1;
      }
    }
    $('[data-list-more]').textContent = cut ? `그 앞 ${cut}건` : '';
  }

  function renderProgress(p) {
    const off = p.conn !== 'ok';
    const sub = $('[data-progress-sub]');
    sub.classList.toggle('ca-pane__sub--off', off);
    sub.textContent = off
      ? `회사 서버에 연결하지 못했습니다\n연결을 확인하고 다시 시도하세요\n자세히: ${p.date} · 마지막 받음 ${p.at}\n그 뒤 바뀐 내용은 아직 보이지 않습니다`
      : `${p.date} · 회사 서버 연결됨 · 마지막 받음 ${p.at}`;
    $('[data-progress-table]').classList.toggle('is-stale', off);
    $('[data-progress-rows]').replaceChildren(...p.rows.map((r) => {
      const tr = el('tr', r.now ? 'is-now' : r.left === 0 ? 'is-done' : '');
      const name = el('td', '', r.item);
      if (r.now) name.append(el('span', 'ca-table__tag', '지금 트레이'));
      tr.append(name, el('td', 'r', num(r.plan)), el('td', 'r', num(r.ready)), el('td', 'r', num(r.left)), el('td', 'r', r.left ? String(r.trays_left) : '끝'));
      return tr;
    }));
  }

  function renderHeld(s) {
    $('[data-park-title]').textContent = `보류 작업 · ${s.held_count}건`;
    $('[data-park]').replaceChildren(...s.park.map((p) => {
      const li = el('li');
      if (p.restorable === false) {
        li.append(el('span', 'ca-park__item', p.label));
        if (p.note) li.append(el('span', 'ca-park__meta', p.note));
        li.append(el('span', 'ca-park__meta', '관리자: 옛 화면에서 복원'));
        return li;
      }
      const name = el('span', 'ca-park__item');
      name.append(...itemDetails(p.item.split(' · ')));
      const meta = el('span', 'ca-park__meta');
      meta.append(...itemDetails([p.tag && `현품표 ${p.tag}`, p.target ? `${p.count} / ${p.target}` : `스캔한 제품 ${p.count}개`, p.at && `보류 ${p.at}`].filter(Boolean), true));
      li.append(name, button('act', '이어 하기', `command:restore:${p.id}`), meta);
      return li;
    }));
    if (s.overflow) {
      $('[data-park]').append(el('li', 'ca-park__meta', `보류 ${s.held_count}건 중 ${s.park.length}건만 보입니다.\n나머지는 옛 화면에서 보세요.`));
    }
    const today = s.today;
    $('[data-today-title]').textContent = `오늘 작업 현황 · 완료 ${today.total_trays} 트레이`;
    $('[data-today-rows]').replaceChildren(...today.rows.map((r) => {
      const tr = el('tr');
      tr.append(el('td', '', r.item), el('td', 'r', String(r.trays)), el('td', 'r', r.products == null ? '—' : num(r.products)));
      return tr;
    }));
    const table = $('[data-today-rows]').closest('table');
    table.closest('.ca-card').classList.add('ca-today');
    let cards = table.parentElement.parentElement.querySelector('.today-items');
    if (!cards) {
      cards = el('div'); const details = el('details', 'today-timeline');
      table.before(cards, details); details.append(el('summary', '', '목록 보기'), table);
    }
    AppFrame.today(cards, today.rows);
    for (const name of cards.querySelectorAll('h3')) name.replaceChildren(...itemDetails(name.textContent.split(' · ')));
    const supply = $('[data-today-supply]');
    supply.hidden = !today.supply;
    supply.textContent = `출고 전 관리자 보충 필요 ${today.supply}건`;
    drawTray($('[data-tray]'), 8, 5, s.work.count);
    $('[data-tray-cap]').textContent = s.work.item ? `${s.work.item.name} ${s.work.item.spec}` : '트레이 그림 — 품목별 사진 자리';
  }
  function drawTray(svg, cols, rows, filled) {
    const shape = (attrs) => {
      const rect = document.createElementNS(SVG, 'rect');
      for (const [k, v] of Object.entries(attrs)) rect.setAttribute(k, v);
      return rect;
    };
    const shapes = [shape({ x: 2, y: 2, width: 204, height: 120, rx: 8, class: 'frame' })];
    for (let i = 0; i < cols * rows; i += 1) {
      const r = Math.floor(i / cols);
      const c = i % cols;
      shapes.push(shape({ x: 10 + c * 24.5, y: 10 + r * 21.5, width: 20, height: 17, rx: 3, class: i < filled ? 'slot slot--in' : 'slot' }));
    }
    svg.replaceChildren(...shapes);
  }

  function renderF8(f) {
    $('[data-f8-steps]').replaceChildren(...F8_STEPS.map((text, i) => {
      const st = i < f.step ? 'is-done' : i === f.step ? (f.stop ? 'is-stop' : 'is-now') : '';
      return el('li', st, `${'①②③④'[i]} ${text}`);
    }));
    $('[data-f8-next]').textContent = f.next;
    $('[data-f8-sub]').textContent = f.sub;
    const card = $('[data-f8-card]');
    card.classList.toggle('ca-f8__card--print', f.card === 'print');
    if (f.card === 'how' || !f.target) {
      card.replaceChildren(el('h2', 'ca-card__title', '언제 쓰나'),
        el('p', 'ca-f8__para', '회사 서버가 수량을 바꾸라고 지시한 현품표만 바꿉니다. 불량 제품을 바꾸는 일은 작업 화면의 「제품 교환」 입니다.'),
        el('p', 'ca-card__note', '제출이 60초 안에 끝나지 않아도 작업 화면과 다음 스캔은 계속 사용할 수 있습니다'));
      return;
    }
    const facts = el('dl', 'ca-f8__facts');
    const qty = el('dd');
    qty.append(`${f.plan.from_qty}개 → `, el('b', '', `${f.plan.to_qty}개`), ` · 새 현품표 ${f.plan.labels}장`);
    facts.append(el('dt', '', '대상 현품표'), el('dd', '', `${f.target.tag} · ${f.target.item}`), el('dt', '', '회사 서버 지시'), qty, el('dt', '', '지시 받음'), el('dd', '', f.plan.received_at));
    if (f.card === 'plan') {
      card.replaceChildren(el('h2', 'ca-card__title', '회사 서버 지시'), facts);
      return;
    }
    card.replaceChildren(el('h2', 'ca-card__title ca-f8__warn', `인쇄 대기 — ${f.print_error || '프린터를 확인하세요'}`), facts,
      el('p', 'ca-f8__para', '프린터를 고친 뒤, 먼저 나온 실물이 없는지 확인하고 다시 인쇄합니다.'),
      button('act', '실물이 없음을 확인 — 다시 인쇄', 'command:f8_reprint'));
  }

  function renderStart(s) {
    const r = s.roster;
    let header = $('[data-pane="start"] .app-start');
    if (!header) { header = el('div'); $('.ca-start__title').replaceWith(header); }
    AppFrame.startup(header, { name: '이적', status: '작업자를 선택하세요', busy: !r.count });
    $('[data-roster-sub]').textContent = r.note || (r.at ? `명단 ${r.count}명 · 회사 서버에서 ${r.at} 받음 · 60초마다 새로 받음` : `명단 ${r.count}명`);
    AppFrame.workers($('[data-names]'), r.names.map(n => ({ id: n.id, label: n.label, recent: n.last, note: n.last ? '지난번' : '', go: `command:start_work:${n.id}` })));
    const error = $('[data-start-error]');
    error.hidden = !s.start_error;
    error.textContent = s.start_error || '';
    $('[data-register]').hidden = !(s.register && s.register.cands.length);
    $('[data-register-cands]').replaceChildren(...(s.register ? s.register.cands : []).map((c) => button('act act--quiet', `${c.label} — 같은 사람이면 이것`, `command:start_work:${c.id}`)));
  }

  // CA owns these text flows. Clock/code-time updates never invalidate them.
  let separatorFrame = 0, separatorDirty = true;
  let separatorFlows = [];
  const sameSeparatorLine = (a, b) => Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top) > Math.min(a.height, b.height) / 2;
  function separatorEntries(root) {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT), nodes = []; let text = '';
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (!node.parentElement.checkVisibility({checkVisibilityCSS: true}) || node.parentElement.closest('svg')) continue;
      nodes.push({node, start: text.length}); text += node.data;
    }
    const rangeAt = index => {
      const item = nodes.find(item => index >= item.start && index < item.start + item.node.length);
      if (!item) return null;
      const range = document.createRange(); range.setStart(item.node, index - item.start); range.setEnd(item.node, index - item.start + 1); return range;
    };
    const entries = [];
    for (const item of nodes) {
      const dot = item.node.parentElement;
      if (dot.closest('.result__code-group, .result__time')) continue;
      for (const match of item.node.data.matchAll(/·/g)) {
      const index = item.start + match.index; let before = index - 1, after = index + 1;
      while (before >= 0 && /[\s·]/.test(text[before])) before--;
      while (after < text.length && /[\s·]/.test(text[after])) after++;
      entries.push({dot, at:rangeAt(index), before:before >= 0 ? rangeAt(before) : null, after:after < text.length ? rangeAt(after) : null});
      }
    }
    return entries;
  }
  function joinShortCodes() {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT), nodes = [];
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (/(?:…|\.{3})\d+/.test(node.data) && node.parentElement.checkVisibility() && !node.parentElement.closest('.ca-code-join, .app-code, .result__code-group, .result__time, svg, script, style')) nodes.push(node);
    }
    for (const node of nodes) {
      const fragment = document.createDocumentFragment(); let last = 0;
      for (const match of node.data.matchAll(/(?:…|\.{3})\d+/g)) {
        fragment.append(document.createTextNode(node.data.slice(last, match.index)), el('span', 'ca-code-join', match[0])); last = match.index + match[0].length;
      }
      fragment.append(document.createTextNode(node.data.slice(last))); node.replaceWith(fragment);
    }
  }
  let separatorPass = 0;
  function prepareSeparators() {
    if (document.fonts.status !== 'loaded') { separatorFrame = 0; return; }
    if (separatorDirty) joinShortCodes();
    const result = document.querySelector('.work > .result');
    const fitKey = `${innerWidth}/${innerHeight}/${document.documentElement.dataset.textLevel}`;
    if (result?.classList.contains('ca-result--needs-room') && result.caFitKey !== fitKey) {
      result.classList.remove('ca-result--needs-room'); result.caFitKey = fitKey;
      separatorFrame = requestAnimationFrame(prepareSeparators); return;
    }
    if (result && document.fonts.status === 'loaded' && innerWidth > 600 && innerWidth <= 1366 && !result.classList.contains('ca-result--needs-room')) {
      result.caFitKey = fitKey;
      const box = result.getBoundingClientRect(), walker = document.createTreeWalker(result, NodeFilter.SHOW_TEXT); let overflow = false;
      while (walker.nextNode()) {
        const node = walker.currentNode;
        if (!node.data.trim() || !node.parentElement.checkVisibility() || node.parentElement.closest('svg')) continue;
        const range = document.createRange(); range.selectNodeContents(node);
        if ([...range.getClientRects()].some(rect => rect.width && rect.height && rect.bottom > box.bottom + .5)) overflow = true;
      }
      if (overflow) result.classList.add('ca-result--needs-room');
    }
    if (separatorDirty) {
      separatorDirty = false;
      const roots = [...document.querySelectorAll('.top__tag, .band, .next__sub, .ca-count__item, .ca-cofill, .ca-count__left, [data-list-title], .work > .result small, .ca-pane__sub, .ca-pane__foot, .ca-park__item, .ca-park__meta, .ca-today h3, .ca-today__supply, .today-timeline > summary, .ca-f8__facts dd, .ca-start__sub, .sheet__lead, .sheet__facts dd, .status__server')];
      const scan = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
      while (scan.nextNode()) {
        const node = scan.currentNode;
        if (!node.data.includes('·') || node.parentElement.closest('svg, script, style, .app-code, .result__code-group, .result__time') || !node.parentElement.checkVisibility()) continue;
        if (roots.some(root => root.contains(node))) continue;
        let root = node.parentElement;
        while (root.parentElement && !root.matches('button, a') && /^(inline|contents)/.test(getComputedStyle(root).display)) root = root.parentElement;
        while (root.parentElement && !root.parentElement.matches('.result') && /^(inline-)?flex$/.test(getComputedStyle(root.parentElement).display) && getComputedStyle(root.parentElement).flexDirection === 'row') root = root.parentElement;
        if (!roots.includes(root)) roots.push(root);
      }
      const visible = [...roots].filter(root => root.checkVisibility() && root.textContent.includes('·')).filter(root => root.classList.contains('ca-separator-flow') || separatorEntries(root).some(entry => { const box = entry.at.getBoundingClientRect(); return entry.before && !sameSeparatorLine(entry.before.getBoundingClientRect(), box) || entry.after && !sameSeparatorLine(box, entry.after.getBoundingClientRect()); })), nodes = [];
      for (const root of visible) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        while (walker.nextNode()) {
          const node = walker.currentNode;
          if (node.data.includes('·') && node.parentElement.checkVisibility() && !node.parentElement.closest('.ca-separator, .result__code-group, .result__time, svg')) nodes.push(node);
        }
      }
      // Finish every visibility read before changing the DOM.
      for (const node of nodes) {
        const fragment = document.createDocumentFragment(); let last = 0;
        for (const match of node.data.matchAll(/[ \t]*·[ \t]*/g)) {
          fragment.append(document.createTextNode(node.data.slice(last, match.index)), el('span', 'ca-separator', match[0])); last = match.index + match[0].length;
        }
        fragment.append(document.createTextNode(node.data.slice(last))); node.replaceWith(fragment);
      }
      separatorFlows = visible.filter(root => root.querySelector('.ca-separator'));
    }
    for (const root of separatorFlows) for (const dot of root.querySelectorAll('.ca-separator--wrapped')) dot.classList.remove('ca-separator--wrapped');
    separatorPass = 0;
    separatorFrame = requestAnimationFrame(measureSeparators);
  }
  function measureSeparators() {
    if (separatorDirty) { prepareSeparators(); return; }
    const hidden = [], regroup = [];
    for (const root of separatorFlows) {
      if (!root.isConnected || !root.checkVisibility()) continue;
      for (const entry of separatorEntries(root)) {
        if (!entry.dot.matches('.ca-separator')) continue;
        const box = entry.at.getBoundingClientRect();
        if (entry.before && !sameSeparatorLine(entry.before.getBoundingClientRect(), box) || entry.after && !sameSeparatorLine(box, entry.after.getBoundingClientRect())) {
          hidden.push(entry.dot);
          if (!root.matches('.ca-count__item, .ca-park__item') && !root.classList.contains('ca-separator-flow') && !regroup.includes(root)) regroup.push(root);
        }
      }
    }
    // Geometry is read as a batch; changed geometry is checked on the next frame.
    for (const root of regroup) {
      const dots = [...root.querySelectorAll('.ca-separator')], ranges = []; let previous = document.createRange(); previous.selectNodeContents(root);
      for (const dot of dots) {
        const next = document.createRange(); next.setStartBefore(dot); next.setEnd(root, root.childNodes.length);
        previous.setEndBefore(dot); ranges.push(previous); previous = next;
      }
      ranges.push(previous);
      const phrases = ranges.reverse().map(range => { const phrase = el('span', 'ca-separator-phrase'); phrase.append(range.extractContents()); return phrase; }).reverse();
      root.replaceChildren(...phrases); root.classList.add('ca-separator-flow');
    }
    for (const dot of hidden) dot.classList.add('ca-separator--wrapped');
    separatorFrame = hidden.length && ++separatorPass < 4 ? requestAnimationFrame(measureSeparators) : 0;
  }
  function queueSeparators() {
    if (separatorFrame) {
      if (!separatorDirty) return;
      cancelAnimationFrame(separatorFrame);
    }
    // Shared code fitting writes on the next frame; measure after its native layout.
    separatorFrame = requestAnimationFrame(() => { separatorFrame = requestAnimationFrame(() => { separatorFrame = requestAnimationFrame(prepareSeparators); }); });
  }

  function render(s) {
    separatorDirty = true;
    renderTop(s);
    renderAdmin(s);
    const view = s.view || 'work';
    for (const pane of document.querySelectorAll('[data-pane]')) pane.hidden = pane.dataset.pane !== view;
    if (view === 'work') renderWork(s);
    else if (view === 'progress' && s.progress) renderProgress(s.progress);
    else if (view === 'held' && s.park && s.today) renderHeld(s);
    else if (view === 'f8' && s.f8) renderF8(s.f8);
    else if (view === 'start' && s.roster) renderStart(s);
    for (const flow of document.querySelectorAll('.ca-separator-flow')) {
      if (![...flow.children].some(child => child.matches('.ca-separator-phrase'))) flow.classList.remove('ca-separator-flow');
    }
    queueSeparators();
  }

  window.addEventListener('resize', fitList);
  window.addEventListener('resize', () => { separatorDirty = true; queueSeparators(); });
  new ResizeObserver(queueSeparators).observe(document.body);
  new MutationObserver(() => { separatorDirty = true; queueSeparators(); }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-text-level', 'data-text-expanded', 'style'] });
  document.fonts.ready.then(() => { separatorDirty = true; queueSeparators(); });
  document.fonts.addEventListener('loadingdone', () => { separatorDirty = true; queueSeparators(); });
  new ResizeObserver(fitList).observe($('[data-list]'));
  // F8 = 현품표 교체(처리 층이 지금 단계에 맞게 열기 · 인쇄) · Esc · 빈 Enter = 확인(현장 「빈 Enter = 확인」 — 처리 층 ack 가 지금 빈 Enter 문,
  // 한 단계 안 화면이면 작업 화면으로). 글이 있는 Enter 는 늘 스캔(틀 1db33db4)
  AppFrame.start({ render, sheets, keys: { F8: 'command:f8', Escape: 'command:ack', Enter: 'command:ack' } });
})();
