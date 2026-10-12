// 이적(CA) 현장 앱 새 화면 — 주인 w9uiflow1014(APP-SCREENS-1013). 그리기 = render(state) 하나: 처리 층 state() 가 진실이고
// 화면은 수 · 남은 수 · 몫을 셈하지 않는다(work.remaining · list_count · today.total_trays · progress 줄 left · trays_left 를 그대로).
// 부르기 · push · 창 초점 · 관리자 ▾ · 판 · PIN · 스캔 받이 = ../frame.js(AppFrame.start) · ../sheet.js · ../scan.js — 이 파일에 KMShell · 키 사건 · 소리 0.
// 꼴 = contract.json, 상태마다 fixtures/<상태>.json. 설계 = w9uiflow1014 apps-mock/CA-STATE.md, 시안 = apps-mock/ca-work.html.
'use strict';
(() => {
  const { el, $, icon, drawResult } = window.AppFrame;
  const SVG = 'http://www.w3.org/2000/svg';
  const num = (n) => n.toLocaleString('ko-KR');

  // 판 — 글은 여기(현장 말), 사실 줄 · 결과 · 목록은 처리 층 state.admin_menu 에서 덮음(render). PIN 판은 admin(이름, {admin_id, pin})
  const PIN = { kind: 'pin', tag: '관리자' };
  const sheets = {
    quarantine_hold: { ...PIN, title: '보류 묶음 따로 두고 다른 작업 계속', go: '따로 두고 계속',
      lead: '현품표 확인 중에 보관한 묶음을 따로 두고 이 PC 에서 다른 현품표 작업을 계속합니다. 찍은 기록은 지우지 않고 그대로 둡니다.' },
    pair_hold: { ...PIN, title: '두 기록 함께 보류하고 계속', go: '함께 보류하고 계속',
      lead: '보류해 둔 기록과 지금 트레이 기록이 서로 다릅니다. 두 기록을 함께 보류하고 다른 현품표 작업을 계속합니다. 두 현품표는 관리자 확인 전까지 잠깁니다.' },
    preserve_check: { ...PIN, title: '현재 현품표 기록 다시 확인 · 다시 저장', go: '다시 저장',
      lead: '지금 현품표의 작업 기록이 이 PC 에 따로 저장됐는지 다시 확인하고, 안 됐으면 다시 저장합니다. 저장이 확인된 뒤에만 「보류하고 다른 현품표 계속」 을 할 수 있습니다.' },
    defer_unsettled: { ...PIN, title: '확정 안 된 묶음 보류하고 다른 작업 계속', go: '보류하고 계속',
      lead: '지금 묶음이 회사 서버에서 확정됐는지 아직 모릅니다. 보낸 요청과 찍은 기록을 보류 목록에 그대로 두고 다른 현품표 작업을 계속합니다.' },
    resend_completion: { kind: 'confirm', tag: '관리자', title: '끝낸 트레이 회사 서버에 다시 보내기', go: '다시 보내기', command: 'resend_completion',
      lead: '관리자로 로그인한 상태에서만 됩니다. 끝낸 트레이를 회사 서버에 다시 보냅니다. 회사 서버가 받았는지 확인되지 않으면 관리자 확인 대기로 남습니다.' },
    recheck_review: { ...PIN, title: '관리자 확인 다시 조회', go: '다시 조회', lead: '회사 서버에 보낸 관리자 확인 요청이 승인됐는지 다시 묻습니다. 승인된 것은 그대로 이어서 처리합니다.' },
    check_unsettled: { kind: 'result', tag: '관리자', title: '보낸 요청 결과 다시 확인' },
    view_handoff: { kind: 'info', tag: '관리자', title: '관리자 인계 내용 보기', lead: '확정 안 된 작업 넘겨받기 — 찍은 기록을 지우지 말고 이 내용대로 확인하세요.' },
    list_paired: { ...PIN, title: '함께 보류한 기록 목록', go: '목록 보기', lead: '두 기록을 함께 보류한 묶음과 따로 둔 기록을 봅니다. 목록 안에서 하는 일은 이 관리자 확인으로 합니다.' },
    view_sync: { kind: 'info', tag: '관리자', title: '전송 상태 상세' },
    // 리셋은 되돌릴 수 없다 — 마우스로만(처음 초점 = 그만두기), 처리 층은 id=confirmed 가 아니면 거절
    reset: { kind: 'confirm', tag: '확인', title: '현재 작업 리셋', go: '리셋', command: 'reset:confirmed',
      note: '리셋은 마우스로만 — 빈 Enter 나 스캔은 그만두기(찍은 것은 그대로 처리)' },
    register: { kind: 'form', tag: '새 이름', title: '새 이름 등록', lead: '이름만 넣으면 명단에 바로 올라갑니다', go: '등록하고 시작',
      command: 'register_worker', fields: [{ name: 'name', label: '이름', placeholder: '이름' }] },
  };

  // 남은 수 줄 — 어느 글인지는 처리 층 left_kind, 수는 처리 층 remaining
  const LEFT = {
    none: () => ['현품표를 찍으면 나옵니다'],
    target_pending: () => ['목표 수 확인 중'],
    remaining: (n) => ['남은 ', el('b', '', `${n}개`)],
    remaining_total: (n) => ['전체 남은 ', el('b', '', `${n}개`)],
    short: (n) => ['부족 ', el('b', '', `${n}개`), '로 마감'],
    full: () => ['다 찼습니다'],
    quota: (n) => ['끊김 — 혼자 더 넣을 수 ', el('b', '', `${n}개`)],
    closed_short: (n) => ['덜 찬 채로 마감 · 모자란 ', el('b', '', `${n}개`)],
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
      else tag.textContent = '현품표를 찍으면 여기 나옵니다';
    }
    $('[data-legacy]').hidden = !s.legacy;
    $('[data-held]').textContent = `보류 ${s.held_count}건 · 오늘 현황`;
    for (const link of document.querySelectorAll('[data-nav] [data-go]')) link.hidden = starting;
    $('[data-change]').hidden = starting;
  }

  function renderAdmin(s) {
    for (const item of s.admin_menu || []) {
      const sheet = sheets[item.name];
      if (!sheet) continue;
      for (const key of ['facts', 'result', 'rows', 'actions']) sheet[key] = item[key];
      const entry = document.querySelector(`[data-admin] [data-open="${item.name}"]`);
      if (entry) entry.disabled = !item.enabled;
    }
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
    $('[data-item]').replaceChildren(...(w.item ? [w.item.name, el('span', '', ` · ${w.item.spec} · ${w.item.code}`)] : ['품목 —']));
    renderCofill(w.cofill);
    $('[data-count]').replaceChildren(String(w.count), el('span', '', w.target ? `/ ${w.target}` : w.item ? '/ …' : '/ —'));
    $('[data-bar] i').style.width = w.target ? `${Math.min(100, (100 * w.count) / w.target)}%` : '0%'; // 막대 길이만(글 수는 처리 층 값)
    $('[data-left]').replaceChildren(...(LEFT[w.left_kind] || LEFT.none)(w.remaining));

    drawResult($('[data-result]'), w.result);

    $('[data-list-title]').textContent = w.checking ? `보관한 제품 · ${w.list_count}개` : w.cofill ? `이 PC 가 넣은 · ${w.list_count}건` : `지금 트레이 · ${w.list_count}건`;
    $('[data-list]').replaceChildren(...(w.list.length ? w.list.map((row) => {
      const li = el('li', `ca-row ca-row--${row.st}`);
      li.append(el('span', 'ca-row__no', row.no), el('span', 'ca-row__code', row.code), el('span', 'ca-row__tag', row.tag || ''), el('span', 'ca-row__at', row.at));
      return li;
    }) : [el('li', 'ca-list__empty', w.item ? '아직 찍은 제품이 없습니다' : '현품표를 찍고 제품을 찍으면 여기 쌓입니다')]));
    fitList();

    for (const node of document.querySelectorAll('[data-allow]')) {
      const key = node.dataset.allow;
      node.disabled = !s.allow[key];
      if (key === 'exchange') node.setAttribute('aria-pressed', String(swapping));
      if (key === 'undo') node.textContent = swapping ? '교환 취소' : '마지막 스캔 취소';
    }
    sheets.reset.lead = [`이 트레이에 찍은 ${w.count}개를 지우고 현품표부터 다시 합니다. `, '되돌릴 수 없습니다.'];
  }

  // 같이 채우기 한 줄 — 「몇 대가 같이 · 내가 넣은 수」(3초: 몇 대가 채우고 전체 몇 개 남았나 = 이 줄 + 큰 수 + 「전체 남은」)
  function renderCofill(c) {
    const line = $('[data-cofill]');
    line.hidden = !c;
    if (!c) return;
    const slots = el('span', 'ca-cofill__pcs');
    for (let i = 0; i < c.max_participants; i += 1) slots.append(el('i', i < c.participants ? 'is-in' : ''));
    const text = c.mode === 'closed' ? '같이 채움 · 마감' : c.total_age_s > 5 ? '같이 채우는 중 · 합계 확인 중' : '같이 채우는 중';
    line.replaceChildren(slots, `${text} · `, el('b', '', `${c.participants}대`), ' · 내가 넣은 ', el('b', '', `${c.mine_good}개`));
  }

  // 목록이 칸을 넘치면 넘친 줄을 숨기고 「그 앞 N건」(작업자는 굴리지 않는다 — 최신 몇 줄이면 됨)
  function fitList() {
    const list = $('[data-list]');
    const rows = [...list.querySelectorAll('.ca-row')];
    for (const li of rows) li.hidden = false;
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
      ? `${p.date} · 회사 서버 연결 끊김 · 마지막 받음 ${p.at} — 그 뒤 바뀐 것은 아직 안 보입니다`
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
    $('[data-park-title]').textContent = `보류 작업 · ${s.park.length}건`;
    $('[data-park]').replaceChildren(...s.park.map((p) => {
      const li = el('li');
      li.append(el('span', 'ca-park__item', p.item), button('act', '이어 하기', `command:restore:${p.id}`),
        el('span', 'ca-park__meta', [p.tag && `현품표 ${p.tag}`, p.target ? `${p.count} / ${p.target}` : `찍은 제품 ${p.count}개`, p.at && `보류 ${p.at}`].filter(Boolean).join(' · ')));
      return li;
    }));
    const today = s.today;
    $('[data-today-title]').textContent = `오늘 작업 현황 · 완료 ${today.total_trays} 트레이`;
    $('[data-today-rows]').replaceChildren(...today.rows.map((r) => {
      const tr = el('tr');
      tr.append(el('td', '', r.item), el('td', 'r', String(r.trays)), el('td', 'r', r.products == null ? '—' : num(r.products)));
      return tr;
    }));
    const supply = $('[data-today-supply]');
    supply.hidden = !today.supply;
    supply.textContent = `출고 전 관리자 보충 필요 ${today.supply}건`;
    $('[data-stats]').replaceChildren(...(s.stats || []).flatMap(([k, v]) => [el('dt', '', k), el('dd', '', v)]));
    drawTray($('[data-tray]'), 8, 5, s.work.count);
    $('[data-tray-cap]').textContent = s.work.item ? `트레이 그림 · ${s.work.item.name} ${s.work.item.spec} — 품목별 사진 자리` : '트레이 그림 — 품목별 사진 자리';
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
        el('p', 'ca-card__note', '제출이 60초 안에 끝나지 않아도 작업 화면과 다음 스캔은 그대로 됩니다'));
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
    $('[data-roster-sub]').textContent = r.note || (r.at ? `명단 ${r.count}명 · 회사 서버에서 ${r.at} 받음 · 60초마다 새로 받음` : `명단 ${r.count}명`);
    $('[data-names]').replaceChildren(...r.names.map((n) => {
      const b = button(`ca-name${n.last ? ' is-last' : ''}`, n.label, `command:start_work:${n.id}`);
      if (n.last) b.append(el('small', '', '지난번'));
      return b;
    }));
    const error = $('[data-start-error]');
    error.hidden = !s.start_error;
    error.textContent = s.start_error || '';
    $('[data-register]').hidden = !(s.register && s.register.cands.length);
    $('[data-register-cands]').replaceChildren(...(s.register ? s.register.cands : []).map((c) => button('act act--quiet', `${c.label} — 같은 사람이면 이것`, `command:start_work:${c.id}`)));
  }

  function render(s) {
    renderTop(s);
    renderAdmin(s);
    const view = s.view || 'work';
    for (const pane of document.querySelectorAll('[data-pane]')) pane.hidden = pane.dataset.pane !== view;
    if (view === 'work') renderWork(s);
    else if (view === 'progress' && s.progress) renderProgress(s.progress);
    else if (view === 'held' && s.park && s.today) renderHeld(s);
    else if (view === 'f8' && s.f8) renderF8(s.f8);
    else if (view === 'start' && s.roster) renderStart(s);
  }

  window.addEventListener('resize', fitList);
  // F8 = 현품표 교체(처리 층이 지금 단계에 맞게 열기 · 인쇄) · Esc · 빈 Enter = 확인(현장 「빈 Enter = 확인」 — 처리 층 ack 가 지금 빈 Enter 문,
  // 한 단계 안 화면이면 작업 화면으로). 글이 있는 Enter 는 늘 스캔(틀 1db33db4)
  AppFrame.start({ render, sheets, keys: { F8: 'command:f8', Escape: 'command:ack', Enter: 'command:ack' } });
})();
