// Progressive enhancement for the server-rendered UI.
//
// Every enhancement below returns immediately when the elements it enhances
// are absent, so a single file can be linked from every page without knowing
// which page it landed on. The server renders working HTML for all of it: the
// filter panel submits as a plain form, each Kanban card carries its own move
// form, and the save-view layout control is merely narrowed here. Nothing in
// this file is required for a route to work.
//
// The enhancements are functions rather than immediately-invoked blocks
// because the body they bind to is no longer stable. `hx-boost` on <body>
// makes a navigation an htmx request whose response replaces the body's
// contents, and no `load` or `DOMContentLoaded` event follows that, so code
// that ran once at first paint would leave every subsequent page inert: a
// filter panel that will not add rows, a board that will not accept a drop.
// `enhanceAll` therefore runs once at the bottom of this file and again on
// every `htmx:load`, the event htmx fires for each element it inserts.
//
// That means it runs several times per navigation — a body swap inserts the
// skip link, the progress bar and the shell as separate nodes, and each one
// gets its own `htmx:load` — so binding has to be idempotent. `claim` hands
// out each element exactly once, recording what it has already handed out in a
// WeakSet. A WeakSet specifically, and not a `data-` attribute: htmx can
// snapshot the body as HTML for its history, so a marker written into the DOM
// would come back from that snapshot claiming elements are bound when their
// listeners died with the old document, which is the same bug one layer
// deeper. The WeakSet instead lets the entries go when the nodes do.
const enhanced = new WeakSet();

// True the first time it is asked about an element, false forever after, and
// false for a missing element so callers can write one guard for both cases.
const claim = (element) => {
  if (!element || enhanced.has(element)) return false;
  enhanced.add(element);
  return true;
};

// Filter builder: swap the operator and value controls to match the field a
// row selects, and add or remove rows without a round trip.
const enhanceFilterBuilder = () => {
  const builder = document.querySelector('[data-filter-builder]');
  if (!claim(builder)) return;
  const disclosure = builder.querySelector('[data-filter-disclosure]');
  const list = builder.querySelector('[data-filter-list]');
  const template = builder.querySelector('template[data-filter-template]');
  const addButton = builder.querySelector('[data-add-filter]');
  const closeButton = builder.querySelector('[data-close-filter]');
  const maximum = Number(builder.dataset.maxFilters || '20');

  const closeDisclosure = () => {
    if (!disclosure) return;
    disclosure.open = false;
    disclosure.querySelector('summary')?.focus();
  };

  closeButton?.addEventListener('click', closeDisclosure);
  builder.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && disclosure?.open) closeDisclosure();
  });

  const reindex = () => {
    const rows = [...list.querySelectorAll('[data-filter-row]')];
    rows.forEach((row, index) => {
      row.querySelector('[data-filter-field]').setAttribute('aria-label', `Filter field ${index + 1}`);
      row.querySelector('[data-filter-operator]').setAttribute('aria-label', `Filter operator ${index + 1}`);
      row.querySelector('[data-filter-value]').setAttribute('aria-label', `Filter value ${index + 1}`);
      row.querySelector('[data-remove-filter]').setAttribute('aria-label', `Remove filter ${index + 1}`);
    });
    addButton.disabled = rows.length >= maximum;
  };

  const replaceValueControl = (row) => {
    const field = row.querySelector('[data-filter-field]');
    const option = field.selectedOptions[0];
    const operator = row.querySelector('[data-filter-operator]').value;
    const slot = row.querySelector('[data-filter-value-slot]');
    const kind = option.dataset.filterKind || 'input';
    let control;
    if (operator === 'is-empty' || operator === 'is-not-empty') {
      control = document.createElement('input');
      control.type = 'hidden';
      control.value = '';
      const hint = document.createElement('span');
      hint.className = 'block px-3 py-2 text-sm text-slate-400';
      hint.textContent = 'No value needed';
      control.name = 'filter_value';
      control.dataset.filterValue = 'true';
      slot.replaceChildren(control, hint);
      reindex();
      return;
    } else if (kind === 'select') {
      control = document.createElement('select');
      const blank = document.createElement('option');
      blank.value = '';
      blank.textContent = 'Select a value…';
      control.appendChild(blank);
      JSON.parse(option.dataset.filterOptions || '[]').forEach((item) => {
        const choice = document.createElement('option');
        choice.value = item.value;
        choice.textContent = item.label;
        control.appendChild(choice);
      });
    } else {
      control = document.createElement('input');
      control.type = option.dataset.filterInputType || 'text';
      if (control.type === 'number') control.step = 'any';
      control.placeholder = control.type === 'number' ? 'Exact number' : 'Exact value';
    }
    control.name = 'filter_value';
    control.dataset.filterValue = 'true';
    control.className = 'w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2';
    slot.replaceChildren(control);
    reindex();
  };

  const replaceOperatorControl = (row) => {
    const field = row.querySelector('[data-filter-field]');
    const selected = field.selectedOptions[0];
    const operator = row.querySelector('[data-filter-operator]');
    const previous = operator.value;
    const options = JSON.parse(selected.dataset.filterOperators || '[]');
    operator.replaceChildren(...options.map((item) => {
      const choice = document.createElement('option');
      choice.value = item.value;
      choice.textContent = item.label;
      return choice;
    }));
    if (options.some((item) => item.value === previous)) operator.value = previous;
    replaceValueControl(row);
  };

  const bindRow = (row) => {
    row.querySelector('[data-filter-field]').addEventListener('change', () => replaceOperatorControl(row));
    row.querySelector('[data-filter-operator]').addEventListener('change', () => replaceValueControl(row));
    row.querySelector('[data-remove-filter]').addEventListener('click', () => {
      const rows = list.querySelectorAll('[data-filter-row]');
      if (rows.length === 1) {
        row.querySelector('[data-filter-field]').value = '';
        row.querySelector('[data-filter-operator]').value = 'eq';
        replaceOperatorControl(row);
      } else {
        row.remove();
        reindex();
      }
    });
  };

  list.querySelectorAll('[data-filter-row]').forEach(bindRow);
  addButton.addEventListener('click', () => {
    if (list.querySelectorAll('[data-filter-row]').length >= maximum) return;
    const row = template.content.firstElementChild.cloneNode(true);
    list.appendChild(row);
    bindRow(row);
    reindex();
    row.querySelector('[data-filter-field]').focus();
  });
  reindex();
};

// Save-as-view: a Kanban view needs a grouping field and a table view has no
// use for one, so the control follows the chosen layout.
const enhanceViewLayout = () => {
  document.querySelectorAll('[data-view-layout]').forEach((layout) => {
    if (!claim(layout)) return;
    const form = layout.closest('form');
    const groupBy = form && form.querySelector('[data-view-group-by]');
    if (!groupBy) return;
    const update = () => {
      const kanban = layout.value === 'kanban';
      groupBy.disabled = !kanban;
      groupBy.required = kanban;
      if (!kanban) groupBy.value = '';
    };
    layout.addEventListener('change', update);
    update();
  });
};

// Kanban drag and drop: a drop submits the same move form the card already
// renders, so the audited server path is identical either way.
const enhanceKanbanBoard = () => {
  const board = document.querySelector('[data-kanban-board]');
  if (!claim(board)) return;
  let draggedCard = null;

  board.querySelectorAll('[data-kanban-card="true"]').forEach((card) => {
    card.addEventListener('dragstart', () => {
      draggedCard = card;
      card.classList.add('opacity-50');
    });
    card.addEventListener('dragend', () => {
      draggedCard = null;
      card.classList.remove('opacity-50');
      board.querySelectorAll('[data-kanban-lane]').forEach((lane) => lane.classList.remove('ring-2', 'ring-blue-400'));
    });
  });

  board.querySelectorAll('[data-kanban-lane]').forEach((lane) => {
    lane.addEventListener('dragover', (event) => {
      event.preventDefault();
      lane.classList.add('ring-2', 'ring-blue-400');
    });
    lane.addEventListener('dragleave', () => lane.classList.remove('ring-2', 'ring-blue-400'));
    lane.addEventListener('drop', (event) => {
      event.preventDefault();
      if (!draggedCard) return;
      const form = document.createElement('form');
      form.method = 'post';
      form.action = draggedCard.dataset.moveUrl;
      const append = (name, value) => {
        const input = document.createElement('input');
        input.type = 'hidden';
        input.name = name;
        input.value = value;
        form.appendChild(input);
      };
      append('_csrf', lane.dataset.kanbanCsrf);
      append('target', lane.dataset.kanbanTarget);
      document.body.appendChild(form);
      // `form.submit()` fires no submit event, so htmx never sees this one and
      // the drop is an ordinary browser POST. That matches the rendered move
      // form, which opts out of boosting (see `UNBOOSTED` in `src/server.rs`)
      // until mutations have a response contract htmx can act on, so both ways
      // of moving a card behave identically.
      form.submit();
    });
  });
};

// htmx configuration. It lives here rather than in a `<script>` block or a
// `meta[name=htmx-config]` tag for the same reason the enhancements above do:
// the pages must stay able to declare `script-src 'self'`, and a configuration
// nobody can read in a JavaScript file is a configuration nobody maintains.
// This runs before htmx reads any of these settings, because both scripts are
// deferred — so they run in document order, htmx first — and htmx applies its
// configuration on DOMContentLoaded, which is after every deferred script.
if (window.htmx) {
  // Otherwise htmx injects a <style> element for the `htmx-indicator` class it
  // ships. Nothing here uses that class — the progress bar is styled in the
  // server's own sheet from htmx's `htmx-request` class — and an injected
  // inline <style> is one more thing standing between these pages and a strict
  // content security policy.
  window.htmx.config.includeIndicatorStyles = false;

  // Do not keep visited pages in sessionStorage. htmx's history cache would
  // make the back button instant, but it writes rendered pages — records,
  // audit entries, whoever the operator was impersonating at the time — into
  // per-tab storage that outlives the response, while the server deliberately
  // sends `Cache-Control: no-store` on every rendered page and adds
  // `Vary: Cookie` whenever access control is on. Storing them anyway would
  // quietly contradict that. With the cache off, htmx re-requests the page on
  // back and forward, which is still a body swap rather than a reload, still
  // shows the progress bar, and for a database on the same machine costs a
  // round trip nobody can see.
  window.htmx.config.historyCacheSize = 0;

  // Because the cache is off, every back and forward is one of those
  // re-requests, and htmx would by default label it `HX-Request: true` while
  // still expecting a whole document to swap into <body>. That header means
  // nothing to the server today, but phase 2 of `.context/htmx-plan.md` gives
  // it a meaning — "answer with the content fragment" — and a fragment swapped
  // into <body> on a history restore would silently delete the sidebar. Turning
  // the label off makes a restore indistinguishable from an ordinary
  // navigation, which is exactly what it is.
  window.htmx.config.historyRestoreAsHxRequest = false;
}

// A boosted navigation has to be able to land on an error page.
//
// htmx ignores the body of a non-2xx response, which is right for the form
// posts phase 3 will boost but wrong for navigation: the server answers a
// request for a record that no longer exists with a rendered 404 page, and
// without this a click on a stale link would leave the previous page on screen
// and look like the click was never registered. Allowing the swap restores what
// the browser would have done, including the URL — htmx decides whether to push
// history before this event and applies it only if the swap happens.
//
// Narrow on purpose. Only boosted GETs, so it cannot pre-empt the response
// contract phase 3 defines for mutations, and only responses that are HTML
// documents, so an error from a route that answers JSON is left to fall through
// rather than being poured into the page as text.
document.addEventListener('htmx:beforeSwap', (event) => {
  const { boosted, requestConfig, xhr } = event.detail;
  const isHtml = (xhr.getResponseHeader('content-type') || '').startsWith('text/html');
  if (boosted && requestConfig.verb === 'get' && xhr.status >= 400 && isHtml) {
    event.detail.shouldSwap = true;
  }
});

// Run the enhancements now — this script is deferred, so the document is
// parsed — and again whenever htmx inserts markup. The first call is what keeps
// every enhancement above working when htmx is absent, blocked, or still in
// flight; it is not htmx that owns them.
const enhanceAll = () => {
  enhanceFilterBuilder();
  enhanceViewLayout();
  enhanceKanbanBoard();
};

enhanceAll();
document.addEventListener('htmx:load', enhanceAll);
