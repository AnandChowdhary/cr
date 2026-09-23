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
//
// Targeted swaps make that distinction load bearing rather than merely tidy.
// Turning a page on a Kanban view replaces the board, which needs its drop
// handlers bound again, while leaving the filter panel's nodes exactly where they
// were — the whole point of swapping a region — so the panel must keep the
// listeners it has and must not be handed out a second time. `claim` decides both
// from one fact: whether this particular node has been seen before.
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
      hint.className = 'block px-3 py-2 text-sm text-gray-400';
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
    control.className = 'w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm outline-none ring-indigo-500 focus:ring-2';
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

// Say something in the page's one live region.
//
// The region is rendered empty by the server on every page (`live_region` in
// `src/server.rs`) and is outside every fragment this UI swaps, so it is on the
// page and being watched before anything asks it to speak. A view's results
// swap fills it directly with an out-of-band swap and needs nothing from this
// file; the one case that does is a message that arrives *with* a page, which
// is the case a live region does not reliably announce — the region and its
// contents are inserted together, and an assistive technology that was not
// already watching the element has nothing to compare against.
//
// Hence the delay. Writing the text one task later makes it a change to a region
// the browser has already registered, which is the only thing live regions are
// specified to announce. A frame would do it in principle; 120ms is chosen to
// also clear the settling window Chromium applies after a document load, because
// the other half of this case is a plain navigation with no htmx involved at all
// — a delete or a Kanban move still answers a browser with `303 See Other`.
const announce = (message) => {
  const region = document.getElementById('cr-announce');
  if (!region || !message) return;
  window.setTimeout(() => {
    region.textContent = message;
  }, 120);
};

// The success banner a mutation redirects to, said once.
//
// `claim` is what makes it once: the banner is a node, this runs on every
// `htmx:load` a navigation produces, and the same banner must not be announced
// twice because the sidebar happened to be inserted after it. A new navigation
// renders a new node, which is a new claim and a new announcement.
//
// The banner itself carries no `role`, deliberately — see the comment beside it
// in `render_view_records`. This is the page's only announcement of it, and with
// JavaScript off there is none, which is correct: without htmx the notice
// arrives at the top of a freshly loaded document, and the navigation is the
// feedback.
const enhanceNotice = () => {
  const notice = document.querySelector('[data-notice]');
  if (!claim(notice)) return;
  announce(notice.textContent.trim());
};

// Timestamps. The server writes each tooltip in UTC because it cannot know the
// reader's time zone; the browser can, so the tooltip is rewritten in local
// time. The visible text — "3 hours ago" — reads the same in every zone.
const enhanceTimes = () => {
  document.querySelectorAll('time.cr-time[datetime]').forEach((time) => {
    if (!claim(time)) return;
    const instant = new Date(time.dateTime);
    if (Number.isNaN(instant.getTime())) return;
    time.title = instant.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  });
};

// Unsaved edits. A navigation swaps the page body rather than loading a new
// document, so a click on the sidebar in the middle of an edit used to throw
// the edit away without a word. A record form becomes unsaved at its first
// change and saved again when it is submitted. While a form on the page is
// unsaved, a request htmx is about to make asks first (see `htmx:confirm`
// below), and leaving the page any other way — a reload, a native form post,
// closing the tab — gets the browser's own `beforeunload` prompt.
//
// A form the server sent back refusing a submission is unsaved from the
// start: it holds exactly what was typed, and none of it was written. A Set
// rather than the WeakSet `claim` uses, because the guard asks which forms are
// unsaved, which a WeakSet cannot answer; a form that has left the document no
// longer counts, which is what `isConnected` checks.
const unsavedForms = new Set();
const hasUnsavedChanges = () => [...unsavedForms].some((form) => form.isConnected);

const enhanceRecordForm = () => {
  const form = document.getElementById('cr-record-form');
  if (!claim(form)) return;
  if (form.querySelector(':scope > [role="alert"]')) unsavedForms.add(form);
  const markUnsaved = () => unsavedForms.add(form);
  form.addEventListener('input', markUnsaved);
  form.addEventListener('change', markUnsaved);
  form.addEventListener('submit', () => unsavedForms.delete(form));
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
  // still expecting a whole document to swap into <body>. That header now
  // means something to the server — with an `HX-Target` naming a region it
  // renders, it answers with that region alone — and a fragment swapped into
  // <body> on a history restore would silently delete the sidebar. Turning the
  // label off makes a restore indistinguishable from an ordinary navigation,
  // which is exactly what it is.
  //
  // Belt and braces, in both directions. htmx sends no `HX-Target` on a
  // restore, so the server would answer with a document even if this were
  // `true`, and `Representation::requested` in `src/server.rs` additionally
  // refuses a fragment to any request carrying `HX-History-Restore-Request`.
  // Three independent reasons, because the failure is silent: a restore that
  // landed a fragment in <body> would leave a page with no navigation and
  // nothing left to boost from.
  window.htmx.config.historyRestoreAsHxRequest = false;
}

// Two things htmx would otherwise drop on the floor, because it ignores the body
// of a response that is not a success.
//
// The first is a boosted navigation that lands on an error page. The server
// answers a request for a record that no longer exists with a rendered 404 page,
// and without this a click on a stale link would leave the previous page on
// screen and look like the click was never registered. Allowing the swap
// restores what the browser would have done, including the URL — htmx decides
// whether to push history before this event and applies it only if the swap
// happens.
//
// "Boosted" is not on its own enough to identify that case, which is why the
// target is checked as well. A view's pagination, sort, filter and search
// controls are boosted elements that override `hx-target` to replace the results
// region alone, and htmx still reports those requests as boosted; without the
// second condition a failed re-sort would paste a whole rendered error document —
// doctype, sidebar and all — inside the table it was supposed to replace. htmx
// resolves a boosted element with no `hx-target` to `<body>`, so comparing
// against it is the same test htmx itself used to pick the target.
//
// The second is a refused form submission. The server answers one with the form
// itself: the same values, escaped, in the controls they were typed into, with
// the reason at the top and beside each field the schema located. Its status is
// the status of the refusal — 422 for a schema violation, 412 for a record that
// changed underneath the form, 409 for an identity already taken — so the server
// marks exactly those answers with `CR-Form-Invalid` rather than making this
// listener keep a list of statuses in step with the routes. Nothing else sends
// that header, which makes this clause as narrow as the one above it: every
// other failed request still swaps nothing and leaves the page as it was.
document.addEventListener('htmx:beforeSwap', (event) => {
  const { boosted, requestConfig, target, xhr } = event.detail;
  const isHtml = (xhr.getResponseHeader('content-type') || '').startsWith('text/html');
  if (boosted && target === document.body && requestConfig.verb === 'get' && xhr.status >= 400 && isHtml) {
    event.detail.shouldSwap = true;
  }
  if (isHtml && xhr.getResponseHeader('CR-Form-Invalid') === 'true') {
    event.detail.shouldSwap = true;
  }
});

// The unsaved-edits guard's two prompts. `htmx:confirm` fires before every
// request htmx makes — a boosted link or form, a targeted swap, the navigation
// that follows a save — and cancels it when prevented. The form's own
// submission is let through, because it is how the changes get saved; so is
// anything once the reader has chosen to discard them.
document.addEventListener('htmx:confirm', (event) => {
  if (!hasUnsavedChanges()) return;
  const form = event.detail.elt?.closest?.('form');
  if (form && unsavedForms.has(form)) return;
  if (window.confirm('You have unsaved changes. Leave without saving them?')) {
    unsavedForms.clear();
  } else {
    event.preventDefault();
  }
});

window.addEventListener('beforeunload', (event) => {
  if (!hasUnsavedChanges()) return;
  event.preventDefault();
  event.returnValue = '';
});

// A submission that never reached the server wrote nothing, so the form is
// unsaved again.
document.addEventListener('htmx:sendError', (event) => {
  const form = event.detail.elt?.closest?.('form');
  if (form && form.id === 'cr-record-form') unsavedForms.add(form);
});

// Run the enhancements now — this script is deferred, so the document is
// parsed — and again whenever htmx inserts markup. The first call is what keeps
// every enhancement above working when htmx is absent, blocked, or still in
// flight; it is not htmx that owns them.
const enhanceAll = () => {
  enhanceNotice();
  enhanceTimes();
  enhanceRecordForm();
  enhanceFilterBuilder();
  enhanceViewLayout();
  enhanceKanbanBoard();
};

enhanceAll();
document.addEventListener('htmx:load', enhanceAll);
