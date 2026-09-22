// Progressive enhancement for the server-rendered UI.
//
// Every block below is a self-guarded IIFE that returns immediately when the
// elements it enhances are absent, so a single file can be linked from every
// page without knowing which page it landed on. The server renders working
// HTML for all of it: the filter panel submits as a plain form, each Kanban
// card carries its own move form, and the save-view layout control is merely
// narrowed here. Nothing in this file is required for a route to work.

// Filter builder: swap the operator and value controls to match the field a
// row selects, and add or remove rows without a round trip.
(() => {
  const builder = document.querySelector('[data-filter-builder]');
  if (!builder) return;
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
})();

// Save-as-view: a Kanban view needs a grouping field and a table view has no
// use for one, so the control follows the chosen layout.
(() => {
  document.querySelectorAll('[data-view-layout]').forEach((layout) => {
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
})();

// Kanban drag and drop: a drop submits the same move form the card already
// renders, so the audited server path is identical either way.
(() => {
  const board = document.querySelector('[data-kanban-board]');
  if (!board) return;
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
      form.submit();
    });
  });
})();
