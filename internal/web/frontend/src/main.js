// Waypoint console.
//
// Everything here lives for exactly as long as the tab does. There is no
// localStorage, no sessionStorage, and no service worker: closing the browser
// discards the buffers, the tabs, and the results. That is deliberate — query
// text and result rows are production data, and leaving them at rest in a
// browser would outlive the connection that was authorized to produce them.

import { EditorState, Compartment } from "@codemirror/state";
import { EditorView, keymap, highlightActiveLine, lineNumbers,
         highlightActiveLineGutter, drawSelection, rectangularSelection,
         crosshairCursor, highlightSpecialChars } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { searchKeymap, highlightSelectionMatches } from "@codemirror/search";
import { autocompletion, completionKeymap, snippetCompletion, closeBrackets,
         closeBracketsKeymap, acceptCompletion } from "@codemirror/autocomplete";
import { linter, lintGutter, lintKeymap, forEachDiagnostic } from "@codemirror/lint";
import { bracketMatching, foldGutter, indentOnInput, syntaxHighlighting,
         defaultHighlightStyle } from "@codemirror/language";
import { sql, PostgreSQL } from "@codemirror/lang-sql";
import { oneDark } from "@codemirror/theme-one-dark";

// ---------------------------------------------------------------------------
// byte/char offset bridge
//
// The server speaks byte offsets (Go strings); CodeMirror speaks UTF-16 code
// units. They agree for ASCII, which is nearly all SQL, but a comment with an
// accented character would silently shift every diagnostic without this.
// ---------------------------------------------------------------------------

const encoder = new TextEncoder();
const isAscii = (s) => !/[^\x00-\x7F]/.test(s);

function charToByte(text, ch) {
  if (isAscii(text)) return Math.min(ch, text.length);
  return encoder.encode(text.slice(0, ch)).length;
}

function byteToChar(text, target) {
  if (isAscii(text)) return Math.min(target, text.length);
  let bytes = 0;
  for (let i = 0; i < text.length; ) {
    if (bytes >= target) return i;
    const cp = text.codePointAt(i);
    bytes += cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    i += cp > 0xffff ? 2 : 1;
  }
  return text.length;
}

// ---------------------------------------------------------------------------
// api
// ---------------------------------------------------------------------------

async function api(path, body) {
  const res = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`;
    try { const j = await res.json(); if (j.error) msg = j.error; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// state (in memory only, for the life of this page)
// ---------------------------------------------------------------------------

const state = {
  session: null,
  database: null,
  catalog: { tables: [], foreignKeys: [], schemas: [] },
  tabs: [],
  activeId: null,
  seq: 1,
  openTable: null,
};

const el = (id) => document.getElementById(id);

// The database the active tab is pointed at. Falls back to the session
// default before any tab exists.
function activeDatabase() {
  return activeTab()?.database || state.database;
}

function activeTab() {
  return state.tabs.find((t) => t.id === state.activeId) || null;
}

function newTab(name, doc = "") {
  const tab = {
    id: state.seq++,
    name: name || `query ${state.seq - 1}`,
    // Per tab, not per page: with several databases offered, repointing
    // every open tab because the picker moved would be surprising, and a
    // tab would keep showing results from the database it no longer names.
    database: state.database,
    editorState: null,
    doc,
    result: null,
    running: false,
    pid: null,
    abort: null,
  };
  state.tabs.push(tab);
  return tab;
}

// ---------------------------------------------------------------------------
// toasts
// ---------------------------------------------------------------------------

function toast(message, kind = "") {
  const node = document.createElement("div");
  node.className = `toast ${kind}`;
  node.textContent = message;
  el("toasts").appendChild(node);
  setTimeout(() => {
    node.style.transition = "opacity 160ms ease";
    node.style.opacity = "0";
    setTimeout(() => node.remove(), 200);
  }, 3600);
}

// ---------------------------------------------------------------------------
// editor
// ---------------------------------------------------------------------------

let view = null;
const schemaCompartment = new Compartment();

// Completions come from the server, not from a schema object shipped to the
// browser. That keeps the payload independent of database size and, more
// importantly, keeps permission scoping server-side: the catalog the server
// reads was introspected on this user's own role.
async function completionSource(context) {
  const before = context.matchBefore(/[\w$"]*/);
  if (!before && !context.explicit) return null;

  const doc = context.state.doc.toString();
  const cursorPos = charToByte(doc, context.pos);

  let res;
  try {
    res = await api("/api/v1/complete", {
      database: activeDatabase(),
      sql: doc,
      cursorPos,
    });
  } catch {
    return null;
  }
  if (!res.options || !res.options.length) return null;

  // Anchor the replacement client-side. Trusting the server's byte offset
  // here would reintroduce the encoding mismatch the bridge above avoids.
  const from = before ? before.from : context.pos;

  const options = res.options.map((o) => {
    const base = {
      label: o.label,
      // Shown instead of label. Matching still runs against label, which is
      // why a qualified column keeps its bare name there.
      displayLabel: o.displayLabel || undefined,
      detail: o.detail || undefined,
      type: o.type || undefined,
      boost: o.boost || 0,
      info: o.info || undefined,
      // The section is what actually orders the list. CodeMirror offsets
      // scores by -1e5 per section rank, which is the only lever strong
      // enough to beat its own match scoring; boost just arranges peers
      // within one section.
      section: o.section ? { name: o.section, rank: o.sectionRank } : undefined,
    };
    // A completion carrying snippet syntax inserts a whole JOIN clause:
    // relation, linked alias tab stop, and the ON predicate the foreign keys
    // imply — including every intermediate join on a multi-hop path.
    if (o.apply && o.apply.includes("${")) {
      return snippetCompletion(o.apply, base);
    }
    if (o.apply) return { ...base, apply: o.apply };
    return base;
  });

  return { from, options, validFor: /^[\w$"]*$/ };
}

// Diagnostics merge three sources server-side: the SQL parser for syntax,
// has_table_privilege for permissions, and statement shape for the classic
// unqualified UPDATE/DELETE. They are advisory: Postgres remains the authority.
async function diagnosticsSource(v) {
  const doc = v.state.doc.toString();
  if (!doc.trim()) return [];
  let res;
  try {
    res = await api("/api/v1/diagnostics", { database: activeDatabase(), sql: doc });
  } catch {
    return [];
  }
  return (res.diagnostics || []).map((d) => ({
    from: byteToChar(doc, d.from),
    to: Math.max(byteToChar(doc, d.to), byteToChar(doc, d.from) + 1),
    severity: d.severity,
    message: d.message,
    source: d.source,
  }));
}

function baseExtensions() {
  return [
    lineNumbers(),
    highlightActiveLineGutter(),
    highlightSpecialChars(),
    history(),
    foldGutter(),
    drawSelection(),
    EditorState.allowMultipleSelections.of(true),
    indentOnInput(),
    syntaxHighlighting(defaultHighlightStyle, { fallback: true }),
    bracketMatching(),
    closeBrackets(),
    rectangularSelection(),
    crosshairCursor(),
    highlightActiveLine(),
    highlightSelectionMatches(),
    lintGutter(),
    linter(diagnosticsSource, { delay: 400 }),
    autocompletion({
      override: [completionSource],
      activateOnTyping: true,
      closeOnBlur: true,
      maxRenderedOptions: 60,
      selectOnOpen: true,
      // The default keymap is installed manually below, minus its Enter
      // binding. Leaving this on would re-add Enter and undo that.
      defaultKeymap: false,
    }),
    schemaCompartment.of(sql({ dialect: PostgreSQL, upperCaseKeywords: true })),
    oneDark,
    keymap.of([
      { key: "Mod-Enter", run: () => { runQuery(false); return true; }, preventDefault: true },
      { key: "Mod-Shift-Enter", run: () => { runQuery(true); return true; }, preventDefault: true },
      { key: "Escape", run: () => { if (activeTab()?.running) { cancelQuery(); return true; } return false; } },
      // Tab accepts the highlighted completion; with no popup open it falls
      // through to indentation. Enter is left alone so it always inserts a
      // newline — accepting on Enter makes it far too easy to take a
      // suggestion you were only scrolling past.
      { key: "Tab", run: acceptCompletion },
      ...closeBracketsKeymap,
      ...defaultKeymap,
      ...searchKeymap,
      ...historyKeymap,
      // completionKeymap minus its Enter binding, which would otherwise
      // accept the selection instead of breaking the line.
      ...completionKeymap.filter((b) => b.key !== "Enter"),
      ...lintKeymap,
      indentWithTab,
    ]),
    EditorView.updateListener.of((u) => {
      if (u.docChanged) {
        const t = activeTab();
        if (t) t.doc = u.state.doc.toString();
      }
      // Lint results land as state effects, so this also catches the moment
      // permission diagnostics arrive.
      if (u.docChanged || u.selectionSet || u.transactions.length) updateRunButton();
    }),
  ];
}

function makeState(doc) {
  return EditorState.create({ doc, extensions: baseExtensions() });
}

function mountEditor() {
  const tab = activeTab();
  view = new EditorView({
    state: tab.editorState || makeState(tab.doc),
    parent: el("editor"),
  });
  view.focus();
}

function switchTab(id) {
  const cur = activeTab();
  if (cur && view) {
    // Per-tab editor state is kept in memory so switching tabs preserves the
    // buffer, cursor, selection, and undo history. That is the cue that makes
    // this feel like an editor — and it costs nothing once the page is gone.
    cur.editorState = view.state;
    cur.doc = view.state.doc.toString();
  }
  const previousDatabase = activeDatabase();
  state.activeId = id;
  const next = activeTab();
  if (!next) return;
  view.setState(next.editorState || makeState(next.doc));
  renderTabs();
  renderResult(next);
  renderStatus();
  updateRunButton();
  // The schema tree follows the tab, so it only reloads when the tab being
  // switched to points somewhere else.
  if (next.database !== previousDatabase) {
    syncPicker();
    state.openTable = null;
    loadSchema();
  }
  view.focus();
}

// ---------------------------------------------------------------------------
// tabs
// ---------------------------------------------------------------------------

// syncPicker points the database selector at the active tab.
function syncPicker() {
  const picker = el("db-picker");
  if (picker && activeDatabase()) picker.value = activeDatabase();
}

function renderTabs() {
  const host = el("tabs");
  host.replaceChildren();
  for (const tab of state.tabs) {
    const node = document.createElement("button");
    node.className = "tab" + (tab.id === state.activeId ? " active" : "");
    node.setAttribute("role", "tab");
    node.setAttribute("aria-selected", String(tab.id === state.activeId));

    if (tab.running) {
      const spin = document.createElement("span");
      spin.className = "spin";
      spin.textContent = "●";
      node.appendChild(spin);
    }

    const label = document.createElement("span");
    label.textContent = tab.name;
    node.appendChild(label);

    if ((state.session?.databases?.length || 0) > 1) {
      const db = document.createElement("span");
      db.className = "tab-db";
      db.textContent = tab.database;
      node.appendChild(db);
    }

    if (state.tabs.length > 1) {
      const close = document.createElement("span");
      close.className = "close";
      close.textContent = "×";
      close.title = "Close tab";
      close.addEventListener("click", (e) => {
        e.stopPropagation();
        closeTab(tab.id);
      });
      node.appendChild(close);
    }

    node.addEventListener("click", () => switchTab(tab.id));
    host.appendChild(node);
  }
}

function closeTab(id) {
  const idx = state.tabs.findIndex((t) => t.id === id);
  if (idx < 0 || state.tabs.length === 1) return;
  const tab = state.tabs[idx];
  if (tab.abort) tab.abort.abort();
  state.tabs.splice(idx, 1);
  if (state.activeId === id) {
    switchTab(state.tabs[Math.max(0, idx - 1)].id);
  } else {
    renderTabs();
  }
}

function addTab(doc = "", name = null) {
  const cur = activeTab();
  if (cur && view) cur.editorState = view.state;
  const tab = newTab(name, doc);
  state.activeId = tab.id;
  view.setState(makeState(doc));
  syncPicker();
  renderStatus();
  renderTabs();
  renderResult(tab);
  view.focus();
  return tab;
}

// ---------------------------------------------------------------------------
// running queries
// ---------------------------------------------------------------------------

function updateRunButton() {
  const tab = activeTab();
  const btn = el("run-btn");
  const cancel = el("cancel-btn");
  if (!tab) return;
  btn.hidden = tab.running;
  cancel.hidden = !tab.running;
  btn.disabled = false;

  // A statement the grant does not permit is flagged before it runs. The
  // check is the same has_table_privilege answer the linter uses; Postgres
  // still gets the final say.
  // A statement the grant does not permit is flagged before it runs, reading
  // the same diagnostics the lint gutter shows. This is a warning, not a
  // block: Postgres still gets the final say, and the button stays enabled so
  // a stale catalog can never lock someone out of a query they can run.
  const blockers = permissionWarnings();
  if (blockers.length) {
    btn.classList.add("blocked");
    btn.title = blockers.join("\n");
  } else {
    btn.classList.remove("blocked");
    btn.title = "";
  }
}

// permissionWarnings collects permission diagnostics overlapping the statement
// the run action would execute.
function permissionWarnings() {
  if (!view) return [];
  const doc = view.state.doc.toString();
  const head = view.state.selection.main.head;
  const messages = [];
  forEachDiagnostic(view.state, (d, from, to) => {
    if (d.source !== "permission" || d.severity !== "warning") return;
    // Only warn about the statement that ⌘↩ would actually run.
    if (head < from - 1 || head > to + statementSlack(doc, to)) return;
    messages.push(d.message);
  });
  return [...new Set(messages)];
}

// statementSlack lets a diagnostic anchored on a table name still count for a
// caret sitting later in the same statement.
function statementSlack(doc, to) {
  const next = doc.indexOf(";", to);
  return (next < 0 ? doc.length : next) - to;
}

async function runQuery(runAll) {
  const tab = activeTab();
  if (!tab || tab.running) return;

  const doc = view.state.doc.toString();
  if (!doc.trim()) return;

  const cursorPos = charToByte(doc, view.state.selection.main.head);
  const controller = new AbortController();

  tab.running = true;
  tab.pid = null;
  tab.abort = controller;
  tab.result = { status: "running", columns: [], rows: [], rowCount: 0, startedAt: performance.now() };
  renderTabs();
  renderResult(tab);
  updateRunButton();

  try {
    const res = await fetch("/api/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ database: activeDatabase(), sql: doc, cursorPos, runAll }),
      signal: controller.signal,
    });

    if (!res.ok) {
      let msg = `${res.status} ${res.statusText}`;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch {}
      tab.result = { status: "error", error: { message: msg } };
      return;
    }

    await consumeStream(res, tab);
  } catch (err) {
    if (err.name === "AbortError") {
      tab.result = { ...(tab.result || {}), status: "cancelled" };
    } else {
      tab.result = { status: "error", error: { message: String(err.message || err) } };
    }
  } finally {
    tab.running = false;
    tab.abort = null;
    renderTabs();
    if (tab.id === state.activeId) {
      renderResult(tab);
      updateRunButton();
    }
  }
}

// consumeStream reads the NDJSON result. The first frame carries the backend
// PID, which arrives before any rows — that is what makes cancellation work
// without the server holding any per-query state.
async function consumeStream(res, tab) {
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = "";

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });

    let nl;
    while ((nl = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;

      let frame;
      try { frame = JSON.parse(line); } catch { continue; }

      switch (frame.type) {
        case "begin":
          tab.pid = frame.pid;
          tab.result.statement = frame.statement;
          break;
        case "columns":
          tab.result.columns = frame.columns;
          if (tab.id === state.activeId) renderResult(tab);
          break;
        case "rows":
          tab.result.rows.push(...frame.rows);
          tab.result.rowCount = tab.result.rows.length;
          if (tab.id === state.activeId) renderResult(tab);
          break;
        case "end":
          tab.result.status = "done";
          tab.result.rowCount = frame.rowCount;
          tab.result.truncated = frame.truncated;
          tab.result.durationMs = frame.durationMs;
          tab.result.command = frame.command;
          break;
        case "error":
          tab.result.status = "error";
          tab.result.error = frame;
          markErrorInEditor(frame);
          break;
      }
    }
  }
}

// markErrorInEditor puts the caret on the byte Postgres complained about.
// PgError.Position is a 1-based character offset into the statement, which is
// exactly what an inline annotation needs.
function markErrorInEditor(frame) {
  if (!frame.position || frame.position <= 0) return;
  const doc = view.state.doc.toString();
  const stmtStart = doc.indexOf(activeTab()?.result?.statement || "");
  const base = stmtStart >= 0 ? stmtStart : 0;
  const pos = Math.min(base + frame.position - 1, doc.length);
  view.dispatch({ selection: { anchor: pos }, scrollIntoView: true });
}

async function cancelQuery() {
  const tab = activeTab();
  if (!tab || !tab.running) return;
  if (!tab.pid) {
    tab.abort?.abort();
    return;
  }
  try {
    await api("/api/v1/cancel", { database: tab.database, pid: tab.pid });
    toast("Query cancelled", "ok");
  } catch (err) {
    toast(`Cancel failed: ${err.message}`, "err");
  }
}

// ---------------------------------------------------------------------------
// results
// ---------------------------------------------------------------------------

const NUMERIC = /^(int|numeric|float|double|real|serial|decimal|money|oid)/i;

function renderResult(tab) {
  const host = el("results");
  const meta = el("result-meta");
  const copy = el("copy-btn");
  host.replaceChildren();
  meta.replaceChildren();
  copy.hidden = true;

  const r = tab?.result;
  if (!r) {
    host.appendChild(placeholder("◇", "No query run yet",
      "Write SQL above, then press ⌘↩ to run the statement under the cursor."));
    return;
  }

  if (r.status === "running" && !r.columns.length) {
    host.appendChild(placeholder("●", "Running…",
      "Press Esc to cancel. You can switch tabs while this runs."));
    meta.textContent = "running…";
    return;
  }

  if (r.status === "error") {
    host.appendChild(errorBox(r.error));
    meta.textContent = "failed";
    return;
  }

  if (r.status === "cancelled") {
    host.appendChild(placeholder("■", "Cancelled", "The statement was cancelled."));
    meta.textContent = "cancelled";
    return;
  }

  if (!r.columns.length) {
    const cmd = r.command || "OK";
    host.appendChild(placeholder("✓", cmd, "Statement completed with no result rows."));
    meta.textContent = `${cmd} · ${r.durationMs ?? 0} ms`;
    return;
  }

  // Plain DOM table: the server caps rows, so there is a hard bound on how
  // much ever reaches the page.
  const table = document.createElement("table");
  table.className = "grid";

  const thead = document.createElement("thead");
  const hrow = document.createElement("tr");
  hrow.appendChild(th("", "rownum"));
  for (const c of r.columns) {
    const cell = th(c.name);
    const type = document.createElement("span");
    type.className = "th-type";
    type.textContent = c.type;
    cell.appendChild(type);
    hrow.appendChild(cell);
  }
  thead.appendChild(hrow);
  table.appendChild(thead);

  const tbody = document.createElement("tbody");
  r.rows.forEach((row, i) => {
    const tr = document.createElement("tr");
    const num = document.createElement("td");
    num.className = "rownum";
    num.textContent = String(i + 1);
    tr.appendChild(num);

    row.forEach((val, ci) => {
      const td = document.createElement("td");
      if (val === null) {
        td.className = "null";
        td.textContent = "NULL";
      } else {
        // textContent, never innerHTML: a cell holding markup is the most
        // likely XSS vector a database console has.
        td.textContent = typeof val === "object" ? JSON.stringify(val) : String(val);
        if (NUMERIC.test(r.columns[ci]?.type || "")) td.className = "num";
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  host.appendChild(table);

  const bits = [`${r.rowCount} row${r.rowCount === 1 ? "" : "s"}`];
  if (r.durationMs !== undefined) bits.push(`${r.durationMs} ms`);
  if (r.status === "running") bits.push("streaming…");
  meta.textContent = bits.join(" · ");
  if (r.truncated) {
    const w = document.createElement("span");
    w.className = "warn";
    w.textContent = `  · truncated at ${state.session?.maxRows ?? "the row cap"}`;
    meta.appendChild(w);
  }
  copy.hidden = false;
}

function th(text, cls) {
  const node = document.createElement("th");
  if (cls) node.className = cls;
  node.textContent = text;
  return node;
}

function placeholder(glyph, title, hint) {
  const node = document.createElement("div");
  node.className = "placeholder";
  const g = document.createElement("div");
  g.className = "big";
  g.textContent = glyph;
  const t = document.createElement("div");
  t.textContent = title;
  const h = document.createElement("div");
  h.className = "hint";
  h.textContent = hint;
  node.append(g, t, h);
  return node;
}

function errorBox(err) {
  const node = document.createElement("div");
  node.className = "err-box";
  if (err.code) {
    const c = document.createElement("div");
    c.className = "code";
    c.textContent = `SQLSTATE ${err.code}`;
    node.appendChild(c);
  }
  const m = document.createElement("div");
  m.className = "msg";
  m.textContent = err.message || "Query failed";
  node.appendChild(m);
  for (const extra of [err.detail, err.hint]) {
    if (!extra) continue;
    const s = document.createElement("div");
    s.className = "sub";
    s.textContent = extra;
    node.appendChild(s);
  }
  return node;
}

function copyTSV() {
  const r = activeTab()?.result;
  if (!r || !r.columns.length) return;
  const lines = [r.columns.map((c) => c.name).join("\t")];
  for (const row of r.rows) {
    lines.push(row.map((v) => (v === null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v))).join("\t"));
  }
  writeClipboard(lines.join("\n"))
    .then(() => toast(`Copied ${r.rows.length} rows`, "ok"))
    .catch(() => toast("Copy failed", "err"));
}

// writeClipboard copies text, falling back when the async Clipboard API is
// unavailable.
//
// navigator.clipboard only exists in a secure context. A console served over
// https (the default for a web listener) always has one; a console configured
// with tls_mode = "off" and reached by hostname does not, and the property is
// undefined there — so calling it directly throws a TypeError rather than
// returning a promise the caller could catch.
function writeClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  return new Promise((resolve, reject) => {
    const scratch = document.createElement("textarea");
    scratch.value = text;
    // Kept out of view and out of the tab order, but still selectable —
    // execCommand will not copy from a hidden element.
    scratch.setAttribute("readonly", "");
    scratch.style.position = "fixed";
    scratch.style.top = "-1000px";
    scratch.style.opacity = "0";
    document.body.appendChild(scratch);
    try {
      scratch.select();
      const ok = document.execCommand("copy");
      ok ? resolve() : reject(new Error("copy rejected"));
    } catch (err) {
      reject(err);
    } finally {
      scratch.remove();
      view?.focus();
    }
  });
}

// ---------------------------------------------------------------------------
// schema tree
// ---------------------------------------------------------------------------

function renderTree() {
  const host = el("tree");
  const filter = el("schema-filter").value.trim().toLowerCase();
  host.replaceChildren();

  const bySchema = new Map();
  for (const t of state.catalog.tables) {
    if (filter && !`${t.schema}.${t.name}`.toLowerCase().includes(filter)) continue;
    if (!bySchema.has(t.schema)) bySchema.set(t.schema, []);
    bySchema.get(t.schema).push(t);
  }

  if (!bySchema.size) {
    const empty = document.createElement("div");
    empty.className = "placeholder";
    empty.style.height = "auto";
    empty.style.paddingTop = "28px";
    empty.textContent = filter ? "No matching tables" : "No tables visible to your grant";
    host.appendChild(empty);
    return;
  }

  for (const [schema, tables] of [...bySchema].sort((a, b) => a[0].localeCompare(b[0]))) {
    const head = document.createElement("div");
    head.className = "tree-schema";
    head.textContent = schema;
    host.appendChild(head);

    for (const t of tables) {
      const qualified = `${t.schema}.${t.name}`;
      const item = document.createElement("div");
      item.className = "tree-item" + (state.openTable === qualified ? " open" : "");
      item.setAttribute("role", "treeitem");

      const name = document.createElement("span");
      name.className = "name";
      name.textContent = t.name;
      item.appendChild(name);

      if (t.kind === "view") {
        const kind = document.createElement("span");
        kind.className = "kind";
        kind.textContent = "view";
        item.appendChild(kind);
      }
      // A relation the user can read but not write is worth showing up front:
      // it explains a warning before the warning appears.
      if (t.select && !t.insert && !t.update && !t.delete) {
        const ro = document.createElement("span");
        ro.className = "ro";
        ro.title = "read-only for you";
        ro.textContent = "ro";
        item.appendChild(ro);
      }

      item.addEventListener("click", () => toggleTable(t, qualified));
      item.addEventListener("dblclick", () => {
        insertAtCursor(`SELECT *\nFROM ${qualified}\nLIMIT 100`);
      });
      host.appendChild(item);

      if (state.openTable === qualified) {
        const cols = document.createElement("div");
        cols.className = "tree-cols";
        cols.dataset.for = qualified;
        cols.textContent = "loading…";
        host.appendChild(cols);
        loadColumns(t, cols);
      }
    }
  }
}

async function toggleTable(t, qualified) {
  state.openTable = state.openTable === qualified ? null : qualified;
  renderTree();
}

async function loadColumns(t, host) {
  try {
    const res = await api("/api/v1/columns", {
      database: activeDatabase(), schema: t.schema, table: t.name,
    });
    host.replaceChildren();
    for (const c of res.columns) {
      const row = document.createElement("div");
      row.className = "tree-col";
      row.title = c.comment || "";
      const n = document.createElement("span");
      n.textContent = c.name;
      const ty = document.createElement("span");
      ty.className = "ctype";
      ty.textContent = c.type;
      row.append(n, ty);
      row.addEventListener("click", () => insertAtCursor(c.name));
      host.appendChild(row);
    }
    if (!res.columns.length) host.textContent = "no columns";
  } catch (err) {
    host.textContent = `failed: ${err.message}`;
  }
}

function insertAtCursor(text) {
  const sel = view.state.selection.main;
  view.dispatch({
    changes: { from: sel.from, to: sel.to, insert: text },
    selection: { anchor: sel.from + text.length },
  });
  view.focus();
}

// ---------------------------------------------------------------------------
// command palette
// ---------------------------------------------------------------------------

let paletteItems = [];
let paletteIndex = 0;

function openPalette() {
  const commands = [
    { label: "Run statement under cursor", sub: "⌘↩", run: () => runQuery(false) },
    { label: "Run entire buffer", sub: "⌘⇧↩", run: () => runQuery(true) },
    { label: "New query tab", sub: "Ctrl+T", run: () => addTab() },
    { label: "Refresh schema", sub: "", run: () => loadSchema(true) },
    { label: "Copy results as TSV", sub: "", run: copyTSV },
  ];
  const tables = state.catalog.tables.map((t) => ({
    label: `${t.schema}.${t.name}`,
    sub: t.kind,
    run: () => insertAtCursor(`${t.schema}.${t.name}`),
  }));
  paletteItems = [...commands, ...tables];
  paletteIndex = 0;

  el("palette").hidden = false;
  const input = el("palette-input");
  input.value = "";
  renderPalette("");
  input.focus();
}

function closePalette() {
  el("palette").hidden = true;
  view?.focus();
}

function filteredPalette(q) {
  const query = q.trim().toLowerCase();
  if (!query) return paletteItems.slice(0, 50);
  return paletteItems.filter((i) => i.label.toLowerCase().includes(query)).slice(0, 50);
}

function renderPalette(q) {
  const list = el("palette-list");
  const items = filteredPalette(q);
  paletteIndex = Math.min(paletteIndex, Math.max(0, items.length - 1));
  list.replaceChildren();
  items.forEach((item, i) => {
    const li = document.createElement("li");
    li.setAttribute("role", "option");
    li.setAttribute("aria-selected", String(i === paletteIndex));
    const label = document.createElement("span");
    label.textContent = item.label;
    li.appendChild(label);
    if (item.sub) {
      const sub = document.createElement("span");
      sub.className = "sub";
      sub.textContent = item.sub;
      li.appendChild(sub);
    }
    li.addEventListener("click", () => { closePalette(); item.run(); });
    list.appendChild(li);
  });
  list._items = items;
}

// ---------------------------------------------------------------------------
// resizers
// ---------------------------------------------------------------------------

function wireResizers() {
  const app = el("app");

  drag(el("divider-x"), (e) => {
    const w = Math.min(Math.max(e.clientX, 180), window.innerWidth - 320);
    app.style.setProperty("--sidebar-w", `${w}px`);
  });

  drag(el("divider-y"), (e) => {
    const main = el("main") || el("results-pane").parentElement;
    const rect = main.getBoundingClientRect();
    const h = Math.min(Math.max(rect.bottom - e.clientY, 90), rect.height - 120);
    document.documentElement.style.setProperty("--results-h", `${h}px`);
  });
}

function drag(handle, onMove) {
  handle.addEventListener("mousedown", (e) => {
    e.preventDefault();
    const move = (ev) => onMove(ev);
    const up = () => {
      document.removeEventListener("mousemove", move);
      document.removeEventListener("mouseup", up);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
    document.body.style.cursor = getComputedStyle(handle).cursor;
    document.body.style.userSelect = "none";
    document.addEventListener("mousemove", move);
    document.addEventListener("mouseup", up);
  });
}

// ---------------------------------------------------------------------------
// bootstrap
// ---------------------------------------------------------------------------

function renderStatus() {
  const s = state.session;
  if (!s) return;
  el("status-identity").textContent = `${s.user}@${s.node}`;
  el("status-listener").textContent = `${s.listener} → ${activeDatabase()}`;

  // Showing the resolved grant is something only this console can do: no
  // other SQL client knows who you are or what your capability grant says.
  const grant = el("status-grant");
  grant.replaceChildren();
  const presets = s.presets && s.presets.length ? s.presets : ["no grant"];
  const span = document.createElement("span");
  const writable = presets.some((p) => p === "readwrite" || p === "admin");
  span.className = writable ? "grant-rw" : "grant-ro";
  span.textContent = presets.join(",");
  grant.appendChild(span);
}

async function loadSchema(force = false) {
  try {
    const q = new URLSearchParams({ database: activeDatabase() });
    if (force) q.set("refresh", "1");
    state.catalog = await api(`/api/v1/schema?${q}`);
    renderTree();
    if (force) toast("Schema refreshed", "ok");
  } catch (err) {
    toast(`Schema failed: ${err.message}`, "err");
  }
}

async function boot() {
  try {
    state.session = await api("/api/v1/session");
  } catch (err) {
    document.body.replaceChildren();
    const box = document.createElement("div");
    box.className = "placeholder";
    box.style.height = "100vh";
    const g = document.createElement("div");
    g.className = "big";
    g.textContent = "⛔";
    const t = document.createElement("div");
    t.textContent = "Access denied";
    const h = document.createElement("div");
    h.className = "hint";
    h.textContent = err.message;
    box.append(g, t, h);
    document.body.appendChild(box);
    return;
  }

  state.database = state.session.database;

  const picker = el("db-picker");
  picker.replaceChildren();
  for (const db of state.session.databases) {
    const opt = document.createElement("option");
    opt.value = db;
    opt.textContent = db;
    picker.appendChild(opt);
  }
  picker.value = state.database;
  picker.addEventListener("change", () => {
    const tab = activeTab();
    if (tab) tab.database = picker.value;
    state.database = picker.value; // the default for tabs opened next
    state.openTable = null;
    renderStatus();
    renderTabs();
    loadSchema();
  });

  newTab("query 1", "");
  state.activeId = state.tabs[0].id;
  mountEditor();
  renderTabs();
  renderResult(activeTab());
  renderStatus();
  updateRunButton();
  await loadSchema();

  el("run-btn").addEventListener("click", () => runQuery(false));
  el("cancel-btn").addEventListener("click", cancelQuery);
  el("copy-btn").addEventListener("click", copyTSV);
  el("new-tab").addEventListener("click", () => addTab());
  el("refresh-schema").addEventListener("click", () => loadSchema(true));
  el("schema-filter").addEventListener("input", renderTree);

  const paletteInput = el("palette-input");
  paletteInput.addEventListener("input", (e) => renderPalette(e.target.value));
  paletteInput.addEventListener("keydown", (e) => {
    const items = el("palette-list")._items || [];
    if (e.key === "ArrowDown") { paletteIndex = Math.min(paletteIndex + 1, items.length - 1); renderPalette(paletteInput.value); e.preventDefault(); }
    else if (e.key === "ArrowUp") { paletteIndex = Math.max(paletteIndex - 1, 0); renderPalette(paletteInput.value); e.preventDefault(); }
    else if (e.key === "Enter") { const it = items[paletteIndex]; closePalette(); it?.run(); e.preventDefault(); }
    else if (e.key === "Escape") { closePalette(); e.preventDefault(); }
  });
  el("palette").addEventListener("mousedown", (e) => {
    if (e.target === el("palette")) closePalette();
  });

  window.addEventListener("keydown", (e) => {
    const mod = e.metaKey || e.ctrlKey;
    if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); openPalette(); }
    else if (e.ctrlKey && e.key.toLowerCase() === "t") { e.preventDefault(); addTab(); }
    else if (mod && e.key.toLowerCase() === "p") { e.preventDefault(); openPalette(); }
  });

  wireResizers();
}

boot();
