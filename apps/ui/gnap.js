'use strict';
// The GNAP suite's shared presentation helpers. They only build DOM nodes from
// data: no request, no storage, no HTML parsing. Text always goes in as text,
// and a link only gets an `href` that passes the reference check below.

const GNAP = (() => {
  // The status words of the workbench reports and of the command line.
  const STATUS = {
    pass: ['✓', 'Passed'],
    passed: ['✓', 'Passed'],
    fail: ['✕', 'Failed'],
    failed: ['✕', 'Failed'],
    not_tested: ['?', 'Not tested'],
    inconclusive: ['?', 'Inconclusive'],
    skipped: ['–', 'Skipped'],
    not_applicable: ['–', 'Not applicable'],
  };
  const statusOf = value => (Object.hasOwn(STATUS, value) ? value : 'not_tested');

  const TAGS = new Set(['a', 'article', 'button', 'h3', 'li', 'p', 'span']);

  // An element of a fixed tag, with a fixed class.
  function el(tag, className) {
    if (!TAGS.has(tag)) throw new Error(`GNAP.el: unsupported tag ${tag}`);
    const node = document.createElement(tag);
    if (className) node.className = className;
    return node;
  }

  // A reference to an RFC section or an IANA registry, as a short citation.
  // Anything else stays plain text: no URL from a report becomes a link
  // unless its scheme, host, port and path are the expected ones.
  function citation(reference) {
    let url;
    try { url = new URL(reference); } catch { return null; }
    if (url.protocol !== 'https:' || url.username || url.password || url.port || url.search) return null;
    if (url.hostname === 'www.rfc-editor.org') {
      const rfc = /^\/rfc\/rfc([0-9]{3,5})\.html$/.exec(url.pathname);
      if (!rfc) return null;
      const section = /^#section-([0-9A-Za-z.-]+)$/.exec(url.hash);
      if (url.hash && !section) return null;
      return { href: url.href, label: section ? `RFC ${rfc[1]} §${section[1]}` : `RFC ${rfc[1]}` };
    }
    if (url.hostname === 'www.iana.org' && /^\/assignments\/[a-z0-9-]+\/?$/.test(url.pathname)) {
      return { href: url.href, label: 'IANA registry' };
    }
    return null;
  }

  // One row per check: a status mark that doesn't rely on color, the check's
  // id, its detail, the reference, and the next action when there is one.
  function checkRow(check) {
    const status = statusOf(check.status);
    const [mark, word] = STATUS[status];
    const row = el('article', 'check');
    row.dataset.status = status;
    const sign = el('span', 'mark');
    sign.textContent = mark;
    sign.ariaHidden = 'true';
    const title = el('h3', '');
    title.textContent = check.id;
    const label = el('p', 'status');
    label.textContent = word;
    row.append(sign, title);
    const cited = typeof check.reference === 'string' ? citation(check.reference) : null;
    if (cited) {
      const link = el('a', 'cite');
      link.href = cited.href;
      link.rel = 'noreferrer';
      link.textContent = cited.label;
      row.append(link);
    } else if (typeof check.reference === 'string' && check.reference) {
      const text = el('span', 'cite');
      text.textContent = check.reference;
      row.append(text);
    }
    row.append(label);
    const detail = el('p', '');
    detail.textContent = check.detail;
    row.append(detail);
    if (check.remediation) {
      const next = el('p', 'next');
      next.textContent = `Next: ${check.remediation}`;
      row.append(next);
    }
    return row;
  }

  // One cell per check, in report order, colored and titled by status.
  function tallyCells(checks) {
    return checks.map(check => {
      const status = statusOf(check.status);
      const cell = el('li', '');
      cell.dataset.status = status;
      cell.title = `${check.id}: ${STATUS[status][1]}`;
      return cell;
    });
  }

  // Shows only the rows of one status, or all of them for `all`.
  function filterRows(rows, status) {
    for (const row of rows) row.hidden = status !== 'all' && row.dataset.status !== status;
  }

  return Object.freeze({ STATUS, statusOf, el, citation, checkRow, tallyCells, filterRows });
})();
