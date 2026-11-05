export function formatBar(done, total, width = 20) {
    if (!Number.isFinite(done) || !Number.isFinite(total) || total <= 0 || !Number.isFinite(width) || width < 0) return '░'.repeat(Math.max(0, Math.floor(Number.isFinite(width) ? width : 20)));
    const size = Math.floor(width);
    const filled = Math.max(0, Math.min(size, Math.round(done / total * size)));
    return '█'.repeat(filled) + '░'.repeat(size - filled);
}

export function createProgressTracker(names, now = () => Date.now()) {
    const total = names.length;
    const known = new Set(names);
    const started = new Set();
    const finished = new Map();
    const runningOrder = [];
    const failed = [];
    const created = now();
    const validate = name => { if (!known.has(name)) throw new Error(`Unknown task: ${name}`); };
    return {
        start(name) {
            validate(name);
            if (!started.has(name)) { started.add(name); runningOrder.push(name); }
        },
        finish(name, ok = true) {
            validate(name);
            if (finished.has(name)) return;
            finished.set(name, Boolean(ok));
            if (!ok) failed.push(name);
        },
        snapshot() {
            const done = finished.size;
            return { done, total, percent: total ? Math.round(done / total * 100) : 0,
                running: runningOrder.filter(name => !finished.has(name)), failed: [...failed], elapsedMs: now() - created };
        }
    };
}

export function formatElapsed(ms) {
    if (!Number.isFinite(ms) || ms < 0) ms = 0;
    const seconds = Math.floor(ms / 1000);
    return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
}

export function formatProgressLine(snapshot) {
    return [`${formatBar(snapshot.done, snapshot.total)} ${snapshot.done}/${snapshot.total} (${snapshot.percent}%)`, snapshot.failed.length ? `${snapshot.failed.length} failed` : null, formatElapsed(snapshot.elapsedMs)].filter(Boolean).join(' · ');
}

export function formatRunning(snapshot, labelFor = n => n, max = 3) {
    if (!snapshot.running.length) return '';
    const limit = Math.max(0, Math.floor(max));
    const labels = snapshot.running.slice(0, limit).map(labelFor);
    const extra = snapshot.running.length - limit;
    return `Running: ${labels.join(', ')}${extra > 0 ? ` +${extra} more` : ''}`;
}

export function renderProgress(root, snapshot, labelFor = n => n) {
    if (root == null) return;
    const bar = root.querySelector('[data-scan-progress-bar]');
    const detail = root.querySelector('[data-scan-progress-detail]');
    if (bar) bar.textContent = formatProgressLine(snapshot);
    if (detail) detail.textContent = formatRunning(snapshot, labelFor);
    root.setAttribute('aria-valuenow', String(snapshot.percent));
    root.setAttribute('aria-valuemin', '0');
    root.setAttribute('aria-valuemax', '100');
    root.setAttribute('aria-valuetext', `${snapshot.done} of ${snapshot.total} collectors finished`);
    root.classList.remove('hidden');
}

export function hideProgress(root) {
    if (root != null) root.classList.add('hidden');
}
