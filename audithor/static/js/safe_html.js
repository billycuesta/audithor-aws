const NAME_PATTERN = /^[A-Za-z_$][\w$]*$/;
const SUPPORTED_EVENTS = ['click', 'change', 'input'];
const DENIED_ACTIONS = new Set([
    'eval', 'Function', 'setTimeout', 'setInterval', 'setImmediate', 'execScript', 'open', 'close',
    'alert', 'confirm', 'prompt', 'fetch', 'XMLHttpRequest', 'importScripts', 'postMessage', 'Window',
    'constructor', '__proto__', 'prototype', 'toString', 'valueOf'
]);
export const ACT_THIS = Object.freeze({ $act: 'this' });

export class SafeHtml {
    constructor(value) { this.value = String(value); }
    toString() { return this.value; }
}

export const escapeHtml = value => value == null ? '' : String(value).replace(/[&<>"'`]/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
})[char]);

const render = value => {
    if (value instanceof SafeHtml) return value.toString();
    if (Array.isArray(value)) return value.map(render).join('');
    if (value == null || value === false) return '';
    return escapeHtml(String(value));
};

export const html = (parts, ...values) => new SafeHtml(parts.reduce((result, part, index) => result + part + (index < values.length ? render(values[index]) : ''), ''));
// Every use of raw() must be justified: it is an intentional trusted-HTML escape hatch.
export const raw = value => new SafeHtml(value);
export const join = (parts, separator = '') => new SafeHtml(Array.from(parts, render).join(separator));
export const setHtml = (element, safeHtml) => {
    if (!(safeHtml instanceof SafeHtml)) throw new TypeError('setHtml requires SafeHtml');
    element.innerHTML = safeHtml.toString();
};

const isJsonValue = (value, seen = new Set()) => {
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
    if (typeof value === 'number') return Number.isFinite(value);
    if (typeof value !== 'object' || seen.has(value)) return false;
    seen.add(value);
    const valid = Array.isArray(value)
        ? value.every(item => isJsonValue(item, seen))
        : Object.getPrototypeOf(value) === Object.prototype && Object.values(value).every(item => isJsonValue(item, seen));
    seen.delete(value);
    return valid;
};

const actionFragment = (eventName, name, args) => {
    if (!NAME_PATTERN.test(name)) throw new TypeError('Invalid action name');
    if (!SUPPORTED_EVENTS.includes(eventName)) throw new TypeError('Unsupported action event');
    if (!isJsonValue(args)) throw new TypeError('Action arguments must be JSON-serializable');
    let encoded;
    try { encoded = JSON.stringify(args); } catch { throw new TypeError('Action arguments must be JSON-serializable'); }
    if (encoded === undefined) throw new TypeError('Action arguments must be JSON-serializable');
    return raw(`data-act${eventName === 'click' ? '' : `-${eventName}`}="${name}" data-args${eventName === 'click' ? '' : `-${eventName}`}="${escapeHtml(encoded)}"`);
};
export const act = (name, ...args) => actionFragment('click', name, args);
export const actOn = (eventName, name, ...args) => actionFragment(eventName, name, args);

const installedRoots = new WeakSet();
export function installActionDelegation(root = document) {
    if (installedRoots.has(root)) return;
    installedRoots.add(root);
    for (const eventName of SUPPORTED_EVENTS) root.addEventListener(eventName, event => {
        const attribute = eventName === 'click' ? 'data-act' : `data-act-${eventName}`;
        const argsAttribute = eventName === 'click' ? 'data-args' : `data-args-${eventName}`;
        const element = event.target.closest?.(`[${attribute}]`);
        // closest() resolves the innermost [data-act], so nested actions do not need stopPropagation support.
        if (!element || !root.contains(element)) return;
        const name = element.getAttribute(attribute);
        if (!NAME_PATTERN.test(name || '') || DENIED_ACTIONS.has(name)) return;
        if (!Object.prototype.hasOwnProperty.call(window, name) || typeof window[name] !== 'function') return;
        let args;
        try { args = JSON.parse(element.getAttribute(argsAttribute)); } catch { return; }
        if (!Array.isArray(args)) return;
        const resolvedArgs = args.map(arg => (
            arg !== null && typeof arg === 'object' && !Array.isArray(arg) &&
            Object.keys(arg).length === 1 && Object.prototype.hasOwnProperty.call(arg, '$act') &&
            arg.$act === 'this'
        ) ? element : arg);
        const result = window[name](...resolvedArgs);
        if (result === false) event.preventDefault();
    });
}
