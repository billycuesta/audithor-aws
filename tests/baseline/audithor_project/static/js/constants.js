// static/js/constants.js
// =====================================================
// 1) ICONOS (si los necesitas en otras vistas)
// =====================================================
const ICONS = {
  S3: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-box w-4 h-4 inline-block mr-2" viewBox="0 0 16 16"><path d="M8.186 1.113a.5.5 0 0 0-.372 0L1.846 3.5 8 5.961 14.154 3.5zM15 4.239l-6.5 2.6v7.922l6.5-2.6V4.24zM7.5 14.762V6.838L1 4.239v7.923zM7.443.184a1.5 1.5 0 0 1 1.114 0l7.129 2.852A.5.5 0 0 1 16 3.5v8.662a1 1 0 0 1-.629.928l-7.185 2.874a.5.5 0 0 1-.372 0L.63 13.09a1 1 0 0 1-.63-.928V3.5a.5.5 0 0 1 .314-.464z"/></svg>',
  CloudWatch: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-earmark-text w-4 h-4 inline-block mr-2" viewBox="0 0 16 16"><path d="M5.5 7a.5.5 0 0 0 0 1h5a.5.5 0 0 0 0-1zM5 9.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m0 2a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 0 1h-2a.5.5 0 0 1-.5-.5"/><path d="M9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V4.5zm0 1v2A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1z"/></svg>',
  Lambda: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-radioactive w-4 h-4 inline-block mr-2" viewBox="0 0 16 16"><path d="M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8"/><path d="M9.653 5.496A2.996 2.996 0 0 0 8 5c-1.012 0-1.9.49-2.463 1.252L5.5 5.5a.5.5 0 0 1 .707-.707l.347.347A3 3 0 0 0 8 5m3.453 3.453a3 3 0 0 0-.707-.707l-.347.347a.5.5 0 0 1-.707-.707l.347-.347A3 3 0 0 0 9.252 5.547l.347-.347a.5.5 0 0 1 .707.707l-.347.347c.453.513.743 1.142.823 1.832a.5.5 0 0 1-.988.136 2.001 2.001 0 0 0-1.568-1.568.5.5 0 0 1 .136-.988c.69.08 1.319.37 1.832.823m-1.76-2.112a2.996 2.996 0 0 1 1.252-2.463L11.5 5.5a.5.5 0 0 1 .707-.707l-.347-.347A3 3 0 0 0 8 3.515a.5.5 0 0 1-.612-.868 4 4 0 0 1 4.965 4.965.5.5 0 0 1-.868-.612A3 3 0 0 0 9.504 6.347Z"/></svg>',
  SQS: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-distribute-horizontal w-4 h-4 inline-block mr-2" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M14.5 1a.5.5 0 0 0-.5.5v13a.5.5 0 0 0 1 0v-13a.5.5 0 0 0-.5-.5m-13 0a.5.5 0 0 0-.5.5v13a.5.5 0 0 0 1 0v-13a.5.5 0 0 0-.5-.5"/><path d="M6 13a1 1 0 1 0 0 2 1 1 0 0 0 0-2m4 0a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/></svg>',
  SNS: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-broadcast w-4 h-4 inline-block mr-2" viewBox="0 0 16 16"><path d="M3.05 3.05a7 7 0 0 0 0 9.9.5.5 0 0 1-.707.707 8 8 0 0 1 0-11.314.5.5 0 0 1 .707.707m9.9 0a7 7 0 0 1 0 9.9.5.5 0 0 1-.707-.707 8 8 0 0 0 0-11.314.5.5 0 0 1 .707.707M5.172 5.172a4 4 0 0 0 0 5.656.5.5 0 1 1-.707.707 5 5 0 0 1 0-7.07.5.5 0 0 1 .707.707m5.656 0a4 4 0 0 1 0 5.656.5.5 0 1 1-.707.707 5 5 0 0 0 0-7.07.5.5 0 0 1 .707.707M8 7a2 2 0 1 1 0 4 2 2 0 0 1 0-4m0-1a3 3 0 1 0 0 6 3 3 0 0 0 0-6"/></svg>',
  Kinesis: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bar-chart-line-fill w-4 h-4 inline-block mr-2" viewBox="0 0 16 16"><path d="M11 2a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v12h.5a.5.5 0 0 1 0 1H.5a.5.5 0 0 1 0-1H1v-3a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v3h1V7a1 1 0 0 1 1-1h2a1 1 0 0 1 1 1v7h1z"/></svg>',
  Firehose: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-fire w-4 h-4 inline-block mr-2" viewBox="0 0 16 16"><path d="M8 16c3.314 0 6-2 6-5.5 0-1.5-.5-4-2.5-6 .25 1.5-1.25 2-1.25 2C11 4 9 .5 6 0c.31 2 .5 4 0 6 .625-1 1-1.5 1.5-2 .25 1.5-1.25 2-1.25 2-2 1.5-2.5 4.5-2.5 6C2 14 4.686 16 8 16m0-1c-1.657 0-3-1-3-2.75 0-.75.25-2 1.25-3C6.125 10 7 10.5 7 10.5c-.375-1.25.5-3.25.5-3.25s.5.625 1 1.375c.5-1.25 1.5-2.5 1.5-2.5-.625 1.5-1.75 2-1.75 2s1.25 1 1.75 2.5c.5-1.25 1-2.5 1-2.5s-1.5 1.25-2 3.25c.75-1.25 1.5-2.25 1.5-2.25s.25 1 .5 2.5c1 1.25 1 2.25 1 2.75C11 14 9.657 15 8 15"/></svg>',
  OpenSearch: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-search w-4 h-4 inline-block mr-2" viewBox="0 0 16 16"><path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001c.03.04.062.078.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1.007 1.007 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0z"/></svg>',
  MetricFilter: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-graph-up-arrow w-4 h-4 inline-block mr-2" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M0 0h1v15h15v1H0zm10 3.5a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 .5.5v4a.5.5 0 0 1-1 0V4.9l-3.613 4.417a.5.5 0 0 1-.74.037L7.06 6.767l-3.656 5.027a.5.5 0 0 1-.808-.588l4-5.5a.5.5 0 0 1 .758-.06l2.609 2.61L13.445 4H10.5a.5.5 0 0 1-.5-.5"/></svg>',
  Alarm: '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bell-fill w-4 h-4 inline-block mr-1 text-red-500" viewBox="0 0 16 16"><path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2m.995-14.901a1 1 0 1 0-1.99 0A5 5 0 0 0 3 6c0 1.098-.5 6-2 7h14c-1.5-1-2-5.902-2-7 0-2.42-1.72-4.44-4.005-4.901"/></svg>'
};

// =====================================================
// 2) RESOLUCIÓN DEL BACKEND BASE
// =====================================================
function normalizeBase(raw) {
  if (!raw) return '';
  let v = raw.trim();
  if (v.startsWith('/')) v = window.location.origin.replace(/\/$/, '') + v;
  if (v.startsWith('//')) v = window.location.protocol + v;
  return v.replace(/\/+$/, '');
}
function resolveBackendBase() {
  if (typeof window.BACKEND_BASE === 'string' && window.BACKEND_BASE.trim()) return normalizeBase(window.BACKEND_BASE);
  const meta = document.querySelector('meta[name="backend-base"]')?.content;
  if (meta) return normalizeBase(meta);
  const dataAttr = document.body?.dataset?.backendBase;
  if (dataAttr) return normalizeBase(dataAttr);
  return normalizeBase(window.location.origin);
}
const BASE = resolveBackendBase();

// =====================================================
// 3) ENDPOINTS DE API
// =====================================================
const API = {
  // BULK JOBS
  BULK_RUN:             `${BASE}/api/run-bulk-audit`,
  JOB_STATUS: (id) =>   `${BASE}/api/scan/status/${encodeURIComponent(id)}`,
  JOB_RESULT: (id) =>   `${BASE}/api/scan/result/${encodeURIComponent(id)}`,

  // RUNS por servicio
  RUN_IAM:                 `${BASE}/api/run-iam-audit`,
  RUN_ACCESS_ANALYZER:     `${BASE}/api/run-access-analyzer-audit`,
  RUN_SECURITYHUB:         `${BASE}/api/run-securityhub-audit`,
  RUN_EXPOSURE:            `${BASE}/api/run-exposure-audit`,
  RUN_GUARDDUTY:           `${BASE}/api/run-guardduty-audit`,
  RUN_WAF:                 `${BASE}/api/run-waf-audit`,
  RUN_CLOUDTRAIL:          `${BASE}/api/run-cloudtrail-audit`,
  RUN_CLOUDWATCH:          `${BASE}/api/run-cloudwatch-audit`,
  RUN_INSPECTOR:           `${BASE}/api/run-inspector-audit`,
  RUN_INSPECTOR_FINDINGS:  `${BASE}/api/run-inspector-findings-audit`,
  RUN_ACM:                 `${BASE}/api/run-acm-audit`,
  RUN_COMPUTE:             `${BASE}/api/run-compute-audit`,
  RUN_ECR:                 `${BASE}/api/run-ecr-audit`,
  RUN_DATABASES:           `${BASE}/api/run-databases-audit`,
  RUN_NETWORK_POLICIES:    `${BASE}/api/run-network-policies-audit`,
  RUN_NETWORK_DETAIL:      `${BASE}/api/run-network-detail-audit`,
  RUN_CLOUDTRAIL_LOOKUP:   `${BASE}/api/run-cloudtrail-lookup`,
  RUN_PLAYGROUND:          `${BASE}/api/run-playground-audit`,
  RUN_SSLSCAN:             `${BASE}/api/run-sslscan`,
  RUN_SIMULATE_POLICY:     `${BASE}/api/run-simulate-policy`,
  RUN_SIMULATE_LAMBDA:     `${BASE}/api/run-simulate-lambda-policy`,
  RUN_S3_SECURITY_CHECK:   `${BASE}/api/run-s3-security-check`,
  GET_USER_ASSUMABLE_ROLES:`${BASE}/api/get-user-assumable-roles`,
  GET_SSO_GROUP_MEMBERS:   `${BASE}/api/get-sso-group-members`,
  ANALYZE_CUSTOM_POLICY:   `${BASE}/api/analyze-custom-policy`,
  RUN_FEDERATION:          `${BASE}/api/run-federation-audit`,
  RUN_CONFIG_SH_STATUS:    `${BASE}/api/run-config-sh-status-audit`,
  RUN_CONFIG_SH:           `${BASE}/api/run-config-sh-audit`,
  RUN_KMS:                 `${BASE}/api/run-kms-audit`,
  RUN_SECRETS_MANAGER:     `${BASE}/api/run-secrets-manager-audit`,
  RUN_CONNECTIVITY:        `${BASE}/api/run-connectivity-audit`,
  RUN_CODEPIPELINE:        `${BASE}/api/run-codepipeline-audit`,
};

// =====================================================
// 3b) Mapa RUNS para modo legacy (lo que espera app.js)
// =====================================================
API.RUNS = {
  iam:                 API.RUN_IAM,
  accessAnalyzer:      API.RUN_ACCESS_ANALYZER,
  securityhub:         API.RUN_SECURITYHUB,
  exposure:            API.RUN_EXPOSURE,
  guardduty:           API.RUN_GUARDDUTY,
  waf:                 API.RUN_WAF,
  cloudtrail:          API.RUN_CLOUDTRAIL,
  cloudwatch:          API.RUN_CLOUDWATCH,
  inspector:           API.RUN_INSPECTOR,
  acm:                 API.RUN_ACM,
  compute:             API.RUN_COMPUTE,
  ecr:                 API.RUN_ECR,
  databases:           API.RUN_DATABASES,
  'kms-secrets':       API.RUN_KMS,
  network_policies:    API.RUN_NETWORK_POLICIES,   // con guion bajo (fallback)
  'network-policies':  API.RUN_NETWORK_POLICIES,   // con guion (UI)
  connectivity:        API.RUN_CONNECTIVITY,
  config_sh_status:    API.RUN_CONFIG_SH_STATUS,   // con guion bajo (fallback)
  'config-sh':         API.RUN_CONFIG_SH_STATUS,   // con guion (UI)
  codepipeline:        API.RUN_CODEPIPELINE,
  federation:          API.RUN_FEDERATION,
  secrets_manager:     API.RUN_SECRETS_MANAGER,    // con guion bajo (fallback)
};

// =====================================================
// 4) HEADERS, TIMERS y EXPORT GLOBAL
// =====================================================
const DEFAULT_HEADERS = { 'Content-Type': 'application/json' };
const TIMERS = { BULK_POLL_INTERVAL_MS: 2000, BULK_TIMEOUT_MIN: 45 };

const CONSTANTS = Object.freeze({ BASE, API, DEFAULT_HEADERS, TIMERS });

// Exponer en ventana (lo que usa app.js)
window.CONSTANTS = CONSTANTS;

// Útil para depurar en consola (no requerido por app.js)
window.API = API;
window.ICONS = ICONS;
