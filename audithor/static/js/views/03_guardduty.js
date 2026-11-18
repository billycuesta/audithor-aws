/**
 * 03_guardduty.js
 * Contiene toda la lógica para construir y renderizar la vista de GuardDuty.
 */

// --- IMPORTACIONES ---
// Importamos las funciones de utilidad que necesita este módulo.
import { handleTabClick, createStatusBadge } from '../utils.js';
import { html, join, setHtml } from '../safe_html.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
    status: {
        title: "GuardDuty Status & Configuration",
        description: "Amazon GuardDuty is a threat detection service that continuously monitors your AWS accounts and workloads for malicious activity using machine learning, anomaly detection, and integrated threat intelligence.",
        useCases: "Automated threat detection, compliance monitoring, incident response triggers, security operations center (SOC) integration, real-time security alerting.",
        auditConsiderations: "Verify GuardDuty is enabled across all regions with business operations. Review data source configurations (S3 logs, Kubernetes logs, Malware Protection) to ensure comprehensive coverage. Confirm findings are being monitored and acted upon through proper incident response procedures."
    },
    findings: {
        title: "GuardDuty Findings Analysis",
        description: "GuardDuty findings represent potential security threats detected through analysis of DNS logs, VPC Flow Logs, CloudTrail events, and other data sources. Each finding includes severity levels, threat intelligence, and recommended actions.",
        useCases: "Threat hunting, incident investigation, security alert prioritization, compliance evidence collection, automated security response workflows.",
        auditConsiderations: "Review high and critical severity findings for immediate response. Validate that findings align with known security events and aren't false positives. Ensure findings are integrated with SIEM/SOAR tools and that response procedures are documented and tested."
    }
};

// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
// Exportamos la función principal para que app.js pueda usarla.
export const buildGuarddutyView = () => {
    const container = document.getElementById('guardduty-view');
    if (!window.guarddutyApiData) return;
    const { status, findings } = window.guarddutyApiData.results;

    setHtml(container, html`
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">GuardDuty Status & Findings</h2>
                <p class="text-sm text-gray-500">${window.guarddutyApiData.metadata.executionDate}</p>
            </div>
        </header>
<div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="guardduty-tabs">
                <a href="#" data-tab="gd-status-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Status per Region</a>
                <a href="#" data-tab="gd-findings-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Findings</a>
            </nav>
        </div>
        <div id="guardduty-tab-content-container">
            <div id="gd-status-content" class="guardduty-tab-content">
                ${renderServiceDescription(serviceDescriptions.status)}
                ${renderGuarddutyStatusTable(status)}
            </div>
            <div id="gd-findings-content" class="guardduty-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.findings)}
                <div id="gd-filter-controls" class="flex flex-wrap items-center gap-2 mb-4">
                    <span class="text-sm font-medium text-gray-700 mr-2">Filter by Severity:</span>
                    <button data-severity="ALL" class="gd-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-[#eb3496] text-white">All</button>
                    <button data-severity="CRITICAL" class="gd-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">Critical</button>
                    <button data-severity="HIGH" class="gd-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">High</button>
                    <button data-severity="MEDIUM" class="gd-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">Medium</button>
                    <button data-severity="LOW" class="gd-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">Low</button>
                </div>
                <div id="gd-findings-table-container"></div>
            </div>
        </div>
    `);

    const tabsNav = container.querySelector('#guardduty-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.guardduty-tab-content'));
    
    setupGuarddutyFindingsFilter();
};  

// --- SERVICE DESCRIPTION RENDERER ---
const renderServiceDescription = (serviceInfo) => html`
    <div class="bg-white border border-gray-200 rounded-lg p-6 mb-6">
        <h3 class="text-lg font-semibold text-gray-800 mb-3">${serviceInfo.title}</h3>
        <div class="space-y-3">
            <div>
                <h4 class="text-sm font-medium text-gray-700 mb-1">Definition:</h4>
                <p class="text-sm text-gray-600">${serviceInfo.description}</p>
            </div>
            <div>
                <h4 class="text-sm font-medium text-gray-700 mb-1">Common Use Cases:</h4>
                <p class="text-sm text-gray-600">${serviceInfo.useCases}</p>
            </div>
            <div class="bg-yellow-50 border border-yellow-200 rounded p-3">
                <h4 class="text-sm font-medium text-yellow-800 mb-1">Audit Considerations:</h4>
                <p class="text-sm text-yellow-700">${serviceInfo.auditConsiderations}</p>
            </div>
        </div>
    </div>
`;

// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const renderGuarddutyStatusTable = (statusList = []) => {
    const activeRegions = statusList.filter(s => (s.Status || '').toLowerCase() === 'enabled');

    if (activeRegions.length === 0) {
        return html`<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">GuardDuty is not enabled in any of the analyzed regions.</p></div>`;
    }

    const rows = activeRegions.map(s => html`<tr class="hover:bg-gray-50">
        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${s.Region}</td>
        <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(s.Status)}</td>
        <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(s['S3 Logs'])}</td>
        <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(s['Kubernetes Logs'])}</td>
        <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(s['Malware Protection'])}</td>
    </tr>`);
    const featureLists = activeRegions.map(s => {
        const collected = s.Enrichment?.features?.status === 'complete';
        const features = collected ? (s.Features ?? []).map(feature => html`<li class="py-1"><span class="font-medium">${feature.Name}</span>: ${feature.Status}${(feature.AdditionalConfiguration ?? []).map(additional => html`<span class="ml-2 text-gray-600">${additional.Name}: ${additional.Status}</span>`)}</li>`) : html`<li class="text-gray-500">Not collected</li>`;
        return html`<section class="mt-4 rounded-lg border border-gray-200 p-4"><h4 class="font-semibold text-gray-800">${s.Region} GuardDuty Features</h4><ul class="mt-2 text-sm text-gray-700">${Array.isArray(features) ? join(features) : features}</ul></section>`;
    });
    return html`<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">S3 Logs</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Kubernetes Logs</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Malware Protection</th>
    </tr></thead><tbody class="bg-white divide-y divide-gray-200">${join(rows)}</tbody></table>${join(featureLists)}</div>`;
};

const renderGuarddutyFindingsTable = (findings) => {
    if (!findings || findings.length === 0) {
        return html`<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No active GuardDuty findings were found.</p></div>`;
    }
    const severityClasses = {
        'CRITICAL': 'bg-red-600 text-white',
        'HIGH': 'bg-orange-500 text-white',
        'MEDIUM': 'bg-yellow-400 text-black',
        'LOW': 'bg-blue-500 text-white',
        'INFORMATIONAL': 'bg-gray-400 text-white'
    };
    const rows = findings.map(f => {
        const severity = f.SeverityLabel || 'N/A';
        const severityClass = severityClasses[severity] || 'bg-gray-200 text-gray-800';
        return html`<tr class="hover:bg-gray-50">
            <td class="px-4 py-4 whitespace-nowrap"><span class="px-2.5 py-0.5 text-xs font-semibold rounded-full ${severityClass}">${severity} (${f.SeverityScore})</span></td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${f.Region}</td>
            <td class="px-4 py-4 text-sm text-gray-800 break-words">${f.Title}</td>
            <td class="px-4 py-4 text-sm text-gray-600 break-words">${f.Resource}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${f.LastSeen}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${f.Source || 'Not collected'}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${f.CollectedAt || 'Not collected'}</td>
        </tr>`;
    });
    return html`<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Resource</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Seen</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Source</th>
        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Collected At</th>
    </tr></thead><tbody class="bg-white divide-y divide-gray-200">${join(rows)}</tbody></table></div>`;
};

const setupGuarddutyFindingsFilter = () => {
    const allFindings = window.guarddutyApiData.results.findings;
    const filterControlsContainer = document.getElementById('gd-filter-controls');
    const tableContainer = document.getElementById('gd-findings-table-container');

    if (!filterControlsContainer || !tableContainer) return;

    const renderFilteredFindings = (severity) => {
        let filteredFindings = allFindings;
        if (severity !== 'ALL') {
            filteredFindings = allFindings.filter(f => f.SeverityLabel === severity);
        }
        setHtml(tableContainer, renderGuarddutyFindingsTable(filteredFindings));
    };

    filterControlsContainer.addEventListener('click', (e) => {
        const filterBtn = e.target.closest('.gd-filter-btn');
        if (!filterBtn) return;

        filterControlsContainer.querySelectorAll('.gd-filter-btn').forEach(btn => {
            btn.classList.remove('bg-[#eb3496]', 'text-white');
            btn.classList.add('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        });
        filterBtn.classList.add('bg-[#eb3496]', 'text-white');
        filterBtn.classList.remove('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        
        const selectedSeverity = filterBtn.dataset.severity;
        renderFilteredFindings(selectedSeverity);
    });

    renderFilteredFindings('ALL');
};