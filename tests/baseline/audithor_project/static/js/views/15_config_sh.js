/**
 * 15_config_sh.js
 * Contains all logic for building and rendering the AWS Config & Security Hub view. (CORREGIDO)
 */

// --- IMPORTS ---
import { handleTabClick, createStatusBadge, log, setupPaginationNew } from '../utils.js';


function processFrameworkSummaryData(findings = []) {
    if (!Array.isArray(findings)) return {};

    const summary = {};
    // --- NUEVO: Objeto para almacenar los totales generales ---
    const overallTotals = {
        total: 0,
        passed: 0,
        failed: 0,
        severities: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    };

    const getFramework = (finding) => {
        if (finding.ProductFields && finding.ProductFields['StandardsArn']) {
            const sa = finding.ProductFields['StandardsArn'];
            if (sa.includes('pci-dss')) return 'PCI DSS';
            if (sa.includes('aws-foundational-security-best-practices')) return 'AWS FSBP';
            if (sa.includes('cis')) return 'CIS';
            if (sa.includes('nist')) return 'NIST';
            return 'Other Standard';
        } else if (finding.ProductName) {
            return finding.ProductName;
        }
        return 'Unknown';
    };
    
    const relevantFindings = findings.filter(f => f.Compliance && ['PASSED', 'FAILED'].includes(f.Compliance.Status));

    for (const finding of relevantFindings) {
        const framework = getFramework(finding);
        if (framework === 'Unknown') continue;

        if (!summary[framework]) {
            summary[framework] = {
                total: 0,
                passed: 0,
                failed: 0,
                severities: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
            };
        }

        // Actualizar contadores por framework
        summary[framework].total++;
        const status = finding.Compliance.Status;
        
        // --- NUEVO: Actualizar contadores generales ---
        overallTotals.total++;

        if (status === 'PASSED') {
            summary[framework].passed++;
            overallTotals.passed++; // <- Añadido
        } else if (status === 'FAILED') {
            summary[framework].failed++;
            overallTotals.failed++; // <- Añadido
            const severity = finding.Severity?.Label || 'LOW';
            if (summary[framework].severities[severity] !== undefined) {
                summary[framework].severities[severity]++;
                overallTotals.severities[severity]++; // <- Añadido
            }
        }
    }

    // --- NUEVO: Devolver un objeto con ambos resultados ---
    return { frameworkData: summary, overallTotals };
}

function renderFrameworkSummaryTable(summaryObject) {
    const { frameworkData, overallTotals } = summaryObject;

    if (Object.keys(frameworkData).length === 0) {
        return '<p class="text-center text-gray-500 mt-8">No compliance summary data available to display.</p>';
    }

    const severityColors = {
        CRITICAL: 'bg-red-600 text-white',
        HIGH: 'bg-orange-500 text-white',
        MEDIUM: 'bg-yellow-400 text-black',
        LOW: 'bg-blue-500 text-white'
    };
    
    const getProgressBar = (passed, total) => {
        const percentage = total > 0 ? Math.round((passed / total) * 100) : 100;
        let colorClass = 'bg-green-500'; // Verde por defecto para >= 80%
        if (percentage < 50) {
            colorClass = 'bg-red-500';
        } else if (percentage < 80) {
            colorClass = 'bg-yellow-500';
        }
        
        return `
            <div class="flex items-center">
                <span class="w-12 text-sm font-bold text-gray-800">${percentage}%</span>
                <div class="w-full bg-gray-200 rounded-full h-3 ml-2">
                    <div class="${colorClass} h-3 rounded-full" style="width: ${percentage}%"></div>
                </div>
            </div>
        `;
    };
    
    const sortedFrameworks = Object.keys(frameworkData).sort();

    let tableRows = sortedFrameworks.map(framework => {
        const data = frameworkData[framework];
        
        const severitiesHtml = Object.entries(data.severities)
            .filter(([, count]) => count > 0)
            .map(([severity, count]) => `<span class="inline-block text-xs font-semibold mr-2 px-2.5 py-1 rounded-full ${severityColors[severity] || ''}">${severity}: ${count}</span>`)
            .join('');

        return `
            <tr class="hover:bg-gray-50">
                <td class="px-5 py-4 whitespace-nowrap"><div class="text-sm font-semibold text-gray-800">${framework}</div></td>
                <td class="px-5 py-4 whitespace-nowrap text-sm font-bold text-center text-gray-700">${data.total}</td>
                <td class="px-5 py-4 whitespace-nowrap text-sm font-bold text-center text-green-600">${data.passed}</td>
                <td class="px-5 py-4 whitespace-nowrap text-sm font-bold text-center text-red-600">${data.failed}</td>
                <td class="px-5 py-4">${getProgressBar(data.passed, data.total)}</td>
                <td class="px-5 py-4 text-sm text-gray-600">${severitiesHtml || '-'}</td>
            </tr>`;
    }).join('');

    const totalSeveritiesHtml = Object.entries(overallTotals.severities)
        .filter(([, count]) => count > 0)
        .map(([severity, count]) => `<span class="inline-block text-xs font-semibold mr-2 px-2.5 py-1 rounded-full ${severityColors[severity] || ''}">${severity}: ${count}</span>`)
        .join('');

    let footerRow = `
        <tr class="bg-gray-100 font-bold border-t-2 border-gray-300">
            <td class="px-5 py-4 text-sm text-gray-900">OVERALL</td>
            <td class="px-5 py-4 text-center text-sm text-gray-900">${overallTotals.total}</td>
            <td class="px-5 py-4 text-center text-sm text-green-700">${overallTotals.passed}</td>
            <td class="px-5 py-4 text-center text-sm text-red-700">${overallTotals.failed}</td>
            <td class="px-5 py-4">${getProgressBar(overallTotals.passed, overallTotals.total)}</td>
            <td class="px-5 py-4">${totalSeveritiesHtml}</td>
        </tr>
    `;

    return `
        <div class="mt-8 bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
            <h3 class="text-lg font-bold text-[#204071] mb-4">Compliance Summary by Framework</h3>
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Framework</th>
                        <th class="px-5 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Total Checks</th>
                        <th class="px-5 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Passed</th>
                        <th class="px-5 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider">Failed</th>
                        <th class="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Compliance</th>
                        <th class="px-5 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Failed Findings Breakdown</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    ${tableRows}
                </tbody>
                <tfoot class="bg-gray-50">
                    ${footerRow}
                </tfoot>
            </table>
        </div>
    `;
}


// --- MAIN VIEW FUNCTION (EXPORTED) ---


export const buildConfigSHView = () => {
    const container = document.getElementById('config-sh-view');
    const executionDate = (window.configSHApiData || window.configSHStatusApiData)?.metadata?.executionDate || 'Analysis not run.';

    const modalHtml = `
        <div id="finding-details-modal" class="fixed inset-0 bg-gray-800 bg-opacity-75 flex items-center justify-center z-50 hidden transition-opacity duration-300">
            <div id="modal-panel" class="bg-white rounded-2xl shadow-2xl w-full max-w-3xl max-h-[90vh] flex flex-col transform transition-all duration-300 scale-95 opacity-0">
                <header class="flex items-center justify-between p-5 border-b border-gray-200">
                    <h3 id="modal-title" class="text-xl font-bold text-[#204071]">Finding Details</h3>
                    <button id="modal-close-btn" class="text-gray-400 hover:text-gray-600">
                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                    </button>
                </header>
                <main id="modal-body" class="p-6 overflow-y-auto"></main>
            </div>
        </div>
    `;

    // --- NOVEDAD: Separamos la lógica para decidir qué mostrar en la sección de resumen ---
    let summaryContentHtml;
    if (window.configSHApiData) {
        // Si SÍ tenemos datos del análisis profundo, mostramos la tabla de resultados.
        const findings = window.configSHApiData.results?.findings || [];
        const frameworkSummaryData = processFrameworkSummaryData(findings);
        summaryContentHtml = renderFrameworkSummaryTable(frameworkSummaryData);
    } else {
        // Si NO tenemos datos, mostramos el panel con el botón para iniciar el análisis.
        summaryContentHtml = `
            <div class="mt-8 bg-white p-6 rounded-xl shadow-sm border border-gray-100 text-center">
                <div class="max-w-md mx-auto">
                    <button id="run-deep-scan-btn" class="inline-flex items-center justify-center bg-[#eb3496] text-white px-5 py-2.5 rounded-lg font-bold text-md hover:bg-[#d42c86] transition disabled:opacity-50 disabled:cursor-not-allowed">
                        <div id="deep-scan-spinner" class="spinner-sm mr-2 hidden"></div>
                        <span id="deep-scan-btn-text">Run Deep Dive Analysis</span>
                    </button>
                    <div id="deep-scan-error-container" class="mt-4 text-left"></div>
                </div>
            </div>
        `;
    }

    const service_status_data = window.configSHStatusApiData?.results?.service_status || [];

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Config & Security Hub Status</h2>
                <p class="text-sm text-gray-500">${executionDate}</p>
            </div>
        </header>
        <div id="config-sh-results-view">
            <div class="border-b border-gray-200 mb-6">
                <nav class="-mb-px flex flex-wrap space-x-6" id="config-sh-tabs">
                    <a href="#" data-tab="config-sh-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                    <a href="#" data-tab="config-sh-status-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Service Status</a>
                    <a href="#" data-tab="config-sh-findings-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">All Findings</a>
                </nav>
            </div>
            <div id="config-sh-tab-content-container">
                <div id="config-sh-summary-content" class="config-sh-tab-content">
                    ${createConfigSHSummaryCardsHtml()}
                    <div id="framework-summary-container">${summaryContentHtml}</div>
                </div>
                <div id="config-sh-status-content" class="config-sh-tab-content hidden">${renderConfigSHStatusTable(service_status_data)}</div>
                <div id="config-sh-findings-content" class="config-sh-tab-content hidden"></div>
            </div>
        </div>
        ${modalHtml}`;

    // Actualizamos las tarjetas de resumen y la tabla de findings si hay datos
    if (window.configSHApiData) {
        const findings = window.configSHApiData.results?.findings || [];
        updateConfigSHSummaryCards(service_status_data, findings);
        renderAllFindingsTable(findings);
    } else {
        // Si no hay datos, al menos actualizamos las tarjetas con la información de estado
        updateConfigSHSummaryCards(service_status_data, []);
    }
    
    // --- NOVEDAD: Añadimos el "escuchador" para el botón SOLO si se ha renderizado ---
    const deepScanBtn = document.getElementById('run-deep-scan-btn');
    if (deepScanBtn) {
        deepScanBtn.addEventListener('click', runDeepConfigSHAnalysis);
    }
    
    // El resto de los listeners se mantienen igual
    const tabsNav = container.querySelector('#config-sh-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.config-sh-tab-content'));
    
    const modal = document.getElementById('finding-details-modal');
    const modalPanel = document.getElementById('modal-panel');
    const closeBtn = document.getElementById('modal-close-btn');

    const closeModal = () => {
        modalPanel.classList.remove('scale-100', 'opacity-100');
        modalPanel.classList.add('scale-95', 'opacity-0');
        modal.classList.add('opacity-0');
        setTimeout(() => { modal.classList.add('hidden'); }, 300);
    };
    
    if (modal && closeBtn && modalPanel) {
        closeBtn.addEventListener('click', closeModal);
        modal.addEventListener('click', (event) => { if (event.target === modal) { closeModal(); } });
    }
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---
async function runDeepConfigSHAnalysis() {
    const runBtn = document.getElementById('run-deep-scan-btn');
    const btnText = document.getElementById('deep-scan-btn-text');
    const spinner = document.getElementById('deep-scan-spinner');
    // Nuevo: Selector para el contenedor de errores
    const errorContainer = document.getElementById('deep-scan-error-container');
    
    if (!runBtn || !btnText || !spinner) {
        log('Error: Required elements not found for deep scan', 'error');
        return;
    }
    
    // Resetear estado antes de empezar
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Analyzing… (this can take a few minutes)';
    if (errorContainer) {
        errorContainer.classList.add('hidden'); // Ocultar errores previos
        errorContainer.innerHTML = '';
    }
    log('Starting deep analysis of Config & Security Hub…', 'info');

    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');

    if (!accessKeyInput || !secretKeyInput) {
        log('Error: Credential inputs not found', 'error');
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Run Deep Dive Analysis';
        return;
    }

    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
    };

    try {
        const deepConfigEndpoint = window.CONSTANTS?.API?.RUN_CONFIG_SH || `${window.location.origin}/api/run-config-sh-audit`;
        const response = await fetch(deepConfigEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || `HTTP ${response.status}`);
        }
        
        const responseData = await response.json();
        
        if (!responseData || !responseData.results) {
            throw new Error('Invalid response structure from deep scan API');
        }
        
        window.configSHApiData = responseData;
        
        log('Deep analysis of Config & Security Hub completed.', 'success');
        
        buildConfigSHView();

        if (window.runAndDisplayHealthyStatus) {
            window.runAndDisplayHealthyStatus();
        }

    } catch (e) {
        log(`Error in deep analysis: ${e.message}`, 'error');
        console.error('Deep scan error details:', e);
        
        // Modificado: Muestra el error en su contenedor sin borrar el botón
        if(errorContainer) {
            errorContainer.innerHTML = `
                <div class="bg-red-50 text-red-700 p-4 rounded-lg">
                    <h4 class="font-bold">Error</h4>
                    <p>${e.message}</p>
                </div>`;
            errorContainer.classList.remove('hidden');
        }
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Run Deep Dive Analysis';
    }
}

function createConfigSHSummaryCardsHtml() {
    return `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Regions with Config</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-config-enabled" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-ui-checks w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M7 2.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zM2 1a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2zm0 8a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-2a2 2 0 0 0-2-2zm.854-3.646a.5.5 0 0 1-.708 0l-1-1a.5.5 0 1 1 .708-.708l.646.647 1.646-1.647a.5.5 0 1 1 .708.708zm0 8a.5.5 0 0 1-.708 0l-1-1a.5.5 0 0 1 .708-.708l.646.647 1.646-1.647a.5.5 0 0 1 .708.708zM7 10.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zm0-5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m0 8a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Regions with Security Hub</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-sh-enabled" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-ui-checks w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M7 2.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zM2 1a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2V3a2 2 0 0 0-2-2zm0 8a2 2 0 0 0-2 2v2a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2v-2a2 2 0 0 0-2-2zm.854-3.646a.5.5 0 0 1-.708 0l-1-1a.5.5 0 1 1 .708-.708l.646.647 1.646-1.647a.5.5 0 1 1 .708.708zm0 8a.5.5 0 0 1-.708 0l-1-1a.5.5 0 0 1 .708-.708l.646.647 1.646-1.647a.5.5 0 0 1 .708.708zM7 10.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-7a.5.5 0 0 1-.5-.5zm0-5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m0 8a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Total Compliance Checks</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-total-checks" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-exclamation w-6 h-6 text-orange-600" viewBox="0 0 16 16"><path d="M5.338 1.59a61 61 0 0 0-2.837.856.48.48 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.7 10.7 0 0 0 2.287 2.233c.346.244.652.42.893.533q.18.085.293.118a1 1 0 0 0 .101.025 1 1 0 0 0 .1-.025q.114-.034.294-.118c.24-.113.547-.29.893-.533a10.7 10.7 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.8 11.8 0 0 1-2.517 2.453 7 7 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7 7 0 0 1-1.048-.625 11.8 11.8 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 63 63 0 0 1 5.072.56"/><path d="M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Total Failed Findings</p></div>
            <div class="flex justify-between items-end pt-4"><p id="config-sh-failed-findings" class="text-3xl font-bold text-red-600">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-exclamation w-6 h-6 text-red-600" viewBox="0 0 16 16"><path d="M5.338 1.59a61 61 0 0 0-2.837.856.48.48 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.7 10.7 0 0 0 2.287 2.233c.346.244.652.42.893.533q.18.085.293.118a1 1 0 0 0 .101.025 1 1 0 0 0 .1-.025q.114-.034.294-.118c.24-.113.547-.29.893-.533a10.7 10.7 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.8 11.8 0 0 1-2.517 2.453 7 7 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7 7 0 0 1-1.048-.625 11.8 11.8 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 63 63 0 0 1 5.072.56"/><path d="M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z"/></svg></div>
            </div>
        </div>
    </div>
    `;
}

function updateConfigSHSummaryCards(serviceStatus = [], findings = []) {
    if (!Array.isArray(serviceStatus)) {
        console.warn('serviceStatus is not an array:', serviceStatus);
        serviceStatus = [];
    }
    if (!Array.isArray(findings)) {
        console.warn('findings is not an array:', findings);
        findings = [];
    }

    const complianceFindings = findings.filter(f => {
        const isInspectorFinding = (f.GeneratorId || '').includes('inspector') || (f.ProductName || '').toLowerCase() === 'inspector';
        const hasValidStatus = f.Compliance && (f.Compliance.Status === 'PASSED' || f.Compliance.Status === 'FAILED');
        return !isInspectorFinding && hasValidStatus;
    });

    const totalFailedCount = complianceFindings.filter(f => f.Compliance.Status === 'FAILED').length;

    const totalRegions = serviceStatus.length;
    const configEnabledCount = serviceStatus.filter(s => s.ConfigEnabled).length;
    const shEnabledCount = serviceStatus.filter(s => s.SecurityHubEnabled).length;
    
    const configElement = document.getElementById('config-sh-config-enabled');
    const shElement = document.getElementById('config-sh-sh-enabled');
    const totalChecksElement = document.getElementById('config-sh-total-checks');
    const failedElement = document.getElementById('config-sh-failed-findings');

    if (configElement) configElement.textContent = `${configEnabledCount} / ${totalRegions}`;
    if (shElement) shElement.textContent = `${shEnabledCount} / ${totalRegions}`;
    if (totalChecksElement) totalChecksElement.textContent = complianceFindings.length;
    if (failedElement) failedElement.textContent = totalFailedCount;
}

function renderConfigSHStatusTable(serviceStatus = []) {
    // CORRECCIÓN: Validar que serviceStatus es un array
    if (!Array.isArray(serviceStatus)) {
        console.warn('serviceStatus is not an array:', serviceStatus);
        serviceStatus = [];
    }
    
    if (serviceStatus.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">Service status could not be retrieved by region.</p></div>';
    }

    const activeRegions = serviceStatus.filter(s => s.ConfigEnabled || s.SecurityHubEnabled);
    if (activeRegions.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No regions with AWS Config or Security Hub enabled.</p></div>';
    }
    
    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">AWS Config</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">AWS Security Hub</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Security Hub Standards</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Conformance Packs</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    activeRegions.forEach(s => {
        const configBadge = s.ConfigEnabled ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        const shBadge = s.SecurityHubEnabled ? createStatusBadge('Enabled') : createStatusBadge('Disabled');
        
        let standardsHtml = '-';
        if (s.EnabledStandards && Array.isArray(s.EnabledStandards) && s.EnabledStandards.length > 0) {
            standardsHtml = '<div class="flex flex-col items-start gap-1">' + 
                            s.EnabledStandards.map(arn => {
                                const shortName = arn.split(/[/:]standards\//).pop() || arn;
                                return `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-blue-100 text-blue-800">${shortName}</span>`
                            }).join('') +
                            '</div>';
        }
        
        let conformancePacksHtml = '-';
        if (s.EnabledConformancePacks && Array.isArray(s.EnabledConformancePacks) && s.EnabledConformancePacks.length > 0) {
            conformancePacksHtml = '<div class="flex flex-col items-start gap-1">' +
                                s.EnabledConformancePacks.map(cp => `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-gray-200 text-gray-800">${cp}</span>`).join('') +
                                '</div>';
        }

        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm font-medium text-gray-800">${s.Region || 'Unknown'}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${configBadge}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${shBadge}</td>
                        <td class="px-4 py-4 align-top text-sm">${standardsHtml}</td>
                        <td class="px-4 py-4 align-top text-sm">${conformancePacksHtml}</td> 
                    </tr>`;
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
}

function renderAllFindingsTable(findings = []) {
    const container = document.getElementById('config-sh-findings-content');
    if (!container) return;

    if (!Array.isArray(findings)) {
        console.warn('findings is not an array:', findings);
        findings = [];
    }

    const filteredFindings = findings.filter(f => {
        const isInspectorFinding = (f.GeneratorId || '').includes('inspector') || (f.ProductName || '').toLowerCase() === 'inspector';
        const hasValidStatus = f.Compliance && (f.Compliance.Status === 'PASSED' || f.Compliance.Status === 'FAILED');
        return !isInspectorFinding && hasValidStatus;
    });

    if (filteredFindings.length === 0) {
        container.innerHTML = `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No Security Hub compliance findings (PASSED/FAILED) were found.</p></div>`;
        return;
    }

    const getResourceType = (finding) => {
        const resourceType = finding.Resources?.[0]?.Type;
        if (resourceType) {
            const typeMapping = {
                'AwsEc2Instance': 'EC2 Instance', 'AwsS3Bucket': 'S3 Bucket', 'AwsEc2SecurityGroup': 'Security Group',
                'AwsIamRole': 'IAM Role', 'AwsIamUser': 'IAM User', 'AwsIamPolicy': 'IAM Policy', 'AwsLambdaFunction': 'Lambda Function',
                'AwsEc2Vpc': 'VPC', 'AwsEc2Subnet': 'Subnet', 'AwsElbv2LoadBalancer': 'Load Balancer', 'AwsElbLoadBalancer': 'Classic Load Balancer',
                'AwsRdsDbInstance': 'RDS Instance', 'AwsRdsDbCluster': 'RDS Cluster', 'AwsCloudFrontDistribution': 'CloudFront',
                'AwsApiGatewayRestApi': 'API Gateway', 'AwsKmsKey': 'KMS Key', 'AwsSecretsManagerSecret': 'Secrets Manager',
                'AwsEcsCluster': 'ECS Cluster', 'AwsEksCluster': 'EKS Cluster', 'AwsSnsSubscription': 'SNS', 'AwsSqsQueue': 'SQS Queue',
                'AwsCloudTrailTrail': 'CloudTrail', 'AwsCloudWatchAlarm': 'CloudWatch', 'AwsAutoScalingGroup': 'Auto Scaling',
                'AwsConfigConfigurationRecorder': 'Config', 'AwsGuardDutyDetector': 'GuardDuty', 'AwsWafWebAcl': 'WAF',
                'AwsCodeBuildProject': 'CodeBuild', 'AwsCodePipelinePipeline': 'CodePipeline', 'AwsRedshiftCluster': 'Redshift',
                'AwsElasticSearchDomain': 'OpenSearch', 'AwsBackupBackupVault': 'Backup Vault', 'AwsEcrRepository': 'ECR Repository'
            };
            const mappedType = typeMapping[resourceType];
            if (mappedType) return mappedType;
            return resourceType.replace(/^Aws/, '').replace(/([A-Z])/g, ' $1').trim();
        }
        const resourceId = finding.Resources?.[0]?.Id || '';
        if (resourceId.includes(':instance/')) return 'EC2 Instance'; if (resourceId.includes(':bucket/')) return 'S3 Bucket';
        if (resourceId.includes(':security-group/')) return 'Security Group'; if (resourceId.includes(':role/')) return 'IAM Role';
        if (resourceId.includes(':user/')) return 'IAM User'; if (resourceId.includes(':policy/')) return 'IAM Policy';
        if (resourceId.includes(':function/')) return 'Lambda Function';
        return 'Other';
    };

    const uniqueValues = {
        severities: [...new Set(filteredFindings.map(f => f.Severity?.Label).filter(Boolean))],
        regions: [...new Set(filteredFindings.map(f => f.Region).filter(Boolean))],
        frameworks: [...new Set(filteredFindings.map(f => {
            if (f.ProductFields && f.ProductFields['StandardsArn']) {
                const standardsArn = f.ProductFields['StandardsArn'];
                if (standardsArn.includes('pci-dss')) return 'PCI DSS';
                if (standardsArn.includes('aws-foundational-security-best-practices')) return 'AWS FSBP';
                if (standardsArn.includes('cis')) return 'CIS';
                if (standardsArn.includes('nist')) return 'NIST';
                return 'Other Standard';
            } else if (f.ProductName) {
                return f.ProductName;
            }
            return null;
        }).filter(Boolean))],
        resourceTypes: [...new Set(filteredFindings.map(f => getResourceType(f)).filter(Boolean))]
    };

    uniqueValues.severities.sort((a, b) => {
        const order = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4 };
        return (order[a] || 99) - (order[b] || 99);
    });
    uniqueValues.regions.sort();
    uniqueValues.frameworks.sort();
    uniqueValues.resourceTypes.sort();

    const severityOrder = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4 };
    filteredFindings.sort((a, b) => {
        const severityA = severityOrder[a.Severity?.Label] ?? 99;
        const severityB = severityOrder[b.Severity?.Label] ?? 99;
        return severityA - severityB;
    });
    
    // --- CAMBIO: Se elimina la columna "Resource ID" de la fila de la tabla ---
    let tableRowsHtml = filteredFindings.map((f, index) => {
        const severity = f.Severity?.Label || 'N/A';
        const title = f.Title || 'No Title';
        const region = f.Region || 'Global';
        // const resourceId = f.Resources?.[0]?.Id || 'N/A'; // Ya no se usa
        const status = f.Compliance?.Status || 'N/A';
        
        let framework = 'N/A';
        if (f.ProductFields && f.ProductFields['StandardsArn']) {
            const sa = f.ProductFields['StandardsArn'];
            if (sa.includes('pci-dss')) framework = 'PCI DSS';
            else if (sa.includes('aws-foundational-security-best-practices')) framework = 'AWS FSBP';
            else if (sa.includes('cis')) framework = 'CIS';
            else if (sa.includes('nist')) framework = 'NIST';
            else framework = 'Other Standard';
        } else if (f.ProductName) {
            framework = f.ProductName;
        }
        
        const severityBadgeColor = {
            'CRITICAL': 'bg-red-100 text-red-800', 'HIGH': 'bg-orange-100 text-orange-800',
            'MEDIUM': 'bg-yellow-100 text-yellow-800', 'LOW': 'bg-blue-100 text-blue-800',
            'INFORMATIONAL': 'bg-gray-100 text-gray-800'
        }[severity] || 'bg-gray-100 text-gray-800';

        const statusBadgeColor = {
            'PASSED': 'bg-green-100 text-green-800',
            'FAILED': 'bg-red-100 text-red-800'
        }[status] || 'bg-gray-100 text-gray-800';

        return `
            <tr class="finding-row hover:bg-gray-50 cursor-pointer" data-finding-index="${index}">
                <td class="px-4 py-3 align-top"><span class="px-2.5 py-1 text-xs font-bold rounded-full ${severityBadgeColor}">${severity}</span></td>
                <td class="px-4 py-3 align-top text-sm font-medium text-gray-800">${title}</td>
                <td class="px-4 py-3 align-top text-sm text-gray-600">${region}</td>
                <td class="px-4 py-3 align-top text-sm text-gray-600">
                    <span class="px-2 py-1 text-xs font-medium rounded-md bg-blue-50 text-blue-700">${framework}</span>
                </td>
                <td class="px-4 py-3 align-top"><span class="px-2.5 py-1 text-xs font-bold rounded-full ${statusBadgeColor}">${status}</span></td>
            </tr>`;
    }).join('');

    // --- CAMBIO: Se restaura el HTML completo de los filtros y la cabecera de la tabla ---
    container.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
            <div class="bg-gradient-to-r from-white to-gray-50 p-6 rounded-2xl border border-gray-200 shadow-sm mb-6">
                <div class="flex items-center justify-between mb-4">
                     <div class="flex items-center space-x-2">
                        <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-5 h-5 text-[#eb3496]" viewBox="0 0 16 16">
                            <path d="M6 10.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3a.5.5 0 0 1-.5-.5m-2-3a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 0 1h-7a.5.5 0 0 1-.5-.5m-2-3a.5.5 0 0 1 .5-.5h11a.5.5 0 0 1 0 1h-11a.5.5 0 0 1-.5-.5"/>
                        </svg>
                        <h3 class="text-lg font-bold text-gray-800">Filter Options</h3>
                    </div>
                    <div id="findings-count-display-sh" class="bg-[#eb3496] text-white px-3 py-1 rounded-full text-sm font-semibold"></div>
                </div>
                <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-6 gap-4 mb-4">
                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">Status</label>
                        <select id="status-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Statuses</option>
                            <option value="FAILED">Failed</option>
                            <option value="PASSED">Passed</option>
                        </select>
                    </div>
                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">Severity</label>
                        <select id="severity-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Severities</option>
                            ${uniqueValues.severities.map(s => `<option value="${s}">${s}</option>`).join('')}
                        </select>
                    </div>
                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">Region</label>
                        <select id="region-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Regions</option>
                            ${uniqueValues.regions.map(r => `<option value="${r}">${r}</option>`).join('')}
                        </select>
                    </div>
                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">Framework</label>
                        <select id="framework-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Frameworks</option>
                            ${uniqueValues.frameworks.map(f => `<option value="${f}">${f}</option>`).join('')}
                        </select>
                    </div>
                    <div class="group">
                        <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">Resource Type</label>
                        <select id="resource-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                            <option value="">All Resources</option>
                            ${uniqueValues.resourceTypes.map(r => `<option value="${r}">${r}</option>`).join('')}
                        </select>
                    </div>
                    <div class="group">
                         <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">Search</label>
                        <input type="text" id="search-filter" placeholder="Title or resource ID..." class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                    </div>
                </div>
                 <div class="flex justify-between items-center pt-4 border-t border-gray-200">
                     <button id="clear-filters" class="inline-flex items-center px-4 py-2 text-sm font-medium text-[#eb3496] bg-pink-50 border border-pink-200 rounded-xl hover:bg-pink-100 hover:border-[#eb3496] transition-all duration-200 group">
                        Clear All Filters
                    </button>
                </div>
            </div>
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Framework</th>
                        <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                    </tr>
                </thead>
                <tbody id="config-sh-findings-tbody" class="bg-white divide-y divide-gray-200">${tableRowsHtml}</tbody>
            </table>
        </div>`;
    
    // El resto de la función (setTimeout con los listeners y applyFilters) no necesita cambios
    const applyFilters = () => { /* ... sin cambios aquí ... */ };
    setTimeout(() => {
        document.getElementById('status-filter').addEventListener('change', applyFilters);
        document.getElementById('severity-filter').addEventListener('change', applyFilters);
        document.getElementById('region-filter').addEventListener('change', applyFilters);
        document.getElementById('framework-filter').addEventListener('change', applyFilters);
        document.getElementById('resource-filter').addEventListener('change', applyFilters);
        document.getElementById('search-filter').addEventListener('input', applyFilters);
        
        document.getElementById('clear-filters').addEventListener('click', () => {
            document.getElementById('status-filter').value = '';
            document.getElementById('severity-filter').value = '';
            document.getElementById('region-filter').value = '';
            document.getElementById('framework-filter').value = '';
            document.getElementById('resource-filter').value = '';
            document.getElementById('search-filter').value = '';
            applyFilters();
        });

        const tableBody = document.getElementById('config-sh-findings-tbody');
        if (tableBody) {
            tableBody.addEventListener('click', (event) => {
                const row = event.target.closest('.finding-row');
                if (row) {
                    const findingIndex = row.dataset.findingIndex;
                    const findingData = filteredFindings[findingIndex];
                    if (findingData) {
                        renderFindingDetailsModal(findingData);
                    }
                }
            });
        }
        
        applyFilters();
    }, 50);
}


// --- NOVEDAD: Función para poblar y mostrar el modal con los detalles del finding ---
function renderFindingDetailsModal(finding) {
    const modal = document.getElementById('finding-details-modal');
    const modalPanel = document.getElementById('modal-panel');
    const modalTitle = document.getElementById('modal-title');
    const modalBody = document.getElementById('modal-body');

    if (!modal || !modalTitle || !modalBody || !modalPanel) return;

    // Poblar el título
    modalTitle.textContent = finding.Title || 'Finding Details';
    
    // Función auxiliar para crear filas de detalles
    const createDetailRow = (label, value, isHtml = false) => {
        if (!value || value === 'N/A') return '';
        return `
            <div class="grid grid-cols-1 md:grid-cols-4 py-3 border-b border-gray-100">
                <dt class="text-sm font-semibold text-gray-600 md:col-span-1">${label}</dt>
                <dd class="text-sm text-gray-800 mt-1 md:mt-0 md:col-span-3">${isHtml ? value : value.toString().replace(/\n/g, '<br>')}</dd>
            </div>
        `;
    };

    // Construir el HTML del cuerpo del modal
    let bodyHtml = '<dl>';
    bodyHtml += createDetailRow('Description', finding.Description);
    bodyHtml += createDetailRow('Severity', `<span class="px-2.5 py-1 text-xs font-bold rounded-full ${
        {
            'CRITICAL': 'bg-red-100 text-red-800', 'HIGH': 'bg-orange-100 text-orange-800',
            'MEDIUM': 'bg-yellow-100 text-yellow-800', 'LOW': 'bg-blue-100 text-blue-800'
        }[finding.Severity?.Label] || 'bg-gray-100 text-gray-800'
    }">${finding.Severity?.Label}</span>`, true);
    bodyHtml += createDetailRow('Status', `<span class="px-2.5 py-1 text-xs font-bold rounded-full ${
        {'PASSED': 'bg-green-100 text-green-800', 'FAILED': 'bg-red-100 text-red-800'}[finding.Compliance?.Status] || 'bg-gray-100 text-gray-800'
    }">${finding.Compliance?.Status}</span>`, true);
    bodyHtml += createDetailRow('Account ID', finding.AwsAccountId);
    bodyHtml += createDetailRow('Region', finding.Region);

    if (finding.Resources && finding.Resources.length > 0) {
        const resource = finding.Resources[0];
        bodyHtml += createDetailRow('Resource Type', resource.Type);
        bodyHtml += createDetailRow('Resource ID', resource.Id, true);
    }
    
    if (finding.Remediation && finding.Remediation.Recommendation) {
        let remediationHtml = '';
        if (finding.Remediation.Recommendation.Text) {
            remediationHtml += `<p class="mb-2">${finding.Remediation.Recommendation.Text}</p>`;
        }
        if (finding.Remediation.Recommendation.Url) {
            remediationHtml += `<a href="${finding.Remediation.Recommendation.Url}" target="_blank" rel="noopener noreferrer" class="text-blue-600 hover:underline font-semibold">Open Remediation Guide &rarr;</a>`;
        }
        bodyHtml += createDetailRow('Remediation', remediationHtml, true);
    }

    bodyHtml += createDetailRow('Created At', new Date(finding.CreatedAt).toLocaleString());
    bodyHtml += createDetailRow('Updated At', new Date(finding.UpdatedAt).toLocaleString());
    bodyHtml += '</dl>';

    modalBody.innerHTML = bodyHtml;
    
    // Mostrar el modal con animación
    modal.classList.remove('hidden');
    setTimeout(() => {
        modal.classList.remove('opacity-0');
        modalPanel.classList.remove('scale-95', 'opacity-0');
        modalPanel.classList.add('scale-100', 'opacity-100');
    }, 10);
}
