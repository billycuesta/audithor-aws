import { renderCollectionNotice, emptyCollectionMessage, coverageIsComplete, mergeInspectorCoverage } from '../collection.js';
/**
 * 08_inspector.js
 * Contains all logic for building and rendering the AWS Inspector view.
 */

// --- IMPORTS ---
import { handleTabClick, log, createStatusBadge, setupPagination } from '../utils.js';


// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildInspectorView = () => {
    const container = document.getElementById('inspector-view');
    if (!window.inspectorApiData) return;

    const hasFindings = window.inspectorApiData.results.findings && window.inspectorApiData.results.findings.length > 0;
    const scanStatus = window.inspectorApiData.results.scan_status;

    if (hasFindings) {
        renderFullInspectorView(window.inspectorApiData.results.findings, window.securityHubApiData ? window.securityHubApiData.results.findings.inspectorFindings : []);
    } else {
        container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">Inspector</h2>
                    <p class="text-sm text-gray-500">${window.inspectorApiData.metadata.executionDate}</p>
                </div>
            </header>
            <div class="border-b border-gray-200 mb-6">
                <nav class="-mb-px flex flex-wrap space-x-6" id="inspector-tabs-initial">
                    <a href="#" data-tab="inspector-status-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                    <a href="#" data-tab="inspector-deep-scan-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Scan for Findings</a>
                </nav>
            </div>
            <div id="inspector-tab-content-container-initial">
                <div id="inspector-status-content" class="inspector-tab-content"></div>
                <div id="inspector-deep-scan-content" class="inspector-tab-content hidden">
                    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 text-center">
                        <p class="text-gray-600 mb-4">Searching all Inspector findings can be a slow process. Run it to obtain a detailed vulnerability analysis.</p>
                        <button id="run-deep-inspector-scan-btn" class="bg-[#eb3496] text-white px-5 py-2.5 rounded-lg font-bold text-md hover:bg-[#d42c86] transition flex items-center justify-center space-x-2 mx-auto">
                            <span id="deep-inspector-scan-btn-text">Search Inspector Findings</span>
                            <div id="deep-inspector-scan-spinner" class="spinner hidden"></div>
                        </button>
                        
                        <div id="deep-inspector-scan-error" class="hidden text-left"></div>

                    </div>
                </div>
            </div>
            <div id="inspector-results-view" class="hidden mt-6"></div>
        `;
        renderCollectionNotice(container, window.inspectorApiData);

        document.getElementById('inspector-status-content').innerHTML = renderInspectorStatusTable(scanStatus);
        document.getElementById('run-deep-inspector-scan-btn').addEventListener('click', runDeepInspectorAnalysis);
        const tabsNav = document.getElementById('inspector-tabs-initial');
        if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.inspector-tab-content'));
    }
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const runDeepInspectorAnalysis = async () => {
    const runBtn = document.getElementById('run-deep-inspector-scan-btn');
    const btnText = document.getElementById('deep-inspector-scan-btn-text');
    const spinner = document.getElementById('deep-inspector-scan-spinner');
    const errorContainer = document.getElementById('deep-inspector-scan-error');

    // Resetear estado antes de empezar
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Searching Findings…';
    if (errorContainer) {
        errorContainer.classList.add('hidden');
        errorContainer.innerHTML = '';
    }
    log('Starting deep search of Inspector findings…', 'info');

    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');

    if (!accessKeyInput.value.trim() || !secretKeyInput.value.trim()) {
        const errorMessage = 'Access Key or Secret Key not provided.';
        log(`Error in deep Inspector search: ${errorMessage}`, 'error');
        if (errorContainer) {
            errorContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg mt-4"><h4 class="font-bold">Error</h4><p>${errorMessage}</p></div>`;
            errorContainer.classList.remove('hidden');
        }
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Search Inspector Findings';
        return;
    }

    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
    };

    try {
        // --- CORRECCIÓN AQUÍ ---
        const inspectorFindingsEndpoint = window.CONSTANTS?.API?.RUN_INSPECTOR_FINDINGS || `${window.location.origin}/api/run-inspector-findings-audit`;
        const response = await fetch(inspectorFindingsEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', ...(window.activeScanId ? { 'X-Scan-Id': window.activeScanId } : {}) },
            body: JSON.stringify(payload)
        });
        const findingsData = await response.json();
        if (!response.ok) throw new Error(findingsData.error || 'Server error');

        window.inspectorApiData.results.findings = findingsData.results.findings || [];
        window.inspectorApiData.results.findingsStatus = findingsData.results.findingsStatus;
        // Preserve the original status scan before any findings attempt can overwrite merged coverage.
        window.inspectorApiData.results._statusCollection ??= window.inspectorApiData.results._collection;
        window.inspectorApiData.results._collection = mergeInspectorCoverage(
            window.inspectorApiData.results._statusCollection, findingsData.results._collection
        );
        
        const inspectorFindingsSH = window.securityHubApiData ? window.securityHubApiData.results.findings.inspectorFindings : [];

        renderFullInspectorView(window.inspectorApiData.results.findings, inspectorFindingsSH);

        log(coverageIsComplete(window.inspectorApiData)
            ? 'Deep Inspector analysis results rendered.'
            : 'Deep Inspector analysis results rendered with incomplete coverage; review collection details.',
        coverageIsComplete(window.inspectorApiData) ? 'success' : 'warning');

        // Evaluate collected findings even when optional collection coverage is incomplete.
        if (window.runAndDisplayHealthyStatus) {
            window.runAndDisplayHealthyStatus();
        }

    } catch(e) {
        window.inspectorApiData.results.findingsStatus = 'failed';
        window.inspectorApiData.results._statusCollection ??= window.inspectorApiData.results._collection;
        window.inspectorApiData.results._collection = mergeInspectorCoverage(
            window.inspectorApiData.results._statusCollection,
            { status: 'partial', coverageKnown: false, units: [
                { service: 'inspector2', operation: 'findings_api_request', status: 'failed', category: 'api_error' }
            ] }
        );
        renderCollectionNotice(document.getElementById('inspector-view'), window.inspectorApiData);
        log(`Error in deep Inspector search: ${e.message}`, 'error');
        if(errorContainer) {
            errorContainer.textContent = `Inspector findings search failed: ${e.message}`;
            errorContainer.classList.remove('hidden');
        }
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Search Inspector Findings';
    }
};

const renderSecurityHubFindingsPage = (tbodyContainer, findings, page, rowsPerPage) => {
    tbodyContainer.innerHTML = '';
    const start = (page - 1) * rowsPerPage;
    const end = start + rowsPerPage;
    const paginatedItems = findings.slice(start, end);

    const severityClasses = { 'CRITICAL': 'bg-red-600 text-white', 'HIGH': 'bg-orange-500 text-white', 'MEDIUM': 'bg-yellow-400 text-black', 'LOW': 'bg-blue-500 text-white', 'INFORMATIONAL': 'bg-gray-400 text-white' };
    let pageHtml = '';
    
    for (const f of paginatedItems) {
        const severity = f.Severity?.Label || 'N/A';
        const severityClass = severityClasses[severity] || 'bg-gray-200 text-gray-800';
        const region = f.Region || 'N/A';
        const title = f.Title || 'Untitled';
        const resourceType = f.Resources?.[0]?.Type || 'N/A';
        pageHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-2 whitespace-nowrap"><span class="px-2.5 py-0.5 text-xs font-semibold rounded-full ${severityClass}">${severity}</span></td>
                        <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-600">${region}</td>
                        <td class="px-4 py-2 text-sm text-gray-800 break-words">${title}</td>
                        <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-600">${resourceType}</td>
                     </tr>`;
    }
    tbodyContainer.innerHTML = pageHtml;
};

const createInspectorSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Active Regions</p></div><div class="flex justify-between items-end pt-4"><p id="inspector-active-regions" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-geo-alt w-6 h-6 text-green-700" viewBox="0 0 16 16">  <path d="M12.166 8.94c-.524 1.062-1.234 2.12-1.96 3.07A32 32 0 0 1 8 14.58a32 32 0 0 1-2.206-2.57c-.726-.95-1.436-2.008-1.96-3.07C3.304 7.867 3 6.862 3 6a5 5 0 0 1 10 0c0 .862-.305 1.867-.834 2.94M8 16s6-5.686 6-10A6 6 0 0 0 2 6c0 4.314 6 10 6 10"/>  <path d="M8 8a2 2 0 1 1 0-4 2 2 0 0 1 0 4m0 1a3 3 0 1 0 0-6 3 3 0 0 0 0 6"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Scanned Resources</p></div><div class="flex justify-between items-end pt-4"><p id="inspector-scanned-resources" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-box w-6 h-6 text-blue-600" viewBox="0 0 16 16">  <path d="M8.186 1.113a.5.5 0 0 0-.372 0L1.846 3.5 8 5.961 14.154 3.5zM15 4.239l-6.5 2.6v7.922l6.5-2.6V4.24zM7.5 14.762V6.838L1 4.239v7.923zM7.443.184a1.5 1.5 0 0 1 1.114 0l7.129 2.852A.5.5 0 0 1 16 3.5v8.662a1 1 0 0 1-.629.928l-7.185 2.874a.5.5 0 0 1-.372 0L.63 13.09a1 1 0 0 1-.63-.928V3.5a.5.5 0 0 1 .314-.464z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Total Findings</p></div><div class="flex justify-between items-end pt-4"><p id="inspector-total-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-search w-6 h-6 text-blue-600" viewBox="0 0 16 16">  <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Critical Findings</p></div><div class="flex justify-between items-end pt-4"><p id="inspector-critical-findings" class="text-3xl font-bold text-red-600">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-triangle w-6 h-6 text-red-600" viewBox="0 0 16 16">  <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/>  <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">High Findings</p></div><div class="flex justify-between items-end pt-4"><p id="inspector-high-findings" class="text-3xl font-bold text-orange-500">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-triangle w-6 h-6 text-orange-600" viewBox="0 0 16 16"> <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/> <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/></svg></div></div></div>
    </div>`;

const updateInspectorSummaryCards = (scanStatus, findings) => {
    document.getElementById('inspector-active-regions').textContent = scanStatus.filter(s => ['ENABLED', 'ENABLING'].includes(s.InspectorStatus)).length;
    let scannedResourceCount = 0;
    scanStatus.forEach(regionStatus => {
        if (regionStatus.ScanEC2 === 'ENABLED') scannedResourceCount++;
        if (regionStatus.ScanECR === 'ENABLED') scannedResourceCount++;
        if (regionStatus.ScanLambda === 'ENABLED') scannedResourceCount++;
    });
    document.getElementById('inspector-scanned-resources').textContent = scannedResourceCount;
    document.getElementById('inspector-total-findings').textContent = findings.length;
    document.getElementById('inspector-critical-findings').textContent = findings.filter(f => f.severity === 'CRITICAL').length;
    document.getElementById('inspector-high-findings').textContent = findings.filter(f => f.severity === 'HIGH').length;
};

const renderInspectorStatusTable = (statusList) => {
    if (!statusList || statusList.length === 0) return `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">${emptyCollectionMessage(window.inspectorApiData, "No Inspector status records returned for the planned scope.")}</p></div>`;
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Inspector Status</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">EC2 Scan</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ECR Scan</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Lambda Scan</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    statusList.sort((a, b) => a.Region.localeCompare(b.Region)).forEach(s => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${s.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(s.InspectorStatus)}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(s.ScanEC2)}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(s.ScanECR)}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(s.ScanLambda)}</td>
                  </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderFullInspectorView = (findings, inspectorFindingsSH) => {
    const container = document.getElementById('inspector-view');
    const scanStatus = window.inspectorApiData.results.scan_status;

    // --- NUEVO: Extraer valores únicos para los filtros ---
    const uniqueValues = {
        severities: [...new Set(findings.map(f => f.severity).filter(Boolean))],
        regions: [...new Set(findings.map(f => f.Region).filter(Boolean))],
        resourceTypes: [...new Set(findings.map(f => {
            const typeMap = {
                'AWS_EC2_INSTANCE': 'EC2 Instance',
                'AWS_ECR_REPOSITORY': 'ECR Repository',
                'AWS_LAMBDA_FUNCTION': 'Lambda Function'
            };
            const resourceTypeRaw = f.resources?.[0]?.type || 'Unknown';
            return typeMap[resourceTypeRaw] || resourceTypeRaw;
        }))]
    };

    // Ordenar valores
    const severityOrder = { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4, "UNDEFINED": 5 };
    uniqueValues.severities.sort((a, b) => (severityOrder[a] || 99) - (severityOrder[b] || 99));
    uniqueValues.regions.sort();
    uniqueValues.resourceTypes.sort();
    
    // --- NUEVO: Función de filtros unificada ---
    const applyFilters = () => {
        const severityFilter = document.getElementById('inspector-severity-filter').value;
        const regionFilter = document.getElementById('inspector-region-filter').value;
        const resourceTypeFilter = document.getElementById('inspector-resource-type-filter').value;
        const searchFilter = document.getElementById('inspector-search-filter').value.toLowerCase();

        const rows = document.querySelectorAll('#inspector-findings-tbody .finding-row');
        let visibleCount = 0;

        rows.forEach((row, index) => {
            const finding = findings[index];
            let shouldShow = true;

            if (severityFilter && finding.severity !== severityFilter) { shouldShow = false; }
            if (regionFilter && finding.Region !== regionFilter) { shouldShow = false; }
            
            if (resourceTypeFilter) {
                const typeMap = { 'AWS_EC2_INSTANCE': 'EC2 Instance', 'AWS_ECR_REPOSITORY': 'ECR Repository', 'AWS_LAMBDA_FUNCTION': 'Lambda Function' };
                const resourceTypeRaw = finding.resources?.[0]?.type || 'Unknown';
                const findingResourceType = typeMap[resourceTypeRaw] || resourceTypeRaw;
                if (findingResourceType !== resourceTypeFilter) { shouldShow = false; }
            }

            if (searchFilter) {
                const title = (finding.title || '').toLowerCase();
                const resourceId = (finding.resources?.[0]?.id || '').toLowerCase();
                if (!title.includes(searchFilter) && !resourceId.includes(searchFilter)) { shouldShow = false; }
            }

            row.style.display = shouldShow ? '' : 'none';
            if (shouldShow) visibleCount++;
        });

        const countDisplay = document.getElementById('inspector-findings-count');
        if (countDisplay) {
            const totalFindings = findings.length;
            if (visibleCount === totalFindings) {
                countDisplay.innerHTML = `<div class="flex items-center space-x-1"><svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg><span>${totalFindings} findings</span></div>`;
                countDisplay.className = "bg-[#eb3496] text-white px-3 py-1 rounded-full text-sm font-semibold flex items-center";
            } else {
                countDisplay.innerHTML = `<div class="flex items-center space-x-1"><svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M3 3a1 1 0 011-1h12a1 1 0 011 1v3a1 1 0 01-.293.707L12 11.414V15a1 1 0 01-.293.707l-2 2A1 1 0 018 17v-5.586L3.293 6.707A1 1 0 013 6V3z" clip-rule="evenodd"></path></svg><span>${visibleCount}/${totalFindings}</span></div>`;
                countDisplay.className = "bg-blue-500 text-white px-3 py-1 rounded-full text-sm font-semibold flex items-center animate-pulse";
            }
        }
    };

    // --- NUEVO: Generar todas las filas de la tabla de una vez ---
    const severityClasses = { 'CRITICAL': 'bg-red-600 text-white', 'HIGH': 'bg-orange-500 text-white', 'MEDIUM': 'bg-yellow-400 text-black', 'LOW': 'bg-blue-500 text-white', 'INFORMATIONAL': 'bg-gray-400 text-white', 'UNDEFINED': 'bg-gray-400 text-white' };
    const tableRowsHtml = findings.map(f => {
        const severity = f.severity || 'UNDEFINED';
        const severityClass = severityClasses[severity] || 'bg-gray-200 text-gray-800';
        const firstSeen = new Date(f.firstObservedAt).toLocaleDateString();

        const resource = f.resources && f.resources.length > 0 ? f.resources[0] : {};
        const resourceId = resource.id || 'N/A';
        const resourceTypeRaw = resource.type || 'Unknown';
        const resourceName = resource.tags?.Name || '';

        const typeMap = { 'AWS_EC2_INSTANCE': 'EC2 Instance', 'AWS_ECR_REPOSITORY': 'ECR Repository', 'AWS_LAMBDA_FUNCTION': 'Lambda Function' };
        const resourceTypeDisplay = typeMap[resourceTypeRaw] || resourceTypeRaw;

        let resourceDisplay = `<div class="font-semibold text-gray-800">${resourceTypeDisplay}</div>`;
        if (resourceName) {
            resourceDisplay += `<div class="text-gray-700">${resourceName}</div>`;
        }
        resourceDisplay += `<div class="font-mono text-gray-500 text-xs">${resourceId}</div>`;

        return `<tr class="finding-row hover:bg-gray-50">
                    <td class="px-4 py-4 align-top whitespace-nowrap"><span class="px-2.5 py-0.5 text-xs font-semibold rounded-full ${severityClass}">${severity}</span></td>
                    <td class="px-4 py-4 align-top whitespace-nowrap text-xs text-gray-600">${firstSeen}</td>
                    <td class="px-4 py-4 align-top whitespace-nowrap text-xs text-gray-600">${f.Region}</td>
                    <td class="px-4 py-4 align-top text-xs text-gray-800 break-words">${f.title}</td>
                    <td class="px-4 py-4 align-top whitespace-nowrap text-xs text-gray-600">${f.type}</td>
                    <td class="px-4 py-4 align-top text-xs text-gray-600 break-words">${resourceDisplay}</td>
                </tr>`;
    }).join('');

    // --- MODIFICADO: Estructura HTML principal con el nuevo filtro y sin paginación ---
    container.innerHTML = `
         <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Inspector</h2>
                <p class="text-sm text-gray-500">${window.inspectorApiData.metadata.executionDate}</p>
            </div>
        </header>
        <div id="inspector-summary-container">${createInspectorSummaryCardsHtml()}</div>
        <div class="border-b border-gray-200 my-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="inspector-tabs-results">
                <a href="#" data-tab="inspector-status-details-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="inspector-findings-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Inspector Findings</a>
                <a href="#" data-tab="inspector-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub Findings (${inspectorFindingsSH.length})</a>
            </nav>
        </div>
        <div id="inspector-tab-content-container-results">
            <div id="inspector-status-details-content" class="inspector-tab-content"></div>
            <div id="inspector-findings-content" class="inspector-tab-content hidden">
                
                <div class="bg-gradient-to-r from-white to-gray-50 p-6 rounded-2xl border border-gray-200 shadow-sm mb-6">
                    <div class="flex items-center justify-between mb-4">
                        <div class="flex items-center space-x-2">
                            <svg class="w-5 h-5 text-[#eb3496]" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293.707L3.293 7.707A1 1 0 013 7V4z"></path></svg>
                            <h3 class="text-lg font-bold text-gray-800">Filter Options</h3>
                        </div>
                        <div id="inspector-findings-count"></div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4 mb-4">
                        <div class="group">
                            <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-red-500" viewBox="0 0 16 16">
                                    <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1-.054-.06.18.18 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/>
                                    <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/>
                                </svg>
                                Severity
                            </label>
                            <select id="inspector-severity-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                                <option value="">All Severities</option>
                                ${uniqueValues.severities.map(s => `<option value="${s}">${s}</option>`).join('')}
                            </select>
                        </div>
                        <div class="group">
                            <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-blue-500" viewBox="0 0 16 16">
                                    <path d="M12.166 8.94c-.524 1.062-1.234 2.12-1.96 3.07A32 32 0 0 1 8 14.58a32 32 0 0 1-2.206-2.57c-.726-.95-1.436-2.008-1.96-3.07C3.304 7.867 3 6.862 3 6a5 5 0 0 1 10 0c0 .862-.305 1.867-.834 2.94M8 16s6-5.686 6-10A6 6 0 0 0 2 6c0 4.314 6 10 6 10"/>
                                    <path d="M8 8a2 2 0 1 1 0-4 2 2 0 0 1 0 4m0 1a3 3 0 1 0 0-6 3 3 0 0 0 0 6"/>
                                </svg>
                                Region
                            </label>
                            <select id="inspector-region-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                                <option value="">All Regions</option>
                                ${uniqueValues.regions.map(r => `<option value="${r}">${r}</option>`).join('')}
                            </select>
                        </div>
                        <div class="group">
                            <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-purple-500" viewBox="0 0 16 16">
                                    <path d="M8.186 1.113a.5.5 0 0 0-.372 0L1.846 3.5 8 5.961 14.154 3.5zM15 4.239l-6.5 2.6v7.922l6.5-2.6V4.24zM7.5 14.762V6.838L1 4.239v7.923zM7.443.184a1.5 1.5 0 0 1 1.114 0l7.129 2.852A.5.5 0 0 1 16 3.5v8.662a1 1 0 0 1-.629.928l-7.185 2.874a.5.5 0 0 1-.372 0L.63 13.09a1 1 0 0 1-.63-.928V3.5a.5.5 0 0 1 .314-.464z"/>
                                </svg>
                                Resource Type
                            </label>
                            <select id="inspector-resource-type-filter" class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                                <option value="">All Resources</option>
                                ${uniqueValues.resourceTypes.map(rt => `<option value="${rt}">${rt}</option>`).join('')}
                            </select>
                        </div>
                        <div class="group">
                            <label class="flex items-center text-sm font-semibold text-gray-700 mb-2">
                                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-4 h-4 mr-1 text-gray-500" viewBox="0 0 16 16">
                                    <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/>
                                </svg>
                                Search
                            </label>
                            <input id="inspector-search-filter" type="text" placeholder="Title or resource ID..." class="w-full px-4 py-2.5 text-sm border-2 border-gray-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#eb3496] focus:border-[#eb3496] transition-all duration-200 bg-white hover:border-gray-300">
                        </div>
                    </div>
                     <div class="flex justify-start items-center pt-4 border-t border-gray-200">
                        <button id="inspector-clear-filters-btn" class="inline-flex items-center px-4 py-2 text-sm font-medium text-[#eb3496] bg-pink-50 border border-pink-200 rounded-xl hover:bg-pink-100 hover:border-[#eb3496] transition-all duration-200 group">
                            <svg class="w-4 h-4 mr-2 group-hover:rotate-180 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                            Clear All Filters
                        </button>
                    </div>
                </div>

                <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Detection Date</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Affected Resource</th>
                            </tr>
                        </thead>
                        <tbody id="inspector-findings-tbody" class="bg-white divide-y divide-gray-200">${tableRowsHtml}</tbody>
                    </table>
                </div>
            </div>
            <div id="inspector-sh-content" class="inspector-tab-content hidden"></div>
        </div>
    `;
    renderCollectionNotice(container, window.inspectorApiData);

    document.getElementById('inspector-status-details-content').innerHTML = renderInspectorStatusTable(scanStatus);
    updateInspectorSummaryCards(scanStatus, findings);
    const tabsNav = document.getElementById('inspector-tabs-results');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.inspector-tab-content'));

    // --- NUEVO: Añadir Event Listeners para los nuevos filtros ---
    setTimeout(() => {
        const filters = ['inspector-severity-filter', 'inspector-region-filter', 'inspector-resource-type-filter'];
        filters.forEach(id => document.getElementById(id).addEventListener('change', applyFilters));
        document.getElementById('inspector-search-filter').addEventListener('input', applyFilters);
        document.getElementById('inspector-clear-filters-btn').addEventListener('click', () => {
            filters.forEach(id => document.getElementById(id).value = '');
            document.getElementById('inspector-search-filter').value = '';
            applyFilters();
        });
        applyFilters(); // Para inicializar el contador
    }, 50);

    const shFindingsContainer = document.getElementById('inspector-sh-content');
    shFindingsContainer.innerHTML = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Title</th><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Resource type</th></tr></thead><tbody id="sh-inspector-tbody" class="bg-white divide-y divide-gray-200"></tbody></table></div><div id="sh-inspector-pagination-controls" class="mt-4 flex justify-center items-center space-x-2"></div>`;
    setupPagination(document.getElementById('sh-inspector-pagination-controls'), document.getElementById('sh-inspector-tbody'), inspectorFindingsSH, renderSecurityHubFindingsPage);
};
