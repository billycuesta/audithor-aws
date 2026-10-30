/**
 * 05_waf.js
 * Contiene toda la lógica para construir y renderizar la vista de WAF & Shield.
 */

// Importamos las funciones de utilidad que vamos a necesitar desde el fichero utils.js
import { handleTabClick, renderSecurityHubFindings, createStatusBadge } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
    webacl: {
        title: "Web Application Firewall (WAF)",
        description: "AWS WAF is a web application firewall that helps protect web applications and APIs from common web exploits and vulnerabilities by filtering, monitoring, and blocking malicious traffic based on configurable rules.",
        useCases: "Protection against SQL injection, cross-site scripting (XSS), DDoS mitigation, bot protection, rate limiting, geo-blocking, and custom security rules for web applications.",
        auditConsiderations: "Review rule configurations for completeness, verify logging is enabled for compliance and incident response, ensure rate limiting rules are properly configured, validate that all critical web applications are protected, and check that rules are regularly updated to address new threats."
    },
    ipsets: {
        title: "IP Sets Management",
        description: "IP Sets allow you to create reusable collections of IP addresses and IP address ranges that can be referenced in WAF rules, providing efficient management of allow/block lists and reducing rule complexity.",
        useCases: "IP-based access control, geographic restrictions, known malicious IP blocking, trusted partner IP allowlisting, and dynamic threat intelligence integration.",
        auditConsiderations: "Verify IP sets are regularly updated with current threat intelligence, ensure legitimate business IPs are not accidentally blocked, review geographic restrictions align with business requirements, and validate that IP ranges are properly maintained and documented."
    },
    logging: {
        title: "WAF Logging & Monitoring",
        description: "WAF logging captures detailed information about web requests that are allowed or blocked by your rules, providing visibility into attack patterns and helping with security monitoring and compliance requirements.",
        useCases: "Security incident investigation, compliance reporting, attack pattern analysis, rule effectiveness measurement, and integration with SIEM systems for comprehensive security monitoring.",
        auditConsiderations: "Ensure comprehensive logging is enabled for all WAF rules, verify logs are properly retained per compliance requirements, validate that sensitive data is not logged inappropriately, and confirm logs are monitored for security incidents and rule tuning opportunities."
    }
};

// La función principal que construye toda la vista. La exportamos para que otros ficheros puedan usarla.
export function buildWafView() {
    const container = document.getElementById('waf-view');
    if (!window.wafApiData || !window.securityHubApiData) {
        console.warn("WAF or Security Hub data not available for rendering.");
        return;
    }
    
    const { acls, ip_sets } = window.wafApiData.results;
    const wafFindings = window.securityHubApiData.results.findings.wafFindings;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">WAF & Shield</h2>
                <p class="text-sm text-gray-500">${window.wafApiData.metadata.executionDate}</p>
            </div>
        </header>
        
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review WAF configurations to ensure comprehensive web application protection, verify logging and monitoring capabilities are properly configured, and validate that rule sets provide adequate coverage against common web exploits while maintaining legitimate traffic flow.</p>
        </div>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="waf-tabs">
                <a href="#" data-tab="waf-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="waf-acls-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Web ACLs (${acls.length})</a>
                <a href="#" data-tab="waf-ipsets-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">IP Sets (${ip_sets.length})</a>
                <a href="#" data-tab="waf-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${wafFindings.length})</a>
            </nav>
        </div>
        <div id="waf-tab-content-container">
            <div id="waf-summary-content" class="waf-tab-content">${createWafSummaryCardsHtml()}</div>
            <div id="waf-acls-content" class="waf-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.webacl)}
                ${renderWafAclsTable(acls)}
            </div>
            <div id="waf-ipsets-content" class="waf-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.ipsets)}
                ${renderWafIpSetsTable(ip_sets)}
            </div>
            <div id="waf-sh-content" class="waf-tab-content hidden">${createWafSecurityHubHtml()}</div>
        </div>
    `;
    
    updateWafSummaryCards(acls, ip_sets, wafFindings);
    renderSecurityHubFindings(wafFindings, 'sh-waf-findings-container', 'No Security Hub findings related to WAF were found.');
    
    const tabsNav = container.querySelector('#waf-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.waf-tab-content'));
}

// --- SERVICE DESCRIPTION RENDERER ---
const renderServiceDescription = (serviceInfo) => {
    return `
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
};

// --- Funciones internas de la vista WAF (no necesitan export porque solo se usan aquí) ---

function createWafSummaryCardsHtml() {
    return `
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm text-gray-500">Total Web ACLs</p>
                        <p id="waf-acl-count" class="text-3xl font-bold text-[#204071] mt-2">--</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="text-[#204071]" viewBox="0 0 16 16">
                            <path d="M0 .5A.5.5 0 0 1 .5 0h15a.5.5 0 0 1 .5.5v3a.5.5 0 0 1-.5.5H14v2h1.5a.5.5 0 0 1 .5.5v3a.5.5 0 0 1-.5.5H14v2h1.5a.5.5 0 0 1 .5.5v3a.5.5 0 0 1-.5.5H.5a.5.5 0 0 1-.5-.5v-3a.5.5 0 0 1 .5-.5H2v-2H.5a.5.5 0 0 1-.5-.5v-3A.5.5 0 0 1 .5 6H2V4H.5a.5.5 0 0 1-.5-.5zM3 4v2h4.5V4zm5.5 0v2H13V4zM3 10v2h4.5v-2zm5.5 0v2H13v-2zM1 1v2h3.5V1zm4.5 0v2h5V1zm6 0v2H15V1zM1 7v2h3.5V7zm4.5 0v2h5V7zm6 0v2H15V7zM1 13v2h3.5v-2zm4.5 0v2h5v-2zm6 0v2H15v-2z"/>
                        </svg>
                    </div>
                </div>
            </div>
            
            <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm text-gray-500">ACLs with Logging</p>
                        <p id="waf-logging-enabled" class="text-3xl font-bold text-green-600 mt-2">--</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="text-green-600" viewBox="0 0 16 16">
                            <path d="M10 13.5a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-6a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5zm-2.5.5a.5.5 0 0 1-.5-.5v-4a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v4a.5.5 0 0 1-.5.5zm-3 0a.5.5 0 0 1-.5-.5v-2a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v2a.5.5 0 0 1-.5.5z"/>
                            <path d="M14 14V4.5L9.5 0H4a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2M9.5 3A1.5 1.5 0 0 0 11 4.5h2V14a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1h5.5z"/>
                        </svg>
                    </div>
                </div>
            </div>
            
            <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm text-gray-500">Protected Resources</p>
                        <p id="waf-protected-resources" class="text-3xl font-bold text-[#204071] mt-2">--</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="text-[#204071]" viewBox="0 0 16 16">
                            <path d="M8.186 1.113a.5.5 0 0 0-.372 0L1.846 3.5 8 5.961 14.154 3.5zM15 4.239l-6.5 2.6v7.922l6.5-2.6V4.24zM7.5 14.762V6.838L1 4.239v7.923zM7.443.184a1.5 1.5 0 0 1 1.114 0l7.129 2.852A.5.5 0 0 1 16 3.5v8.662a1 1 0 0 1-.629.928l-7.185 2.874a.5.5 0 0 1-.372 0L.63 13.09a1 1 0 0 1-.63-.928V3.5a.5.5 0 0 1 .314-.464z"/>
                        </svg>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm mb-8">
            <h3 class="font-bold text-lg text-[#204071] mb-2">Top 5 Blocked Rules (Last 30 Days)</h3>
            <div class="h-48"><canvas id="wafTopRulesChart"></canvas></div>
        </div>`;
}


function updateWafSummaryCards(acls, ipSets, wafFindings) {
    const aclCount = acls.length;
    
    // Calculate new logging metrics
    const allLoggingEnabled = acls.filter(acl => 
        acl.LoggingDetails && acl.LoggingDetails.all_logging && acl.LoggingDetails.all_logging.enabled
    ).length;
    
    const destinationOnlyEnabled = acls.filter(acl => 
        acl.LoggingDetails && acl.LoggingDetails.destination_only_logging && acl.LoggingDetails.destination_only_logging.enabled
    ).length;
    
    const anyLoggingEnabled = acls.filter(acl => 
        (acl.LoggingDetails && acl.LoggingDetails.all_logging && acl.LoggingDetails.all_logging.enabled) ||
        (acl.LoggingDetails && acl.LoggingDetails.destination_only_logging && acl.LoggingDetails.destination_only_logging.enabled) ||
        (acl.LoggingConfiguration && Object.keys(acl.LoggingConfiguration).length > 0)
    ).length;
    
    document.getElementById('waf-acl-count').textContent = aclCount;
    
    // Update logging display to show breakdown
    const loggingBreakdown = `${anyLoggingEnabled} / ${aclCount}`;
    document.getElementById('waf-logging-enabled').textContent = loggingBreakdown;
    
    // Add tooltip or additional display for logging breakdown if needed
    const loggingElement = document.getElementById('waf-logging-enabled');
    if (loggingElement && loggingElement.parentElement) {
        const parentCard = loggingElement.parentElement;
        const existingDetails = parentCard.querySelector('.logging-details');
        if (existingDetails) {
            existingDetails.remove();
        }
        
        const loggingDetails = document.createElement('div');
        loggingDetails.className = 'logging-details text-xs text-gray-500 mt-1';
        loggingDetails.innerHTML = `
            <div>All: ${allLoggingEnabled}</div>
            <div>Destination Only: ${destinationOnlyEnabled}</div>
        `;
        loggingElement.parentElement.appendChild(loggingDetails);
    }
    
    const protectedResources = acls.reduce((sum, acl) => sum + (acl.AssociatedResourceArns?.length || 0), 0);
    document.getElementById('waf-protected-resources').textContent = protectedResources;
    updateWafTopRulesChart(acls);
}

function updateWafTopRulesChart(acls) {
    const ctx = document.getElementById('wafTopRulesChart');
    if (!ctx) return;
    const ruleCounts = {};
    acls.forEach(acl => {
        if (acl.TopRules) {
            acl.TopRules.forEach(rule => {
                ruleCounts[rule.RuleName] = (ruleCounts[rule.RuleName] || 0) + rule.BlockedRequests;
            });
        }
    });
    const sortedRules = Object.entries(ruleCounts).sort(([, a], [, b]) => b - a).slice(0, 5);
    if (sortedRules.length === 0) {
        ctx.parentElement.innerHTML = '<div class="flex items-center justify-center h-full text-center text-gray-500"><p>No blocked requests found in the last 30 days.</p></div>';
        return;
    }
    const labels = sortedRules.map(item => item[0]);
    const data = sortedRules.map(item => item[1]);
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Blocked Requests',
                data: data,
                backgroundColor: 'rgba(235, 52, 150, 0.6)',
                borderColor: 'rgba(235, 52, 150, 1)',
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: { x: { beginAtZero: true, ticks: { precision: 0 } } }
        }
    });
}

function createWafSecurityHubHtml() {
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (WAF)</h3><div id="sh-waf-findings-container" class="overflow-x-auto"></div></div>`;
}

function renderWafAclsTable(acls) {
    if (!acls || acls.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No Web ACLs found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have WAF Web ACLs configured, which may leave web applications vulnerable to common attacks.</p>
                </div>
            </div>
        `;
    }
    
    return `
        <div class="space-y-6">
            ${renderLoggingConfigurationGuide()}
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">All Logging</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Destination Only</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Sampled Requests</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protected Resources</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${acls.sort((a,b) => a.Name.localeCompare(b.Name)).map(acl => renderWafAclRow(acl)).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
}

function renderWafAclRow(acl) {
    // Resources HTML
    let resourcesHtml = '<span class="px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">No associated resources</span>';

    if (acl.Version === 'Classic') {
        resourcesHtml = `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-yellow-100 text-yellow-800" title="La API de WAF Classic no permite listar recursos asociados directamente. Revisa manualmente en la consola.">Revisión Manual Requerida</span>`;
    } 
    // --- FIN DE LA MODIFICACIÓN ---
    else if (acl.AssociatedResourceArns && acl.AssociatedResourceArns.length > 0) {
        resourcesHtml = `<div class="flex flex-col space-y-1">` + 
            acl.AssociatedResourceArns.map(arn => 
                `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800 font-mono">${arn}</span>`
            ).join('') + `</div>`;
    }

    if (acl.AssociatedResourceArns && acl.AssociatedResourceArns.length > 0) {
        resourcesHtml = `<div class="flex flex-col space-y-1">` + 
            acl.AssociatedResourceArns.map(arn => 
                `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800 font-mono">${arn}</span>`
            ).join('') + `</div>`;
    }
    
    // Logging configuration HTML
    const loggingDetails = acl.LoggingDetails || {
        all_logging: { enabled: false, destinations: [] },
        destination_only_logging: { enabled: false, destinations: [] }
    };
    
    let allLoggingHtml = createLoggingStatusBadge(loggingDetails.all_logging);
    let destinationOnlyHtml = createLoggingStatusBadge(loggingDetails.destination_only_logging);
    
    // Sampled requests con colores apropiados
    const sampledEnabled = acl.VisibilityConfig ? acl.VisibilityConfig.SampledRequestsEnabled : false;
    const sampledBadge = sampledEnabled ? 
        '<span class="px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">Enabled</span>' :
        '<span class="px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">Disabled</span>';
    
    return `
        <tr class="hover:bg-gray-50">
            <td class="px-4 py-4 align-top whitespace-nowrap text-sm font-medium text-gray-800">${acl.Name}</td>
            <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${acl.Scope}</td>
            <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${acl.Region}</td>
            <td class="px-4 py-4 align-top text-sm">${allLoggingHtml}</td>
            <td class="px-4 py-4 align-top text-sm">${destinationOnlyHtml}</td>
            <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${sampledBadge}</td>
            <td class="px-4 py-4 align-top text-sm">${resourcesHtml}</td>
        </tr>
    `;
}

function createLoggingStatusBadge(loggingConfig) {
    if (!loggingConfig.enabled) {
        return '<span class="px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">Disabled</span>';
    }
    
    if (loggingConfig.destinations && loggingConfig.destinations.length > 0) {
        const destination = loggingConfig.destinations[0];
        const destinationName = destination.split('/').pop();
        return `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800 font-mono" title="${destination}">${destinationName}</span>`;
    }
    
    return '<span class="px-2 py-1 text-xs font-semibold rounded-full bg-yellow-100 text-yellow-800">Enabled (No Destination)</span>';
}

function renderLoggingConfigurationGuide() {
    return `
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-6">
            <h3 class="text-lg font-semibold text-blue-800 mb-4">WAF Logging Configuration Types</h3>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-white border border-blue-200 rounded-lg p-4">
                    <h4 class="text-sm font-semibold text-blue-800 mb-2 flex items-center">
                        <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M3 17a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm3.293-7.707a1 1 0 011.414 0L9 10.586V3a1 1 0 112 0v7.586l1.293-1.293a1 1 0 111.414 1.414l-3 3a1 1 0 01-1.414 0l-3-3a1 1 0 010-1.414z" clip-rule="evenodd"></path>
                        </svg>
                        All Logging
                    </h4>
                    <p class="text-sm text-blue-700 mb-3">
                        <strong>What it does:</strong> Logs all web requests processed by the Web ACL, regardless of whether they are allowed or blocked.
                    </p>
                    <p class="text-sm text-blue-700 mb-3">
                        <strong>Use case:</strong> Comprehensive traffic analysis, security monitoring, compliance requirements, and forensic investigations.
                    </p>
                    <div class="bg-blue-100 border border-blue-300 rounded p-2">
                        <p class="text-xs text-blue-800">
                            <strong>Audit Recommendation:</strong> Enable for high-security environments and compliance requirements, but consider cost implications for high-traffic applications.
                        </p>
                    </div>
                </div>
                
                <div class="bg-white border border-blue-200 rounded-lg p-4">
                    <h4 class="text-sm font-semibold text-blue-800 mb-2 flex items-center">
                        <svg class="w-4 h-4 mr-2" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M3 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1zm0 4a1 1 0 011-1h12a1 1 0 110 2H4a1 1 0 01-1-1z" clip-rule="evenodd"></path>
                        </svg>
                        Logging Destination Only
                    </h4>
                    <p class="text-sm text-blue-700 mb-3">
                        <strong>What it does:</strong> Logs only requests that match specific filter conditions (e.g., only blocked requests, only requests from specific rules).
                    </p>
                    <p class="text-sm text-blue-700 mb-3">
                        <strong>Use case:</strong> Cost optimization, focused security monitoring, specific compliance requirements for blocked traffic only.
                    </p>
                    <div class="bg-green-100 border border-green-300 rounded p-2">
                        <p class="text-xs text-green-800">
                            <strong>Audit Recommendation:</strong> Ideal for cost-conscious environments where you only need to monitor security events and blocked requests.
                        </p>
                    </div>
                </div>
            </div>
        </div>
    `;
}

function renderWafIpSetsTable(ipSets) { 
    if (!ipSets || ipSets.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="mx-auto h-12 w-12 text-gray-400" viewBox="0 0 16 16">
                        <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
                        <path d="M5.255 5.786a.237.237 0 0 0 .241.247h.825c.138 0 .248-.113.266-.25.09-.656.54-1.134 1.342-1.134.686 0 1.314.343 1.314 1.168 0 .635-.374.927-.965 1.371-.673.489-1.206 1.06-1.168 1.987l.003.217a.25.25 0 0 0 .25.246h.811a.25.25 0 0 0 .25-.25v-.105c0-.718.273-.927 1.01-1.486.609-.463 1.244-.977 1.244-2.056 0-1.511-1.276-2.241-2.673-2.241-1.267 0-2.655.59-2.75 2.286m1.557 5.763c0 .533.425.927 1.01.927.609 0 1.028-.394 1.028-.927 0-.552-.42-.94-1.029-.94-.584 0-1.009.388-1.009.94"/>
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No IP Sets found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have WAF IP Sets configured. Consider creating IP sets for better management of allow/block lists.</p>
                </div>
            </div>
        `;
    }
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Version</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase"># Addresses</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">'; 
    ipSets.sort((a,b) => a.Name.localeCompare(b.Name)).forEach(ipSet => { 
        table += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${ipSet.Name}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.Scope}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.Region}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.IPAddressVersion}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${ipSet.AddressCount}</td></tr>`; 
    }); 
    table += '</tbody></table></div>'; 
    return table; 
}