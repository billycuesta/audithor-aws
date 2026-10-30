/**
 * 01_iam.js
 * Contiene toda la lógica para construir y renderizar la vista de Identity & Access (IAM).
 */

// --- IMPORTACIONES ---
// Importamos las funciones de utilidad que vamos a necesitar desde el fichero utils.js
import { handleTabClick, renderSecurityHubFindings, log } from '../utils.js';


// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
// La función principal que construye toda la vista. La exportamos para que app.js pueda usarla.


export const buildIamView = () => {
    const container = document.getElementById('iam-view');
    if (!container) return;

    const accessAnalyzerFindingsCount = window.accessAnalyzerApiData?.results?.findings?.length || 0;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div><h2 class="text-2xl font-bold text-[#204071]">Identity & Access</h2><p class="text-sm text-gray-500 scan-info"></p></div>
        </header>
        
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review Identity and Access Management components to ensure proper access controls, compliance with least privilege principle, and adequate security measures. Each tab provides specific audit considerations for different IAM components.</p>
        </div>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="iam-tabs">
                <a href="#" data-tab="resumen-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="usuarios-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Users</a>
                <a href="#" data-tab="grupos-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Groups</a>
                <a href="#" data-tab="roles-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Roles</a>
                <a href="#" data-tab="politicas-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Password Policies</a>
                <a href="#" data-tab="access-analyzer-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Access Analyzer (${accessAnalyzerFindingsCount})</a>
                <a href="#" data-tab="detalle-permisos-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Permission Details</a>
                <a href="#" data-tab="critical-perms-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Users with Critical Permissions</a>
                <a href="#" data-tab="federation-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Federation</a>
                <a href="#" data-tab="securityhub-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub</a>
            </nav>
        </div>
        <div id="iam-tab-content-container">
            <div id="resumen-content" class="iam-tab-content">
                ${renderServiceDescription(serviceDescriptions.summary)}
                ${createIamResumenHtml()}
            </div>
            <div id="usuarios-content" class="iam-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.users)}
                ${createIamUsuariosHtml()}
            </div>
            <div id="grupos-content" class="iam-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.groups)}
                ${createIamGruposHtml()}
            </div>
            <div id="roles-content" class="iam-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.roles)}
                ${createIamRolesHtml()}
            </div>
            <div id="politicas-content" class="iam-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.policies)}
                ${createIamPoliticasHtml()}
            </div>
            <div id="access-analyzer-content" class="iam-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.accessAnalyzer)}
            </div>
            <div id="securityhub-content" class="iam-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.securityHub)}
                ${createSecurityHubHtml()}
            </div>
            <div id="detalle-permisos-content" class="iam-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.permissionDetails)}
                ${renderIamDetailsViewHtml()}
            </div>
            <div id="critical-perms-content" class="iam-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.criticalPermissions)}
            </div>
            <div id="federation-content" class="iam-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.federation)}
            </div>
        </div>`;

    const tabsNav = container.querySelector('#iam-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.iam-tab-content'));

    // Event listeners para los controles de Permission Details
    setupPermissionDetailsControls();

    if (window.iamApiData) updateIamDashboard();
    
    if (window.securityHubApiData || window.securityHubStatusApiData) {
        updateSecurityHubDashboard();
    }
    
    if (window.accessAnalyzerApiData) {
        renderAccessAnalyzerContent();
    }
    if (window.federationApiData) {
        renderFederationView();
    }
};


// 11. Función para configurar los controles de Permission Details
const setupPermissionDetailsControls = () => {
    // Event listener para el botón de búsqueda
    const searchBtn = document.getElementById('iam-search-btn');
    if (searchBtn) {
        searchBtn.addEventListener('click', getIamPermissionDetails);
    }

    // Event listener para Enter en el input
    const searchInput = document.getElementById('iam-search-input');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                getIamPermissionDetails();
            }
        });
    }

    // Event listeners para los botones de tipo de búsqueda
    const principalBtn = document.getElementById('search-type-principal');
    const policyBtn = document.getElementById('search-type-policy');
    
    if (principalBtn && policyBtn) {
        principalBtn.addEventListener('click', () => {
            setSearchType('principal');
        });
        
        policyBtn.addEventListener('click', () => {
            setSearchType('policy');
        });
    }
};

// 12. Función para cambiar el tipo de búsqueda
const setSearchType = (type) => {
    const principalBtn = document.getElementById('search-type-principal');
    const policyBtn = document.getElementById('search-type-policy');
    const searchLabel = document.getElementById('search-label');
    const searchInput = document.getElementById('iam-search-input');
    
    if (!principalBtn || !policyBtn || !searchLabel || !searchInput) return;
    
    // Reset styles
    [principalBtn, policyBtn].forEach(btn => {
        btn.classList.remove('bg-[#eb3496]', 'text-white');
        btn.classList.add('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
    });
    
    if (type === 'principal') {
        principalBtn.classList.add('bg-[#eb3496]', 'text-white');
        principalBtn.classList.remove('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        searchLabel.textContent = 'Name of User, Group, or Role';
        searchInput.placeholder = 'E.g.: admin-user, DevelopersGroup, EC2AdminRole';
    } else if (type === 'policy') {
        policyBtn.classList.add('bg-[#eb3496]', 'text-white');
        policyBtn.classList.remove('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        searchLabel.textContent = 'Name of Custom Policy';
        searchInput.placeholder = 'E.g.: MyCustomDeveloperPolicy, CustomS3ReadOnlyAccess';
    }
    
    // Clear previous results
    const resultsContainer = document.getElementById('iam-search-results-container');
    if (resultsContainer) {
        resultsContainer.innerHTML = '';
    }
    
    // Clear input
    searchInput.value = '';
};




// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const renderAccessAnalyzerStatusTable = (summary) => {
    if (!summary || summary.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100 mb-6"><p class="text-center text-gray-500">No active Access Analyzers found in any region.</p></div>';
    }

    let tableHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto mb-6">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">Enabled Analyzers Summary</h3>
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Analyzer Name</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">`;

    summary.sort((a, b) => a.Region.localeCompare(b.Region)).forEach(analyzer => {
        tableHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${analyzer.Region}</td>
                <td class="px-4 py-4 text-sm text-gray-800 font-mono break-all">${analyzer.Name}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${analyzer.Type}</td>
            </tr>`;
    });

    tableHtml += `</tbody></table></div>`;
    return tableHtml;
};

const renderAccessAnalyzerContent = () => {
    const container = document.getElementById('access-analyzer-content');
    if (!container || !window.accessAnalyzerApiData) return;

    const { findings, summary } = window.accessAnalyzerApiData.results;

    let contentHtml = renderAccessAnalyzerStatusTable(summary);

    if (!findings || findings.length === 0) {
        contentHtml += `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">Good job! No external access findings were found.</p></div>`;
        container.innerHTML = contentHtml;
        return;
    }

    contentHtml += `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">External Access Findings</h3>
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-1/12">Region</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-4/12">Affected Resource</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-4/12">External Principal</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-1/12">Public</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase w-2/12">Allowed Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">`;

    const scannedAccountId = window.iamApiData?.metadata?.accountId;
    const rolesFromScan = window.iamApiData?.results?.roles;

    findings.forEach(f => {
        const publicBadge = f.IsPublic 
            ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">YES</span>`
            : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">No</span>`;
        
        const principalDisplay = f.Principal === 'Public' 
            ? `<span class="font-bold text-red-600">* (Anyone)</span>` 
            : f.Principal;

        let vipBadge = '';
        if (f.ResourceType === 'AWS::IAM::Role' && scannedAccountId && rolesFromScan) {
            try {
                const resourceArn = f.Resource;
                const resourceAccountId = resourceArn.split(':')[4];
                if (resourceAccountId === scannedAccountId) {
                    const roleNameParts = resourceArn.split('/');
                    const roleName = roleNameParts[roleNameParts.length - 1];
                    const roleDetails = rolesFromScan.find(r => r.RoleName === roleName);
                    if (roleDetails && roleDetails.IsPrivileged) {
                        vipBadge = '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>';
                    }
                }
            } catch (e) { /* silent fail */ }
        }

        contentHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-4 align-top whitespace-nowrap text-xs text-gray-600">${f.Region}</td>
                <td class="px-4 py-4 align-top text-xs text-gray-800 font-mono break-all whitespace-normal">
                    <div>
                        ${vipBadge}
                        <span class="font-semibold">${f.ResourceType}</span>
                    </div>
                    ${f.Resource}
                </td>
                <td class="px-4 py-4 align-top whitespace-normal text-xs text-gray-600 font-mono break-all">${principalDisplay}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-xs">${publicBadge}</td>
                <td class="px-4 py-4 align-top whitespace-normal text-xs text-gray-600 break-all">${f.Action}</td>
            </tr>`;
    });

    contentHtml += `</tbody></table></div>`;
    container.innerHTML = contentHtml;
};

const createIamResumenHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Total Users</p></div><div class="flex justify-between items-end pt-4"><p id="iam-total-users" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M8 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6m2-3a2 2 0 1 1-4 0 2 2 0 0 1 4 0m4 8c0 1-1 1-1 1H3s-1 0-1-1 1-4 6-4 6 3 6 4m-1-.004c-.001-.246-.154-.986-.832-1.664C11.516 10.68 10.289 10 8 10s-3.516.68-4.168 1.332c-.678.678-.83 1.418-.832 1.664z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Users with Elevated Privileges</p></div><div class="flex justify-between items-end pt-4"><p id="iam-privileged-users" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-yellow-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-yellow-600" viewBox="0 0 16 16"><path d="M12.5 16a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7m.5-5v1h1a.5.5 0 0 1 0 1h-1v1a.5.5 0 0 1-1 0v-1h-1a.5.5 0 0 1 0-1h1v-1a.5.5 0 0 1 1 0m-2-6a3 3 0 1 1-6 0 3 3 0 0 1 6 0M8 7a2 2 0 1 0 0-4 2 2 0 0 0 0 4"/><path d="M8.256 14a4.5 4.5 0 0 1-.229-1.004H3c.001-.246.154-.986.832-1.664C4.484 10.68 5.711 10 8 10q.39 0 .74.025c.226-.341.496-.65.804-.918Q8.844 9.002 8 9c-5 0-6 3-6 4s1 1 1 1z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Groups with Elevated Privileges</p></div><div class="flex justify-between items-end pt-4"><p id="iam-privileged-groups" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-yellow-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-yellow-600" viewBox="0 0 16 16"><path d="M5 8a2 2 0 1 0 0-4 2 2 0 0 0 0 4m4-2.5a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1h-4a.5.5 0 0 1-.5-.5M9 8a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1h-4A.5.5 0 0 1 9 8m1 2.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3a.5.5 0 0 1-.5-.5"/><path d="M2 2a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zM1 4a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v8a1 1 0 0 1-1 1H8.96q.04-.245.04-.5C9 10.567 7.21 9 5 9c-2.086 0-3.8 1.398-3.984 3.181A1 1 0 0 1 1 12z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Users with Elevated Privileges</p></div><div class="flex justify-between items-end pt-4"><p id="iam-privileged-roles" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-yellow-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-yellow-600" viewBox="0 0 16 16"><path d="M0 4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2zm9 1.5a.5.5 0 0 0 .5.5h4a.5.5 0 0 0 0-1h-4a.5.5 0 0 0-.5.5M9 8a.5.5 0 0 0 .5.5h4a.5.5 0 0 0 0-1h-4A.5.5 0 0 0 9 8m1 2.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 0 1h-3a.5.5 0 0 1-.5-.5m-1 2C9 10.567 7.21 9 5 9c-2.086 0-3.8 1.398-3.984 3.181A1 1 0 0 1 1 12zM7 6a2 2 0 1 0-4 0 2 2 0 0 0 4 0"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">MFA Compliance</p></div><div class="flex justify-between items-end pt-4"><p id="iam-mfa-compliance" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"><path d="M6.5 2a.5.5 0 0 0 0 1h3a.5.5 0 0 0 0-1zM11 8a3 3 0 1 1-6 0 3 3 0 0 1 6 0"/><path d="M4.5 0A2.5 2.5 0 0 0 2 2.5V14a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V2.5A2.5 2.5 0 0 0 11.5 0zM3 2.5A1.5 1.5 0 0 1 4.5 1h7A1.5 1.5 0 0 1 13 2.5v10.795a4.2 4.2 0 0 0-.776-.492C11.392 12.387 10.063 12 8 12s-3.392.387-4.224.803a4.2 4.2 0 0 0-.776.492z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Password Policies</p></div><div class="flex justify-between items-end pt-4"><p id="iam-password-compliance" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M14.5 3a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-9a.5.5 0 0 1 .5-.5zm-13-1A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2z"/><path d="M7 5.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m-1.496-.854a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 1 1 .708-.708l.146.147 1.146-1.147a.5.5 0 0 1 .708 0M7 9.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5m-1.496-.854a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0l-.5-.5a.5.5 0 0 1 .708-.708l.146.147 1.146-1.147a.5.5 0 0 1 .708 0"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">IAM Findings (Crit/High)</p></div><div class="flex justify-between items-end pt-4"><p id="iam-critical-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"> <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/></svg></div></div></div>
    </div>`;

const createIamUsuariosHtml = () => `
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">IAM Users List</h3>
        <div class="overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">User</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Password</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Use of Password</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">MFA</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">CLI MFA</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Groups</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Roles</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attached Policies</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Inline Policies</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-3/12">Access Keys</th>
                    </tr>
                </thead>
                <tbody id="users-table-body" class="bg-white divide-y divide-gray-200"></tbody>
            </table>
        </div>
    </div>`;

// 2. Agregar función para abrir modal con detalles de roles
export const openModalWithUserRoles = async (username, userIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    
    if (!modal || !modalTitle || !modalContent) return;

    // Obtener datos del usuario desde la cache local
    const user = window.iamApiData.results.users[userIndex];
    const tagBasedRoles = user.Roles || [];

    modalTitle.textContent = `Roles for User: ${username}`;
    
    // Mostrar loading state
    modalContent.innerHTML = `
        <div class="space-y-4">
            <!-- Roles por tags (inmediato) -->
            ${tagBasedRoles.length > 0 ? `
            <div>
                <h4 class="font-semibold text-md mb-3 text-[#204071] border-b border-gray-200 pb-2">
                    Organizational Roles (from tags)
                </h4>
                <div class="space-y-2">
                    ${tagBasedRoles.map(role => `
                        <div class="p-3 bg-blue-50 border border-blue-200 rounded-md">
                            <div class="flex items-center justify-between">
                                <span class="font-medium text-gray-800">${role.RoleName || role}</span>
                                <span class="px-2 py-1 text-xs font-semibold bg-blue-100 text-blue-800 rounded-full">
                                    Tag-based
                                </span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
            ` : ''}
            
            <!-- Roles asumibles (loading) -->
            <div>
                <h4 class="font-semibold text-md mb-3 text-[#204071] border-b border-gray-200 pb-2">
                    Assumable IAM Roles
                </h4>
                <div class="flex items-center justify-center py-8">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-[#204071]"></div>
                    <span class="ml-3 text-gray-600">Loading assumable roles...</span>
                </div>
            </div>
        </div>`;
    
    modal.classList.remove('hidden');

    // Hacer llamada API para obtener roles asumibles
    log(`Fetching assumable roles for user: ${username}`, 'info');
    
    const payload = {
        access_key: document.getElementById('access-key-input').value.trim(),
        secret_key: document.getElementById('secret-key-input').value.trim(),
        session_token: document.getElementById('session-token-input').value.trim() || null,
        username: username
    };

    try {
        const assumableRolesEndpoint = window.API?.GET_USER_ASSUMABLE_ROLES || '/api/get-user-assumable-roles';
        const response = await fetch(assumableRolesEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || `HTTP error! status: ${response.status}`);
        }

        // Actualizar contenido del modal con los resultados
        let rolesHtml = '<div class="space-y-4">';
        
        // Mostrar roles por tags si existen
        if (tagBasedRoles.length > 0) {
            rolesHtml += `
                <div>
                    <h4 class="font-semibold text-md mb-3 text-[#204071] border-b border-gray-200 pb-2">
                        Organizational Roles (from tags)
                    </h4>
                    <div class="space-y-2">`;
            
            tagBasedRoles.forEach(role => {
                rolesHtml += `
                    <div class="p-3 bg-blue-50 border border-blue-200 rounded-md">
                        <div class="flex items-center justify-between">
                            <span class="font-medium text-gray-800">${role.RoleName || role}</span>
                            <span class="px-2 py-1 text-xs font-semibold bg-blue-100 text-blue-800 rounded-full">
                                Tag-based
                            </span>
                        </div>
                    </div>`;
            });
            
            rolesHtml += '</div></div>';
        }
        
        // Mostrar roles asumibles
        const assumableRoles = result.assumable_roles || [];
        rolesHtml += `
            <div>
                <h4 class="font-semibold text-md mb-3 text-[#204071] border-b border-gray-200 pb-2">
                    Assumable IAM Roles
                </h4>`;
        
        if (assumableRoles.length > 0) {
            rolesHtml += '<div class="space-y-2">';
            
            assumableRoles.forEach(role => {
                rolesHtml += `
                    <div class="p-3 bg-green-50 border border-green-200 rounded-md">
                        <div class="flex items-center justify-between mb-2">
                            <span class="font-medium text-gray-800">${role.RoleName}</span>
                            <span class="px-2 py-1 text-xs font-semibold bg-green-100 text-green-800 rounded-full">
                                Policy-based
                            </span>
                        </div>
                        <p class="text-xs text-gray-600 font-mono break-all">${role.RoleArn}</p>
                    </div>`;
            });
            
            rolesHtml += '</div>';
        } else {
            rolesHtml += '<p class="text-center text-gray-500 py-4">No assumable roles found for this user.</p>';
        }
        
        rolesHtml += '</div></div>';
        
        modalContent.innerHTML = rolesHtml;
        
        const totalRoles = tagBasedRoles.length + assumableRoles.length;
        log(`Successfully loaded ${totalRoles} roles for user ${username} (${tagBasedRoles.length} tag-based, ${assumableRoles.length} assumable)`, 'success');

    } catch (error) {
        log(`Error fetching assumable roles: ${error.message}`, 'error');
        
        // Mostrar error en el modal pero mantener roles por tags
        let errorContent = '<div class="space-y-4">';
        
        // Mantener roles por tags visibles
        if (tagBasedRoles.length > 0) {
            errorContent += `
                <div>
                    <h4 class="font-semibold text-md mb-3 text-[#204071] border-b border-gray-200 pb-2">
                        Organizational Roles (from tags)
                    </h4>
                    <div class="space-y-2">`;
            
            tagBasedRoles.forEach(role => {
                errorContent += `
                    <div class="p-3 bg-blue-50 border border-blue-200 rounded-md">
                        <div class="flex items-center justify-between">
                            <span class="font-medium text-gray-800">${role.RoleName || role}</span>
                            <span class="px-2 py-1 text-xs font-semibold bg-blue-100 text-blue-800 rounded-full">
                                Tag-based
                            </span>
                        </div>
                    </div>`;
            });
            
            errorContent += '</div></div>';
        }
        
        // Mostrar error para roles asumibles
        errorContent += `
            <div>
                <h4 class="font-semibold text-md mb-3 text-[#204071] border-b border-gray-200 pb-2">
                    Assumable IAM Roles
                </h4>
                <div class="bg-red-50 text-red-700 p-3 rounded-lg">
                    <h5 class="font-bold">Error loading assumable roles</h5>
                    <p class="text-sm">${error.message}</p>
                </div>
            </div>
        </div>`;
        
        modalContent.innerHTML = errorContent;
    }
};


const createIamGruposHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">IAM Groups List</h3><div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Group name</th><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Creation Date</th><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attached Policies</th></tr></thead><tbody id="groups-table-body" class="bg-white divide-y divide-gray-200"></tbody></table></div></div>`;
const createIamRolesHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">IAM Roles List</h3><div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role name</th><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Creation Date</th><th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Attached Policies</th></tr></thead><tbody id="roles-table-body" class="bg-white divide-y divide-gray-200"></tbody></table></div></div>`;
const createIamPoliticasHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Account password policy</h3><div id="password-policy-container"></div></div>`;   

const createSecurityHubHtml = () => `
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
        <h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (IAM)</h3>
        
        <div id="iam-sh-filter-controls" class="flex flex-wrap items-center gap-2 mb-4">
            <span class="text-sm font-medium text-gray-700 mr-2">Filter by Severity:</span>
            <button data-severity="ALL" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-[#eb3496] text-white">All</button>
            <button data-severity="CRITICAL" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">Critical</button>
            <button data-severity="HIGH" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">High</button>
            <button data-severity="MEDIUM" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">Medium</button>
            <button data-severity="LOW" class="iam-sh-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">Low</button>
        </div>
        <div id="sh-iam-findings-container" class="overflow-x-auto"></div>
    </div>`;

const updateIamDashboard = () => { 
    const { users, roles, groups, password_policy } = window.iamApiData.results;
    const { accountId, executionDate } = window.iamApiData.metadata;
    const scanInfo = `Results for Account ${accountId} - ${executionDate}`;
    const infoElement = document.querySelector('#iam-view .scan-info');
    if (infoElement) infoElement.textContent = scanInfo;
    const totalUsers = users.length;
    const privilegedUsersCount = users.filter(u => u.IsPrivileged).length;
    const privilegedGroupsCount = groups.filter(g => g.IsPrivileged).length;
    const privilegedRolesCount = roles.filter(r => r.IsPrivileged).length;
    const mfaEnabledUsers = users.filter(u => u.MFADevices.length > 0).length;
    const mfaCompliance = totalUsers > 0 ? Math.round((mfaEnabledUsers / totalUsers) * 100) : 0;
    let passwordPolicyCompliance = 0;
    if (!password_policy.Error) {
        const checks = [ (password_policy.MinimumPasswordLength || 0) >= 12, password_policy.RequireUppercaseCharacters, password_policy.RequireLowercaseCharacters, password_policy.RequireNumbers, password_policy.RequireSymbols, password_policy.MaxPasswordAge && password_policy.MaxPasswordAge <= 90, (password_policy.PasswordReusePrevention || 0) >= 4, password_policy.HardExpiry ];
        const passedChecks = checks.filter(Boolean).length;
        passwordPolicyCompliance = Math.round((passedChecks / checks.length) * 100);
    }
    const criticalHighIamFindings = window.securityHubApiData.results.findings.iamFindings.filter(f => f.Severity?.Label === 'CRITICAL' || f.Severity?.Label === 'HIGH').length;
    document.getElementById('iam-total-users').textContent = totalUsers;
    document.getElementById('iam-privileged-users').textContent = privilegedUsersCount;
    document.getElementById('iam-privileged-groups').textContent = privilegedGroupsCount;
    document.getElementById('iam-privileged-roles').textContent = privilegedRolesCount;
    document.getElementById('iam-mfa-compliance').textContent = `${mfaCompliance}%`;
    document.getElementById('iam-password-compliance').textContent = `${passwordPolicyCompliance}%`;
    document.getElementById('iam-critical-findings').textContent = criticalHighIamFindings;
    renderUsersTable(users);
    renderGroupsTable(groups);
    renderRolesTable(roles);
    renderPasswordPolicy(password_policy);

    renderCriticalPermissionsTable(users);
};

const renderCriticalPermissionsTable = (users) => {
    const container = document.getElementById('critical-perms-content');
    if (!container) return;

    const permissionsByCategory = {
        network: [],
        cloudtrail: [],
        database: [],
        waf: []
    };

    users.forEach(user => {
        if (user.criticalPermissions) {
            for (const category in user.criticalPermissions) {
                if (user.criticalPermissions[category].length > 0) {
                    permissionsByCategory[category].push({
                        userName: user.UserName,
                        permissions: user.criticalPermissions[category]
                    });
                }
            }
        }
    });

    const categoryNames = {
        network: 'Red (VPC, SG, ACLs)',
        cloudtrail: 'CloudTrail',
        database: 'Bases de Datos (RDS, DynamoDB)',
        waf: 'WAF'
    };
    const categoryStyles = {
        network: 'bg-blue-100 text-blue-800',
        cloudtrail: 'bg-indigo-100 text-indigo-800',
        database: 'bg-purple-100 text-purple-800',
        waf: 'bg-pink-100 text-pink-800'
    };

    const hasAnyPrivilegedUser = Object.values(permissionsByCategory).some(userList => userList.length > 0);

    if (!hasAnyPrivilegedUser) {
        container.innerHTML = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><p class="text-center text-gray-500">Good job! No users with critical permissions were found in the analyzed categories.</p></div>`;
        return;
    }

    let tableHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                        <h3 class="font-bold text-lg mb-4 text-[#204071]">Critical Permissions by Service</h3>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider w-1/4">Critical Service</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Users and Assigned Permissions</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">`;

    for (const category in permissionsByCategory) {
        const userList = permissionsByCategory[category];
        if (userList.length > 0) {
            tableHtml += `<tr class="hover:bg-gray-50">
                            <td class="px-6 py-4 align-top">
                                <span class="inline-block ${categoryStyles[category]} text-sm font-semibold mr-2 px-4 py-1.5 rounded-full">${categoryNames[category]}</span>
                            </td>
                            <td class="px-6 py-4 text-sm align-top">
                                <div class="space-y-4">`;
            
            userList.forEach(user => {
                const permissionsBadges = user.permissions.map(perm => 
                    `<span class="inline-block bg-gray-100 text-gray-800 text-xs font-mono font-medium mr-2 mb-2 px-2.5 py-0.5 rounded-full">${perm}</span>`
                ).join('');

                tableHtml += `<div class="border-b border-gray-100 pb-3 last:border-b-0">
                                <p class="font-semibold text-gray-800">${user.userName}</p>
                                <div class="mt-1">${permissionsBadges}</div>
                            </div>`;
            });

            tableHtml += `</div></td></tr>`;
        }
    }

    tableHtml += `</tbody></table></div></div>`;
    container.innerHTML = tableHtml;
};

const renderFederationView = () => {
    const container = document.getElementById('federation-content');
    if (!container || !window.federationApiData || !window.federationApiData.results) {
        if(container) container.innerHTML = '<p class="text-center text-gray-500 py-4">Federation data is not available. Run a scan or check for API errors.</p>';
        return;
    }

    const { iam_federation = {}, identity_center = {} } = window.federationApiData.results;

    let aliasHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 mb-6">
                        <h3 class="font-bold text-lg mb-2 text-[#204071]">Account Alias</h3>`;
    if (iam_federation.account_alias) {
        const signInUrl = `https://${iam_federation.account_alias}.signin.aws.amazon.com/console`;
        aliasHtml += `<p class="text-sm text-gray-600">Alias: <strong class="font-mono bg-gray-100 p-1 rounded">${iam_federation.account_alias}</strong></p>
                    <p class="text-sm text-gray-600 mt-2">Sign-in URL:</p>
                    <a href="${signInUrl}" target="_blank" class="text-blue-600 hover:underline font-mono text-sm break-all">${signInUrl}</a>`;
    } else {
        aliasHtml += `<p class="text-sm text-gray-600">This account does not have a custom alias configured.</p>`;
    }
    aliasHtml += `</div>`;
    
    let identityCenterHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 mt-6">
                                <h3 class="font-bold text-lg mb-4 text-[#204071]">AWS Identity Center (SSO)</h3>`;

    if (identity_center.status === 'Found') {
        const { instance_arn, assignments } = identity_center;

        identityCenterHtml += `<div class="mb-6 space-y-2 text-sm">
                                    <p><strong class="text-gray-600">Instance ARN:</strong> <span class="font-mono bg-gray-100 p-1 rounded">${instance_arn}</span></p>
                                </div>`;

        if (assignments && assignments.length > 0) {
            identityCenterHtml += `<h4 class="font-semibold text-md mb-2">Permission Assignments</h4>
                                    <div class="overflow-x-auto">
                                    <table id="sso-assignments-table" class="min-w-full divide-y divide-gray-200">
                                        <thead class="bg-gray-50"><tr>
                                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Group</th>
                                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Permission Set (Role)</th>
                                            <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">AWS Account ID</th>
                                            <th class="px-4 py-2 text-center text-xs font-medium text-gray-500 uppercase">Details</th>
                                        </tr></thead>
                                        <tbody class="bg-white divide-y divide-gray-200">`;
            assignments.forEach(a => {
                const vipBadge = a.IsPrivileged ? '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>' : '';
                
                identityCenterHtml += `<tr class="hover:bg-gray-50">
                                        <td class="px-4 py-3 text-sm font-medium text-gray-800">${a.GroupName}</td>
                                        <td class="px-4 py-3 text-sm text-gray-600">${vipBadge}${a.PermissionSetName}</td>
                                        <td class="px-4 py-3 text-sm text-gray-600 font-mono">${a.AccountId}</td>
                                        <td class="px-4 py-3 text-center">
                                            <button onclick="openModalWithSsoDetails('${a.GroupId}', '${a.GroupName}')" class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">View</button>
                                        </td>
                                    </tr>`;
            });
            identityCenterHtml += `</tbody></table></div>`;
        } else {
            identityCenterHtml += `<p class="text-center text-gray-500 py-4">Identity Center is enabled, but no group permission assignments were found.</p>`;
        }
    } else {
        const message = identity_center.message || "Could not retrieve Identity Center information. Necessary permissions (sso-admin, identitystore) may be missing or the service is not configured.";
        identityCenterHtml += `<p class="text-center text-gray-500 py-4">${message}</p>`;
    }
    
    identityCenterHtml += `</div>`;
    
    container.innerHTML = aliasHtml + identityCenterHtml;
};

export const openModalWithSsoDetails = async (groupId, groupName) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    if (!modal || !modalTitle || !modalContent) return;

    modalTitle.textContent = `Members of Group: ${groupName}`;
    modalContent.innerHTML = `
        <div class="space-y-3 animate-pulse p-2">
            <div class="h-8 bg-slate-200 rounded-md w-full"></div>
            <div class="h-8 bg-slate-200 rounded-md w-5/6"></div>
            <div class="h-8 bg-slate-200 rounded-md w-2/3"></div>
        </div>`;
    modal.classList.remove('hidden');

    log(`Fetching members for SSO Group ID: ${groupId}`, 'info');
    const payload = {
        access_key: document.getElementById('access-key-input').value.trim(),
        secret_key: document.getElementById('secret-key-input').value.trim(),
        session_token: document.getElementById('session-token-input').value.trim() || null,
        group_id: groupId
    };

    try {
        const ssoMembersEndpoint = window.API?.GET_SSO_GROUP_MEMBERS || '/api/get-sso-group-members';
        const response = await fetch(ssoMembersEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error);

        const memberCount = data.members ? data.members.length : 0;
        let membersListHtml = '';
        if (memberCount > 0) {
            membersListHtml = '<div class="space-y-2 text-left">';
            data.members.forEach(member => {
                membersListHtml += `<div class="bg-slate-100 text-slate-800 text-sm font-mono p-2 rounded-md">${member}</div>`;
            });
            membersListHtml += '</div>';
        } else {
            membersListHtml = '<p class="text-sm text-gray-500 text-center py-4">This group has no members.</p>';
        }
        modalContent.innerHTML = membersListHtml;
        log(`Successfully fetched ${memberCount} members for group ${groupName}.`, 'success');

    } catch (e) {
        modalContent.innerHTML = `<div class="bg-red-50 text-red-700 p-3 rounded-lg text-left"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
        log(`Error fetching group members: ${e.message}`, 'error');
    }
};

export const openModalWithAccessKeyDetails = (userIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const user = window.iamApiData.results.users[userIndex];
    if (!modal || !user || !user.AccessKeys || user.AccessKeys.length === 0) return;

    modalTitle.textContent = `Access Keys for User: ${user.UserName}`;
    const keysDetailsHtml = user.AccessKeys.map(k => {
        const createDate = new Date(k.CreateDate);
        const now = new Date();
        const ageDays = Math.floor((now - createDate) / (1000 * 60 * 60 * 24));
        const ageClass = ageDays > 90 ? 'text-red-600 font-bold' : 'text-gray-600';
        const statusClass = k.Status === 'Active' ? 'text-green-600' : 'text-gray-500';
        const lastUsed = k.LastUsedDate !== 'N/A' ? new Date(k.LastUsedDate).toLocaleDateString() : 'Never';

        return `
            <div class="p-3 bg-gray-100 rounded-md border border-gray-200 text-xs text-left">
                <div class="font-mono font-semibold text-gray-800">${k.AccessKeyId}</div>
                <div class="mt-1"><span class="font-semibold">Status:</span> <span class="${statusClass}">${k.Status}</span></div>
                <div><span class="font-semibold">Age:</span> <span class="${ageClass}">${ageDays} days</span></div>
                <div><span class="font-semibold">Last Used:</span> ${lastUsed}</div>
            </div>`;
    }).join('');
    modalContent.innerHTML = `<div class="space-y-3">${keysDetailsHtml}</div>`;
    modal.classList.remove('hidden');
};

export const openModalWithUserGroups = (userIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const user = window.iamApiData.results.users[userIndex];
    if (!modal || !user || !user.Groups || user.Groups.length === 0) return;

    modalTitle.textContent = `Groups for User: ${user.UserName}`;
    const groupsListHtml = user.Groups.map(groupName => {
        return `<div class="p-3 bg-gray-100 rounded-md border border-gray-200 text-sm text-left font-semibold text-gray-800">
                    ${groupName}
                </div>`;
    }).join('');
    modalContent.innerHTML = `<div class="space-y-3">${groupsListHtml}</div>`;
    modal.classList.remove('hidden');
};

export const updateSecurityHubDashboard = () => {
    const securityHubData = window.securityHubApiData || window.securityHubStatusApiData;
    const containerElement = document.getElementById('sh-iam-findings-container');
    
    if (!securityHubData || !securityHubData.results || !securityHubData.results.findings) {
        // Si no hay findings, mostrar mensaje vacío
        const container = document.getElementById('sh-iam-findings-container');
        if (container) {
            container.innerHTML = '<p class="text-center text-gray-500 py-4">No Security Hub data available. Run an analysis first.</p>';
        }
        return;
    }

    const allIamFindings = securityHubData.results.findings.iamFindings || [];
    const filterControlsContainer = document.getElementById('iam-sh-filter-controls');

    const renderFilteredFindings = (severity) => {
        let filteredFindings = allIamFindings;
        if (severity !== 'ALL') {
            filteredFindings = allIamFindings.filter(f => f.Severity?.Label === severity);
        }
        renderSecurityHubFindings(filteredFindings, 'sh-iam-findings-container', `No IAM findings with severity '${severity}' were found.`);
    };

    if (filterControlsContainer) {
        // Aseguramos que el listener solo se añade una vez
        if (!filterControlsContainer.dataset.listenerAttached) {
            filterControlsContainer.addEventListener('click', (e) => {
                const filterBtn = e.target.closest('.iam-sh-filter-btn');
                if (!filterBtn) return;
                filterControlsContainer.querySelectorAll('.iam-sh-filter-btn').forEach(btn => {
                    btn.classList.remove('bg-[#eb3496]', 'text-white');
                    btn.classList.add('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
                });
                filterBtn.classList.add('bg-[#eb3496]', 'text-white');
                filterBtn.classList.remove('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
                const selectedSeverity = filterBtn.dataset.severity;
                renderFilteredFindings(selectedSeverity);
            });
            filterControlsContainer.dataset.listenerAttached = 'true';
        }
    }

    renderFilteredFindings('ALL');
};

const renderUsersTable = (users) => {
    const tableBody = document.getElementById('users-table-body');
    tableBody.innerHTML = '';
    if (!users || users.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="10" class="text-center text-gray-500 py-4">No users were found.</td></tr>`;
        return;
    }
    
    users.forEach((user, index) => {
        const vipBadge = user.IsPrivileged ? '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>' : '';
        const passwordEnabled = user.PasswordEnabled ? 'YES' : 'NO';
        const mfaEnabled = user.MFADevices.length > 0 ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">YES</span>' : '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">NO</span>';
        
        // CLI MFA Compliance check
        let cliMfaCompliance = '-';
        if (user.mfa_compliance) {
            const isCompliant = user.mfa_compliance.cli_compliant;
            const riskLevel = user.mfa_compliance.risk_level;
            
            if (riskLevel === 'none') {
                cliMfaCompliance = '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">N/A</span>';
            } else if (isCompliant) {
                cliMfaCompliance = '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">YES</span>';
            } else {
                cliMfaCompliance = '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">NO</span>';
            }
        }
        
        // Groups column
        let groupsHtml = '-';
        if (user.Groups && user.Groups.length > 0) {
            groupsHtml = `<button 
                              onclick="openModalWithUserGroups(${index})" 
                              class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                              View (${user.Groups.length})
                          </button>`;
        }
        
        // COLUMNA ROLES: Mostrar botón siempre, carga bajo demanda
        const tagBasedRoles = user.Roles || [];
        let rolesButtonText = 'View';
        
        if (tagBasedRoles.length > 0) {
            rolesButtonText = `View (${tagBasedRoles.length} Tag)`;
        }
        
        const rolesHtml = `<button 
                             onclick="openModalWithUserRoles('${user.UserName}', ${index})" 
                             class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                             ${rolesButtonText}
                         </button>`;

        const attachedPolicies = user.AttachedPolicies.join(', ') || '-';
        const inlinePolicies = user.InlinePolicies.join(', ') || '-';
        
        let accessKeysHtml = '-';
        if (user.AccessKeys && user.AccessKeys.length > 0) {
            accessKeysHtml = `<button 
                                onclick="openModalWithAccessKeyDetails(${index})" 
                                class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                                View (${user.AccessKeys.length})
                              </button>`;
        }
        
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50';
        
        row.innerHTML = `
            <td class="px-6 py-4 whitespace-nowrap text-xs font-medium text-[#204071] flex items-center">${vipBadge}${user.UserName}</td> 
            <td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${passwordEnabled}</td> 
            <td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${user.PasswordLastUsed}</td> 
            <td class="px-6 py-4 whitespace-nowrap text-xs">${mfaEnabled}</td> 
            <td class="px-6 py-4 whitespace-nowrap text-xs">${cliMfaCompliance}</td>
            <td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${groupsHtml}</td> 
            <td class="px-6 py-4 whitespace-nowrap text-xs text-gray-500">${rolesHtml}</td>
            <td class="px-6 py-4 text-xs text-gray-500 break-words">${attachedPolicies}</td> 
            <td class="px-6 py-4 text-xs text-gray-500 break-words">${inlinePolicies}</td> 
            <td class="px-6 py-4 text-xs text-gray-500 align-top">${accessKeysHtml}</td>`;
        tableBody.appendChild(row);
    });
};


const renderGroupsTable = (groups) => {
    const tableBody = document.getElementById('groups-table-body');
    tableBody.innerHTML = '';
    if (!groups || groups.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="3" class="text-center text-gray-500 py-4">No groups were found.</td></tr>`;
        return;
    }
    groups.forEach(group => {
        const vipBadge = group.IsPrivileged ? '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>' : '';
        const attachedPolicies = group.AttachedPolicies.join(', ') || '-';
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50';
        row.innerHTML = `<td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-[#204071] flex items-center">${vipBadge}${group.GroupName}</td> <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${new Date(group.CreateDate).toLocaleDateString()}</td> <td class="px-6 py-4 text-sm text-gray-500 break-words">${attachedPolicies}</td>`;
        tableBody.appendChild(row);
    });
};

const renderRolesTable = (roles) => {
    const tableBody = document.getElementById('roles-table-body');
    tableBody.innerHTML = '';
    if (!roles || roles.length === 0) {
        tableBody.innerHTML = `<tr><td colspan="3" class="text-center text-gray-500 py-4">No roles were found.</td></tr>`;
        return;
    }
    roles.forEach(role => {
        const vipBadge = role.IsPrivileged ? '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>' : '';
        const attachedPolicies = role.AttachedPolicies.join(', ') || '-';
        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-50';
        row.innerHTML = `<td class="px-6 py-4 text-sm font-medium text-[#204071] break-words flex items-center">${vipBadge}${role.RoleName}</td> <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${new Date(role.CreateDate).toLocaleDateString()}</td> <td class="px-6 py-4 text-sm text-gray-500 break-words">${attachedPolicies}</td>`;
        tableBody.appendChild(row);
    });
};


const renderPasswordPolicy = (policy) => {
    const container = document.getElementById('password-policy-container');
    container.innerHTML = '';
    
    if (policy.Error) {
        container.innerHTML = `<p class="text-red-600 font-medium">There is no password policy configured for this account.</p>`;
        return;
    }
    
    // Verificaciones de política de contraseñas
    const checks = [
        { desc: "Minimum length >= 12", ok: (policy.MinimumPasswordLength || 0) >= 12, val: policy.MinimumPasswordLength },
        { desc: "Requires uppercase", ok: policy.RequireUppercaseCharacters, val: policy.RequireUppercaseCharacters },
        { desc: "Requires lowercase letters", ok: policy.RequireLowercaseCharacters, val: policy.RequireLowercaseCharacters },
        { desc: "Requires numbers", ok: policy.RequireNumbers, val: policy.RequireNumbers },
        { desc: "Requires symbols", ok: policy.RequireSymbols, val: policy.RequireSymbols },
        { desc: "Expiration ≤ 90 days", ok: policy.MaxPasswordAge && policy.MaxPasswordAge <= 90, val: policy.MaxPasswordAge },
        { desc: "Reuse ≥ 4 passwords", ok: (policy.PasswordReusePrevention || 0) >= 4, val: policy.PasswordReusePrevention },
    ];
    
    let checksHtml = `<h4 class="font-semibold text-md mb-2">Password Policy Compliance</h4>
                      <div class="overflow-x-auto">
                          <table class="min-w-full divide-y divide-gray-200 mb-6">
                              <thead class="bg-gray-50">
                                  <tr>
                                      <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Check</th>
                                      <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                      <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Configured Value</th>
                                  </tr>
                              </thead>
                              <tbody class="bg-white divide-y divide-gray-200">`;
    
    checks.forEach(({ desc, ok, val }) => {
        const statusIcon = ok ? 
            '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">OK</span>' : 
            '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">KO</span>';
        checksHtml += `<tr>
                          <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-700">${desc}</td>
                          <td class="px-4 py-2 whitespace-nowrap text-sm">${statusIcon}</td>
                          <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-500">${val === undefined ? 'Not defined' : val}</td>
                       </tr>`;
    });
    checksHtml += `</tbody></table></div>`;
    
    // NUEVA FUNCIONALIDAD: Verificar MFA del usuario root con detección de hardware
    let rootMfaHtml = '';
    if (policy.RootMFAStatus) {
        const rootMfaStatus = policy.RootMFAStatus;
        
        rootMfaHtml = `<h4 class="font-semibold text-md mb-2 mt-6">Root User Security</h4>
                       <div class="overflow-x-auto">
                           <table class="min-w-full divide-y divide-gray-200 mb-6">
                               <thead class="bg-gray-50">
                                   <tr>
                                       <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Security Check</th>
                                       <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                                       <th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Details</th>
                                   </tr>
                               </thead>
                               <tbody class="bg-white divide-y divide-gray-200">`;
        
        if (rootMfaStatus.error) {
            // Mostrar error si no se pudo verificar
            rootMfaHtml += `<tr>
                               <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-700">Root MFA Enabled</td>
                               <td class="px-4 py-2 whitespace-nowrap text-sm">
                                   <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">UNKNOWN</span>
                               </td>
                               <td class="px-4 py-2 text-sm text-gray-500 break-words">${rootMfaStatus.error}</td>
                            </tr>`;
        } else {
            // Fila 1: Estado del MFA del root
            const mfaStatusIcon = rootMfaStatus.root_mfa_enabled ? 
                '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">ENABLED</span>' : 
                '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">DISABLED</span>';
            
            const mfaDetails = rootMfaStatus.root_mfa_enabled ? 
                `MFA is properly configured for the root user${rootMfaStatus.virtual_mfa_devices > 0 ? ` (${rootMfaStatus.virtual_mfa_devices} virtual device(s))` : ''}` :
                'Root user does not have MFA enabled - CRITICAL SECURITY RISK';
            
            rootMfaHtml += `<tr>
                               <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-700">Root MFA Enabled</td>
                               <td class="px-4 py-2 whitespace-nowrap text-sm">${mfaStatusIcon}</td>
                               <td class="px-4 py-2 text-sm text-gray-500 break-words">${mfaDetails}</td>
                            </tr>`;
            
            // Fila 2: Tipo de MFA (solo si MFA está habilitado)
            if (rootMfaStatus.root_mfa_enabled && rootMfaStatus.iam6_check_available) {
                let hardwareStatusIcon, hardwareDetails;
                
                if (rootMfaStatus.mfa_is_hardware === true) {
                    hardwareStatusIcon = '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">HARDWARE</span>';
                    hardwareDetails = rootMfaStatus.iam6_finding_details || 'Hardware MFA detected via Security Hub compliance';
                } else if (rootMfaStatus.mfa_is_hardware === false) {
                    hardwareStatusIcon = '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-orange-100 text-orange-800">VIRTUAL</span>';
                    hardwareDetails = rootMfaStatus.iam6_finding_details || 'Virtual MFA detected - consider upgrading to hardware';
                } else {
                    hardwareStatusIcon = '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">UNKNOWN</span>';
                    hardwareDetails = rootMfaStatus.iam6_finding_details || 'Unable to determine MFA type via Security Hub';
                }
                
                rootMfaHtml += `<tr>
                                   <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-700">Root MFA Type</td>
                                   <td class="px-4 py-2 whitespace-nowrap text-sm">${hardwareStatusIcon}</td>
                                   <td class="px-4 py-2 text-sm text-gray-500 break-words">${hardwareDetails}</td>
                                </tr>`;
            } else if (rootMfaStatus.root_mfa_enabled && !rootMfaStatus.iam6_check_available) {
                // MFA habilitado pero no se pudo verificar el tipo
                rootMfaHtml += `<tr>
                                   <td class="px-4 py-2 whitespace-nowrap text-sm text-gray-700">Root MFA Type</td>
                                   <td class="px-4 py-2 whitespace-nowrap text-sm">
                                       <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">UNKNOWN</span>
                                   </td>
                                   <td class="px-4 py-2 text-sm text-gray-500 break-words">Security Hub check not available - unable to determine hardware vs virtual</td>
                                </tr>`;
            }
        }
        
        rootMfaHtml += `</tbody></table></div>`;
        
        // Alertas de seguridad solo para casos que requieren acción
        if (rootMfaStatus.root_mfa_enabled === false) {
            rootMfaHtml += `<div class="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
                               <h5 class="text-red-800 font-semibold mb-2">Critical Security Recommendation</h5>
                               <p class="text-red-700 text-sm">
                                   The root user does not have MFA enabled. This represents a significant security risk. 
                                   Enable MFA for the root user immediately through the AWS Console Security Credentials section.
                               </p>
                           </div>`;
        } else if (rootMfaStatus.root_mfa_enabled && rootMfaStatus.mfa_is_hardware === false) {
            rootMfaHtml += `<div class="bg-orange-50 border border-orange-200 rounded-lg p-4 mb-4">
                               <h5 class="text-orange-800 font-semibold mb-2">Security Enhancement Recommendation</h5>
                               <p class="text-orange-700 text-sm">
                                   While the root user has MFA enabled, it appears to be using a virtual device. 
                                   For enhanced security, consider upgrading to a hardware MFA device (AWS Security Hub finding IAM.6).
                               </p>
                           </div>`;
        }
        
        // Detectar inconsistencia entre IAM y Security Hub
        if (rootMfaStatus.root_mfa_enabled && 
            rootMfaStatus.iam6_check_available && 
            rootMfaStatus.virtual_mfa_devices > 0 && 
            rootMfaStatus.mfa_is_hardware === true) {
            
            rootMfaHtml += `<div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-4">
                               <h5 class="text-yellow-800 font-semibold mb-2">Potential Data Inconsistency Detected</h5>
                               <div class="text-yellow-700 text-sm space-y-2">
                                   <p><strong>Issue:</strong> IAM reports ${rootMfaStatus.virtual_mfa_devices} virtual MFA device(s) for the root user, but Security Hub indicates hardware MFA is enabled.</p>
                                   
                                   <p><strong>Possible causes:</strong></p>
                                   <ul class="list-disc list-inside ml-4 space-y-1">
                                       <li>Security Hub findings may take 12-24 hours to update after configuration changes</li>
                                       <li>An IAM.6 finding may have been manually suppressed or resolved in Security Hub</li>
                                       <li>AWS Config may not be properly evaluating the IAM.6 rule</li>
                                       <li>There may be multiple MFA devices configured (both virtual and hardware)</li>
                                   </ul>
                                   
                                   <p><strong>Recommendation:</strong> Manually verify the root user's MFA configuration in the AWS Console → IAM → Dashboard → Security Credentials to confirm the actual MFA type.</p>
                               </div>
                           </div>`;
        }
    }
    
    // JSON raw de la política
    const rawJsonHtml = `<h4 class="font-semibold text-md mb-2 mt-6">API Raw Response</h4>
                         <pre class="bg-[#204071] text-white p-4 rounded-lg text-sm overflow-x-auto">
                             <code>${JSON.stringify(policy, null, 2)}</code>
                         </pre>`;
    
    container.innerHTML = checksHtml + rootMfaHtml + rawJsonHtml;
};

const renderIamDetailsViewHtml = () => {
    return `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-4 text-[#204071]">View Detailed Permissions</h3>
            <p class="text-sm text-gray-600 mb-4">Enter the name of a principal or policy to view detailed information.</p>
            
            <!-- Selector de tipo -->
            <div class="mb-4">
                <label class="block text-sm font-medium text-gray-700 mb-2">Search Type</label>
                <div class="flex flex-wrap gap-2">
                    <button id="search-type-principal" class="search-type-btn px-4 py-2 text-sm font-semibold rounded-md bg-[#eb3496] text-white">
                        IAM Principal (User/Group/Role)
                    </button>
                    <button id="search-type-policy" class="search-type-btn px-4 py-2 text-sm font-semibold rounded-md bg-white text-gray-700 border border-gray-300 hover:bg-gray-50">
                        Custom Policy
                    </button>
                </div>
            </div>
            
            <!-- Campo de búsqueda -->
            <div class="flex flex-col sm:flex-row gap-4 items-end">
                <div class="flex-grow">
                    <label for="iam-search-input" class="block text-sm font-medium text-gray-700 mb-1">
                        <span id="search-label">Name of User, Group, or Role</span>
                    </label>
                    <input type="text" id="iam-search-input" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="E.g.: admin-user, DevelopersGroup, EC2AdminRole">
                </div>
                <button id="iam-search-btn" class="w-full sm:w-auto bg-[#204071] text-white px-5 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition">
                    <span id="search-btn-text">View Details</span>
                </button>
            </div>
        </div>
        <div id="iam-search-results-container" class="mt-6"></div>
    `;
};


const getIamPermissionDetails = () => {
    const searchType = getSelectedSearchType();
    const searchInput = document.getElementById('iam-search-input').value.trim();
    
    if (!searchInput) {
        showSearchError('Please provide a name to search.');
        return;
    }
    
    if (searchType === 'principal') {
        searchIamPrincipal(searchInput);
    } else if (searchType === 'policy') {
        analyzeCustomPolicy(searchInput);
    }
};

const getSelectedSearchType = () => {
    const principalBtn = document.getElementById('search-type-principal');
    return principalBtn.classList.contains('bg-[#eb3496]') ? 'principal' : 'policy';
};

// 4. Función auxiliar para mostrar errores
const showSearchError = (message) => {
    const resultsContainer = document.getElementById('iam-search-results-container');
    resultsContainer.innerHTML = `<p class="text-yellow-600 font-medium">${message}</p>`;
};

const searchIamPrincipal = (rawInput) => {
    log('Fetching IAM principal details...', 'info');
    const resultsContainer = document.getElementById('iam-search-results-container');
    let principalNameToSearch = rawInput;

    // Manejar ARNs
    if (rawInput.toLowerCase().startsWith('arn:aws:iam::')) {
        try {
            const parts = rawInput.split('/');
            principalNameToSearch = parts[parts.length - 1];
            log(`ARN detected. Searching for extracted name: '${principalNameToSearch}'`, 'info');
        } catch (e) {
            log('Error parsing ARN. Using full value.', 'error');
        }
    }

    if (!window.iamApiData || !window.iamApiData.results) {
        resultsContainer.innerHTML = `<p class="text-red-600 font-medium">No IAM data loaded. Please run an analysis first.</p>`;
        log('Attempted permission search without IAM data.', 'error');
        return;
    }

    const { users, groups, roles } = window.iamApiData.results;
    let foundPrincipal = null;
    let principalType = '';

    const user = users.find(u => u.UserName.toLowerCase() === principalNameToSearch.toLowerCase());
    if (user) {
        foundPrincipal = user;
        principalType = 'User';
    } else {
        const group = groups.find(g => g.GroupName.toLowerCase() === principalNameToSearch.toLowerCase());
        if (group) {
            foundPrincipal = group;
            principalType = 'Group';
        } else {
            const role = roles.find(r => r.RoleName.toLowerCase() === principalNameToSearch.toLowerCase());
            if (role) {
                foundPrincipal = role;
                principalType = 'Role';
            }
        }
    }
    
    renderIamPrincipalDetails(foundPrincipal, principalType, rawInput);
};

const analyzeCustomPolicy = async (policyName) => {
    log(`Analyzing custom policy: ${policyName}`, 'info');
    const resultsContainer = document.getElementById('iam-search-results-container');
    const searchBtn = document.getElementById('iam-search-btn');
    const btnText = document.getElementById('search-btn-text');
    
    // Mostrar loading state
    searchBtn.disabled = true;
    btnText.textContent = 'Analyzing...';
    
    resultsContainer.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <div class="flex items-center justify-center py-8">
                <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-[#204071]"></div>
                <span class="ml-3 text-gray-600">Analyzing custom policy...</span>
            </div>
        </div>`;

    const payload = {
        access_key: document.getElementById('access-key-input').value.trim(),
        secret_key: document.getElementById('secret-key-input').value.trim(),
        session_token: document.getElementById('session-token-input').value.trim() || null,
        policy_name: policyName
    };

    try {
        const analyzeCustomPolicyEndpoint = window.API?.ANALYZE_CUSTOM_POLICY || '/api/analyze-custom-policy';
        const response = await fetch(analyzeCustomPolicyEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || `HTTP error! status: ${response.status}`);
        }

        if (result.status === 'error') {
            throw new Error(result.error);
        }

        renderCustomPolicyAnalysis(result);
        log(`Successfully analyzed policy: ${policyName}`, 'success');

    } catch (error) {
        log(`Error analyzing custom policy: ${error.message}`, 'error');
        resultsContainer.innerHTML = `
            <div class="bg-red-50 text-red-700 p-4 rounded-lg">
                <h4 class="font-bold">Error Analyzing Policy</h4>
                <p>${error.message}</p>
            </div>`;
    } finally {
        searchBtn.disabled = false;
        btnText.textContent = 'View Details';
    }
};

// 7. Función para renderizar el análisis de política custom
const renderCustomPolicyAnalysis = (result) => {
    const resultsContainer = document.getElementById('iam-search-results-container');
    const { policy_name, metadata, analysis, used_by, policy_document } = result;
    
    // Determinar color del badge de privilegio
    const getPrivilegeBadge = (level) => {
        const badges = {
            'critical': 'bg-red-100 text-red-800',
            'high': 'bg-orange-100 text-orange-800',
            'medium': 'bg-yellow-100 text-yellow-800',
            'low': 'bg-green-100 text-green-800',
            'unknown': 'bg-gray-100 text-gray-800'
        };
        return `<span class="px-3 py-1 text-sm font-semibold rounded-full ${badges[level] || badges.unknown}">${level.toUpperCase()}</span>`;
    };

    // Crear lista de servicios
    const servicesHtml = analysis.services_affected && analysis.services_affected.length > 0 
        ? analysis.services_affected.map(service => 
            `<span class="inline-block bg-blue-100 text-blue-800 text-xs font-medium mr-2 mb-2 px-2.5 py-0.5 rounded-full">${service}</span>`
        ).join('')
        : '<span class="text-gray-500">No services detected</span>';

    // Crear lista de preocupaciones de seguridad
    const securityConcernsHtml = analysis.security_concerns && analysis.security_concerns.length > 0
        ? analysis.security_concerns.map(concern => 
            `<li class="text-red-700 text-sm">• ${concern}</li>`
        ).join('')
        : '<li class="text-green-700 text-sm">• No obvious security concerns detected</li>';

    // Crear lista de entidades que usan la política
    const entitiesHtml = createEntitiesUsageHtml(used_by);

    resultsContainer.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="text-xl font-bold text-[#204071] mb-4">Custom Policy Analysis: ${policy_name}</h3>
            
            <!-- Metadata Section -->
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                <div class="bg-gray-50 p-4 rounded-lg">
                    <h4 class="font-semibold text-gray-700 text-sm">Privilege Level</h4>
                    <div class="mt-2">${getPrivilegeBadge(analysis.privilege_level)}</div>
                </div>
                <div class="bg-gray-50 p-4 rounded-lg">
                    <h4 class="font-semibold text-gray-700 text-sm">Statements</h4>
                    <p class="mt-2 text-lg font-bold text-[#204071]">${analysis.statement_count}</p>
                    <p class="text-xs text-gray-600">${analysis.allows_statements} Allow, ${analysis.denies_statements} Deny</p>
                </div>
                <div class="bg-gray-50 p-4 rounded-lg">
                    <h4 class="font-semibold text-gray-700 text-sm">Last Updated</h4>
                    <p class="mt-2 text-sm font-mono text-gray-800">${new Date(metadata.update_date).toLocaleDateString()}</p>
                </div>
                <div class="bg-gray-50 p-4 rounded-lg">
                    <h4 class="font-semibold text-gray-700 text-sm">Attachments</h4>
                    <p class="mt-2 text-lg font-bold text-[#204071]">${metadata.attachment_count}</p>
                </div>
            </div>

            <!-- Analysis Section -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                <div>
                    <h4 class="font-semibold text-md mb-3 text-[#204071]">AWS Services Affected</h4>
                    <div class="bg-gray-50 p-4 rounded-lg">
                        ${servicesHtml}
                    </div>
                </div>
                
                <div>
                    <h4 class="font-semibold text-md mb-3 text-[#204071]">Security Analysis</h4>
                    <div class="bg-gray-50 p-4 rounded-lg">
                        <ul>
                            ${securityConcernsHtml}
                        </ul>
                        ${analysis.resources_wildcard ? '<p class="text-orange-600 text-sm mt-2">⚠️ Uses wildcard (*) resources</p>' : ''}
                        ${analysis.has_conditions ? '<p class="text-green-600 text-sm mt-2">✓ Has security conditions</p>' : ''}
                    </div>
                </div>
            </div>

            <!-- Entities using this policy -->
            ${entitiesHtml}

            <!-- Policy Document -->
            <div class="mt-6">
                <h4 class="font-semibold text-md mb-3 text-[#204071]">Policy Document</h4>
                <div class="bg-[#204071] text-white p-4 rounded-lg overflow-x-auto">
                    <pre class="text-xs font-mono whitespace-pre-wrap"><code>${JSON.stringify(policy_document, null, 2)}</code></pre>
                </div>
            </div>

            <!-- Metadata Details -->
            <div class="mt-6 pt-6 border-t border-gray-200">
                <h4 class="font-semibold text-md mb-3 text-[#204071]">Policy Metadata</h4>
                <div class="bg-gray-50 p-4 rounded-lg">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                        <div><strong>Policy ID:</strong> <span class="font-mono">${metadata.policy_id}</span></div>
                        <div><strong>Version ID:</strong> <span class="font-mono">${metadata.default_version_id}</span></div>
                        <div><strong>Created:</strong> ${new Date(metadata.creation_date).toLocaleDateString()}</div>
                        <div><strong>Attachable:</strong> ${metadata.is_attachable ? 'Yes' : 'No'}</div>
                    </div>
                </div>
            </div>
        </div>
    `;
};

// 8. Función auxiliar para crear HTML de entidades que usan la política
const createEntitiesUsageHtml = (used_by) => {
    if (!used_by || (used_by.users.length === 0 && used_by.groups.length === 0 && used_by.roles.length === 0)) {
        return `
            <div class="mb-6">
                <h4 class="font-semibold text-md mb-3 text-[#204071]">Usage</h4>
                <div class="bg-gray-50 p-4 rounded-lg">
                    <p class="text-gray-500">This policy is not currently attached to any users, groups, or roles.</p>
                </div>
            </div>
        `;
    }

    let entitiesHtml = `
        <div class="mb-6">
            <h4 class="font-semibold text-md mb-3 text-[#204071]">Entities Using This Policy</h4>
            <div class="bg-gray-50 p-4 rounded-lg">
                <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
    `;

    // Usuarios
    if (used_by.users.length > 0) {
        entitiesHtml += `
            <div>
                <h5 class="font-medium text-sm text-gray-700 mb-2">Users (${used_by.users.length})</h5>
                <ul class="space-y-1">
                    ${used_by.users.map(user => `<li class="text-sm font-mono text-gray-600">• ${user.name}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    // Grupos
    if (used_by.groups.length > 0) {
        entitiesHtml += `
            <div>
                <h5 class="font-medium text-sm text-gray-700 mb-2">Groups (${used_by.groups.length})</h5>
                <ul class="space-y-1">
                    ${used_by.groups.map(group => `<li class="text-sm font-mono text-gray-600">• ${group.name}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    // Roles
    if (used_by.roles.length > 0) {
        entitiesHtml += `
            <div>
                <h5 class="font-medium text-sm text-gray-700 mb-2">Roles (${used_by.roles.length})</h5>
                <ul class="space-y-1">
                    ${used_by.roles.map(role => `<li class="text-sm font-mono text-gray-600">• ${role.name}</li>`).join('')}
                </ul>
            </div>
        `;
    }

    entitiesHtml += `
                </div>
            </div>
        </div>
    `;

    return entitiesHtml;
};

// 9. Función original renombrada
const renderIamPrincipalDetails = (principal, type, searchedTerm) => {
    const resultsContainer = document.getElementById('iam-search-results-container');
    if (!principal) {
        resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Not Found</h4><p>Could not find any user, group, or role with the name or ARN '${searchedTerm}'.</p></div>`;
        log(`IAM Principal '${searchedTerm}' not found.`, 'error');
        return;
    }

    let detailsToShow = {};
    const name = type === 'User' ? principal.UserName : (type === 'Group' ? principal.GroupName : principal.RoleName);

    if (type === 'User') {
        detailsToShow = {
            Type: 'User',
            Name: principal.UserName,
            DirectPermissions: {
                AttachedPolicies: principal.AttachedPolicies,
                InlinePolicies: principal.InlinePolicies,
            },
            InheritedPermissions: {
                 Groups: principal.Groups,
                 OrganizationalRoles_by_Tag: principal.Roles || [],
                 AssumableRoles_by_Policy: principal.AssumableRoles || []
            }
        };
    } else if (type === 'Group') {
         detailsToShow = {
            Type: 'Group',
            Name: principal.GroupName,
            Permissions: {
                AttachedPolicies: principal.AttachedPolicies,
            }
        };
    } else if (type === 'Role') {
         detailsToShow = {
            Type: 'Role',
            Name: principal.RoleName,
            Permissions: {
                AttachedPolicies: principal.AttachedPolicies,
                InlinePolicies: principal.InlinePolicies
            }
        };
    }
    
    const formattedJson = JSON.stringify(detailsToShow, null, 2);
    log(`Showing details for ${type}: ${name}`, 'success');

    resultsContainer.innerHTML = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="text-xl font-bold text-[#204071] mb-4">Details for ${type}: ${name}</h3>
            <pre class="bg-[#204071] text-white p-4 rounded-lg text-xs font-mono overflow-x-auto">${formattedJson}</pre>
        </div>
    `;
};

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

const serviceDescriptions = {
    summary: {
        title: "IAM Summary Overview",
        description: "The summary provides a high-level view of Identity and Access Management components including users, groups, roles, and security compliance metrics.",
        useCases: "Initial security assessment, compliance reporting, identifying privilege escalation risks, monitoring MFA adoption and password policy compliance.",
        auditConsiderations: "Focus on privileged user counts, MFA compliance rates, and critical findings. Look for accounts with elevated privileges that may indicate over-permissioned access or potential insider threats."
    },
    users: {
        title: "IAM Users",
        description: "IAM Users represent individual identities that can authenticate to AWS and perform actions based on attached policies. Each user has unique security credentials.",
        useCases: "Individual developer access, service accounts, cross-account access, emergency break-glass procedures, human user authentication.",
        auditConsiderations: "Verify users follow least privilege principle, check for unused or dormant accounts, ensure MFA is enabled for privileged users, and review access key age and usage patterns."
    },
    groups: {
        title: "IAM Groups",
        description: "IAM Groups are collections of users that inherit the same permissions. Groups simplify permission management by allowing batch policy assignments.",
        useCases: "Team-based access control, role-based permissions (developers, admins, auditors), department-specific access, temporary project access.",
        auditConsiderations: "Review group memberships for appropriate segregation of duties, ensure no overly broad permissions, and verify that group purposes align with business functions."
    },
    roles: {
        title: "IAM Roles",
        description: "IAM Roles are assumable identities with specific permissions, designed for temporary access by users, applications, or AWS services.",
        useCases: "Cross-account access, EC2 instance permissions, Lambda function execution, federated user access, service-to-service communication.",
        auditConsiderations: "Examine trust policies for overly permissive assumptions, review role session durations, and ensure roles follow least privilege with appropriate conditions and restrictions."
    },
    policies: {
        title: "Password Policies",
        description: "Account password policies define complexity requirements, expiration rules, and reuse restrictions for IAM user passwords.",
        useCases: "Compliance with organizational security standards, meeting regulatory requirements, preventing weak password usage, enforcing password rotation.",
        auditConsiderations: "Verify policy meets industry standards (minimum 12 characters, complexity requirements, rotation), check for proper enforcement, and ensure alignment with compliance frameworks."
    },
    accessAnalyzer: {
        title: "Access Analyzer",
        description: "IAM Access Analyzer identifies resources shared with external entities and helps validate that resource-based policies provide intended access.",
        useCases: "External access discovery, unintended resource sharing detection, policy validation, compliance monitoring for data exposure.",
        auditConsiderations: "Review all external access findings for business justification, ensure public access is intentional, and verify that cross-account access follows approved patterns."
    },
    permissionDetails: {
        title: "Permission Details",
        description: "Detailed analysis of specific IAM principals or policies, showing exact permissions, inheritance chains, and effective access rights.",
        useCases: "Troubleshooting access issues, privilege escalation analysis, policy impact assessment, detailed security reviews.",
        auditConsiderations: "Focus on high-privilege users and custom policies, trace permission inheritance paths, and identify potential privilege escalation vectors through policy combinations."
    },
    criticalPermissions: {
        title: "Critical Permissions",
        description: "Users with permissions to critical AWS services like networking, logging, databases, and security controls that could impact overall security posture.",
        useCases: "Identifying high-risk access, privileged user monitoring, compliance reporting, security control validation.",
        auditConsiderations: "Verify business justification for critical permissions, ensure proper approval processes, monitor usage patterns, and implement additional controls like MFA and logging."
    },
    federation: {
        title: "Federation & SSO",
        description: "Identity federation allows external identity providers to grant access to AWS resources, including SAML, OIDC, and AWS SSO integrations.",
        useCases: "Corporate directory integration, single sign-on implementation, external contractor access, multi-account management.",
        auditConsiderations: "Review trust relationships with identity providers, validate attribute mappings, ensure proper session controls, and verify that federated access follows least privilege principles."
    },
    securityHub: {
        title: "Security Hub IAM Findings",
        description: "Security Hub aggregates IAM-related security findings from various AWS security services, providing centralized visibility into identity and access issues.",
        useCases: "Centralized security monitoring, compliance dashboard, automated finding correlation, security posture assessment.",
        auditConsiderations: "Prioritize critical and high severity findings, track remediation progress, ensure findings align with security policies, and validate that automated detection rules are appropriate."
    }
};
