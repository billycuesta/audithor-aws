/**
 * 10_compute.js
 * Contiene toda la lógica para construir y renderizar la vista de Compute Resources.
 */

// --- IMPORTACIONES ---
import { handleTabClick, createStatusBadge } from '../utils.js';


// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
export const buildComputeView = () => {
    const container = document.getElementById('compute-view');
    if (!window.computeApiData) return;

    const activeTabEl = container.querySelector('#compute-tabs .border-\\[\\#eb3496\\]');
    const activeTabData = activeTabEl ? activeTabEl.dataset.tab : 'compute-summary-content';
    const { ec2_instances, lambda_functions, eks_clusters, ecs_clusters } = window.computeApiData.results;
    const allRegions = window.allAvailableRegions;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Compute Resources</h2>
                <p class="text-sm text-gray-500">${window.computeApiData.metadata.executionDate}</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="compute-tabs">
                <a href="#" data-tab="compute-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="compute-ec2-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">EC2 (${ec2_instances.length})</a>
                <a href="#" data-tab="compute-lambda-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Lambda (${lambda_functions.length})</a>
                <a href="#" data-tab="compute-eks-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">EKS (${eks_clusters.length})</a>
                <a href="#" data-tab="compute-ecs-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">ECS (${ecs_clusters.length})</a>
            </nav>
        </div>
        <div id="compute-tab-content-container">
            <div id="compute-summary-content" class="compute-tab-content">${createComputeSummaryCardsHtml()}</div>
            <div id="compute-ec2-content" class="compute-tab-content hidden"></div>
            <div id="compute-lambda-content" class="compute-tab-content hidden"></div>
            <div id="compute-eks-content" class="compute-tab-content hidden">${renderEksClustersTable(eks_clusters)}</div>
            <div id="compute-ecs-content" class="compute-tab-content hidden">${renderEcsClustersTable(ecs_clusters)}</div>
        </div>
    `;

    updateComputeSummaryCards(ec2_instances, lambda_functions, eks_clusters, ecs_clusters);

    const ec2TabContent = document.getElementById('compute-ec2-content');
    ec2TabContent.innerHTML = renderEc2InstancesTable(ec2_instances, allRegions, 'all', 'all');

    const lambdaTabContent = document.getElementById('compute-lambda-content');
    lambdaTabContent.innerHTML = renderLambdaFunctionsTable(lambda_functions, lambda_functions, 'all', 'all');
    
    setupEc2Filters();
    setupLambdaFilters();

    const tabsNav = container.querySelector('#compute-tabs');

    if (activeTabData !== 'compute-summary-content') {
        // Quitamos el estado activo de la pestaña "Summary" por defecto
        const defaultActiveLink = tabsNav.querySelector('a[data-tab="compute-summary-content"]');
        const defaultActiveContent = document.getElementById('compute-summary-content');
        defaultActiveLink.classList.remove('border-[#eb3496]', 'text-[#eb3496]');
        defaultActiveLink.classList.add('border-transparent', 'text-gray-500');
        defaultActiveContent.classList.add('hidden');

        // Activamos la pestaña correcta
        const newActiveLink = tabsNav.querySelector(`a[data-tab="${activeTabData}"]`);
        const newActiveContent = document.getElementById(activeTabData);
        if (newActiveLink && newActiveContent) {
            newActiveLink.classList.add('border-[#eb3496]', 'text-[#eb3496]');
            newActiveLink.classList.remove('border-transparent', 'text-gray-500');
            newActiveContent.classList.remove('hidden');
        }
    }

    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.compute-tab-content'));
};


// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const createComputeSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">EC2 Instances</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="compute-total-ec2" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-orange-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-orange-600" fill="currentColor" viewBox="0 0 16 16">
                        <path d="M5 0a.5.5 0 0 1 .5.5V2h1V.5a.5.5 0 0 1 1 0V2h1V.5a.5.5 0 0 1 1 0V2h1V.5a.5.5 0 0 1 1 0V2A2.5 2.5 0 0 1 14 4.5h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14a2.5 2.5 0 0 1-2.5 2.5v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14A2.5 2.5 0 0 1 2 11.5H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2A2.5 2.5 0 0 1 4.5 2V.5A.5.5 0 0 1 5 0m-.5 3A1.5 1.5 0 0 0 3 4.5v7A1.5 1.5 0 0 0 4.5 13h7a1.5 1.5 0 0 0 1.5-1.5v-7A1.5 1.5 0 0 0 11.5 3zM5 6.5A1.5 1.5 0 0 1 6.5 5h3A1.5 1.5 0 0 1 11 6.5v3A1.5 1.5 0 0 1 9.5 11h-3A1.5 1.5 0 0 1 5 9.5zM6.5 6a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5z"/>
                    </svg>
                </div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">Lambda Functions</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="compute-total-lambda" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-purple-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-purple-600" fill="currentColor" viewBox="0 0 16 16">
                        <path d="M14 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1zM2 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2z"/>
                        <path d="M6.854 4.646a.5.5 0 0 1 0 .708L4.207 8l2.647 2.646a.5.5 0 0 1-.708.708l-3-3a.5.5 0 0 1 0-.708l3-3a.5.5 0 0 1 .708 0m2.292 0a.5.5 0 0 0 0 .708L11.793 8l-2.647 2.646a.5.5 0 0 0 .708.708l3-3a.5.5 0 0 0 0-.708l-3-3a.5.5 0 0 0-.708 0"/>
                    </svg>
                </div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">EKS Clusters</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="compute-total-eks" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-blue-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-blue-600" fill="currentColor" viewBox="0 0 16 16">
                        <path d="M7.752.066a.5.5 0 0 1 .496 0l3.75 2.143a.5.5 0 0 1 .252.434v3.995l3.498 2A.5.5 0 0 1 16 9.07v4.286a.5.5 0 0 1-.252.434l-3.75 2.143a.5.5 0 0 1-.496 0l-3.502-2-3.502 2.001a.5.5 0 0 1-.496 0l-3.75-2.143A.5.5 0 0 1 0 13.357V9.071a.5.5 0 0 1 .252-.434L3.75 6.638V2.643a.5.5 0 0 1 .252-.434zM4.25 7.504 1.508 9.071l2.742 1.567 2.742-1.567zM7.5 9.933l-2.75 1.571v3.134l2.75-1.571zm1 3.134 2.75 1.571v-3.134L8.5 9.933zm.508-3.996 2.742 1.567 2.742-1.567-2.742-1.567zm2.242-2.433V3.504L8.5 5.076V8.21zM7.5 8.21V5.076L4.75 3.504v3.134zM5.258 2.643 8 4.21l2.742-1.567L8 1.076zM15 9.933l-2.75 1.571v3.134L15 13.067zM3.75 14.638v-3.134L1 9.933v3.134z"/>
                    </svg>
                </div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full">
            <div><p class="text-sm text-gray-500">ECS Clusters</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="compute-total-ecs" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-green-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" class="w-6 h-6 text-green-600" fill="currentColor" viewBox="0 0 16 16">
                        <path d="M7.752.066a.5.5 0 0 1 .496 0l3.75 2.143a.5.5 0 0 1 .252.434v3.995l3.498 2A.5.5 0 0 1 16 9.07v4.286a.5.5 0 0 1-.252.434l-3.75 2.143a.5.5 0 0 1-.496 0l-3.502-2-3.502 2.001a.5.5 0 0 1-.496 0l-3.75-2.143A.5.5 0 0 1 0 13.357V9.071a.5.5 0 0 1 .252-.434L3.75 6.638V2.643a.5.5 0 0 1 .252-.434zM4.25 7.504 1.508 9.071l2.742 1.567 2.742-1.567zM7.5 9.933l-2.75 1.571v3.134l2.75-1.571zm1 3.134 2.75 1.571v-3.134L8.5 9.933zm.508-3.996 2.742 1.567 2.742-1.567-2.742-1.567zm2.242-2.433V3.504L8.5 5.076V8.21zM7.5 8.21V5.076L4.75 3.504v3.134zM5.258 2.643 8 4.21l2.742-1.567L8 1.076zM15 9.933l-2.75 1.571v3.134L15 13.067zM3.75 14.638v-3.134L1 9.933v3.134z"/>
                    </svg>
                </div>
            </div>
        </div>
    </div>`;

const updateComputeSummaryCards = (ec2s, lambdas, eks, ecs) => {
    document.getElementById('compute-total-ec2').textContent = ec2s.length;
    document.getElementById('compute-total-lambda').textContent = lambdas.length;
    document.getElementById('compute-total-eks').textContent = eks.length;
    document.getElementById('compute-total-ecs').textContent = ecs.length;
};

const renderEc2InstancesTable = (instances, allRegions, selectedState = 'all', selectedRegion = 'all') => {
    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');

    const filterControlsHtml = `
        <div class="mb-4 flex flex-wrap gap-4 items-center">
            <div class="flex items-center space-x-2">
                <span class="text-sm font-medium text-gray-700">Status:</span>
                <div class="flex space-x-2">
                    <button data-state="all" class="ec2-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm ${selectedState === 'all' ? 'bg-[#eb3496] text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'}">All</button>
                    <button data-state="running" class="ec2-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm ${selectedState === 'running' ? 'bg-[#eb3496] text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'}">Running</button>
                    <button data-state="stopped" class="ec2-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm ${selectedState === 'stopped' ? 'bg-[#eb3496] text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'}">Stopped</button>
                </div>
            </div>
            <div class="flex items-center space-x-2">
                <label for="ec2-region-filter" class="text-sm font-medium text-gray-700">Region:</label>
                <select id="ec2-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5">
                    <option value="all" ${selectedRegion === 'all' ? 'selected' : ''}>All Regions</option>
                    ${regionOptions}
                </select>
            </div>
        </div>`;

    if (!instances || instances.length === 0) {
        return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControlsHtml}<p class="text-center text-gray-500 py-4">No EC2 instances matching the selected filters were found.</p></div>`;
    }

    let tableContent = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Instance ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Security Groups</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">IAM Role</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">State</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public IP</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">OS</th>' +
                '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tags</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    instances.forEach((i) => {
        const originalIndex = window.computeApiData.results.ec2_instances.findIndex(orig => orig.ARN === i.ARN);
        const tagCount = Object.keys(i.Tags).length;
        const sgCount = i.SecurityGroups ? i.SecurityGroups.length : 0;
        let sgHtml = '-';
        if (sgCount > 0) {
            sgHtml = i.SecurityGroups.map(sgId => 
                `<div class="bg-gray-100 text-gray-800 text-xs font-mono px-2 py-0.5 rounded mb-1 whitespace-nowrap">${sgId}</div>`
            ).join('');
        }
        let tagsHtml = '-';
        if (tagCount > 0) {
            tagsHtml = `<button 
                            onclick="openModalWithEc2Tags(${originalIndex})" 
                            class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                            View (${tagCount})
                        </button>`;
        }

        const scopeDetails = window.scopedResources[i.ARN];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped 
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16"><path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>` 
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>`;
        const scopeButton = `<button onclick="openScopeModal('${i.ARN}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;


        tableContent += `<tr class="${rowClass}">
                    <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${i.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${i.InstanceId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-mono text-gray-600">${i.VpcId || 'N/A'}</td>
                    <td class="px-4 py-4 text-sm">${sgHtml}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-mono text-gray-600">${i.IamInstanceProfile}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(i.State)}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${i.PublicIpAddress || '-'}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 break-words">${i.OperatingSystem}</td>
                    <td class="px-4 py-4 text-center">
                        <button onclick="copyToClipboard(this, '${i.ARN}')" title="${i.ARN}" class="p-1 rounded-md hover:bg-gray-200 transition">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
                        </button>
                    </td>
                    <td class="px-4 py-4 text-sm text-gray-600">${tagsHtml}</td>
                </tr>`;
    });
    tableContent += '</tbody></table></div>';

    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControlsHtml}${tableContent}</div>`;
};

const renderLambdaFunctionsTable = (functionsToRender, allFunctions, selectedRegion = 'all', selectedVpc = 'all') => {
    const allRegions = [...new Set(allFunctions.map(f => f.Region))].sort();
    const allVpcs = [...new Set(allFunctions.map(f => f.VpcConfig?.VpcId).filter(Boolean))].sort();

    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');
    const vpcOptions = allVpcs.map(v => `<option value="${v}" ${selectedVpc === v ? 'selected' : ''}>${v}</option>`).join('');

    const filterControlsHtml = `
        <div class="mb-4 flex flex-wrap gap-4 items-center">
            <div class="flex items-center space-x-2">
                <label for="lambda-region-filter" class="text-sm font-medium text-gray-700">Region:</label>
                <select id="lambda-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5">
                    <option value="all">All Regions</option>
                    ${regionOptions}
                </select>
            </div>
            <div class="flex items-center space-x-2">
                <label for="lambda-vpc-filter" class="text-sm font-medium text-gray-700">VPC:</label>
                <select id="lambda-vpc-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5">
                    <option value="all">All VPCs</option>
                    ${vpcOptions}
                </select>
            </div>
        </div>`;

    if (!functionsToRender || functionsToRender.length === 0) {
        return `<div class="bg-white p-6 rounded-xl border border-gray-100">${filterControlsHtml}<p class="text-center text-gray-500 py-4">No Lambda functions matching the selected filters were found.</p></div>`;
    }

    let tableHtml = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Function Name</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Execution Role</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Runtime</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tags</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    const allFunctionsForIndexing = window.computeApiData.results.lambda_functions;
    const allIamRoles = window.iamApiData.results.roles;

    functionsToRender.forEach(f => {
        const originalIndex = allFunctionsForIndexing.findIndex(orig => orig.ARN === f.ARN);
        const vpcId = f.VpcConfig?.VpcId || 'N/A';
        const tagCount = Object.keys(f.Tags || {}).length;
        
        const roleName = f.Role ? f.Role.split('/').pop() : null;
        const roleDetails = roleName ? allIamRoles.find(r => r.RoleName === roleName) : null;
        const vipBadge = (roleDetails && roleDetails.IsPrivileged) 
            ? '<span class="bg-yellow-200 text-yellow-800 text-xs font-semibold mr-2 px-2.5 py-0.5 rounded-full">VIP</span>' 
            : '';

        let tagsHtml = '-';
        if (tagCount > 0) {
            tagsHtml = `<button 
                            onclick="openModalWithLambdaTags(${originalIndex})" 
                            class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                            View (${tagCount})
                        </button>`;
        }
        
        const scopeDetails = window.scopedResources[f.ARN];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped 
            ? `<svg xmlns="http://www.w.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16"><path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>` 
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>`;
        const scopeButton = `<button onclick="openScopeModal('${f.ARN}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;



        tableHtml += `
            <tr class="${rowClass}">
                <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${f.Region}</td>
                <td class="px-4 py-4 text-sm font-medium text-gray-800 break-all">${vipBadge}${f.FunctionName}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm">
                    <button 
                        onclick="openModalWithLambdaRole(${originalIndex})"
                        class="bg-slate-200 text-slate-700 px-3 py-1 text-xs font-bold rounded-md hover:bg-slate-300 transition">
                        View Role
                    </button>
                </td>
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${f.Runtime}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm font-mono text-gray-600">${vpcId}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm">${tagsHtml}</td>
            </tr>`;
    });
    
    tableHtml += '</tbody></table></div>';
    
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControlsHtml}${tableHtml}</div>`;
};

const renderEksClustersTable = (clusters) => {
    if (!clusters || clusters.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No EKS clusters were found.</p></div>';
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Cluster Name</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    clusters.forEach(c => {
        const scopeDetails = window.scopedResources[c.ARN];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped 
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16"><path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>` 
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>`;
        const scopeButton = `<button onclick="openScopeModal('${c.ARN}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;

        table += `<tr class="${rowClass}">
                    <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${c.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${c.ClusterName}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 break-all font-mono">${c.ARN}</td>
                </tr>`;
    });

    table += '</tbody></table></div>';
    return table;
};

const renderEcsClustersTable = (clusters) => {
    if (!clusters || clusters.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No ECS clusters were found.</p></div>';
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Cluster Name</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase"># Services</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    clusters.forEach(c => {
    const scopeDetails = window.scopedResources[c.ARN];
    const isScoped = !!scopeDetails;
    const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
    const scopeComment = isScoped ? scopeDetails.comment : '';
    const scopeIcon = isScoped 
        ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16"><path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>` 
        : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>`;
    const scopeButton = `<button onclick="openScopeModal('${c.ARN}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;

    table += `<tr class="${rowClass}">
                <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${c.Region}</td>
                <td class="px-4 py-4 text-sm font-medium text-gray-800 break-all">${c.ClusterName}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(c.Status)}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${c.ServicesCount}</td>
                <td class="px-4 py-4 text-sm text-gray-600 break-all font-mono">${c.ARN}</td>
            </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const setupEc2Filters = () => {
    const ec2TabContent = document.getElementById('compute-ec2-content');
    if (!ec2TabContent) return;

    const handleFilterChange = () => {
        const allInstances = window.computeApiData.results.ec2_instances;
        const allRegions = window.allAvailableRegions;
        const selectedState = ec2TabContent.querySelector('.ec2-filter-btn.bg-\\[\\#eb3496\\]')?.dataset.state || 'all';
        const selectedRegion = ec2TabContent.querySelector('#ec2-region-filter').value;

        let filteredInstances = allInstances;
        if (selectedState !== 'all') {
            filteredInstances = filteredInstances.filter(i => i.State.toLowerCase() === selectedState);
        }
        if (selectedRegion !== 'all') {
            filteredInstances = filteredInstances.filter(i => i.Region === selectedRegion);
        }

        ec2TabContent.innerHTML = renderEc2InstancesTable(filteredInstances, allRegions, selectedState, selectedRegion);
    };

    ec2TabContent.addEventListener('click', (e) => {
        const filterBtn = e.target.closest('.ec2-filter-btn');
        if (!filterBtn) return;
        ec2TabContent.querySelectorAll('.ec2-filter-btn').forEach(btn => {
            btn.classList.remove('bg-[#eb3496]', 'text-white');
            btn.classList.add('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        });
        filterBtn.classList.add('bg-[#eb3496]', 'text-white');
        filterBtn.classList.remove('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        handleFilterChange();
    });

    ec2TabContent.addEventListener('change', (e) => {
        if (e.target.id === 'ec2-region-filter') {
            handleFilterChange();
        }
    });
};

const setupLambdaFilters = () => {
    const lambdaTabContent = document.getElementById('compute-lambda-content');
    if (!lambdaTabContent) return;

    const handleFilterChange = () => {
        const allFunctions = window.computeApiData.results.lambda_functions;
        const selectedRegion = lambdaTabContent.querySelector('#lambda-region-filter').value;
        const selectedVpc = lambdaTabContent.querySelector('#lambda-vpc-filter').value;

        let filteredFunctions = allFunctions;
        if (selectedRegion !== 'all') {
            filteredFunctions = filteredFunctions.filter(f => f.Region === selectedRegion);
        }
        if (selectedVpc !== 'all') {
            filteredFunctions = filteredFunctions.filter(f => f.VpcConfig?.VpcId === selectedVpc);
        }

        lambdaTabContent.innerHTML = renderLambdaFunctionsTable(filteredFunctions, allFunctions, selectedRegion, selectedVpc);
    };

    lambdaTabContent.addEventListener('input', (e) => {
        if (e.target.id === 'lambda-region-filter' || e.target.id === 'lambda-vpc-filter') {
            handleFilterChange();
        }
    });
};
// Add these three functions to the end of 10_compute.js

export const openModalWithEc2Tags = (instanceIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const instance = window.computeApiData.results.ec2_instances[instanceIndex];

    if (!modal || !instance || !instance.Tags) return;

    modalTitle.textContent = `Tags for Instance: ${instance.InstanceId}`;
    const tags = instance.Tags;
    const tagCount = Object.keys(tags).length;
    let tagsListHtml = '';

    if (tagCount > 0) {
        tagsListHtml = '<div class="space-y-2 text-left">';
        for (const key in tags) {
            tagsListHtml += `
                <div class="flex items-center bg-slate-100 p-2 rounded-md text-sm">
                    <span class="font-bold text-slate-600 w-1/3">${key}:</span>
                    <span class="font-mono text-slate-800 w-2/3">${tags[key]}</span>
                </div>`;
        }
        tagsListHtml += '</div>';
    } else {
        tagsListHtml = '<p class="text-sm text-gray-500 text-center py-4">This instance has no tags.</p>';
    }

    modalContent.innerHTML = tagsListHtml;
    modal.classList.remove('hidden');
};

export const openModalWithLambdaTags = (lambdaIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const lambda = window.computeApiData.results.lambda_functions[lambdaIndex];

    if (!modal || !lambda || !lambda.Tags) return;

    modalTitle.textContent = `Tags for Lambda: ${lambda.FunctionName}`;
    const tags = lambda.Tags;
    const tagCount = Object.keys(tags).length;
    let tagsListHtml = '';

    if (tagCount > 0) {
        tagsListHtml = '<div class="space-y-2 text-left">';
        for (const key in tags) {
            tagsListHtml += `
                <div class="flex items-center bg-slate-100 p-2 rounded-md text-sm">
                    <span class="font-bold text-slate-600 w-1/3">${key}:</span>
                    <span class="font-mono text-slate-800 w-2/3">${tags[key]}</span>
                </div>`;
        }
        tagsListHtml += '</div>';
    } else {
        tagsListHtml = '<p class="text-sm text-gray-500 text-center py-4">This Lambda function has no tags.</p>';
    }
    
    modalContent.innerHTML = tagsListHtml;
    modal.classList.remove('hidden');
};

export const openModalWithLambdaRole = (lambdaIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const lambda = window.computeApiData.results.lambda_functions[lambdaIndex];
    const allRoles = window.iamApiData.results.roles;

    if (!modal || !lambda) return;

    const roleArn = lambda.Role;
    const roleName = roleArn ? roleArn.split('/').pop() : 'N/A';
    modalTitle.textContent = `Execution Role for: ${lambda.FunctionName}`;

    let contentHtml = `<div class="space-y-3 text-left text-sm">
                        <div class="flex items-center bg-slate-100 p-2 rounded-md">
                            <span class="font-bold text-slate-600 w-1/3">Role Name:</span>
                            <span class="font-mono text-slate-800 w-2/3">${roleName}</span>
                        </div>`;

    const roleDetails = allRoles.find(r => r.RoleName === roleName);
    if (roleDetails && roleDetails.IsPrivileged) {
        const reasonsHtml = roleDetails.PrivilegeReasons.map(reason => 
            `<li class="list-disc list-inside">${reason}</li>`
        ).join('');
        contentHtml += `<div class="bg-yellow-50 border border-yellow-200 p-3 rounded-md mt-2">
                            <h4 class="font-bold text-yellow-800">Privileged Role</h4>
                            <p class="text-xs text-yellow-700 mt-1">This role is considered privileged for the following reasons:</p>
                            <ul class="text-xs text-yellow-700 mt-1">${reasonsHtml}</ul>
                        </div>`;
    }

    contentHtml += `</div>`;
    modalContent.innerHTML = contentHtml;
    modal.classList.remove('hidden');
};