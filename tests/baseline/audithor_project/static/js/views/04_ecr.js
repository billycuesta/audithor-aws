/**
 * 04_ecr.js
 * Contiene toda la lógica para construir y renderizar la vista de Elastic Container Registry (ECR).
 */

// --- IMPORTACIONES ---
import { handleTabClick, renderSecurityHubFindings, createStatusBadge } from '../utils.js';

// --- DESCRIPCIONES DE SERVICIOS ---
const serviceDescriptions = {
    overview: {
        title: "AWS Elastic Container Registry (ECR) - Security Overview",
        description: "ECR is a fully managed Docker container registry with integrated security features including vulnerability scanning, image signing, encryption at rest/transit, and fine-grained access control through IAM and resource policies.",
        useCases: "Container image storage and distribution, CI/CD pipelines for containerized applications, microservices architectures, secure container image management with vulnerability scanning, cross-account image sharing, compliance-ready container deployments.",
        auditConsiderations: "Review repository policies for public access and excessive permissions, ensure vulnerability scanning and image signing are enabled for production workloads, verify image tag immutability for production images, validate encryption configuration, check lifecycle policies for cost optimization and security hygiene."
    },
    repositories: {
        title: "Repository Management & Configuration",
        description: "ECR repository configuration encompasses security controls, lifecycle management, and access policies. Proper configuration includes tag immutability, vulnerability scanning, encryption, and lifecycle policies for automated cleanup.",
        useCases: "Production image immutability, automated vulnerability detection, cost optimization through lifecycle management, cross-account sharing with controlled access, compliance with container security standards.",
        auditConsiderations: "Ensure production repositories use immutable tags, verify scan-on-push is enabled, validate encryption settings meet compliance requirements, review lifecycle policies for appropriate retention periods, check for unused or vulnerable images that should be removed."
    }
};

// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
export const buildEcrView = () => {
    const container = document.getElementById('ecr-view');
    if (!container || !window.ecrApiData) return;

    const { repositories } = window.ecrApiData.results;
    const executionDate = window.ecrApiData.metadata.executionDate;
    const ecrSecurityHubFindings = window.securityHubApiData?.results?.findings?.ecrFindings || [];

    // Calculate security metrics for summary
    const securityIssues = repositories.filter(r => 
        r.IsPublic || !r.ScanOnPush || !r.ImageSigningEnabled || r.ImageTagMutability === 'MUTABLE'
    ).length;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Elastic Container Registry (ECR)</h2>
                <p class="text-sm text-gray-500">${executionDate}</p>
            </div>
        </header>
        
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review ECR repositories for comprehensive security configuration including vulnerability scanning, image signing, access controls, and lifecycle management. Focus on identifying public repositories, missing security controls, and compliance gaps.</p>
        </div>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="ecr-tabs">
                <a href="#" data-tab="ecr-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="ecr-overview-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Analysis</a>
                <a href="#" data-tab="ecr-repositories-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Repository Details (${repositories.length})</a>
                <a href="#" data-tab="ecr-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${ecrSecurityHubFindings.length})</a>
            </nav>
        </div>
        <div id="ecr-tab-content-container">
            <div id="ecr-summary-content" class="ecr-tab-content">${createEcrSummaryCardsHtml()}</div>
            <div id="ecr-overview-content" class="ecr-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.overview)}
                ${renderSecurityAnalysisTable(repositories)}
            </div>
            <div id="ecr-repositories-content" class="ecr-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.repositories)}
                ${renderComprehensiveRepositoriesTable(repositories)}
            </div>
            <div id="ecr-sh-content" class="ecr-tab-content hidden">${createEcrSecurityHubHtml()}</div>
        </div>
    `;

    updateEcrSummaryCards(repositories);
    renderSecurityHubFindings(ecrSecurityHubFindings, 'sh-ecr-findings-container', 'No Security Hub findings related to ECR were found.');
    
    const tabsNav = container.querySelector('#ecr-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.ecr-tab-content'));
};

// --- RENDERIZADOR DE DESCRIPCIÓN DE SERVICIOS ---
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

// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const createEcrSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Total Repositories</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="ecr-total-repos" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-blue-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-box w-6 h-6 text-blue-600" viewBox="0 0 16 16">
                        <path d="M8.186 1.113a.5.5 0 0 0-.372 0L1.846 3.5 8 5.961 14.154 3.5zM15 4.239l-6.5 2.6v7.922l6.5-2.6V4.24zM7.5 14.762V6.838L1 4.239v7.923zM7.443.184a1.5 1.5 0 0 1 1.114 0l7.129 2.852A.5.5 0 0 1 16 3.5v8.662a1 1 0 0 1-.629.928l-7.185 2.874a.5.5 0 0 1-.372 0L.629 13.09A1 1 0 0 1 0 12.162V3.5a.5.5 0 0 1 .314-.464z"/>
                    </svg>
                </div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Security Issues</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="ecr-security-issues" class="text-3xl font-bold text-red-600">--</p>
                <div class="bg-red-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-shield-exclamation w-6 h-6 text-red-600" viewBox="0 0 16 16">
                        <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.725 10.725 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.615.615 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.855C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524zM5.072.56C6.157.265 7.31 0 8 0s1.843.265 2.928.56c1.11.3 2.229.655 2.887.87a1.54 1.54 0 0 1 1.044 1.262c.596 4.477-.787 7.795-2.465 9.99a11.775 11.775 0 0 1-2.517 2.453 7.159 7.159 0 0 1-1.048.625c-.28.132-.581.24-.829.24s-.548-.108-.829-.24a7.158 7.158 0 0 1-1.048-.625 11.777 11.777 0 0 1-2.517-2.453C1.928 10.487.545 7.169 1.141 2.692A1.54 1.54 0 0 1 2.185 1.43 62.456 62.456 0 0 1 5.072.56z"/>
                        <path d="M7.001 11a1 1 0 1 1 2 0 1 1 0 0 1-2 0zM7.1 4.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z"/>
                    </svg>
                </div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Public Repositories</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="ecr-public-repos" class="text-3xl font-bold text-red-600">--</p>
                <div class="bg-red-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-globe w-6 h-6 text-red-600" viewBox="0 0 16 16">
                        <path d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8m7.5-6.923c-.67.204-1.335.82-1.887 1.855A8 8 0 0 0 5.145 4H7.5zM4.09 4a9.3 9.3 0 0 1 .64-1.539 7 7 0 0 1 .597-.933A7.03 7.03 0 0 0 2.255 4zm-.582 3.5c.03-.877.138-1.718.312-2.5H1.674a7 7 0 0 0-.656 2.5zM4.847 5a12.5 12.5 0 0 0-.338 2.5H7.5V5zM8.5 5v2.5h2.99a12.5 12.5 0 0 0-.337-2.5zM4.51 8.5a12.5 12.5 0 0 0 .337 2.5H7.5V8.5zm3.99 0V11h2.653c.187-.765.306-1.608.338-2.5zM5.145 12q.208.58.468 1.068c.552 1.035 1.218 1.65 1.887 1.855V12zm.182 2.472a7 7 0 0 1-.597-.933A9.3 9.3 0 0 1 4.09 12h2.342zm3.328 0a7 7 0 0 0 .597-.933A9.3 9.3 0 0 0 11.91 12H9.655zm.182-2.472c.26-.487.545-.991.468-1.068L8.5 12v2.923c.67-.204 1.335-.82 1.887-1.855M8.5 1.077c.67.204 1.335.82 1.887 1.855q.26.487.468 1.068H8.5zm3.846 1.423A7.03 7.03 0 0 0 13.745 4H11.91a9.3 9.3 0 0 0-.64-1.539 7 7 0 0 0-.597-.933zM1.674 8.5H3.82c-.03.877-.138 1.718-.312 2.5H1.674a7 7 0 0 1-.656-2.5zm6.371 0h3.845c.23.782.338 1.623.312 2.5h-1.674a7 7 0 0 1-.656-2.5z"/>
                    </svg>
                </div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Missing Security Controls</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="ecr-missing-controls" class="text-3xl font-bold text-yellow-600">--</p>
                <div class="bg-yellow-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-triangle w-6 h-6 text-yellow-600" viewBox="0 0 16 16">
                        <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1-.054-.06.18.18 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/>
                        <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.553.553 0 0 1-1.1 0z"/>
                    </svg>
                </div>
            </div>
        </div>
    </div>
`;

const updateEcrSummaryCards = (repositories) => {
    document.getElementById('ecr-total-repos').textContent = repositories.length;
    document.getElementById('ecr-public-repos').textContent = repositories.filter(r => r.IsPublic).length;
    
    const securityIssues = repositories.filter(r => 
        r.IsPublic || !r.ScanOnPush || !r.ImageSigningEnabled || r.ImageTagMutability === 'MUTABLE'
    ).length;
    document.getElementById('ecr-security-issues').textContent = securityIssues;
    
    const missingControls = repositories.filter(r => 
        !r.ScanOnPush || !r.ImageSigningEnabled || !r.HasLifecyclePolicy
    ).length;
    document.getElementById('ecr-missing-controls').textContent = missingControls;
};

export const openModalWithEcrPolicy = (repoIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const repo = window.ecrApiData.results.repositories[repoIndex];
    if (!modal || !repo || !repo.Policy) return;

    modalTitle.textContent = `Repository Policy for: ${repo.RepositoryName}`;
    const formattedPolicy = JSON.stringify(repo.Policy, null, 2);
    modalContent.innerHTML = `<div class="text-left"><pre class="bg-[#204071] text-white text-xs font-mono rounded-md p-3 overflow-x-auto"><code>${formattedPolicy}</code></pre></div>`;
    modal.classList.remove('hidden');
};


const renderSecurityAnalysisTable = (repositories) => {
    if (!repositories || repositories.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="mx-auto h-12 w-12 text-gray-400" viewBox="0 0 16 16">
                        <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
                        <path d="M5.255 5.786a.237.237 0 0 0 .241.247h.825c.138 0 .248-.113.266-.25.09-.656.54-1.134 1.342-1.134.686 0 1.314.343 1.314 1.168 0 .635-.374.927-.965 1.371-.673.489-1.206 1.06-1.168 1.987l.003.217a.25.25 0 0 0 .25.246h.811a.25.25 0 0 0 .25-.25v-.105c0-.718.273-.927 1.01-1.486.609-.463 1.244-.977 1.244-2.056 0-1.511-1.276-2.241-2.673-2.241-1.267 0-2.655.59-2.75 2.286m1.557 5.763c0 .533.425.927 1.01.927.609 0 1.028-.394 1.028-.927 0-.552-.42-.94-1.029-.94-.584 0-1.009.388-1.009.94"/>
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No ECR repositories found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have any ECR repositories configured.</p>
                </div>
            </div>
        `;
    }

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Repository</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Repository ARN</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public Access</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Vulnerability Scanning</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Image Signing</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tag Mutability</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk Level</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    repositories.sort((a,b) => a.Region.localeCompare(b.Region) || a.RepositoryName.localeCompare(b.RepositoryName)).forEach((repo) => {
        const publicBadge = createSecurityStatusBadge('', !repo.IsPublic, 'public');
        const scanBadge = createSecurityStatusBadge(repo.ScanOnPush ? 'Enabled' : 'Disabled', repo.ScanOnPush);
        const signingBadge = createSecurityStatusBadge(repo.ImageSigningEnabled ? 'Enabled' : 'Disabled', repo.ImageSigningEnabled);
        const mutabilityBadge = createSecurityStatusBadge('', repo.ImageTagMutability === 'IMMUTABLE', 'mutability');
        
        // Calculate comprehensive risk level
        let riskLevel = 'Low Risk';
        let riskColor = 'green';
        
        const riskFactors = [];
        if (repo.IsPublic) riskFactors.push('Public');
        if (!repo.ScanOnPush) riskFactors.push('No Scanning');
        if (!repo.ImageSigningEnabled) riskFactors.push('No Signing');
        if (repo.ImageTagMutability === 'MUTABLE') riskFactors.push('Mutable Tags');
        
        if (riskFactors.length >= 3) {
            riskLevel = 'Critical Risk';
            riskColor = 'red';
        } else if (riskFactors.length >= 2) {
            riskLevel = 'High Risk';
            riskColor = 'red';
        } else if (riskFactors.length === 1) {
            riskLevel = 'Medium Risk';
            riskColor = 'yellow';
        }

        const riskBadge = `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-${riskColor}-100 text-${riskColor}-800">${riskLevel}</span>`;

        const scopeDetails = window.scopedResources[repo.RepositoryArn];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped 
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16"><path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>` 
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>`;
        const scopeButton = `<button onclick="openScopeModal('${repo.RepositoryArn}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;


        tableHtml += `
            <tr class="${rowClass}">
                <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${repo.Region}</td>
                <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${repo.RepositoryName}</td>
                <td class="px-4 py-4 align-top text-xs font-mono text-gray-500 break-all">${repo.RepositoryArn}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${publicBadge}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${scanBadge}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${signingBadge}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${mutabilityBadge}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${riskBadge}</td>
            </tr>
        `;
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
};


const renderComprehensiveRepositoriesTable = (repositories) => {
    if (!repositories || repositories.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="mx-auto h-12 w-12 text-gray-400" viewBox="0 0 16 16">
                        <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
                        <path d="M5.255 5.786a.237.237 0 0 0 .241.247h.825c.138 0 .248-.113.266-.25.09-.656.54-1.134 1.342-1.134.686 0 1.314.343 1.314 1.168 0 .635-.374.927-.965 1.371-.673.489-1.206 1.06-1.168 1.987l.003.217a.25.25 0 0 0 .25.246h.811a.25.25 0 0 0 .25-.25v-.105c0-.718.273-.927 1.01-1.486.609-.463 1.244-.977 1.244-2.056 0-1.511-1.276-2.241-2.673-2.241-1.267 0-2.655.59-2.75 2.286m1.557 5.763c0 .533.425.927 1.01.927.609 0 1.028-.394 1.028-.927 0-.552-.42-.94-1.029-.94-.584 0-1.009.388-1.009.94"/>
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No ECR repositories found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have any ECR repositories configured.</p>
                </div>
            </div>
        `;
    }

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>' + 
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Repository</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Repository ARN</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encryption</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Lifecycle Policy</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Signing Profile</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Repository Policy</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Recommendations</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    repositories.sort((a,b) => a.Region.localeCompare(b.Region) || a.RepositoryName.localeCompare(b.RepositoryName)).forEach((repo, index) => {
        const lifecyclePolicyStatus = repo.HasLifecyclePolicy ? 
            '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800">Configured</span>' :
            '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">None</span>';

        const signingProfile = repo.SigningProfileName ? 
            `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-green-100 text-green-800 font-mono">${repo.SigningProfileName}</span>` : 
            '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">None</span>';
        
        const policyButton = repo.Policy ? 
            `<button onclick="openModalWithEcrPolicy(${index})" class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">View Policy</button>` : 
            '<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">None</span>';

        // Generate recommendations
        const recommendations = [];
        if (repo.IsPublic) recommendations.push('Remove public access');
        if (!repo.ScanOnPush) recommendations.push('Enable vulnerability scanning');
        if (!repo.ImageSigningEnabled) recommendations.push('Configure image signing');
        if (repo.ImageTagMutability === 'MUTABLE') recommendations.push('Enable tag immutability');
        if (!repo.HasLifecyclePolicy) recommendations.push('Add lifecycle policy');
        
        const recommendationText = recommendations.length > 0 ? 
            recommendations.slice(0, 2).join(', ') + (recommendations.length > 2 ? '...' : '') : 
            'Good configuration';
        
        const recommendationColor = recommendations.length > 2 ? 'red' : 
                                   recommendations.length > 0 ? 'yellow' : 'green';

        const recommendationBadge = `<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-${recommendationColor}-100 text-${recommendationColor}-800">${recommendationText}</span>`;

        const scopeDetails = window.scopedResources[repo.RepositoryArn];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped 
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16"><path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>` 
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>`;
        const scopeButton = `<button onclick="openScopeModal('${repo.RepositoryArn}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;


        tableHtml += `
            <tr class="${rowClass}">
                <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${repo.Region}</td>
                <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${repo.RepositoryName}</td>
                <td class="px-4 py-4 align-top text-xs font-mono text-gray-500 break-all">${repo.RepositoryArn}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm font-mono text-gray-600">${repo.EncryptionType}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${lifecyclePolicyStatus}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${signingProfile}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${policyButton}</td>
                <td class="px-4 py-4 align-top text-sm">${recommendationBadge}</td>
            </tr>
        `;
    });
    tableHtml += '</tbody></table></div>';
    return tableHtml;
};



const createEcrSecurityHubHtml = () => {
    return `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (ECR)</h3>
            <div id="sh-ecr-findings-container" class="overflow-x-auto"></div>
        </div>
    `;
};

const createSecurityStatusBadge = (value, isSecure, type = 'default') => {
    if (type === 'public') {
        // Para acceso público: YES es rojo (malo), NO es verde (bueno)
        return isSecure ? 
            '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">NO</span>' :
            '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">YES</span>';
    } else if (type === 'mutability') {
        // Para mutabilidad: IMMUTABLE es verde (bueno), MUTABLE es rojo (malo)
        return isSecure ?
            '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">IMMUTABLE</span>' :
            '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">MUTABLE</span>';
    } else {
        // Para otras configuraciones: Enabled/Yes es verde (bueno), Disabled/No es rojo (malo)
        return isSecure ?
            `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">${value}</span>` :
            `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">${value}</span>`;
    }
};