/**
 * 18_codepipeline.js
 * Contains all logic for building and rendering the CodePipeline view.
 */

// --- IMPORTS ---
import { handleTabClick, createStatusBadge } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
    overview: {
        title: "AWS CodePipeline - CI/CD Security Overview",
        description: "CodePipeline is a fully managed continuous integration and continuous delivery (CI/CD) service that automates software release pipelines. It orchestrates build, test, and deployment phases with integrated security controls including artifact encryption, manual approvals, IAM-based access control, and integration with security scanning tools.",
        useCases: "Automated software delivery pipelines, multi-stage deployments (dev/staging/production), infrastructure as code (IaC) deployment automation, microservices CI/CD orchestration, compliance-driven release processes with mandatory approvals, integration with security tools for vulnerability scanning and code quality gates.",
        auditConsiderations: "Verify production pipelines have manual approval gates to prevent unauthorized deployments. Ensure artifact stores use encryption at rest and in transit. Validate pipeline IAM roles follow least privilege principles. Check integration with security tools (CodeBuild security scans, third-party vulnerability scanners). Review source code access controls and webhook security for repository integrations."
    },
    pipelines: {
        title: "Pipeline Configuration & Security Controls",
        description: "Pipeline configuration encompasses security controls across all stages of the software delivery process. Proper configuration includes encrypted artifact storage, manual approval steps for production deployments, least-privilege IAM roles, and integration with security scanning tools to maintain code quality and security posture.",
        useCases: "Production deployment controls with human oversight, automated security scanning integration, encrypted artifact management, cross-account deployment strategies, compliance-ready release processes with audit trails, integration with container security scanning and infrastructure validation.",
        auditConsiderations: "Ensure production pipelines require manual approval before deployment stages. Verify artifact stores are encrypted with appropriate KMS keys. Check pipeline service roles have minimal required permissions. Validate integration with security tools like CodeBuild for SAST/DAST scanning, or third-party security tools. Review source provider configurations for secure webhook handling and access token management."
    },
    security: {
        title: "Security Analysis & Risk Assessment",
        description: "Security analysis focuses on identifying pipelines with insufficient security controls that could lead to unauthorized deployments, data exposure, or compliance violations. Key areas include missing manual approvals, unencrypted artifacts, overly permissive IAM roles, and lack of security scanning integration.",
        useCases: "Risk assessment for production pipelines, compliance validation for regulated environments, security gap identification in CI/CD processes, audit preparation for pipeline security controls, remediation planning for security deficiencies.",
        auditConsiderations: "Prioritize pipelines that deploy to production environments without manual approval steps. Focus on pipelines with unencrypted artifact stores that may expose sensitive code or configuration data. Review pipelines lacking integration with security scanning tools that could deploy vulnerable code. Assess pipeline IAM roles for excessive permissions that could enable privilege escalation."
    }
};

// --- RENDERIZADO DE ESTADO VACÍO ---
const renderEmptyState = (message) => {
    return `
        <div class="bg-white p-6 rounded-xl border border-gray-100">
            <div class="text-center">
                <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="mx-auto h-12 w-12 text-gray-400" viewBox="0 0 16 16">
                    <path d="M8 15A7 7 0 1 1 8 1a7 7 0 0 1 0 14m0 1A8 8 0 1 0 8 0a8 8 0 0 0 0 16"/>
                    <path d="M5.255 5.786a.237.237 0 0 0 .241.247h.825c.138 0 .248-.113.266-.25.09-.656.54-1.134 1.342-1.134.686 0 1.314.343 1.314 1.168 0 .635-.374.927-.965 1.371-.673.489-1.206 1.06-1.168 1.987l.003.217a.25.25 0 0 0 .25.246h.811a.25.25 0 0 0 .25-.25v-.105c0-.718.273-.927 1.01-1.486.609-.463 1.244-.977 1.244-2.056 0-1.511-1.276-2.241-2.673-2.241-1.267 0-2.655.59-2.75 2.286m1.557 5.763c0 .533.425.927 1.01.927.609 0 1.028-.394 1.028-.927 0-.552-.42-.94-1.029-.94-.584 0-1.009.388-1.009.94"/>
                </svg>
                <h3 class="mt-2 text-sm font-medium text-gray-900">No CodePipeline pipelines found</h3>
                <p class="mt-1 text-sm text-gray-500">${message}</p>
            </div>
        </div>
    `;
};

// --- RENDERIZADOR DE DESCRIPCIÓN DE SERVICIOS (ACTUALIZADO AL ESTILO ECR) ---
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

// --- FUNCIÓN PARA CREAR TARJETAS DE RESUMEN (ACTUALIZADA CON NUEVOS ICONOS) ---
const createCodePipelineSummaryCardsHtml = (pipelines) => {
    const totalPipelines = pipelines.length;
    const encryptedPipelines = pipelines.filter(p => p.IsEncrypted).length;
    const pipelinesWithApproval = pipelines.filter(p => p.HasManualApproval).length;
    const pipelinesWithSecurity = pipelines.filter(p => p.HasSecurityScan).length;
    
    // Agrupar por región
    const regionCounts = {};
    pipelines.forEach(p => {
        regionCounts[p.Region] = (regionCounts[p.Region] || 0) + 1;
    });
    
    const topRegions = Object.entries(regionCounts)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 5)
        .map(([region, count]) => `<span class="inline-block bg-gray-100 text-gray-800 text-xs px-2 py-1 rounded-full mr-2 mb-1">${region}: ${count}</span>`)
        .join('');

    return `
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-6">
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm font-medium text-gray-600">Total Pipelines</p>
                        <p class="text-2xl font-bold text-[#204071]">${totalPipelines}</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="text-blue-500" viewBox="0 0 16 16">
                            <path d="M14 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1zM2 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2z"/>
                            <path d="M6.854 4.646a.5.5 0 0 1 0 .708L4.207 8l2.647 2.646a.5.5 0 0 1-.708.708l-3-3a.5.5 0 0 1 0-.708l3-3a.5.5 0 0 1 .708 0m2.292 0a.5.5 0 0 0 0 .708L11.793 8l-2.647 2.646a.5.5 0 0 0 .708.708l3-3a.5.5 0 0 0 0-.708l-3-3a.5.5 0 0 0-.708 0"/>
                        </svg>
                    </div>
                </div>
            </div>

            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm font-medium text-gray-600">Security Issues</p>
                        <p class="text-2xl font-bold text-red-600">${pipelines.filter(p => !p.IsEncrypted || !p.HasManualApproval || !p.HasSecurityScan).length}</p>
                        <p class="text-xs text-gray-500">Pipelines with risks</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="text-red-500" viewBox="0 0 16 16">
                            <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1-.054-.06.18.18 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/>
                            <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/>
                        </svg>
                    </div>
                </div>
            </div>

            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm font-medium text-gray-600">Manual Approval</p>
                        <p class="text-2xl font-bold text-green-600">${pipelinesWithApproval}</p>
                        <p class="text-xs text-gray-500">${totalPipelines > 0 ? Math.round((pipelinesWithApproval/totalPipelines)*100) : 0}% with approval</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="text-green-500" viewBox="0 0 16 16">
                            <path d="M6.75 1a.75.75 0 0 1 .75.75V8a.5.5 0 0 0 1 0V5.467l.086-.004c.317-.012.637-.008.816.027.134.027.294.096.448.182.077.042.15.147.15.314V8a.5.5 0 0 0 1 0V6.435l.106-.01c.316-.024.584-.01.708.04.118.046.3.207.486.43.081.096.15.19.2.259V8.5a.5.5 0 1 0 1 0v-1h.342a1 1 0 0 1 .995 1.1l-.271 2.715a2.5 2.5 0 0 1-.317.991l-1.395 2.442a.5.5 0 0 1-.434.252H6.118a.5.5 0 0 1-.447-.276l-1.232-2.465-2.512-4.185a.517.517 0 0 1 .809-.631l2.41 2.41A.5.5 0 0 0 6 9.5V1.75A.75.75 0 0 1 6.75 1M8.5 4.466V1.75a1.75 1.75 0 1 0-3.5 0v6.543L3.443 6.736A1.517 1.517 0 0 0 1.07 8.588l2.491 4.153 1.215 2.43A1.5 1.5 0 0 0 6.118 16h6.302a1.5 1.5 0 0 0 1.302-.756l1.395-2.441a3.5 3.5 0 0 0 .444-1.389l.271-2.715a2 2 0 0 0-1.99-2.199h-.581a5 5 0 0 0-.195-.248c-.191-.229-.51-.568-.88-.716-.364-.146-.846-.132-1.158-.108l-.132.012a1.26 1.26 0 0 0-.56-.642 2.6 2.6 0 0 0-.738-.288c-.31-.062-.739-.058-1.05-.046zm2.094 2.025"/>
                        </svg>
                    </div>
                </div>
            </div>

            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="flex items-center">
                    <div class="flex-1">
                        <p class="text-sm font-medium text-gray-600">Encrypted Artifacts</p>
                        <p class="text-2xl font-bold text-blue-600">${encryptedPipelines}</p>
                        <p class="text-xs text-gray-500">${totalPipelines > 0 ? Math.round((encryptedPipelines/totalPipelines)*100) : 0}% encrypted</p>
                    </div>
                    <div class="flex-shrink-0">
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" fill="currentColor" class="text-blue-500" viewBox="0 0 16 16">
                            <path fill-rule="evenodd" d="M8 0a4 4 0 0 1 4 4v2.05a2.5 2.5 0 0 1 2 2.45v5a2.5 2.5 0 0 1-2.5 2.5h-7A2.5 2.5 0 0 1 2 13.5v-5a2.5 2.5 0 0 1 2-2.45V4a4 4 0 0 1 4-4M4.5 7A1.5 1.5 0 0 0 3 8.5v5A1.5 1.5 0 0 0 4.5 15h7a1.5 1.5 0 0 0 1.5-1.5v-5A1.5 1.5 0 0 0 11.5 7zM8 1a3 3 0 0 0-3 3v2h6V4a3 3 0 0 0-3-3"/>
                        </svg>
                    </div>
                </div>
            </div>
        </div>

        <div class="bg-white p-6 rounded-xl border border-gray-100 mb-6">
            <h3 class="text-lg font-semibold text-[#204071] mb-4">Pipelines by Region</h3>
            <div class="flex flex-wrap">
                ${topRegions}
            </div>
        </div>
    `;
};


// --- FUNCIÓN PARA RENDERIZAR ANÁLISIS DE SEGURIDAD ---

const renderSecurityAnalysisTable = (pipelines) => {
    const securityIssues = pipelines.filter(p => !p.IsEncrypted || !p.HasManualApproval || !p.HasSecurityScan);
    
    if (securityIssues.length === 0) {
        return `
            <div class="bg-green-50 border border-green-200 rounded-lg p-4">
                <div class="flex">
                    <svg class="h-5 w-5 text-green-400" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                    </svg>
                    <div class="ml-3">
                        <h3 class="text-sm font-medium text-green-800">All pipelines follow security best practices</h3>
                        <p class="mt-1 text-sm text-green-700">No security issues detected in your CodePipeline configurations.</p>
                    </div>
                </div>
            </div>
        `;
    }

    return `
        <div class="bg-white rounded-xl border border-gray-100 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-100">
                <h3 class="text-lg font-semibold text-[#204071]">Security Issues Found (${securityIssues.length})</h3>
                <p class="text-sm text-gray-600 mt-1">Pipelines that may need attention for security compliance</p>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Pipeline</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Region</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Encrypted</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Manual Approval</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Security Scan</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Risk Level</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Recommendations</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${securityIssues.map(pipeline => {
                            const issues = [];
                            if (!pipeline.IsEncrypted) issues.push('Unencrypted artifacts');
                            if (!pipeline.HasManualApproval) issues.push('No manual approval');
                            if (!pipeline.HasSecurityScan) issues.push('No security scanning');
                            
                            // Calculate risk level
                            let riskLevel = 'Medium Risk';
                            let riskColor = 'yellow';
                            if (issues.length >= 2) {
                                riskLevel = 'High Risk';
                                riskColor = 'red';
                            } else if (issues.length === 1 && pipeline.HasManualApproval) {
                                riskLevel = 'Low Risk';
                                riskColor = 'green';
                            }
                            
                            const recommendations = [];
                            if (!pipeline.IsEncrypted) recommendations.push('Enable encryption');
                            if (!pipeline.HasManualApproval) recommendations.push('Add manual approval');
                            if (!pipeline.HasSecurityScan) recommendations.push('Integrate security scanning');
                            
                            return `
                                <tr class="hover:bg-gray-50">
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-sm font-medium text-gray-900">${pipeline.Name}</div>
                                        <div class="text-sm text-gray-500">${pipeline.SourceProvider}</div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${pipeline.Region}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createColoredStatusBadge(pipeline.IsEncrypted ? 'Yes' : 'No', pipeline.IsEncrypted)}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createColoredStatusBadge(pipeline.HasManualApproval ? 'Yes' : 'No', pipeline.HasManualApproval)}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createColoredStatusBadge(pipeline.HasSecurityScan ? 'Yes' : 'No', pipeline.HasSecurityScan)}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-${riskColor}-100 text-${riskColor}-800">${riskLevel}</span>
                                    </td>
                                    <td class="px-6 py-4 text-sm text-gray-600">${recommendations.join(', ')}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
};


// --- FUNCIÓN PARA RENDERIZAR TABLA COMPLETA DE PIPELINES ---

const renderPipelinesTable = (pipelines) => {
    if (pipelines.length === 0) {
        return renderEmptyState("No CodePipeline pipelines found in any region");
    }

    return `
        <div class="bg-white rounded-xl border border-gray-100 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-100">
                <h3 class="text-lg font-semibold text-[#204071]">All CodePipeline Pipelines (${pipelines.length})</h3>
                <p class="text-sm text-gray-600 mt-1">Complete pipeline inventory with configuration details</p>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Region</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Source</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Encrypted</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Manual Approval</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Security Scan</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">IAM Role</th>
                            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Updated</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
                        ${pipelines.map(pipeline => {
                            const updatedDate = pipeline.Updated ? new Date(pipeline.Updated).toLocaleDateString() : 'N/A';
                            const roleName = pipeline.RoleArn ? pipeline.RoleArn.split('/').pop() : 'N/A';
                            
                            return `
                                <tr class="hover:bg-gray-50">
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-sm font-medium text-gray-900">${pipeline.Name}</div>
                                        ${pipeline.Error ? '<div class="text-xs text-red-500">Limited access</div>' : ''}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${pipeline.Region}</td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-sm text-gray-900">${pipeline.SourceProvider}</div>
                                        ${pipeline.SourceDetails?.Owner ? `<div class="text-xs text-gray-500">${pipeline.SourceDetails.Owner}/${pipeline.SourceDetails.Repo || 'N/A'}</div>` : ''}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createColoredStatusBadge(pipeline.IsEncrypted ? 'Yes' : 'No', pipeline.IsEncrypted)}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createColoredStatusBadge(pipeline.HasManualApproval ? 'Yes' : 'No', pipeline.HasManualApproval)}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        ${createColoredStatusBadge(pipeline.HasSecurityScan ? 'Yes' : 'No', pipeline.HasSecurityScan)}
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap">
                                        <div class="text-xs text-gray-600 font-mono max-w-32 truncate" title="${pipeline.RoleArn}">${roleName}</div>
                                    </td>
                                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">${updatedDate}</td>
                                </tr>
                            `;
                        }).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `;
};



// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildCodePipelineView = () => {
    const container = document.getElementById('codepipeline-view');
    if (!container) {
        console.error('CodePipeline container not found');
        return;
    }

    // Verificar si hay datos de la API
    if (!window.codepipelineApiData) {
        container.innerHTML = `
            <div class="text-center py-16 bg-white rounded-lg">
                <h3 class="mt-2 text-lg font-medium text-[#204071]">Scan required</h3>
                <p class="mt-1 text-sm text-gray-500">Complete an account scan to unlock this view.</p>
            </div>
        `;
        return;
    }

    const { pipelines = [] } = window.codepipelineApiData.results || {};
    const executionDate = window.codepipelineApiData.metadata?.executionDate || 'N/A';
    
    console.log('CodePipeline data:', { pipelines: pipelines.length, data: pipelines });
    
    // Si no hay pipelines, mostrar mensaje explicativo pero no detener el renderizado
    if (pipelines.length === 0) {
        container.innerHTML = `
            <header class="flex justify-between items-center mb-6">
                <div>
                    <h2 class="text-2xl font-bold text-[#204071]">CodePipeline</h2>
                    <p class="text-sm text-gray-500">${executionDate}</p>
                </div>
            </header>
            ${renderServiceDescription(serviceDescriptions.overview)}
            ${renderEmptyState("This AWS account does not have any CodePipeline pipelines configured. This could indicate that the service is not in use for automated deployments.")}
        `;
        return;
    }

    const securityIssues = pipelines.filter(p => !p.IsEncrypted || !p.HasManualApproval || !p.HasSecurityScan).length;
    
    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">CodePipeline</h2>
                <p class="text-sm text-gray-500">${executionDate}</p>
            </div>
        </header>

        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review CodePipeline configurations for comprehensive security controls including artifact encryption, manual approval gates, IAM role permissions, and integration with security scanning tools. Focus on identifying pipelines with missing security controls and compliance gaps.</p>
        </div>

        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="codepipeline-tabs">
                <a href="#" data-tab="cp-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="cp-security-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Analysis (${securityIssues})</a>
                <a href="#" data-tab="cp-details-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Pipeline Details (${pipelines.length})</a>
            </nav>
        </div>

        <div id="codepipeline-tab-content-container">
            <div id="cp-summary-content" class="codepipeline-tab-content">${createCodePipelineSummaryCardsHtml(pipelines)}</div>
            <div id="cp-security-content" class="codepipeline-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.security)}
                ${renderSecurityAnalysisTable(pipelines)}
            </div>
            <div id="cp-details-content" class="codepipeline-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.pipelines)}
                ${renderPipelinesTable(pipelines)}
            </div>
        </div>
    `;

    const tabsNav = container.querySelector('#codepipeline-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.codepipeline-tab-content'));
};

const createColoredStatusBadge = (value, isSecure) => {
    if (isSecure) {
        return `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-green-100 text-green-800">${value}</span>`;
    } else {
        return `<span class="px-2 py-1 text-xs font-semibold rounded-full bg-red-100 text-red-800">${value}</span>`;
    }
};
