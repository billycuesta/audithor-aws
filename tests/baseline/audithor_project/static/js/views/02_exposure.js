/**
 * 02_exposure.js
 * Contiene toda la lÃ³gica para construir y renderizar la vista de Internet Exposure.
 */

// --- IMPORTACIONES ---
// Importamos las funciones de utilidad que este mÃ³dulo necesita.
import { handleTabClick, renderSecurityHubFindings, createStatusBadge } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const exposureServiceDescriptions = {
    "S3 Public Buckets": {
        title: "S3 Public Buckets",
        description: "S3 buckets configured with public read or write access through bucket policies, Access Control Lists (ACLs), or bucket-level permissions that allow anonymous internet access.",
        useCases: "Static website hosting, public content distribution, open data sharing, public documentation repositories, content delivery for web applications.",
        auditConsiderations: "Verify that public access is intentional and necessary. Review bucket policies and ACLs for overly permissive configurations. Ensure sensitive data is not accidentally exposed and that versioning/MFA delete are enabled for critical buckets."
    },
    "EC2 Public Instances": {
        title: "EC2 Public Instances",
        description: "EC2 instances that have been assigned public IP addresses, making them directly accessible from the internet through their public interface.",
        useCases: "Web servers, application servers, bastion hosts, NAT instances, public-facing APIs, development environments that require direct internet access.",
        auditConsiderations: "Ensure instances with public IPs have appropriate security groups and NACLs. Verify that only necessary ports are open and that proper authentication mechanisms are in place. Consider using load balancers instead of direct public access."
    },
    "Security Groups Open": {
        title: "Security Groups Open",
        description: "Security groups with inbound rules that allow traffic from 0.0.0.0/0 (anywhere on the internet), effectively creating open firewall rules for specific ports or protocols.",
        useCases: "Web server access (ports 80/443), SSH access for administration (port 22), database connections, API endpoints, custom application ports that need internet access.",
        auditConsiderations: "Review all rules allowing 0.0.0.0/0 access. Ensure SSH (22) and RDP (3389) are not open to the world. Verify that database ports and sensitive services are properly restricted. Consider using more specific CIDR ranges or source security groups."
    },
    "ALB/NLB Public": {
        title: "ALB/NLB Public",
        description: "Application Load Balancers (ALB) and Network Load Balancers (NLB) configured with internet-facing schemes, allowing direct access from the public internet to distribute traffic to backend targets.",
        useCases: "Web application front-ends, API gateways, microservices exposure, SSL termination points, traffic distribution for high-availability applications.",
        auditConsiderations: "Verify TLS/SSL configurations and cipher suites. Ensure WAF is enabled for ALBs when appropriate. Review listener rules and target group health checks. Confirm that only intended services are exposed through the load balancer."
    },
    "Lambda URLs": {
        title: "Lambda URLs",
        description: "AWS Lambda functions configured with Function URLs that have authentication type set to 'NONE', allowing anonymous public access to invoke the function via HTTPS.",
        useCases: "Webhooks, public APIs, serverless web applications, integration endpoints, event processing from external services, simple HTTP-triggered functions.",
        auditConsiderations: "Verify that public access is intentional and that functions don't expose sensitive data or operations. Review function permissions and ensure proper input validation. Consider implementing authentication or API Gateway for better control."
    },
    "API Gateway Public": {
        title: "API Gateway Public",
        description: "API Gateway endpoints configured for public access without authentication requirements, making REST or HTTP APIs accessible from the internet.",
        useCases: "Public REST APIs, mobile application backends, third-party integrations, webhooks, microservices exposure, serverless application endpoints.",
        auditConsiderations: "Review authentication and authorization mechanisms. Verify that API keys, IAM, or Cognito authorization is properly configured. Check throttling limits and usage plans to prevent abuse. Ensure proper input validation and error handling."
    },
    "Route53 Subdomains": {
        title: "Route 53 Subdomains",
        description: "DNS records in Route 53 hosted zones that represent subdomains and can expand the internet-facing attack surface.",
        useCases: "Application endpoints, service aliases, environment separation (dev/stage/prod), CDN origins, API hostnames.",
        auditConsiderations: "Review unknown or legacy subdomains, validate ownership, and ensure records do not point to abandoned resources. Subdomain inventory is critical to prevent takeover and shadow IT exposure."
    },
    "Publicly Exposed Network Ports": {
        title: "Publicly Exposed Network Ports",
        description: "Network Access Control Lists (NACLs) and Security Group rules that allow inbound traffic from 0.0.0.0/0 on specific ports, creating pathways for internet traffic to reach AWS resources.",
        useCases: "Web traffic (80/443), secure shell access (22), remote desktop (3389), email services (25/587/993), FTP/SFTP, custom application ports, database connections.",
        auditConsiderations: "Identify all ports open to the internet and verify business justification. Ensure administrative ports (SSH/RDP) are not globally accessible. Review database and management ports for unnecessary exposure. Consider implementing VPN or bastion hosts for administrative access."
    },
    "Security Hub Findings": {
        title: "Security Hub Findings",
        description: "AWS Security Hub findings specifically related to internet exposure risks, aggregated from various security services like GuardDuty, Inspector, and Config rules.",
        useCases: "Centralized security monitoring, compliance reporting, vulnerability management, security posture assessment, automated remediation triggers.",
        auditConsiderations: "Review critical and high severity findings first. Verify remediation status and assign ownership for resolution. Ensure findings are not being suppressed without proper justification. Track trends and recurring issues for systemic improvements."
    },
    "Lambda Credential Harvesting": {
        title: "Lambda Credential Harvesting",
        description: "Analysis of AWS Lambda functions to identify potentially hardcoded credentials, API keys, passwords, and other sensitive information in environment variables and configuration.",
        useCases: "Security auditing, credential leak detection, compliance verification, penetration testing reconnaissance, identifying secrets management gaps.",
        auditConsiderations: "Review all findings marked as CRITICAL or HIGH severity. Verify that detected patterns are actual credentials and not false positives. Ensure Lambda functions use proper secrets management (AWS Secrets Manager, Parameter Store) instead of hardcoded values. Check for exposed database connection strings and API keys."
    }
};

// --- FUNCIÃ"N PRINCIPAL DE LA VISTA (EXPORTADA) ---
// Exportamos la funciÃ³n principal para que app.js pueda encontrarla y usarla.
export const buildExposureView = () => {
    const container = document.getElementById('exposure-view');
    if (!window.exposureApiData) return;

    const allExposureServices = [
        "S3 Public Buckets", "EC2 Public Instances", "Security Groups Open", 
        "ALB/NLB Public", "Lambda URLs", "API Gateway Public", "Route53 Subdomains", "Lambda Credential Harvesting"
    ];

    const details = window.exposureApiData.results.details;
    const networkPorts = window.exposureApiData.results.network_ports || [];
    const lambdaCredentials = window.exposureApiData.results.lambda_credentials || [];  // AÑADIR ESTA LÍNEA
    const securityHubFindings = window.securityHubApiData.results.findings.exposureFindings;

    let tabsHtml = `<a href="#" data-tab="exposure-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>`;
    

    allExposureServices.forEach(service => {
        const count = service === "Lambda Credential Harvesting" 
            ? lambdaCredentials.length 
            : Object.values(details[service] || {}).flat().length;
        const safeId = service.replace(/\s+/g, '-').replace(/\//g, '-');
        tabsHtml += `<a href="#" data-tab="exposure-${safeId}-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">${service} (${count})</a>`;
    });

    tabsHtml += `<a href="#" data-tab="exposure-network-ports-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Publicly Exposed Network Ports (${networkPorts.length})</a>`;
    tabsHtml += `<a href="#" data-tab="exposure-securityhub-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub Findings</a>`;

    let contentHtml = `<div id="exposure-summary-content" class="exposure-tab-content">${createExposureSummaryCardsHtml()}</div>`;
    
    allExposureServices.forEach(service => {
        const safeId = service.replace(/\s+/g, '-').replace(/\//g, '-');
        contentHtml += `<div id="exposure-${safeId}-content" class="exposure-tab-content hidden"></div>`;
    });

    contentHtml += `<div id="exposure-network-ports-content" class="exposure-tab-content hidden"></div>`;
    contentHtml += `<div id="exposure-securityhub-content" class="exposure-tab-content hidden">${createExposureSecurityHubHtml()}</div>`;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div><h2 class="text-2xl font-bold text-[#204071]">Internet Exposure</h2><p class="text-sm text-gray-500">${window.exposureApiData.metadata.executionDate}</p></div>
        </header>
        
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review internet-exposed resources to ensure they follow security best practices and have legitimate business justification. Each tab provides specific audit considerations and security implications for that exposure type.</p>
        </div>
        
        <div class="border-b border-gray-200 mb-6"><nav class="-mb-px flex flex-wrap space-x-6">${tabsHtml}</nav></div>
        <div>${contentHtml}</div>`;

    updateExposureSummaryCards(window.exposureApiData.results.summary, securityHubFindings);


    allExposureServices.forEach(service => {
        const safeId = service.replace(/\s+/g, '-').replace(/\//g, '-');
        const serviceContainer = container.querySelector(`#exposure-${safeId}-content`);

        if (service === 'Lambda Credential Harvesting') {
            serviceContainer.innerHTML = renderServiceDescription(exposureServiceDescriptions[service]) + 
                                    renderLambdaCredentialsTable(lambdaCredentials);
        } else if (service === 'EC2 Public Instances') {
            const allInstancesWithIndex = (window.computeApiData?.results?.ec2_instances || [])
                .map((instance, originalIndex) => ({ instance, originalIndex }))
                .filter(({ instance }) => instance.PublicIpAddress && instance.PublicIpAddress !== 'N/A');
            serviceContainer.innerHTML = renderServiceDescription(exposureServiceDescriptions[service]) + 
                                    renderPublicEc2InstancesTable(allInstancesWithIndex, window.allAvailableRegions, 'all', 'all');
        } else {
            serviceContainer.innerHTML = renderServiceDescription(exposureServiceDescriptions[service]) +
                                    renderExposureDetails(service, details[service] || {});
        }
    });

    const networkPortsContainer = container.querySelector('#exposure-network-ports-content');
    networkPortsContainer.innerHTML = renderServiceDescription(exposureServiceDescriptions["Publicly Exposed Network Ports"]) +
                                    renderNetworkPortsTable(networkPorts);

    const securityHubContainer = container.querySelector('#exposure-securityhub-content');
    securityHubContainer.innerHTML = renderServiceDescription(exposureServiceDescriptions["Security Hub Findings"]) +
                                   createExposureSecurityHubHtml();

    renderSecurityHubFindings(securityHubFindings, 'sh-exposure-findings-container', 'No Security Hub findings related to internet exposure were found.');
    
    const ec2TabContent = container.querySelector('#exposure-EC2-Public-Instances-content');
    
    const handleFilterChange = () => {
        const selectedState = ec2TabContent.querySelector('.public-ec2-filter-btn.bg-\\[\\#eb3496\\]')?.dataset.state || 'all';
        const selectedRegion = ec2TabContent.querySelector('#public-ec2-region-filter').value;
        const allInstancesWithIndex = (window.computeApiData?.results?.ec2_instances || []).map((instance, originalIndex) => ({ instance, originalIndex }));

        let filteredInstances = allInstancesWithIndex
            .filter(({ instance }) => instance.PublicIpAddress && instance.PublicIpAddress !== 'N/A');

        if (selectedState !== 'all') {
            filteredInstances = filteredInstances.filter(({ instance }) => instance.State.toLowerCase() === selectedState);
        }
        if (selectedRegion !== 'all') {
            filteredInstances = filteredInstances.filter(({ instance }) => instance.Region === selectedRegion);
        }
        
        ec2TabContent.innerHTML = renderServiceDescription(exposureServiceDescriptions["EC2 Public Instances"]) +
                                 renderPublicEc2InstancesTable(filteredInstances, window.allAvailableRegions, selectedState, selectedRegion);
    };
    
    ec2TabContent.addEventListener('click', (e) => {
        const filterBtn = e.target.closest('.public-ec2-filter-btn');
        if (!filterBtn) return;
        
        ec2TabContent.querySelectorAll('.public-ec2-filter-btn').forEach(btn => {
            btn.classList.remove('bg-[#eb3496]', 'text-white');
            btn.classList.add('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        });
        filterBtn.classList.add('bg-[#eb3496]', 'text-white');
        filterBtn.classList.remove('bg-white', 'text-gray-700', 'border', 'border-gray-300', 'hover:bg-gray-50');
        handleFilterChange();
    });

    ec2TabContent.addEventListener('change', (e) => {
        if (e.target.id === 'public-ec2-region-filter') {
            handleFilterChange();
        }
    });
    
    const tabsNav = container.querySelector('nav');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.exposure-tab-content'));
};

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

// --- FUNCIONES INTERNAS DEL MÃ"DULO (NO SE EXPORTAN) ---

const createExposureSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">ALB/NLB Public</p></div><div class="flex justify-between items-end pt-4"><p id="exp-total-albs" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path fill-rule="evenrule" d="M6 3.5a.5.5 0 0 1 .5-.5h8a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-8a.5.5 0 0 1-.5-.5v-2a.5.5 0 0 0-1 0v2A1.5 1.5 0 0 0 6.5 14h8a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2h-8A1.5 1.5 0 0 0 5 3.5v2a.5.5 0 0 0 1 0z"/> <path fill-rule="evenrule" d="M11.854 8.354a.5.5 0 0 0 0-.708l-3-3a.5.5 0 1 0-.708.708L10.293 7.5H1.5a.5.5 0 0 0 0 1h8.793l-2.147 2.146a.5.5 0 0 0 .708.708z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">EC2 Public Instances</p></div><div class="flex justify-between items-end pt-4"><p id="exp-total-ec2s" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path d="M5 0a.5.5 0 0 1 .5.5V2h1V.5a.5.5 0 0 1 1 0V2h1V.5a.5.5 0 0 1 1 0V2h1V.5a.5.5 0 0 1 1 0V2A2.5 2.5 0 0 1 14 4.5h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14v1h1.5a.5.5 0 0 1 0 1H14a2.5 2.5 0 0 1-2.5 2.5v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14h-1v1.5a.5.5 0 0 1-1 0V14A2.5 2.5 0 0 1 2 11.5H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2v-1H.5a.5.5 0 0 1 0-1H2A2.5 2.5 0 0 1 4.5 2V.5A.5.5 0 0 1 5 0m-.5 3A1.5 1.5 0 0 0 3 4.5v7A1.5 1.5 0 0 0 4.5 13h7a1.5 1.5 0 0 0 1.5-1.5v-7A1.5 1.5 0 0 0 11.5 3zM5 6.5A1.5 1.5 0 0 1 6.5 5h3A1.5 1.5 0 0 1 11 6.5v3A1.5 1.5 0 0 1 9.5 11h-3A1.5 1.5 0 0 1 5 9.5zM6.5 6a.5.5 0 0 0-.5.5v3a.5.5 0 0 0 .5.5h3a.5.5 0 0 0 .5-.5v-3a.5.5 0 0 0-.5-.5z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Security Groups Open</p></div><div class="flex justify-between items-end pt-4"><p id="exp-total-sgs" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path fill-rule="evenrule" d="M12 0a4 4 0 0 1 4 4v2.5h-1V4a3 3 0 1 0-6 0v2h.5A2.5 2.5 0 0 1 12 8.5v5A2.5 2.5 0 0 1 9.5 16h-7A2.5 2.5 0 0 1 0 13.5v-5A2.5 2.5 0 0 1 2.5 6H8V4a4 4 0 0 1 4-4M2.5 7A1.5 1.5 0 0 0 1 8.5v5A1.5 1.5 0 0 0 2.5 15h7a1.5 1.5 0 0 0 1.5-1.5v-5A1.5 1.5 0 0 0 9.5 7z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">S3 Buckets Public</p></div><div class="flex justify-between items-end pt-4"><p id="exp-total-s3" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path d="M2.522 5H2a.5.5 0 0 0-.494.574l1.372 9.149A1.5 1.5 0 0 0 4.36 16h7.278a1.5 1.5 0 0 0 1.483-1.277l1.373-9.149A.5.5 0 0 0 14 5h-.522A5.5 5.5 0 0 0 2.522 5m1.005 0a4.5 4.5 0 0 1 8.945 0zm9.892 1-1.286 8.574a.5.5 0 0 1-.494.426H4.36a.5.5 0 0 1-.494-.426L2.58 6h10.838z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Findings (Crit/High)</p></div><div class="flex justify-between items-end pt-4"><p id="exp-critical-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"> <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/></svg></div></div></div>
    </div>`;

const createExposureSecurityHubHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (Exposed to the Internet)</h3><div id="sh-exposure-findings-container" class="overflow-x-auto"></div></div>`;

const updateExposureSummaryCards = (summaryData, findingsData) => { 
    const sumValues = (serviceName) => { 
        if (!summaryData[serviceName]) return 0; 
        return Object.values(summaryData[serviceName]).reduce((total, count) => total + count, 0); 
    }; 
    document.getElementById('exp-total-albs').textContent = sumValues('ALB/NLB Public'); 
    document.getElementById('exp-total-ec2s').textContent = sumValues('EC2 Public Instances'); 
    document.getElementById('exp-total-sgs').textContent = sumValues('Security Groups Open'); 
    document.getElementById('exp-total-s3').textContent = sumValues('S3 Public Buckets'); 
    const criticalHighFindings = findingsData.filter(f => f.Severity?.Label === 'CRITICAL' || f.Severity?.Label === 'HIGH').length; 
    const lambdaCredentials = window.exposureApiData.results.lambda_credentials || [];
    const criticalCredentials = lambdaCredentials.filter(c => c.severity === 'CRITICAL').length;
    document.getElementById('exp-critical-findings').textContent = criticalHighFindings; 
};

const renderPublicEc2InstancesTable = (instances, allRegions, selectedState = 'all', selectedRegion = 'all') => {
    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');

    const filterControlsHtml = `
        <div class="mb-4 flex flex-wrap gap-4 items-center">
            <div class="flex items-center space-x-2">
                <span class="text-sm font-medium text-gray-700">Status:</span>
                <div class="flex space-x-2">
                    <button data-state="all" class="public-ec2-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm ${selectedState === 'all' ? 'bg-[#eb3496] text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'}">All</button>
                    <button data-state="running" class="public-ec2-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm ${selectedState === 'running' ? 'bg-[#eb3496] text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'}">Running</button>
                    <button data-state="stopped" class="public-ec2-filter-btn px-3 py-1 text-sm font-semibold rounded-md shadow-sm ${selectedState === 'stopped' ? 'bg-[#eb3496] text-white' : 'bg-white text-gray-700 border border-gray-300 hover:bg-gray-50'}">Stopped</button>
                </div>
            </div>
            <div class="flex items-center space-x-2">
                <label for="public-ec2-region-filter" class="text-sm font-medium text-gray-700">Region:</label>
                <select id="public-ec2-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5">
                    <option value="all">All Regions</option>
                    ${regionOptions}
                </select>
            </div>
        </div>`;

    if (!instances || instances.length === 0) {
        return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControlsHtml}<p class="text-center text-gray-500 py-4">No EC2 instances with public IPs match the selected filters.</p></div>`;
    }

    let tableHtml = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Instance ID</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public IP</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Operating System</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Security Groups</th>' +
                    '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tags</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    instances.forEach((instanceData) => {
        const { instance, originalIndex } = instanceData;
        const tagCount = Object.keys(instance.Tags).length;
        let tagsHtml = '-';
        if (tagCount > 0) {
            tagsHtml = `<button 
                            onclick="openModalWithEc2Tags(${originalIndex})" 
                            class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                            View (${tagCount})
                        </button>`;
        }

        const sgHtml = instance.SecurityGroups && instance.SecurityGroups.length > 0
            ? instance.SecurityGroups.map(sg => `<span class="inline-block bg-gray-100 text-gray-800 text-xs font-medium mr-2 mb-1 px-2.5 py-0.5 rounded-full">${sg}</span>`).join('')
            : '-';

        tableHtml += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${instance.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${instance.InstanceId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${instance.InstanceType}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(instance.State)}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${instance.PublicIpAddress}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 break-words">${instance.OperatingSystem}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 break-words">${sgHtml}</td>
                    <td class="px-4 py-4 text-center">
                        <button onclick="copyToClipboard(this, '${instance.ARN}')" title="${instance.ARN}" class="p-1 rounded-md hover:bg-gray-200 transition">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
                        </button>
                    </td>
                    <td class="px-4 py-4 text-sm text-gray-600">${tagsHtml}</td>
                </tr>`;
    });
    tableHtml += '</tbody></table></div>';
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControlsHtml}${tableHtml}</div>`;
};

export const openModalWithTlsDetails = (lbIndex, listenerIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    const allLbs = Object.values(window.exposureApiData.results.details['ALB/NLB Public'] || {}).flat();
    const lb = allLbs[lbIndex];
    const listener = lb.listeners[listenerIndex];

    if (!modal || !listener) return;

    modalTitle.textContent = `TLS Details for ${lb.name}:${listener.port}`;
    
    const tlsVersionsHtml = listener.tlsVersions.map(v => {
        const isOutdated = ['TLSv1.0', 'TLSv1.1', 'SSLv3'].includes(v);
        return `<li class="${isOutdated ? 'text-red-600 font-bold' : 'text-green-700'}">${v}</li>`;
    }).join('');

    const ciphersHtml = listener.ciphers.map(c => `<li class="font-mono text-xs">${c}</li>`).join('');

    modalContent.innerHTML = `
        <div class="space-y-4 text-left text-sm">
            <div>
                <h4 class="font-semibold text-gray-800">TLS Versions Supported</h4>
                <ul class="list-disc list-inside pl-2 mt-1">${tlsVersionsHtml}</ul>
            </div>
            <div>
                <h4 class="font-semibold text-gray-800">Cipher Suites Enabled</h4>
                <ul class="list-disc list-inside pl-2 mt-1 text-gray-600">${ciphersHtml}</ul>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
};

export const openModalWithResourceMap = (lbIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    const allLbs = Object.values(window.exposureApiData.results.details['ALB/NLB Public'] || {}).flat();
    const lb = allLbs[lbIndex];

    if (!modal || !lb) {
        console.error("No se pudo encontrar el modal o los datos del balanceador.");
        return;
    }

    modalTitle.textContent = `Resource Map for: ${lb.name}`;
    
    // Llamamos a una nueva función que generará el HTML del diagrama
    modalContent.innerHTML = renderResourceMapDiagram(lb);
    
    modal.classList.remove('hidden');
};

const renderResourceMapDiagram = (lb) => {
    // Inspirado en el estilo de network_policies.js
    let diagramHtml = '<div class="flex items-start space-x-4 p-4 overflow-x-auto bg-gray-50 rounded-lg">';

    // Columna 1: Listeners
    let listenersHtml = `<div class="flex-shrink-0 w-48 space-y-3">
        <h4 class="font-bold text-gray-700">Listeners (${lb.listeners.length})</h4>`;
    if (lb.listeners.length > 0) {
        lb.listeners.forEach(listener => {
            listenersHtml += `
                <div class="bg-white border border-gray-200 rounded-lg p-3 shadow-sm">
                    <p class="font-semibold text-sm text-[#204071]">${listener.protocol} : ${listener.port}</p>
                    <p class="text-xs text-gray-500">${listener.rules ? listener.rules.length : '1'} rule(s)</p>
                </div>`;
        });
    } else {
        listenersHtml += `<div class="bg-white border border-gray-200 rounded-lg p-3 text-center text-xs text-gray-500">No listeners</div>`;
    }
    listenersHtml += '</div>';

    // Columna 2: Rules (simplificado, asumiendo una regla por listener para este ejemplo)
    let rulesHtml = `<div class="flex-shrink-0 w-64 space-y-3 pt-10">`; // pt-10 para alinear
    lb.listeners.forEach(listener => {
        // Asumimos que la información de la regla y el target group está en el listener
        // En una implementación real, aquí iterarías sobre listener.rules
        rulesHtml += `
            <div class="relative flex items-center">
                <div class="text-gray-400 absolute -left-6 top-1/2 -translate-y-1/2">⟶</div>
                <div class="bg-white border border-gray-200 rounded-lg p-3 shadow-sm flex-grow">
                    <p class="font-semibold text-xs text-gray-500">Priority: default</p>
                    <p class="font-semibold text-sm text-[#204071]">Forward to: <span class="font-mono">${listener.targetGroupName || 'N/A'}</span></p>
                    <p class="text-xs text-gray-500 mt-1">Conditions: If no other rule applies</p>
                </div>
            </div>`;
    });
    rulesHtml += `</div>`;

    // Columna 3: Target Groups
    let targetGroupsHtml = `<div class="flex-shrink-0 w-64 space-y-3">
        <h4 class="font-bold text-gray-700">Target Groups</h4>`;
    lb.listeners.forEach(listener => {
        const targetsCount = listener.targets ? listener.targets.length : 0;
        targetGroupsHtml += `
            <div class="relative flex items-center">
                <div class="text-gray-400 absolute -left-6 top-1/2 -translate-y-1/2">⟶</div>
                <div class="bg-white border border-gray-200 rounded-lg p-3 shadow-sm flex-grow">
                    <p class="font-semibold text-sm text-[#204071] break-all">
                        <svg viewBox="0 0 20 20" fill="currentColor" class="w-4 h-4 inline-block mr-1"><path d="M2 3a1 1 0 011-1h3.5a1 1 0 011 1v1.5a1 1 0 01-1 1H3a1 1 0 01-1-1V3zm2.5 7.5a1 1 0 011-1h3.5a1 1 0 011 1v1.5a1 1 0 01-1 1H5.5a1 1 0 01-1-1v-1.5zM2 12a1 1 0 011-1h3.5a1 1 0 011 1v1.5a1 1 0 01-1 1H3a1 1 0 01-1-1v-1.5z"></path></svg>
                        ${listener.targetGroupName || 'N/A'}
                    </p>
                    <p class="text-xs text-gray-500">${targetsCount} targets</p>
                    </div>
            </div>`;
    });
    targetGroupsHtml += `</div>`;
    
    // Columna 4: Targets
    let targetsHtml = `<div class="flex-shrink-0 w-48 space-y-3 pt-10">`;
    lb.listeners.forEach(listener => {
        targetsHtml += `<div class="relative flex items-center h-full">
            <div class="text-gray-400 absolute -left-6 top-1/2 -translate-y-1/2">⟶</div>
            <div class="bg-white border border-gray-200 rounded-lg p-3 shadow-sm w-full">`;
        if (listener.targets && listener.targets.length > 0) {
            listener.targets.forEach(target => {
                 targetsHtml += `<div class="text-sm font-mono text-gray-800">${target.Id}</div>`;
            });
        } else {
            targetsHtml += `<p class="text-center text-xs text-gray-500">No targets</p>`;
        }
        targetsHtml += `</div></div>`;
    });
    targetsHtml += '</div>';

    diagramHtml += listenersHtml + rulesHtml + targetGroupsHtml + targetsHtml + '</div>';
    return diagramHtml;
};

const renderPublicLoadBalancersTable = (loadBalancersByRegion) => {
    const allLbs = Object.values(loadBalancersByRegion || {}).flat();
    if (allLbs.length === 0) {
         return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No public Load Balancers were found.</p></div>';
    }

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Load Balancer Name</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Listener Port</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">TLS Policy</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">TLS Status</th>' +
                    '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Details</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    allLbs.forEach((lb, lbIndex) => {
        if (lb.listeners.length > 0) {
            lb.listeners.forEach((listener, listenerIndex) => {
                const statusBadge = listener.isOutdated
                    ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Outdated</span>'
                    : '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Secure</span>';
                
                tableHtml += `<tr 
                                class="hover:bg-blue-50 cursor-pointer" 
                                onclick="openModalWithResourceMap(${lbIndex})">

                                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${lb.region}</td>
                                <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${lb.name}</td>
                                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${listener.port} (${listener.protocol})</td>
                                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${listener.policyName}</td>
                                <td class="px-4 py-4 whitespace-nowrap text-sm">${statusBadge}</td>
                                <td class="px-4 py-4 text-center">
                                    <button 
                                        onclick="event.stopPropagation(); openModalWithTlsDetails(${lbIndex}, ${listenerIndex})" 
                                        class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">
                                        Details
                                    </button>
                                </td>
                            </tr>`;

            });
        } else {
            tableHtml += `<tr class="hover:bg-gray-50">
                            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${lb.region}</td>
                            <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${lb.name}</td>
                            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-500 italic" colspan="4">No HTTPS/TLS listeners</td>
                        </tr>`;
        }
    });

    tableHtml += '</tbody></table></div>';
    return tableHtml;
};

const renderOpenSecurityGroupsTable = (openSgs) => {
    if (!openSgs || openSgs.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No open security groups were found.</p></div>';
    }
    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Group ID</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Group Name</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Port Range</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    openSgs.forEach(sg => {
        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${sg.Region}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${sg.GroupId}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${sg.GroupName}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${sg.Protocol}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-red-600 font-semibold">${sg.PortRange}</td>
                    </tr>`;
    });

    tableHtml += '</tbody></table></div>';
    return tableHtml;
};


const renderApiGatewayTable = (apisByRegion) => {
    const allApis = Object.values(apisByRegion || {}).flat();
    if (allApis.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No public API Gateway endpoints were found.</p></div>';
    }

    // AÑADIDO: Ordenar la lista para un índice estable
    allApis.sort((a, b) => (a.region + a.name).localeCompare(b.region + b.name));

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">API Name</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">API ID</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">API Type</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Endpoint Type</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Port</th>' +
                    
                    '' +
                    '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Details</th>' +
                    
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Stages</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Creation Date</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>' +
                    '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">Invoke URL</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    // MODIFICADO: Cambiado el bucle para usar la lista plana 'allApis'
    allApis.forEach((api, apiIndex) => {
        const region = api.region; // <-- Definir 'region' desde el objeto api

        // Manejar tanto el formato antiguo (string) como el nuevo (objeto)
        let apiName = '';
        let apiId = '';
        let apiType = 'REST';
        let endpointTypes = ['Regional'];
        let stages = [];
        let createdDate = 'N/A';
        let description = 'No description';
        let invokeUrl = 'N/A';

        if (typeof api === 'string') {
            // Formato antiguo - mantener compatibilidad
            if (api.includes('(Regional)')) {
                apiName = api.replace(' (Regional)', '');
                endpointTypes = ['Regional'];
            } else if (api.includes('(Edge)')) {
                apiName = api.replace(' (Edge)', '');
                endpointTypes = ['Edge Optimized'];
            } else if (api.includes('(Private)')) {
                apiName = api.replace(' (Private)', '');
                endpointTypes = ['Private'];
            } else {
                apiName = api;
            }
        } else if (typeof api === 'object') {
            // Formato nuevo - usar todas las propiedades disponibles
            apiName = api.name || 'Unknown API';
            apiId = api.id || 'Unknown ID';
            apiType = api.apiType || 'REST';
            endpointTypes = api.endpointConfiguration || ['Regional'];
            stages = api.stages || [];
            createdDate = api.createdDate;
            description = api.description || 'No description';
            
            // Construir URL de invocación
            if (apiId && region) {
                const primaryStage = stages.length > 0 ? stages[0] : 'prod';
                invokeUrl = `https://${apiId}.execute-api.${region}.amazonaws.com/${primaryStage}/`;
            }
        }

        // Formatear endpoint types
        const endpointTypeText = endpointTypes.join(', ');
        const endpointBadgeClass = endpointTypes.includes('REGIONAL') ? 'bg-blue-100 text-blue-800' : 
                                 endpointTypes.includes('EDGE') ? 'bg-green-100 text-green-800' :
                                 'bg-purple-100 text-purple-800';

        // Formatear API type
        const apiTypeBadgeClass = apiType === 'REST' ? 'bg-indigo-100 text-indigo-800' : 'bg-cyan-100 text-cyan-800';

        // Formatear stages
        const stagesHtml = stages.length > 0 ? 
            stages.map(stage => `<span class="inline-block bg-gray-100 text-gray-800 text-xs font-medium mr-1 mb-1 px-2 py-0.5 rounded">${stage}</span>`).join('') :
            '<span class="text-gray-400 text-xs">No stages</span>';

        // Formatear fecha
        const formattedDate = createdDate && createdDate !== 'N/A' ? 
            new Date(createdDate).toLocaleDateString() : 'N/A';

        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${region}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${apiName}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${apiId}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm">
                            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${apiTypeBadgeClass}">${apiType}</span>
                        </td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm">
                            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${endpointBadgeClass}">${endpointTypeText}</span>
                        </td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">
                            <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">
                                443 (HTTPS)
                            </span>
                        </td>

                        <td class="px-4 py-4 text-center">
                            <button 
                                onclick="event.stopPropagation(); openModalWithApiMap(${apiIndex})" 
                                class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">
                                Map
                            </button>
                        </td>

                        <td class="px-4 py-4 text-sm text-gray-600 break-words max-w-xs">${stagesHtml}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${formattedDate}</td>
                        <td class="px-4 py-4 text-sm text-gray-600 break-words max-w-xs" title="${description}">${description.length > 50 ? description.substring(0, 50) + '...' : description}</td>
                        <td class="px-4 py-4 text-center">
                            ${invokeUrl !== 'N/A' ? 
                                `<button onclick="copyToClipboard(this, '${invokeUrl}')" title="${invokeUrl}" class="p-1 rounded-md hover:bg-gray-200 transition">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
                                </button>` : 
                                '<span class="text-gray-400 text-xs">N/A</span>'
                            }
                        </td>
                    </tr>`;
    }); // <-- MODIFICADO: Bucle 'forEach' simple
    // }); <-- ELIMINADO: Cierre del bucle 'Object.entries'

    tableHtml += '</tbody></table></div>';
    return tableHtml;
};


const renderExposureDetails = (service, regions) => {
    const flattenedData = Object.values(regions).flat();

    if (flattenedData.length === 0) {
        return `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No exposed resources of type "${service}" were found.</p></div>`;
    }

    if (service === "EC2 Public Instances") {
        return renderPublicEc2InstancesTable();
    }

    if (service === "Security Groups Open") {
        return renderOpenSecurityGroupsTable(flattenedData);
    }

    if (service === "ALB/NLB Public") {
        return renderPublicLoadBalancersTable(regions);
    }

    if (service === "API Gateway Public") {
        return renderApiGatewayTable(regions);
    }

    if (service === "Route53 Subdomains") {
        return renderRoute53SubdomainsTable(regions);
    }

    // Agregar soporte para S3 Public Buckets con tabla
    if (service === "S3 Public Buckets") {
        return renderPublicS3BucketsTable(regions);
    }

    // Fallback para otros servicios (Lambda URLs y Assumable Roles)
    let html = '<div class="space-y-6">';
    Object.entries(regions).sort(([keyA], [keyB]) => keyA.localeCompare(keyB)).forEach(([region, items]) => {
        html += `<div class="bg-white p-4 rounded-xl shadow-sm border border-gray-100"><h4 class="font-semibold text-md text-[#204071] mb-2">${region}</h4><ul class="space-y-2 font-mono text-sm">`;
        items.forEach(item => { html += `<li class="text-gray-600 list-disc list-inside">${item}</li>`; });
        html += '</ul></div>';
    });
    html += '</div>';
    return html;
};


const renderNetworkPortsTable = (ports) => {
    if (!ports || ports.length === 0) {
        return `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">Excellent! No publicly exposed network ports were found.</p></div>`;
    }

    let tableHtml = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type of Resource</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Resource ID</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Protocol</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Port Range</th>
                    <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">`;

    ports.sort((a,b) => a.Region.localeCompare(b.Region)).forEach(p => {
        const protocol = p.Protocol === "-1" ? "All" : p.Protocol;
        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${p.Region}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${p.ResourceType}</td>
                        <td class="px-4 py-4 text-sm text-gray-600 break-all font-mono">${p.ResourceId}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${protocol.toString().toUpperCase()}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${p.PortRange}</td>
                        <td class="px-4 py-4 text-sm text-gray-600 break-words">${p.Description}</td>
                      </tr>`;
    });

    tableHtml += `</tbody></table></div>`;
    return tableHtml;
};

const renderPublicS3BucketsTable = (bucketsByRegion) => {
    const allBuckets = Object.values(bucketsByRegion || {}).flat();
    if (allBuckets.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No public S3 buckets were found.</p></div>';
    }

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Bucket Name</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public Access Type</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">URL</th>' +
                    '<th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    // Procesar buckets por región
    Object.entries(bucketsByRegion).sort(([keyA], [keyB]) => keyA.localeCompare(keyB)).forEach(([region, buckets]) => {
        buckets.forEach(bucketName => {
            const publicAccessType = "Public Read";
            const bucketUrl = `https://${bucketName}.s3.amazonaws.com/`;
            const bucketArn = `arn:aws:s3:::${bucketName}`;
            
            // Mostrar región como "Global" ya que S3 es un servicio global
            const displayRegion = "Global";

            tableHtml += `<tr class="hover:bg-gray-50">
                            <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${bucketName}</td>
                            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${displayRegion}</td>
                            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">
                                <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                    ${publicAccessType}
                                </span>
                            </td>
                            <td class="px-4 py-4 whitespace-nowrap text-sm text-blue-600 font-mono">
                                <a href="${bucketUrl}" target="_blank" class="hover:text-blue-800 transition">
                                    ${bucketUrl}
                                </a>
                            </td>
                            <td class="px-4 py-4 text-center">
                                <button onclick="copyToClipboard(this, '${bucketArn}')" title="${bucketArn}" class="p-1 rounded-md hover:bg-gray-200 transition">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
                                </button>
                            </td>
                            <td class="px-4 py-4 whitespace-nowrap text-sm">
                                <div class="flex space-x-2">
                                    <button onclick="openS3BucketDetails('${bucketName}', '${region}')" class="bg-[#204071] text-white px-2 py-1 text-xs font-medium rounded hover:bg-[#1a335a] transition">
                                        Details
                                    </button>
                                    <button onclick="runS3BucketSecurityCheck('${bucketName}')" class="bg-orange-600 text-white px-2 py-1 text-xs font-medium rounded hover:bg-orange-700 transition">
                                        Security Check
                                    </button>
                                </div>
                            </td>
                        </tr>`;
        });
    });

    tableHtml += '</tbody></table></div>';
    
    const infoNote = `
        <div class="mt-4 bg-yellow-50 border border-yellow-200 rounded-lg p-4">
            <div class="flex">
                <div class="flex-shrink-0">
                    <svg class="h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd" />
                    </svg>
                </div>
                <div class="ml-3">
                    <h3 class="text-sm font-medium text-yellow-800">Security Recommendation</h3>
                    <div class="mt-2 text-sm text-yellow-700">
                        <p>Public S3 buckets can expose sensitive data to the internet. Review each bucket to ensure public access is intentional and necessary. Consider implementing:</p>
                        <ul class="list-disc list-inside mt-2 space-y-1">
                            <li>Block Public Access settings at account and bucket level</li>
                            <li>Bucket policies with explicit deny statements for unauthorized access</li>
                            <li>CloudFront distributions for controlled public content delivery</li>
                            <li>S3 Access Logs and CloudTrail for monitoring access patterns</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    return tableHtml + infoNote;
};

const renderRoute53SubdomainsTable = (subdomainsByRegion) => {
    const allSubdomains = Object.values(subdomainsByRegion || {}).flat();

    if (allSubdomains.length === 0) {
        return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No Route 53 subdomains were found.</p></div>';
    }

    allSubdomains.sort((a, b) => {
        const zoneA = (a.HostedZone || '').localeCompare(b.HostedZone || '');
        if (zoneA !== 0) return zoneA;
        return (a.Name || '').localeCompare(b.Name || '');
    });

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Hosted Zone</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Subdomain</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Record Type</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">TTL</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';

    allSubdomains.forEach((record) => {
        tableHtml += `<tr class="hover:bg-gray-50">
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${record.HostedZone || '-'}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${record.Name || '-'}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${record.Type || '-'}</td>
                        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${record.TTL ?? '-'}</td>
                      </tr>`;
    });

    tableHtml += '</tbody></table></div>';
    return tableHtml;
};

// Función implementada para el Security Check REAL mejorada
window.runS3BucketSecurityCheck = async (bucketName) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    if (!modal) return;

    modalTitle.textContent = `Security Analysis: ${bucketName}`;
    modalContent.innerHTML = `
        <div class="space-y-4 text-left text-sm">
            <div class="animate-pulse">
                <div class="flex items-center space-x-2">
                    <div class="animate-spin h-4 w-4 border-2 border-blue-500 border-t-transparent rounded-full"></div>
                    <span class="text-blue-600">Analyzing bucket security configuration...</span>
                </div>
                <div class="mt-2 text-xs text-gray-500">Checking AWS configuration: ACLs, policies, encryption, versioning...</div>
            </div>
        </div>
    `;
    
    modal.classList.remove('hidden');

    try {
        // Obtener credenciales del header
        const accessKeyInput = document.getElementById("access-key-input");
        const secretKeyInput = document.getElementById("secret-key-input");
        const sessionTokenInput = document.getElementById("session-token-input");

        if (!accessKeyInput?.value || !secretKeyInput?.value) {
            throw new Error("AWS credentials are required for security analysis");
        }

        const payload = {
            access_key: accessKeyInput.value.trim(),
            secret_key: secretKeyInput.value.trim(),
            session_token: sessionTokenInput.value.trim() || null,
            bucket_name: bucketName
        };

        const s3SecurityCheckEndpoint = window.API?.RUN_S3_SECURITY_CHECK || '/api/run-s3-security-check';
        const response = await fetch(s3SecurityCheckEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Security analysis failed');
        }

        const analysis = data.analysis;
        
        // Determinar color del risk level
        const getRiskColor = (risk) => {
            switch(risk) {
                case 'CRITICAL': return 'text-red-800 bg-red-100 border-red-200';
                case 'HIGH': return 'text-orange-800 bg-orange-100 border-orange-200';
                case 'MEDIUM': return 'text-yellow-800 bg-yellow-100 border-yellow-200';
                case 'LOW': return 'text-blue-800 bg-blue-100 border-blue-200';
                default: return 'text-green-800 bg-green-100 border-green-200';
            }
        };

        modalContent.innerHTML = `
            <div class="space-y-6 text-left text-sm">
                <!-- Risk Score Header Mejorado -->
                <div class="bg-gradient-to-r from-gray-50 to-gray-100 rounded-lg p-4 border-l-4 ${
                    analysis.risk_level === 'CRITICAL' ? 'border-red-500' :
                    analysis.risk_level === 'HIGH' ? 'border-orange-500' :
                    analysis.risk_level === 'MEDIUM' ? 'border-yellow-500' :
                    analysis.risk_level === 'LOW' ? 'border-blue-500' : 'border-green-500'
                }">
                    <div class="flex justify-between items-start">
                        <div>
                            <h4 class="font-bold text-lg text-gray-800">Security Risk Assessment</h4>
                            <p class="text-sm text-gray-600 mt-1">Real-time AWS configuration analysis</p>
                        </div>
                        <div class="text-right">
                            <!-- Barra de progreso visual -->
                            <div class="w-24 bg-gray-200 rounded-full h-3 mb-2">
                                <div class="h-3 rounded-full transition-all duration-500 ${
                                    analysis.risk_score >= 80 ? 'bg-red-500' :
                                    analysis.risk_score >= 60 ? 'bg-orange-500' :
                                    analysis.risk_score >= 40 ? 'bg-yellow-500' :
                                    analysis.risk_score >= 20 ? 'bg-blue-500' : 'bg-green-500'
                                }" style="width: ${analysis.risk_score}%"></div>
                            </div>
                            <div class="text-right">
                                <div class="text-2xl font-bold ${
                                    analysis.risk_score >= 80 ? 'text-red-700' :
                                    analysis.risk_score >= 60 ? 'text-orange-700' :
                                    analysis.risk_score >= 40 ? 'text-yellow-700' :
                                    analysis.risk_score >= 20 ? 'text-blue-700' : 'text-green-700'
                                }">${analysis.risk_score}/100</div>
                                <span class="px-3 py-1 text-xs font-bold rounded-full border ${getRiskColor(analysis.risk_level)}">
                                    ${analysis.risk_level}
                                </span>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <!-- Columna Izquierda: Issues y Warnings -->
                    <div class="space-y-4">
                        <!-- Issues Section -->
                        ${analysis.issues.length > 0 ? `
                        <div class="bg-red-50 border-l-4 border-red-400 rounded-lg p-4">
                            <div class="flex items-center mb-3">
                                <svg class="w-5 h-5 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                <h4 class="font-semibold text-red-800">
                                    Critical Issues (${analysis.issues.length})
                                </h4>
                            </div>
                            <div class="space-y-2">
                                ${analysis.issues.map(issue => `
                                    <div class="flex items-start">
                                        <span class="text-red-500 mr-2 mt-0.5">•</span>
                                        <span class="text-red-700 text-sm">${issue}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                        ` : `
                        <div class="bg-green-50 border-l-4 border-green-400 rounded-lg p-4">
                            <div class="flex items-center">
                                <svg class="w-5 h-5 text-green-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                <span class="font-semibold text-green-800">No Critical Issues Found</span>
                            </div>
                        </div>
                        `}

                        <!-- Warnings Section -->
                        ${analysis.warnings.length > 0 ? `
                        <div class="bg-yellow-50 border-l-4 border-yellow-400 rounded-lg p-4">
                            <div class="flex items-center mb-3">
                                <svg class="w-5 h-5 text-yellow-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.996-.833-2.464 0L3.732 16c-.77.833.192 2.5 1.732 2.5z"></path>
                                </svg>
                                <h4 class="font-semibold text-yellow-800">
                                    Warnings (${analysis.warnings.length})
                                </h4>
                            </div>
                            <div class="space-y-2">
                                ${analysis.warnings.map(warning => `
                                    <div class="flex items-start">
                                        <span class="text-yellow-500 mr-2 mt-0.5">•</span>
                                        <span class="text-yellow-700 text-sm">${warning}</span>
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                        ` : ''}
                    </div>

                    <!-- Columna Derecha: Configuration -->
                    <div>
                        <div class="bg-gray-50 border border-gray-200 rounded-lg p-4">
                            <h4 class="font-semibold text-gray-800 mb-4 flex items-center">
                                <svg class="w-5 h-5 text-gray-600 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path>
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                </svg>
                                Current Configuration
                            </h4>
                            <div class="space-y-3 text-sm">
                                <!-- Configuration Pills -->
                                <div class="flex flex-wrap gap-2">
                                    <div class="flex items-center">
                                        <strong class="text-gray-700 mr-2">Encryption:</strong>
                                        <span class="px-3 py-1 rounded-full text-xs font-medium ${analysis.configuration.encryption ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                                            ${analysis.configuration.encryption ? 'Enabled' : 'Disabled'}
                                        </span>
                                    </div>
                                    <div class="flex items-center">
                                        <strong class="text-gray-700 mr-2">Versioning:</strong>
                                        <span class="px-3 py-1 rounded-full text-xs font-medium ${analysis.configuration.versioning === 'Enabled' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                                            ${analysis.configuration.versioning === 'Enabled' ? 'Enabled' : 'Disabled'}
                                        </span>
                                    </div>
                                    <div class="flex items-center">
                                        <strong class="text-gray-700 mr-2">Access Logging:</strong>
                                        <span class="px-3 py-1 rounded-full text-xs font-medium ${analysis.configuration.access_logging ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                                            ${analysis.configuration.access_logging ? 'Enabled' : 'Disabled'}
                                        </span>
                                    </div>
                                    <div class="flex items-center">
                                        <strong class="text-gray-700 mr-2">Bucket Policy:</strong>
                                        <span class="px-3 py-1 rounded-full text-xs font-medium ${analysis.configuration.has_bucket_policy ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}">
                                            ${analysis.configuration.has_bucket_policy ? 'Present' : 'None'}
                                        </span>
                                    </div>
                                </div>
                                
                                ${analysis.configuration.public_access_block ? `
                                    <div class="mt-4 pt-3 border-t border-gray-200">
                                        <h5 class="font-semibold text-gray-700 mb-3">Public Access Block Settings:</h5>
                                        <div class="flex flex-wrap gap-2">
                                            ${Object.entries(analysis.configuration.public_access_block).map(([key, value]) => `
                                                <div class="flex items-center">
                                                    <strong class="text-gray-700 mr-2">${key.replace(/([A-Z])/g, ' $1').trim()}:</strong>
                                                    <span class="px-3 py-1 rounded-full text-xs font-medium ${value ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}">
                                                        ${value ? 'Yes' : 'No'}
                                                    </span>
                                                </div>
                                            `).join('')}
                                        </div>
                                    </div>
                                ` : '<div class="mt-4 pt-3 border-t border-gray-200"><div class="flex items-center"><strong class="text-gray-700 mr-2">Public Access Block:</strong><span class="px-3 py-1 rounded-full text-xs font-medium bg-red-100 text-red-800">Not configured</span></div></div>'}
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Recommendations Section -->
                <div class="bg-blue-50 border-l-4 border-blue-400 rounded-lg p-4">
                    <div class="flex items-center mb-3">
                        <svg class="w-5 h-5 text-blue-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z"></path>
                        </svg>
                        <h4 class="font-semibold text-blue-800">Security Recommendations</h4>
                    </div>
                    <div class="space-y-2">
                        ${analysis.recommendations.map((rec, index) => `
                            <div class="flex items-start">
                                <span class="inline-flex items-center justify-center w-5 h-5 rounded-full bg-blue-100 text-blue-600 text-xs font-bold mr-3 mt-0.5">${index + 1}</span>
                                <span class="text-blue-700 text-sm">${rec}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
                
                <div class="text-xs text-gray-500 border-t pt-3 flex justify-between">
                    <span>Real-time AWS configuration analysis</span>
                    <span>Completed at ${new Date().toLocaleString()}</span>
                </div>
            </div>
        `;
        
    } catch (error) {
        modalContent.innerHTML = `
            <div class="space-y-4 text-left text-sm">
                <div class="bg-red-50 border-l-4 border-red-400 rounded-lg p-4">
                    <div class="flex items-center mb-3">
                        <svg class="w-5 h-5 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                        </svg>
                        <h4 class="font-semibold text-red-800">Analysis Failed</h4>
                    </div>
                    <p class="text-red-700 mb-3">${error.message}</p>
                    <div class="bg-red-100 rounded p-3">
                        <p class="text-red-800 font-medium text-sm mb-2">Possible causes:</p>
                        <ul class="list-disc list-inside text-red-700 text-sm space-y-1">
                            <li>Invalid or expired AWS credentials</li>
                            <li>Insufficient S3 permissions for the bucket</li>
                            <li>Bucket doesn't exist or is in a different region</li>
                            <li>Network connectivity issues</li>
                            <li>AWS service temporarily unavailable</li>
                        </ul>
                    </div>
                    <div class="mt-3 p-3 bg-yellow-50 border border-yellow-200 rounded">
                        <p class="text-yellow-800 text-sm"><strong>Required permissions:</strong></p>
                        <p class="text-yellow-700 text-xs mt-1">s3:GetPublicAccessBlock, s3:GetBucketPolicy, s3:GetEncryptionConfiguration, s3:GetBucketVersioning, s3:GetBucketLogging, s3:GetBucketAcl</p>
                    </div>
                </div>
            </div>
        `;
    }
};





// Funciones de placeholder para los botones de acción (se pueden implementar más adelante)
window.openS3BucketDetails = (bucketName, region) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    if (!modal) return;

    modalTitle.textContent = `S3 Bucket Details: ${bucketName}`;
    modalContent.innerHTML = `
        <div class="space-y-4 text-left text-sm">
            <div>
                <h4 class="font-semibold text-gray-800">Bucket Information</h4>
                <ul class="list-disc list-inside pl-2 mt-1 space-y-1">
                    <li><strong>Name:</strong> ${bucketName}</li>
                    <li><strong>Region:</strong> ${region}</li>
                    <li><strong>ARN:</strong> arn:aws:s3:::${bucketName}</li>
                    <li><strong>URL:</strong> https://${bucketName}.s3.amazonaws.com/</li>
                </ul>
            </div>
            <div class="bg-red-50 border border-red-200 rounded p-3">
                <h4 class="font-semibold text-red-800">Security Concerns</h4>
                <p class="text-red-700 text-sm mt-1">This bucket allows public access. Verify that this is intentional and that no sensitive data is exposed.</p>
            </div>
            <div>
                <h4 class="font-semibold text-gray-800">Recommended Actions</h4>
                <ul class="list-disc list-inside pl-2 mt-1 space-y-1 text-sm">
                    <li>Review bucket policy and ACLs</li>
                    <li>Enable Block Public Access if not needed</li>
                    <li>Implement least privilege access</li>
                    <li>Enable logging and monitoring</li>
                </ul>
            </div>
        </div>
    `;
    modal.classList.remove('hidden');
};

const renderLambdaCredentialsTable = (credentials) => {
    if (!credentials || credentials.length === 0) {
        return `<div class="bg-white p-6 rounded-xl border border-gray-100">
            <div class="text-center py-8">
                <svg class="mx-auto h-12 w-12 text-green-400" fill="none" stroke="currentColor" viewBox="0 0 48 48">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                </svg>
                <h3 class="mt-2 text-sm font-medium text-green-800">No Credential Issues Found</h3>
                <p class="mt-1 text-sm text-green-600">No hardcoded credentials or suspicious environment variables detected in Lambda functions.</p>
            </div>
        </div>`;
    }

    // Agrupar por severidad
    const critical = credentials.filter(c => c.severity === 'CRITICAL');
    const high = credentials.filter(c => c.severity === 'HIGH');
    const info = credentials.filter(c => c.severity === 'INFO');

    const getSeverityBadge = (severity) => {
        const colors = {
            'CRITICAL': 'bg-red-100 text-red-800 border-red-200',
            'HIGH': 'bg-orange-100 text-orange-800 border-orange-200', 
            'INFO': 'bg-blue-100 text-blue-800 border-blue-200'
        };
        return `<span class="px-3 py-1 text-xs font-bold rounded-full border ${colors[severity] || 'bg-gray-100 text-gray-800'}">${severity}</span>`;
    };

    let tableHtml = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <!-- Resumen de Severidades -->
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div class="bg-red-50 border border-red-200 rounded-lg p-4 text-center">
                    <div class="text-2xl font-bold text-red-700">${critical.length}</div>
                    <div class="text-sm text-red-600">Critical Issues</div>
                </div>
                <div class="bg-orange-50 border border-orange-200 rounded-lg p-4 text-center">
                    <div class="text-2xl font-bold text-orange-700">${high.length}</div>
                    <div class="text-sm text-orange-600">High Severity</div>
                </div>
                <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 text-center">
                    <div class="text-2xl font-bold text-blue-700">${info.length}</div>
                    <div class="text-sm text-blue-600">Info/Analysis</div>
                </div>
            </div>

            <!-- Tabla de Hallazgos -->
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Function Name</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Runtime</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Finding Type</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">
    `;

    // Ordenar por severidad (Critical primero)
    const sortedCredentials = [...credentials].sort((a, b) => {
        const severityOrder = { 'CRITICAL': 0, 'HIGH': 1, 'INFO': 2 };
        return severityOrder[a.severity] - severityOrder[b.severity];
    });

    sortedCredentials.forEach((cred, index) => {
        const rowClass = cred.severity === 'CRITICAL' ? 'bg-red-50' : 
                        cred.severity === 'HIGH' ? 'bg-orange-50' : 'bg-white';
        
        tableHtml += `
            <tr class="${rowClass} hover:bg-gray-50">
                <td class="px-4 py-4 whitespace-nowrap text-sm">${getSeverityBadge(cred.severity)}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${cred.region}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${cred.function_name}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${cred.runtime}</td>
                <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${cred.type}</td>
                <td class="px-4 py-4 text-sm text-gray-800 max-w-xs">
                    <div class="truncate" title="${cred.finding}">${cred.finding}</div>
                    ${cred.env_var_name ? `<div class="text-xs text-gray-500 mt-1">Env var: <code>${cred.env_var_name}</code></div>` : ''}
                    ${cred.sample_value ? `<div class="text-xs text-red-600 mt-1 font-mono">Sample: ${cred.sample_value}</div>` : ''}
                </td>
                <td class="px-4 py-4 whitespace-nowrap text-sm">
                    <button onclick="openLambdaCredentialDetails(${index})" 
                            class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">
                        View Details
                    </button>
                </td>
            </tr>
        `;
    });

    tableHtml += `
                    </tbody>
                </table>
            </div>
        </div>
    `;

    return tableHtml;
};

window.openLambdaCredentialDetails = (credentialIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    const credentials = window.exposureApiData.results.lambda_credentials;
    const cred = credentials[credentialIndex];

    if (!modal || !cred) return;

    modalTitle.textContent = `Lambda Credential Finding: ${cred.function_name}`;
    
    const severityColor = cred.severity === 'CRITICAL' ? 'red' : 
                         cred.severity === 'HIGH' ? 'orange' : 'blue';

    modalContent.innerHTML = `
        <div class="space-y-4 text-left text-sm">
            <div class="bg-${severityColor}-50 border border-${severityColor}-200 rounded-lg p-4">
                <div class="flex items-center">
                    <span class="px-3 py-1 text-xs font-bold rounded-full bg-${severityColor}-100 text-${severityColor}-800">${cred.severity}</span>
                    <span class="ml-3 font-semibold text-${severityColor}-800">${cred.type}</span>
                </div>
            </div>

            <div class="space-y-3">
                <div>
                    <h4 class="font-semibold text-gray-800">Function Information</h4>
                    <ul class="list-none space-y-1 mt-2">
                        <li><strong>Name:</strong> <code class="bg-gray-100 px-2 py-1 rounded text-sm">${cred.function_name}</code></li>
                        <li><strong>Region:</strong> ${cred.region}</li>
                        <li><strong>Runtime:</strong> ${cred.runtime}</li>
                        <li><strong>ARN:</strong> <code class="bg-gray-100 px-2 py-1 rounded text-xs break-all">${cred.function_arn}</code></li>
                    </ul>
                </div>

                <div>
                    <h4 class="font-semibold text-gray-800">Finding Details</h4>
                    <div class="bg-gray-50 p-3 rounded-md">
                        <p class="text-gray-800">${cred.finding}</p>
                        ${cred.env_var_name ? `
                            <div class="mt-2 pt-2 border-t border-gray-200">
                                <p><strong>Environment Variable:</strong> <code class="bg-yellow-100 px-2 py-1 rounded">${cred.env_var_name}</code></p>
                                ${cred.env_var_value ? `<p><strong>Value Preview:</strong> <code class="bg-red-100 px-2 py-1 rounded text-red-800">${cred.env_var_value}</code></p>` : ''}
                                ${cred.detected_pattern ? `<p><strong>Pattern Detected:</strong> ${cred.detected_pattern}</p>` : ''}
                            </div>
                        ` : ''}
                        ${cred.code_size ? `
                            <div class="mt-2 pt-2 border-t border-gray-200">
                                <p><strong>Code Size:</strong> ${cred.code_size} bytes</p>
                                <p class="text-xs text-gray-600">Function code is accessible for deeper analysis</p>
                            </div>
                        ` : ''}
                    </div>
                </div>

                <div class="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                    <h4 class="font-semibold text-yellow-800 mb-2">Recommended Actions</h4>
                    <ul class="list-disc list-inside text-yellow-700 text-sm space-y-1">
                        <li>Remove hardcoded credentials from environment variables</li>
                        <li>Use AWS Secrets Manager or Systems Manager Parameter Store</li>
                        <li>Implement least privilege IAM roles for Lambda execution</li>
                        <li>Enable AWS CloudTrail logging for function access monitoring</li>
                        <li>Consider rotating any exposed credentials immediately</li>
                        ${cred.type === 'Code Analysis Opportunity' ? '<li>Download and analyze function code for additional hardcoded secrets</li>' : ''}
                    </ul>
                </div>
            </div>
        </div>
    `;
    
    modal.classList.remove('hidden');
};


const renderApiMapDiagram = (api) => {
    if (!api) return '<p class="text-gray-500">No API data found.</p>';

    const integrations = api.integrations || [];
    const stages = api.stages || [];

    // --- Col 1: Stages ---
    let stagesHtml = '';
    if (stages.length > 0) {
        stages.forEach(stage => {
            stagesHtml += `
                <div class="bg-white border border-gray-200 rounded-lg p-3 shadow-sm">
                    <p class="font-semibold text-sm text-[#204071]">${stage}</p>
                </div>`;
        });
    } else {
        stagesHtml += `<div class="bg-white border border-gray-200 rounded-lg p-3 text-center text-xs text-gray-500">No stages</div>`;
    }

    // --- Col 2 & 3: Resources & Backends (vinculados) ---
    let resourcesHtml = '';
    let backendsHtml = '';
    
    if (integrations.length > 0) {
        // Ordenar para agrupar (opcional, pero más limpio)
        integrations.sort((a, b) => (a.path + a.method).localeCompare(b.path + b.method));
        
        integrations.forEach(integ => {
            const method = integ.method ? `<span class="px-2 py-0.5 text-xs font-semibold rounded-full ${integ.method === 'OPTIONS' ? 'bg-gray-100 text-gray-700' : 'bg-blue-100 text-blue-800'}">${integ.method}</span>` : '';
            const path = integ.path || 'N/A';
            
            // Col 2 Box
            resourcesHtml += `
                <div class="bg-white border border-gray-200 rounded-lg p-3 shadow-sm flex-grow">
                    <div class="flex justify-between items-center">
                        <p class="font-semibold text-sm text-[#204071] break-all">${path}</p>
                        ${method}
                    </div>
                    <p class="text-xs text-gray-500 mt-1">${integ.type || 'N/A'}</p>
                </div>`;

            // Col 3 Box
            let backendName = integ.uri || 'N/A';
            let icon = 'M14 2H6C4.9 2 4 2.9 4 4V20C4 21.1 4.9 22 6 22H18C19.1 22 20 21.1 20 20V8L14 2ZM18 20H6V4H13V9H18V20ZM12.94 13.06L10.88 15.12L8.7 12.94L7.29 14.35L10.88 17.94L14.35 14.47L12.94 13.06Z'; // Icono genérico
            
            if (integ.type === 'MOCK') {
                backendName = 'N/A';
            } else if (backendName.includes('lambda:path')) {
                backendName = backendName.split('/').pop();
            } else if (backendName.includes('arn:aws:apigateway:')) {
                backendName = backendName.split(':').pop().replace('integration', '');
            }

            backendsHtml += `
                <div class="bg-white border border-gray-200 rounded-lg p-3 shadow-sm flex-grow">
                    <p class="font-semibold text-sm ${integ.type === 'MOCK' ? 'text-gray-500' : 'text-green-700'} break-all">
                        <svg fill="currentColor" class="w-4 h-4 inline-block mr-1" viewBox="0 0 24 24"><path d="${icon}"></path></svg>
                        ${backendName}
                    </p>
                    <p class="text-xs text-gray-500">${integ.type}</p>
                </div>`;
        });
    } else {
        resourcesHtml += `<div class="bg-white border border-gray-200 rounded-lg p-3 text-center text-xs text-gray-500">No resources defined</div>`;
        backendsHtml += `<div class="bg-white border border-gray-200 rounded-lg p-3 text-center text-xs text-gray-500">No integrations</div>`;
    }

    // --- Ensamblar el HTML final con la nueva estructura ---
    return `
    <div class="flex items-stretch space-x-2 p-4 overflow-x-auto bg-gray-50 rounded-lg">
        
        <div class="flex flex-col flex-shrink-0 w-48">
            <h4 class="font-bold text-sm text-gray-700 mb-2 text-center">Stages (${stages.length})</h4>
            <div class="flex flex-col justify-center space-y-3 flex-grow">
                ${stagesHtml}
            </div>
        </div>
        
        <div class="flex flex-col justify-center flex-shrink-0">
            <div class="text-gray-400 text-2xl mx-2">⟶</div>
        </div>

        <div class="flex flex-col flex-shrink-0 w-64">
            <h4 class="font-bold text-sm text-gray-700 mb-2 text-center">Resources (${integrations.length})</h4>
            <div class="flex flex-col justify-center space-y-3 flex-grow">
                ${resourcesHtml}
            </div>
        </div>
        
        <div class="flex flex-col justify-center flex-shrink-0">
            <div class="text-gray-400 text-2xl mx-2">⟶</div>
        </div>

        <div class="flex flex-col flex-shrink-0 w-64">
            <h4 class="font-bold text-sm text-gray-700 mb-2 text-center">Integrations (${integrations.length})</h4>
            <div class="flex flex-col justify-center space-y-3 flex-grow">
                ${backendsHtml}
            </div>
        </div>

    </div>`;
};

/**
 * Abre el modal para mostrar el mapa de recursos de una API Gateway.
 */
window.openModalWithApiMap = (apiIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    const allApis = Object.values(window.exposureApiData.results.details['API Gateway Public'] || {}).flat().sort((a, b) => (a.region + a.name).localeCompare(b.region + b.name));
    const api = allApis[apiIndex];

    if (!modal || !api) {
        console.error("No se pudo encontrar el modal o los datos de la API.");
        return;
    }

    modalTitle.textContent = `Resource Map for: ${api.name}`;
    modalContent.innerHTML = renderApiMapDiagram(api);

    modal.classList.remove('hidden');
};
