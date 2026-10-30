import { renderCollectionNotice, emptyCollectionMessage, coverageIsComplete } from '../collection.js';
/**
 * 09_acm.js
 * Contains all logic for building and rendering the AWS Certificate Manager (ACM) view.
 */

// --- IMPORTS ---
import { handleTabClick, renderSecurityHubFindings } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
    certificates: {
        title: "Digital Certificates",
        description: "ACM provisions, manages, and deploys SSL/TLS certificates for use with AWS services. These certificates encrypt data in transit between clients and your applications.",
        useCases: "HTTPS encryption for web applications, API Gateway SSL termination, CloudFront distributions, Application Load Balancers, secure email communications.",
        auditConsiderations: "Verify certificate validity periods, ensure proper domain validation, check for expired or soon-to-expire certificates, validate certificate chain integrity, and confirm encryption strength meets organizational requirements."
    },
    validation: {
        title: "Certificate Validation",
        description: "ACM validates domain ownership through DNS or email validation before issuing certificates. This process ensures that only authorized parties can obtain certificates for specific domains.",
        useCases: "Domain ownership verification, automated certificate renewal, compliance with Certificate Authority Browser Forum requirements.",
        auditConsiderations: "Review validation methods used, ensure DNS records are properly configured, verify that validation emails are sent to authorized addresses, and check for any failed validation attempts."
    },
    lifecycle: {
        title: "Certificate Lifecycle Management",
        description: "ACM automatically handles certificate renewal for certificates that are in use by integrated AWS services, reducing the risk of service outages due to expired certificates.",
        useCases: "Automated renewal processes, certificate deployment across multiple services, centralized certificate management, compliance reporting.",
        auditConsiderations: "Monitor certificate expiration dates, verify automatic renewal is functioning, ensure proper integration with AWS services, and maintain inventory of all certificates including their usage."
    }
};

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildAcmView = () => {
    const container = document.getElementById('acm-view');
    if (!container || !window.acmApiData) return;

    
    const activeTabEl = container.querySelector('#acm-tabs .border-\\[\\#eb3496\\]');
    const activeTabData = activeTabEl ? activeTabEl.dataset.tab : 'acm-summary-content';
    const { certificates } = window.acmApiData.results;
    const acmSecurityHubFindings = (window.securityHubApiData?.results?.findings?.cloudwatchFindings || []).filter(f => f.Title.includes('Certificate') || f.Title.includes('SSL') || f.Title.includes('TLS'));

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">AWS Certificate Manager (ACM)</h2>
                <p class="text-sm text-gray-500">${window.acmApiData.metadata.executionDate}</p>
            </div>
        </header>
        
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review SSL/TLS certificate management to ensure proper encryption, validate certificate lifecycles, and verify compliance with security policies. Focus on certificate expiration monitoring, validation methods, and integration with AWS services.</p>
        </div>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="acm-tabs">
                <a href="#" data-tab="acm-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="acm-certificates-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Digital Certificates (${certificates.length})</a>
                <a href="#" data-tab="acm-lifecycle-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Certificate Management</a>
                <a href="#" data-tab="acm-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${acmSecurityHubFindings.length})</a>
            </nav>
        </div>
        <div id="acm-tab-content-container">
            <div id="acm-summary-content" class="acm-tab-content">${createAcmSummaryCardsHtml()}</div>
            <div id="acm-certificates-content" class="acm-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.certificates)}
                ${renderAcmCertificatesTable(certificates)}
            </div>
            <div id="acm-lifecycle-content" class="acm-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.lifecycle)}
                ${renderCertificateLifecycleAnalysis(certificates)}
            </div>
            <div id="acm-sh-content" class="acm-tab-content hidden">${createAcmSecurityHubHtml()}</div>
        </div>
    `;
    renderCollectionNotice(container, window.acmApiData);
    
    updateAcmSummaryCards(certificates, acmSecurityHubFindings);
    renderSecurityHubFindings(acmSecurityHubFindings, 'sh-acm-findings-container', window.securityHubApiData ? 'No Security Hub findings related to ACM were found.' : 'Security Hub data unavailable; related findings could not be assessed.');

    // Si no es la pestaña por defecto, cambiar la vista activa
    if (activeTabData !== 'acm-summary-content') {
        // Quitar el estado activo de la pestaña "Summary" por defecto
        const defaultActiveLink = container.querySelector('#acm-tabs a[data-tab="acm-summary-content"]');
        const defaultActiveContent = document.getElementById('acm-summary-content');
        if (defaultActiveLink && defaultActiveContent) {
            defaultActiveLink.classList.remove('border-[#eb3496]', 'text-[#eb3496]');
            defaultActiveLink.classList.add('border-transparent', 'text-gray-500');
            defaultActiveContent.classList.add('hidden');
        }

        // Activar la pestaña correcta
        const newActiveLink = container.querySelector(`#acm-tabs a[data-tab="${activeTabData}"]`);
        const newActiveContent = document.getElementById(activeTabData);
        if (newActiveLink && newActiveContent) {
            newActiveLink.classList.add('border-[#eb3496]', 'text-[#eb3496]');
            newActiveLink.classList.remove('border-transparent', 'text-gray-500');
            newActiveContent.classList.remove('hidden');
        }
    }


    const tabsNav = container.querySelector('#acm-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.acm-tab-content'));
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

// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const createAcmSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Total Certificates</p></div><div class="flex justify-between items-end pt-4"><p id="acm-total-certs" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-card-heading w-6 h-6 text-blue-600" viewBox="0 0 16 16">  <path d="M14.5 3a.5.5 0 0 1 .5.5v9a.5.5 0 0 1-.5.5h-13a.5.5 0 0 1-.5-.5v-9a.5.5 0 0 1 .5-.5zm-13-1A1.5 1.5 0 0 0 0 3.5v9A1.5 1.5 0 0 0 1.5 14h13a1.5 1.5 0 0 0 1.5-1.5v-9A1.5 1.5 0 0 0 14.5 2z"/>  <path d="M3 8.5a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 0 1h-9a.5.5 0 0 1-.5-.5m0 2a.5.5 0 0 1 .5-.5h6a.5.5 0 0 1 0 1h-6a.5.5 0 0 1-.5-.5m0-5a.5.5 0 0 1 .5-.5h9a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-9a.5.5 0 0 1-.5-.5z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Issued Certificates</p></div><div class="flex justify-between items-end pt-4"><p id="acm-issued-certs" class="text-3xl font-bold text-green-600">--</p><div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-patch-check w-6 h-6 text-green-600" viewBox="0 0 16 16"><path fill-rule="evenodd" d="M10.354 6.146a.5.5 0 0 1 0 .708l-3 3a.5.5 0 0 1-.708 0l-1.5-1.5a.5.5 0 1 1 .708-.708L7 8.793l2.646-2.647a.5.5 0 0 1 .708 0z"/><path d="m10.273 2.513-.921-.944.715-.698.622.637.89-.011a2.89 2.89 0 0 1 2.924 2.924l-.01.89.636.622a2.89 2.89 0 0 1 0 4.134l-.637.622.011.89a2.89 2.89 0 0 1-2.924 2.924l-.89-.01-.622.636a2.89 2.89 0 0 1-4.134 0l-.622-.637-.89.01a2.89 2.89 0 0 1-2.924-2.924l.01-.89-.636-.622a2.89 2.89 0 0 1 0-4.134l.637-.622-.011-.89a2.89 2.89 0 0 1 2.924-2.924l.89.01.622-.636a2.89 2.89 0 0 1 4.134 0l-.715.698a1.89 1.89 0 0 0-2.704 0l-.92.944-1.32-.016a1.89 1.89 0 0 0-1.911 1.912l.016 1.318-.944.921a1.89 1.89 0 0 0 0 2.704l.944.92-.016 1.32a1.89 1.89 0 0 0 1.912 1.911l1.318-.016.921.944a1.89 1.89 0 0 0 2.704 0l.92-.944 1.32.016a1.89 1.89 0 0 0 1.911-1.912l-.016-1.318.944-.921a1.89 1.89 0 0 0 0-2.704l-.944-.92.016-1.32a1.89 1.89 0 0 0-1.912-1.911z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Pending Certificates</p></div><div class="flex justify-between items-end pt-4"><p id="acm-pending-certs" class="text-3xl font-bold text-yellow-600">--</p><div class="bg-yellow-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clock w-6 h-6 text-yellow-600" viewBox="0 0 16 16"><path d="M8 3.5a.5.5 0 0 0-1 0V9a.5.5 0 0 0 .252.434l3.5 2a.5.5 0 0 0 .496-.868L8 8.71z"/><path d="M8 16A8 8 0 1 0 8 0a8 8 0 0 0 0 16m7-8A7 7 0 1 1 1 8a7 7 0 0 1 14 0"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Expired/Revoked</p></div><div class="flex justify-between items-end pt-4"><p id="acm-expired-revoked-certs" class="text-3xl font-bold text-red-600">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-triangle w-6 h-6 text-red-600" viewBox="0 0 16 16"> <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1-.054-.06.18.18 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/> <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Findings (Crit/High)</p></div><div class="flex justify-between items-end pt-4"><p id="acm-critical-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"> <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/></svg></div></div></div>
    </div>`;

const updateAcmSummaryCards = (certificates, securityHubFindings) => {
    document.getElementById('acm-total-certs').textContent = certificates.length;
    document.getElementById('acm-issued-certs').textContent = certificates.filter(c => c.Status === 'ISSUED').length;
    document.getElementById('acm-pending-certs').textContent = certificates.filter(c => c.Status === 'PENDING_VALIDATION').length;
    document.getElementById('acm-expired-revoked-certs').textContent = certificates.filter(c => c.Status === 'EXPIRED' || c.Status === 'REVOKED').length;
    document.getElementById('acm-critical-findings').textContent = securityHubFindings.filter(f => f.Severity?.Label === 'CRITICAL' || f.Severity?.Label === 'HIGH').length;
};

const createAcmSecurityHubHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (ACM via SH)</h3><div id="sh-acm-findings-container" class="overflow-x-auto"></div></div>`;

const renderAcmCertificatesTable = (certificates) => {
    if (!certificates || certificates.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">${emptyCollectionMessage(window.acmApiData, "No ACM certificates found")}</h3>
                    <p class="mt-1 text-sm text-gray-500">${coverageIsComplete(window.acmApiData) ? 'This account does not have SSL/TLS certificates managed through ACM, which may indicate manual certificate management or use of third-party providers.' : 'Review the collection details above to see which checks failed.'}</p>
                </div>
            </div>
        `;
    }

    const statusColors = {
        'ISSUED': 'bg-green-100 text-green-800',
        'PENDING_VALIDATION': 'bg-yellow-100 text-yellow-800',
        'EXPIRED': 'bg-red-100 text-red-800',
        'REVOKED': 'bg-red-100 text-red-800',
        'INACTIVE': 'bg-gray-100 text-gray-800',
        'VALIDATION_TIMED_OUT': 'bg-red-100 text-red-800',
        'FAILED': 'bg-red-100 text-red-800',
    };

    let tableHtml = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                    '<th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Main Domain</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Issued By</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Issue Date</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Expiration Date</th>' +
                    '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">SANs</th>' +
                    '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    certificates.forEach(cert => {
        const domainName = cert.DomainName || 'N/A';
        const region = cert.Region || 'N/A';
        const status = cert.Status || 'N/A';
        const statusClass = statusColors[status] || 'bg-gray-100 text-gray-800';
        const issuer = cert.Issuer || 'N/A';
        const issuedAt = cert.IssuedAt ? new Date(cert.IssuedAt).toLocaleDateString() : 'N/A';
        const expiresAt = cert.NotAfter ? new Date(cert.NotAfter).toLocaleDateString() : 'N/A';
        const sans = cert.SubjectAlternativeNames && cert.SubjectAlternativeNames.length > 0 ? cert.SubjectAlternativeNames.join(', ') : '-';
        const certArn = cert.CertificateArn || `arn:aws:acm:${region}:certificate/${domainName}`;
        const scopeDetails = window.scopedResources[certArn];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped 
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16"><path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>` 
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>`;
        const scopeButton = `<button onclick="openScopeModal('${certArn}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;

        tableHtml += `<tr class="${rowClass}">
                        <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
                        <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${domainName}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${region}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap"><span class="px-2.5 py-0.5 text-xs font-semibold rounded-full ${statusClass}">${status}</span></td>
                        <td class="px-4 py-4 align-top text-sm text-gray-600 break-words">${issuer}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${issuedAt}</td>
                        <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${expiresAt}</td>
                        <td class="px-4 py-4 align-top text-sm text-gray-600 break-words">${sans}</td>
                      </tr>`;
    });

    
    tableHtml += '</tbody></table></div>';
    return tableHtml;
};

const renderCertificateLifecycleAnalysis = (certificates) => {
    // Calculate certificate expiration analysis
    const now = new Date();
    const thirtyDaysFromNow = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
    const ninetyDaysFromNow = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000);

    let expiringSoon = 0;
    let expiringIn90Days = 0;
    let validCertificates = 0;
    let autoRenewalEnabled = 0;

    certificates.forEach(cert => {
        if (cert.Status === 'ISSUED' && cert.NotAfter) {
            const expirationDate = new Date(cert.NotAfter);
            validCertificates++;
            
            if (expirationDate <= thirtyDaysFromNow) {
                expiringSoon++;
            } else if (expirationDate <= ninetyDaysFromNow) {
                expiringIn90Days++;
            }
            
            // ACM certificates in use by AWS services are auto-renewed
            if (cert.InUseBy && cert.InUseBy.length > 0) {
                autoRenewalEnabled++;
            }
        }
    });

    return `
        <div class="space-y-6">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 bg-blue-100 rounded-full flex items-center justify-center">
                                <svg class="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                            </div>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-gray-500">Valid Certificates</p>
                            <p class="text-2xl font-semibold text-gray-900">${validCertificates}</p>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 bg-green-100 rounded-full flex items-center justify-center">
                                <svg class="w-4 h-4 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                                </svg>
                            </div>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-gray-500">Auto-Renewal Enabled</p>
                            <p class="text-2xl font-semibold text-gray-900">${autoRenewalEnabled}</p>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 bg-yellow-100 rounded-full flex items-center justify-center">
                                <svg class="w-4 h-4 text-yellow-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                                </svg>
                            </div>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-gray-500">Expiring in 90 Days</p>
                            <p class="text-2xl font-semibold text-gray-900">${expiringIn90Days}</p>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white border border-gray-200 rounded-lg p-4">
                    <div class="flex items-center">
                        <div class="flex-shrink-0">
                            <div class="w-8 h-8 bg-red-100 rounded-full flex items-center justify-center">
                                <svg class="w-4 h-4 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                            </div>
                        </div>
                        <div class="ml-3">
                            <p class="text-sm font-medium text-gray-500">Expiring Soon (30d)</p>
                            <p class="text-2xl font-semibold text-gray-900">${expiringSoon}</p>
                        </div>
                    </div>
                </div>
            </div>
            
            ${renderLifecycleRecommendations(certificates, expiringSoon, expiringIn90Days, autoRenewalEnabled)}
        </div>
    `;
};

const renderLifecycleRecommendations = (certificates, expiringSoon, expiringIn90Days, autoRenewalEnabled) => {
    const recommendations = [];
    
    if (expiringSoon > 0) {
        recommendations.push({
            type: 'critical',
            title: 'Certificates Expiring Soon',
            message: `${expiringSoon} certificate(s) will expire within 30 days. Immediate action required to prevent service disruption.`,
            action: 'Review expiring certificates and ensure renewal or replacement is scheduled.'
        });
    }
    
    if (expiringIn90Days > 0) {
        recommendations.push({
            type: 'warning',
            title: 'Certificates Expiring in 90 Days',
            message: `${expiringIn90Days} certificate(s) will expire within 90 days. Plan renewal activities.`,
            action: 'Schedule certificate renewal and validation processes in advance.'
        });
    }
    
    const manualCertificates = certificates.filter(cert => 
        cert.Status === 'ISSUED' && (!cert.InUseBy || cert.InUseBy.length === 0)
    ).length;
    
    if (manualCertificates > 0) {
        recommendations.push({
            type: 'info',
            title: 'Manual Renewal Required',
            message: `${manualCertificates} certificate(s) require manual renewal as they are not integrated with AWS services.`,
            action: 'Consider integrating certificates with AWS services for automatic renewal or establish manual renewal procedures.'
        });
    }
    
    const pendingCertificates = certificates.filter(cert => cert.Status === 'PENDING_VALIDATION').length;
    if (pendingCertificates > 0) {
        recommendations.push({
            type: 'warning',
            title: 'Pending Certificate Validation',
            message: `${pendingCertificates} certificate(s) are pending validation and may time out.`,
            action: 'Complete domain validation process by responding to validation emails or configuring DNS records.'
        });
    }
    
    if (!coverageIsComplete(window.acmApiData)) {
        recommendations.push({type: 'warning', title: 'Assessment incomplete',
            message: 'Failed or unverified checks prevent a complete certificate assessment.',
            action: 'Review collection diagnostics and repeat the affected checks.'});
    }
    if (recommendations.length === 0) {
        recommendations.push({
            type: 'success',
            title: 'Certificate Management Healthy',
            message: 'All certificates are properly managed with no immediate concerns.',
            action: 'Continue monitoring certificate expiration dates and maintain current practices.'
        });
    }
    
    const typeColors = {
        critical: 'border-red-200 bg-red-50',
        warning: 'border-yellow-200 bg-yellow-50',
        info: 'border-blue-200 bg-blue-50',
        success: 'border-green-200 bg-green-50'
    };
    
    const typeTextColors = {
        critical: 'text-red-800',
        warning: 'text-yellow-800',
        info: 'text-blue-800',
        success: 'text-green-800'
    };
    
    const typeIcons = {
        critical: '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7 4a1 1 0 11-2 0 1 1 0 012 0zm-1-9a1 1 0 00-1 1v4a1 1 0 102 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>',
        warning: '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clip-rule="evenodd"></path></svg>',
        info: '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clip-rule="evenodd"></path></svg>',
        success: '<svg class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path></svg>'
    };
    
    return `
        <div class="bg-white border border-gray-200 rounded-lg p-6">
            <h3 class="text-lg font-semibold text-gray-800 mb-4">Certificate Lifecycle Recommendations</h3>
            <div class="space-y-4">
                ${recommendations.map(rec => `
                    <div class="border rounded-lg p-4 ${typeColors[rec.type]}">
                        <div class="flex items-start">
                            <div class="flex-shrink-0 ${typeTextColors[rec.type]} mt-0.5">
                                ${typeIcons[rec.type]}
                            </div>
                            <div class="ml-3 flex-1">
                                <h4 class="text-sm font-medium ${typeTextColors[rec.type]}">${rec.title}</h4>
                                <p class="text-sm ${typeTextColors[rec.type]} mt-1">${rec.message}</p>
                                <p class="text-sm ${typeTextColors[rec.type]} mt-2 font-medium">Recommended Action: ${rec.action}</p>
                            </div>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `;
};