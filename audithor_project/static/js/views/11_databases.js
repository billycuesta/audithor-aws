import { renderCollectionNotice, emptyCollectionMessage } from '../collection.js';
/**
 * 11_databases.js
 * Contains all logic for building and rendering the Databases view.
 */

// --- IMPORTS ---
import { handleTabClick, createStatusBadge } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
    rds: {
        title: "RDS Instances",
        description: "Amazon Relational Database Service (RDS) simplifies the setup, operation, and scaling of relational databases in the cloud. It manages the underlying infrastructure, including patching, backups, and scaling.",
        useCases: "Web and mobile applications, enterprise applications, e-commerce platforms, and general-purpose relational database workloads.",
        auditConsiderations: "Verify that instances are not publicly accessible and use private subnets. Ensure that storage is encrypted with KMS. Check for proper security group and network ACL configurations to restrict access. Review the use of IAM database authentication."
    },
    aurora: {
        title: "Aurora Clusters",
        description: "Amazon Aurora is a MySQL and PostgreSQL-compatible relational database built for the cloud, combining the performance of high-end commercial databases with the simplicity and cost-effectiveness of open-source databases.",
        useCases: "High-performance, mission-critical applications that require scalability and high availability, multi-tenant SaaS applications, and modern e-commerce platforms.",
        auditConsiderations: "Confirm that clusters are encrypted and configured for multi-AZ deployment. Review replication settings and ensure that the cluster endpoint is not exposed to public networks."
    },
    dynamodb: {
        title: "DynamoDB Tables",
        description: "Amazon DynamoDB is a fully managed, serverless NoSQL database service that provides single-digit millisecond performance at any scale. It supports both document and key-value data models.",
        useCases: "Mobile and web applications, gaming, ad tech, and IoT that require high-performance, low-latency data access at massive scale.",
        auditConsiderations: "Check that tables are encrypted with AWS KMS. Review IAM policies to ensure least-privilege access. Verify that access to the data is secured via fine-grained access control (FGAC) and that private endpoints are used."
    },
    docdb: {
        title: "DocumentDB Clusters",
        description: "Amazon DocumentDB is a fully managed document database service that supports MongoDB workloads. It's designed to be highly scalable, durable, and fully managed.",
        useCases: "Content management, user profiles, and catalog data that requires a flexible, JSON-based document model.",
        auditConsiderations: "Ensure that clusters are encrypted at rest and in transit. Verify that network access is properly restricted and that audit logging is enabled to track access to the database."
    }
};

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildDatabasesView = () => {
    const container = document.getElementById('databases-view');
    if (!container || !window.databasesApiData) return;

    const { rds_instances = [], aurora_clusters = [], dynamodb_tables = [], documentdb_clusters = [] } =
        window.databasesApiData.results || {};
    
    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Databases</h2>
                <p class="text-sm text-gray-500">${window.databasesApiData.metadata.executionDate}</p>
            </div>
        </header>

        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review database configurations to ensure data integrity, availability, and confidentiality. Each tab provides specific audit considerations for that database service type.</p>
        </div>

        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="databases-tabs">
                <a href="#" data-tab="db-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="db-rds-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">RDS Instances (${rds_instances.length})</a>
                <a href="#" data-tab="db-aurora-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Aurora Clusters (${aurora_clusters.length})</a>
                <a href="#" data-tab="db-dynamodb-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">DynamoDB Tables (${dynamodb_tables.length})</a>
                <a href="#" data-tab="db-docdb-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">DocumentDB (${documentdb_clusters.length})</a>
            </nav>
        </div>

        <div id="databases-tab-content-container">
            <div id="db-summary-content" class="databases-tab-content">
                ${createDatabasesSummaryCardsHtml()}
            </div>

            <div id="db-rds-content" class="databases-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.rds)}
                ${renderRdsTable(rds_instances)}
            </div>

            <div id="db-aurora-content" class="databases-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.aurora)}
                ${renderAuroraTable(aurora_clusters)}
            </div>

            <div id="db-dynamodb-content" class="databases-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.dynamodb)}
                ${renderDynamoDbTable(dynamodb_tables)}
            </div>

            <div id="db-docdb-content" class="databases-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.docdb)}
                ${renderDocumentDbTable(documentdb_clusters)}
            </div>
        </div>
    `;
    renderCollectionNotice(container, window.databasesApiData);
    
    updateDatabasesSummaryCards(rds_instances, aurora_clusters, dynamodb_tables, documentdb_clusters);
    
    const tabsNav = container.querySelector('#databases-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.databases-tab-content'));
};

// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const createDatabasesSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">RDS Instances (Standalone)</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="db-total-rds" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-blue-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-database w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg>
                </div>
            </div>
        </div>

        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Aurora Clusters</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="db-total-aurora" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-green-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-database w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg>
                </div>
            </div>
        </div>

        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">DynamoDB Tables</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="db-total-dynamodb" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-purple-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-database w-6 h-6 text-purple-600" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg>
                </div>
            </div>
        </div>

        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">DocumentDB Clusters</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="db-total-docdb" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-teal-100 p-3 rounded-full">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-file-earmark-code w-6 h-6 text-teal-600" viewBox="0 0 16 16"><path d="M14 4.5V14a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V2a2 2 0 0 1 2-2h5.5zm-3 0A1.5 1.5 0 0 1 9.5 3V1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V4.5z"/><path d="M8.646 6.646a.5.5 0 0 1 .708 0l2 2a.5.5 0 0 1 0 .708l-2 2a.5.5 0 0 1-.708-.708L10.293 8 8.646 6.354a.5.5 0 0 1 0-.708m-1.292 0a.5.5 0 0 0-.708 0l-2 2a.5.5 0 0 0 0 .708l2 2a.5.5 0 0 0 .708-.708L5.707 8l1.647-1.646a.5.5 0 0 0 0-.708"/></svg>
                </div>
            </div>
        </div>
    </div>
`;

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

const createEncryptionBadge = (isEncrypted) => {
    if (isEncrypted == null) return `<span class="text-gray-500">UNKNOWN</span>`;
    return isEncrypted
        ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">YES</span>`
        : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">NO</span>`;
};

const updateDatabasesSummaryCards = (rds, aurora, dynamodb, docdb) => {
    document.getElementById('db-total-rds').textContent = rds.length;
    document.getElementById('db-total-aurora').textContent = aurora.length;
    document.getElementById('db-total-dynamodb').textContent = dynamodb.length;
    document.getElementById('db-total-docdb').textContent = docdb.length;
};

// ===== RDS =====
const renderRdsTable = (instances) => {
    if (!instances || instances.length === 0)
        return `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">${emptyCollectionMessage(window.databasesApiData, "No standalone RDS instances were found.")}</p></div>`;
    
    let table = `
      <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Motor</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public Access</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encrypted</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">KMS Key Alias/ID</th>
              <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>
            </tr>
          </thead>
          <tbody class="bg-white divide-y divide-gray-200">`;
    
    instances.forEach(i => {
        const region = i.Region ?? 'Unknown';
        const identifier = i.DBInstanceIdentifier ?? 'Unknown';
        const engine = i.Engine ?? 'Unknown';
        const status = i.DBInstanceStatus ?? 'Unknown';
        const kmsKeyAlias = i.KmsKeyAlias ?? 'Unknown';
        const arn = i.ARN ?? '';
        const publicBadge = i.PubliclyAccessible
            ? `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">YES</span>`
            : `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">NO</span>`;

        const scopeDetails = window.scopedResources[arn];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16">
                 <path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/>
                 <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/>
               </svg>`
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16">
                 <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/>
               </svg>`;

        const scopeButton = `<button onclick="openScopeModal('${arn}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;

        table += `
          <tr class="${rowClass}">
            <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${region}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${identifier}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${engine}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(status)}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">${publicBadge}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">${createEncryptionBadge(i.Encrypted)}</td>
            <td class="px-4 py-4 text-sm text-gray-600 font-mono break-all">${kmsKeyAlias}</td>
            <td class="px-4 py-4 text-center">
              <button onclick="copyToClipboard(this, '${arn}')" title="${arn}" class="p-1 rounded-md hover:bg-gray-200 transition">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
              </button>
            </td>
          </tr>`;
    });
    table += `</tbody></table></div>`;
    return table;
};

// ===== AURORA =====
const renderAuroraTable = (clusters) => {
    if (!clusters || clusters.length === 0)
        return `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">${emptyCollectionMessage(window.databasesApiData, "No Aurora clusters were found.")}</p></div>`;
    
    let table = `
      <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encrypted</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">KMS Key Alias/ID</th>
              <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>
            </tr>
          </thead>
          <tbody class="bg-white divide-y divide-gray-200">`;

    clusters.forEach(c => {
        const region = c.Region ?? 'Unknown';
        const identifier = c.ClusterIdentifier ?? 'Unknown';
        const status = c.Status ?? 'Unknown';
        const kmsKeyAlias = c.KmsKeyAlias ?? 'Unknown';
        const arn = c.ARN ?? '';
        const scopeDetails = window.scopedResources[arn];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16">
                 <path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/>
                 <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/>
               </svg>`
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16">
                 <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/>
               </svg>`;

        const scopeButton = `<button onclick="openScopeModal('${arn}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;

        table += `
          <tr class="${rowClass}">
            <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${region}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${identifier}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(status)}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">${createEncryptionBadge(c.Encrypted)}</td>
            <td class="px-4 py-4 text-sm text-gray-600 font-mono break-all">${kmsKeyAlias}</td>
            <td class="px-4 py-4 text-center">
              <button onclick="copyToClipboard(this, '${arn}')" title="${arn}" class="p-1 rounded-md hover:bg-gray-200 transition">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
              </button>
            </td>
          </tr>`;
    });

    table += `</tbody></table></div>`;
    return table;
};

// ===== DYNAMODB =====
const renderDynamoDbTable = (tables) => {
    if (!tables || tables.length === 0)
        return `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">${emptyCollectionMessage(window.databasesApiData, "No DynamoDB tables were found.")}</p></div>`;
    
    let table = `
      <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Table Name</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encrypted</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">KMS Key Alias/Type</th>
              <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>
            </tr>
          </thead>
          <tbody class="bg-white divide-y divide-gray-200">`;

    tables.forEach(t => {
        const scopeKey = t.ARN || `dynamodb:${t.Region}:${t.TableName}`;
        const scopeDetails = window.scopedResources[scopeKey];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16">
                 <path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/>
                 <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/>
               </svg>`
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16">
                 <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/>
               </svg>`;

        const scopeButton = `<button onclick="openScopeModal('${scopeKey}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;

        table += `
          <tr class="${rowClass}">
            <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${t.Region}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${t.TableName}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">${createEncryptionBadge(t.Encrypted)}</td>
            <td class="px-4 py-4 text-sm text-gray-600 font-mono break-all">${t.KmsKeyAlias ?? "Unknown"}</td>
            <td class="px-4 py-4 text-center">
              <button ${t.ARN ? `onclick="copyToClipboard(this, '${t.ARN}')" title="${t.ARN}"` : 'disabled title="ARN is unavailable"'} class="p-1 rounded-md hover:bg-gray-200 transition">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
              </button>
            </td>
          </tr>`;
    });

    table += `</tbody></table></div>`;
    return table;
};

// ===== DOCUMENTDB =====
const renderDocumentDbTable = (clusters) => {
    if (!clusters || clusters.length === 0)
        return `<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">${emptyCollectionMessage(window.databasesApiData, "No DocumentDB clusters were found.")}</p></div>`;
    
    let table = `
      <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200">
          <thead class="bg-gray-50">
            <tr>
              <th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Encrypted</th>
              <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">KMS Key Alias/ID</th>
              <th class="px-4 py-3 text-center text-xs font-medium text-gray-500 uppercase">ARN</th>
            </tr>
          </thead>
          <tbody class="bg-white divide-y divide-gray-200">`;

    clusters.forEach(c => {
        const region = c.Region ?? 'Unknown';
        const identifier = c.ClusterIdentifier ?? 'Unknown';
        const status = c.Status ?? 'Unknown';
        const kmsKeyAlias = c.KmsKeyAlias ?? 'Unknown';
        const arn = c.ARN ?? '';
        const scopeDetails = window.scopedResources[arn];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16">
                 <path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/>
                 <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/>
               </svg>`
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16">
                 <path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/>
               </svg>`;

        const scopeButton = `<button onclick="openScopeModal('${arn}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;

        table += `
          <tr class="${rowClass}">
            <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${region}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${identifier}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">${createStatusBadge(status)}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">${createEncryptionBadge(c.Encrypted)}</td>
            <td class="px-4 py-4 text-sm text-gray-600 font-mono break-all">${kmsKeyAlias}</td>
            <td class="px-4 py-4 text-center">
              <button onclick="copyToClipboard(this, '${arn}')" title="${arn}" class="p-1 rounded-md hover:bg-gray-200 transition">
                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-clipboard w-5 h-5 text-gray-500" viewBox="0 0 16 16"><path d="M4 1.5H3a2 2 0 0 0-2 2V14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V3.5a2 2 0 0 0-2-2h-1v1h1a1 1 0 0 1 1 1V14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V3.5a1 1 0 0 1 1-1h1z"/><path d="M9.5 1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-3a.5.5 0 0 1-.5-.5v-1a.5.5 0 0 1 .5-.5zm-3-1A1.5 1.5 0 0 0 5 1.5v1A1.5 1.5 0 0 0 6.5 4h3A1.5 1.5 0 0 0 11 2.5v-1A1.5 1.5 0 0 0 9.5 0z"/></svg>
              </button>
            </td>
          </tr>`;
    });

    table += `</tbody></table></div>`;
    return table;
};
