/**
 * 12_kms_secrets.js
 * Contains all logic for building and rendering the KMS & Secrets Manager view.
 */

// --- IMPORTS ---
import { handleTabClick, createStatusBadge } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
  overview: {
    title: "AWS KMS & Secrets Manager",
    description: "AWS KMS provides centralized key management for encryption keys, while Secrets Manager helps you protect secrets needed to access your applications, services, and IT resources.",
    useCases: "Data encryption, secret rotation, database credentials management, API keys storage, certificate management, compliance with regulatory requirements.",
    auditConsiderations: "Review key policies and secret access permissions, verify automatic rotation is enabled, ensure proper separation of duties, validate that sensitive workloads use customer-managed keys and secrets."
  },
  kmsOverview: {
    title: "AWS Key Management Service (KMS)",
    description: "AWS KMS is a managed service that makes it easy to create and control cryptographic keys used to encrypt your data. It provides centralized key management integrated with other AWS services.",
    useCases: "Data encryption at rest and in transit, database encryption, S3 bucket encryption, EBS volume encryption, application-level encryption, compliance with regulatory requirements.",
    auditConsiderations: "Review key policies for least privilege access, verify automatic key rotation is enabled for customer-managed keys, ensure proper separation of duties for key administration, validate that sensitive workloads use customer-managed keys instead of AWS-managed keys."
  },
  secretsOverview: {
    title: "AWS Secrets Manager",
    description: "AWS Secrets Manager helps you protect secrets needed to access your applications, services, and IT resources. It enables you to easily rotate, manage, and retrieve database credentials, API keys, and other secrets throughout their lifecycle.",
    useCases: "Database credential management, API key storage, third-party service credentials, automatic credential rotation, cross-region secret replication, application secret injection.",
    auditConsiderations: "Ensure automatic rotation is enabled for database credentials, review resource policies for least privilege access, verify secrets are encrypted with appropriate KMS keys, validate that secrets have proper tagging and documentation."
  },
  customerManagedKeys: {
    title: "Customer Managed Keys (CMK)",
    description: "Customer Managed Keys are KMS keys that you create, own, and manage. You have full control over these keys including key policies, rotation, and deletion.",
    useCases: "High-security environments requiring full control, compliance requirements mandating customer key ownership, cross-account access scenarios, custom key rotation policies.",
    auditConsiderations: "Verify that sensitive data uses CMKs instead of AWS-managed keys, ensure key rotation is enabled and appropriate, review key policies for overly permissive access, validate key usage logging in CloudTrail."
  },
  keyRotation: {
    title: "Key Rotation & Secret Rotation",
    description: "Regular rotation of cryptographic keys and secrets is a security best practice that reduces the risk of credential compromise and meets compliance requirements.",
    useCases: "Compliance requirements for regular rotation, reducing cryptographic risk over time, maintaining security best practices for long-lived credentials.",
    auditConsiderations: "Verify automatic rotation is enabled for all customer-managed keys and secrets unless there's a valid business reason, review rotation schedules align with compliance requirements, ensure applications can handle rotation transparently."
  }
};

// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildKmsSecretsView = () => {
  const container = document.getElementById('kms-secrets-view');
  if (!container) return;

  // ensure globals exist
  window.scopedResources = window.scopedResources || {};

  const activeTabEl = container.querySelector('#kms-secrets-tabs .border-\\[\\#eb3496\\]');
  const activeTabData = activeTabEl ? activeTabEl.dataset.tab : 'kms-secrets-summary-content';
  const hasKmsData = window.kmsApiData && window.kmsApiData.results;
  const hasSecretsData = window.secretsManagerApiData && window.secretsManagerApiData.results;

  if (!hasKmsData && !hasSecretsData) {
    container.innerHTML = createEmptyState();
    return;
  }

  const kmsKeys = hasKmsData ? window.kmsApiData.results.keys || [] : [];
  const secrets = hasSecretsData ? window.secretsManagerApiData.results.secrets || [] : [];
  const executionDate = hasKmsData
    ? window.kmsApiData.metadata.executionDate
    : hasSecretsData
    ? window.secretsManagerApiData.metadata.executionDate
    : 'N/A';

  // Separate keys by type for tab counts
  const customerManagedKeys = kmsKeys.filter(k => k.KeyManager === 'CUSTOMER');
  const awsManagedKeys = kmsKeys.filter(k => k.KeyManager === 'AWS');

  container.innerHTML = `
    <header class="flex justify-between items-center mb-6">
      <div>
        <h2 class="text-2xl font-bold text-[#204071]">KMS & Secrets Manager</h2>
        <p class="text-sm text-gray-500">${executionDate}</p>
      </div>
    </header>
    
    <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
      <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
      <p class="text-sm text-blue-700">Review KMS key management and Secrets Manager configuration to ensure proper encryption controls, secret rotation policies, and access management. Focus on customer-managed keys and automatic secret rotation for sensitive workloads.</p>
    </div>
    
    <div class="border-b border-gray-200 mb-6">
      <nav class="-mb-px flex flex-wrap space-x-6" id="kms-secrets-tabs">
        <a href="#" data-tab="kms-secrets-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
        <a href="#" data-tab="kms-secrets-overview-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Overview</a>
        ${hasSecretsData ? '<a href="#" data-tab="secrets-manager-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Secrets Manager (' + secrets.length + ')</a>' : ''}
        ${hasKmsData ? '<a href="#" data-tab="kms-customer-keys-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Customer Keys (' + customerManagedKeys.length + ')</a>' : ''}
        ${hasKmsData ? '<a href="#" data-tab="kms-aws-keys-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">AWS Keys (' + awsManagedKeys.length + ')</a>' : ''}
        <a href="#" data-tab="rotation-analysis-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Rotation Analysis</a>
      </nav>
    </div>
    <div id="kms-secrets-tab-content-container">
      <div id="kms-secrets-summary-content" class="kms-secrets-tab-content">${createKmsSecretsSummaryHtml(kmsKeys, secrets)}</div>
      <div id="kms-secrets-overview-content" class="kms-secrets-tab-content hidden">
        ${renderServiceDescription(serviceDescriptions.overview)}
        ${renderCombinedOverviewTable(kmsKeys, secrets)}
      </div>
      ${hasSecretsData ? `<div id="secrets-manager-content" class="kms-secrets-tab-content hidden">
        ${renderServiceDescription(serviceDescriptions.secretsOverview)}
        ${renderSecretsManagerTable(secrets)}
      </div>` : ''}
      ${hasKmsData ? `<div id="kms-customer-keys-content" class="kms-secrets-tab-content hidden">
        ${renderServiceDescription(serviceDescriptions.customerManagedKeys)}
        ${renderCustomerManagedKeysTable(customerManagedKeys)}
      </div>` : ''}
      ${hasKmsData ? `<div id="kms-aws-keys-content" class="kms-secrets-tab-content hidden">
        ${renderAwsManagedKeysTable(awsManagedKeys)}
      </div>` : ''}
      <div id="rotation-analysis-content" class="kms-secrets-tab-content hidden">
        ${renderServiceDescription(serviceDescriptions.keyRotation)}
        ${renderRotationAnalysisTable(customerManagedKeys, secrets)}
      </div>
    </div>
  `;

  // RESTORE ACTIVE TAB STATE
  const tabsNav = container.querySelector('#kms-secrets-tabs');

  if (activeTabData !== 'kms-secrets-summary-content') {
    const defaultActiveLink = tabsNav.querySelector('a[data-tab="kms-secrets-summary-content"]');
    const defaultActiveContent = document.getElementById('kms-secrets-summary-content');
    defaultActiveLink.classList.remove('border-[#eb3496]', 'text-[#eb3496]');
    defaultActiveLink.classList.add('border-transparent', 'text-gray-500');
    defaultActiveContent.classList.add('hidden');

    const newActiveLink = tabsNav.querySelector(`a[data-tab="${activeTabData}"]`);
    const newActiveContent = document.getElementById(activeTabData);
    if (newActiveLink && newActiveContent) {
      newActiveLink.classList.add('border-[#eb3496]', 'text-[#eb3496]');
      newActiveLink.classList.remove('border-transparent', 'text-gray-500');
      newActiveContent.classList.remove('hidden');
    }
  }

  if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.kms-secrets-tab-content'));
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

// --- SUMMARY FUNCTIONS ---
const createKmsSecretsSummaryHtml = (kmsKeys, secrets) => {
  const rotationDisabledSecrets = secrets.filter(s => !s.RotationEnabled && !s.Error).length;
  const highRiskSecrets = secrets.filter(s => s.RiskScore && s.RiskScore >= 60).length;
  
  return `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
      <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
        <div><p class="text-sm text-gray-500">Total KMS Keys</p></div>
        <div class="flex justify-between items-end pt-4">
          <p class="text-3xl font-bold text-[#204071]">${kmsKeys.length}</p>
          <div class="bg-blue-100 p-3 rounded-full">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-lock w-6 h-6 text-blue-600" viewBox="0 0 16 16">
              <path fill-rule="evenodd" d="M8 0a4 4 0 0 1 4 4v2.05a2.5 2.5 0 0 1 2 2.45v5a2.5 2.5 0 0 1-2.5 2.5h-7A2.5 2.5 0 0 1 2 13.5v-5a2.5 2.5 0 0 1 2-2.45V4a4 4 0 0 1 4-4M4.5 7A1.5 1.5 0 0 0 3 8.5v5A1.5 1.5 0 0 0 4.5 15h7a1.5 1.5 0 0 0 1.5-1.5v-5A1.5 1.5 0 0 0 11.5 7zM8 1a3 3 0 0 0-3 3v2h6V4a3 3 0 0 0-3-3"/>
            </svg>
          </div>
        </div>
      </div>
      <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
        <div><p class="text-sm text-gray-500">Total Secrets</p></div>
        <div class="flex justify-between items-end pt-4">
          <p class="text-3xl font-bold text-[#204071]">${secrets.length}</p>
          <div class="bg-purple-100 p-3 rounded-full">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-key w-6 h-6 text-purple-600" viewBox="0 0 16 16">
              <path d="M0 8a4 4 0 0 1 7.465-2H14a.5.5 0 0 1 .354.146l1.5 1.5a.5.5 0 0 1 0 .708l-1.5 1.5a.5.5 0 0 1-.708 0L13 9.207l-.646.647a.5.5 0 0 1-.708 0L11 9.207l-.646.647a.5.5 0 0 1-.708 0L9 9.207l-.646.647A.5.5 0 0 1 8 10h-.535A4 4 0 0 1 0 8zm4-3a3 3 0 1 0 2.712 4.285A.5.5 0 0 1 7.163 9h.63l.853-.854a.5.5 0 0 1 .708 0l.646.647.646-.647a.5.5 0 0 1 .708 0l.646.647.646-.647a.5.5 0 0 1 .708 0L14.293 8l.853-.854A.5.5 0 0 1 15.5 7h-5.535a.5.5 0 0 1-.447-.276A3 3 0 0 0 4 5z"/>
              <circle cx="4" cy="8" r="1"/>
            </svg>
          </div>
        </div>
      </div>
      <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
        <div><p class="text-sm text-gray-500">Rotation Disabled</p></div>
        <div class="flex justify-between items-end pt-4">
          <p class="text-3xl font-bold text-red-600">${kmsKeys.filter(k => k.RotationEnabled === 'Disabled').length + rotationDisabledSecrets}</p>
          <div class="bg-red-100 p-3 rounded-full">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-arrow-clockwise w-6 h-6 text-red-600" viewBox="0 0 16 16">
              <path fill-rule="evenodd" d="M8 3a5 5 0 1 0 4.546 2.914.5.5 0 0 1 .908-.417A6 6 0 1 1 8 2z"/>
              <path d="M8 4.466V.534a.25.25 0 0 1 .41-.192l2.36 1.966c.12.1.12.284 0 .384L8.41 4.658A.25.25 0 0 1 8 4.466"/>
            </svg>
          </div>
        </div>
      </div>
      <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
        <div><p class="text-sm text-gray-500">High Risk Secrets</p></div>
        <div class="flex justify-between items-end pt-4">
          <p class="text-3xl font-bold text-orange-600">${highRiskSecrets}</p>
          <div class="bg-orange-100 p-3 rounded-full">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-exclamation-triangle w-6 h-6 text-orange-600" viewBox="0 0 16 16">
              <path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.146.146 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.163.163 0 0 1-.054.06.116.116 0 0 1-.066.017H1.146a.115.115 0 0 1-.066-.017.163.163 0 0 1-.054-.06.176.176 0 0 1 .002-.183L7.884 2.073a.147.147 0 0 1 .054-.057zm1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767L8.982 1.566z"/>
              <path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0zM7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3a.905.905 0 1 1-1.8 0l.35-3"/>
            </svg>
          </div>
        </div>
      </div>
    </div>
  `;
};

// --- COMBINED OVERVIEW TABLE ---
const renderCombinedOverviewTable = (kmsKeys, secrets) => {
  return `
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div class="bg-white border border-gray-200 rounded-lg p-6">
        <h4 class="text-lg font-semibold text-gray-800 mb-4">KMS Keys Summary</h4>
        <div class="space-y-3">
          <div class="flex justify-between">
            <span class="text-sm text-gray-600">Total Keys:</span>
            <span class="text-sm font-medium">${kmsKeys.length}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-sm text-gray-600">Customer Managed:</span>
            <span class="text-sm font-medium">${kmsKeys.filter(k => k.KeyManager === 'CUSTOMER').length}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-sm text-gray-600">AWS Managed:</span>
            <span class="text-sm font-medium">${kmsKeys.filter(k => k.KeyManager === 'AWS').length}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-sm text-gray-600">Rotation Disabled:</span>
            <span class="text-sm font-medium text-red-600">${kmsKeys.filter(k => k.RotationEnabled === 'Disabled').length}</span>
          </div>
        </div>
      </div>
      
      <div class="bg-white border border-gray-200 rounded-lg p-6">
        <h4 class="text-lg font-semibold text-gray-800 mb-4">Secrets Manager Summary</h4>
        <div class="space-y-3">
          <div class="flex justify-between">
            <span class="text-sm text-gray-600">Total Secrets:</span>
            <span class="text-sm font-medium">${secrets.length}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-sm text-gray-600">Rotation Enabled:</span>
            <span class="text-sm font-medium text-green-600">${secrets.filter(s => s.RotationEnabled && !s.Error).length}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-sm text-gray-600">Rotation Disabled:</span>
            <span class="text-sm font-medium text-red-600">${secrets.filter(s => !s.RotationEnabled && !s.Error).length}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-sm text-gray-600">High Risk Secrets:</span>
            <span class="text-sm font-medium text-orange-600">${secrets.filter(s => s.RiskScore && s.RiskScore >= 60).length}</span>
          </div>
        </div>
      </div>
    </div>
  `;
};

// --- SECRETS MANAGER TABLE ---
const renderSecretsManagerTable = (secrets) => {
  if (!secrets || secrets.length === 0) {
    return `
      <div class="bg-white p-6 rounded-xl border border-gray-100">
        <div class="text-center">
          <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 class="mt-2 text-sm font-medium text-gray-900">No secrets found</h3>
          <p class="mt-1 text-sm text-gray-500">No secrets were found in AWS Secrets Manager.</p>
        </div>
      </div>
    `;
  }

  let tableHtml = `
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
      <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rotation</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">KMS Key</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk Score</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Accessed</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
  `;

  secrets
    .sort((a, b) => a.Region.localeCompare(b.Region) || a.Name.localeCompare(b.Name))
    .forEach((secret, index) => {
      const isScoped = !!window.scopedResources[secret.ARN];
      if (secret.Error) {
        tableHtml += `
          <tr class="${isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50'}">
            <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${createScopeButton(secret.ARN)}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${secret.Region}</td>
            <td class="px-4 py-4 text-sm font-medium text-gray-800">${secret.Name}</td>
            <td class="px-4 py-4 text-sm text-red-600" colspan="6">${secret.Error}</td>
          </tr>
        `;
        return;
      }

      const rotationBadge = secret.RotationEnabled
        ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Enabled</span>'
        : '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Disabled</span>';

      const riskBadge = getRiskBadge(secret.RiskScore || 0);
      const kmsKeyDisplay = secret.KmsKeyId.includes('alias/aws/secretsmanager') ? 'AWS Managed' : 'Customer Managed';
      const lastAccessed = secret.LastAccessedDate ? new Date(secret.LastAccessedDate).toLocaleDateString() : 'Never';

      tableHtml += `
        <tr class="${isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50'}">
          <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${createScopeButton(secret.ARN)}</td>
          <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${secret.Region}</td>
          <td class="px-4 py-4 text-sm font-medium text-gray-800 break-words max-w-xs">${secret.Name}</td>
          <td class="px-4 py-4 text-sm text-gray-600 max-w-xs truncate" title="${secret.Description}">${secret.Description}</td>
          <td class="px-4 py-4 whitespace-nowrap text-sm">${rotationBadge}</td>
          <td class="px-4 py-4 text-sm text-gray-600">${kmsKeyDisplay}</td>
          <td class="px-4 py-4 whitespace-nowrap text-sm">${riskBadge}</td>
          <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${lastAccessed}</td>
          <td class="px-4 py-4 whitespace-nowrap text-sm">
            <button 
              onclick="openModalWithSecretDetails(${index})" 
              class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">
              View Details
            </button>
          </td>
        </tr>
      `;
    });

  tableHtml += '</tbody></table></div>';
  return tableHtml;
};

// --- CUSTOMER MANAGED KEYS TABLE ---
const renderCustomerManagedKeysTable = (keys) => {
  if (!keys || keys.length === 0) {
    return `
      <div class="bg-white p-6 rounded-xl border border-gray-100">
        <div class="text-center">
          <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 class="mt-2 text-sm font-medium text-gray-900">No customer-managed keys found</h3>
          <p class="mt-1 text-sm text-gray-500">Consider creating customer-managed keys for enhanced security control over sensitive workloads.</p>
        </div>
      </div>
    `;
  }
  return renderKmsKeysTable(keys, 'Customer Managed Keys');
};

// --- AWS MANAGED KEYS TABLE ---
const renderAwsManagedKeysTable = (keys) => {
  if (!keys || keys.length === 0) {
    return `
      <div class="bg-white p-6 rounded-xl border border-gray-100">
        <div class="text-center">
          <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 class="mt-2 text-sm font-medium text-gray-900">No AWS-managed keys found</h3>
          <p class="mt-1 text-sm text-gray-500">AWS-managed keys are automatically created when AWS services require encryption.</p>
        </div>
      </div>
    `;
  }
  return renderKmsKeysTable(keys, 'AWS Managed Keys');
};

// --- ROTATION ANALYSIS TABLE ---
const renderRotationAnalysisTable = (customerKeys, secrets) => {
  const rotationIssues = [];
  
  customerKeys.forEach(key => {
    if (key.RotationEnabled === 'Disabled') {
      rotationIssues.push({
        type: 'KMS Key',
        resource: key.Aliases || key.KeyId,
        region: key.Region,
        issue: 'Rotation disabled',
        recommendation: 'Enable automatic key rotation',
        severity: 'Medium'
      });
    }
  });
  
  secrets.forEach(secret => {
    if (!secret.RotationEnabled && !secret.Error) {
      rotationIssues.push({
        type: 'Secret',
        resource: secret.Name,
        region: secret.Region,
        issue: 'Rotation disabled',
        recommendation: 'Enable automatic secret rotation',
        severity: secret.OwningService ? 'Low' : 'High'
      });
    }
  });
  
  if (rotationIssues.length === 0) {
    return `
      <div class="bg-white p-6 rounded-xl border border-gray-100">
        <div class="text-center">
          <svg class="mx-auto h-12 w-12 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <h3 class="mt-2 text-sm font-medium text-gray-900">Excellent rotation hygiene!</h3>
          <p class="mt-1 text-sm text-gray-500">All KMS keys and secrets have appropriate rotation settings.</p>
        </div>
      </div>
    `;
  }

  let tableHtml = `
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
      <div class="mb-4">
        <h4 class="text-lg font-semibold text-gray-800">Rotation Issues Found: ${rotationIssues.length}</h4>
        <p class="text-sm text-gray-600">Resources that should have automatic rotation enabled</p>
      </div>
      <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Resource</th>
            <th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Issue</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Recommendation</th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
  `;
  
  rotationIssues.forEach(issue => {
    const isScoped = false;
    const severityBadge = getSeverityBadge(issue.severity);
    
    tableHtml += `
      <tr class="${isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50'}">
        <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${issue.type}</td>
        <td class="px-4 py-4 text-sm text-gray-800 break-words max-w-xs">${issue.resource}</td>
        <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${issue.region}</td>
        <td class="px-4 py-4 text-sm text-gray-600">${issue.issue}</td>
        <td class="px-4 py-4 whitespace-nowrap text-sm">${severityBadge}</td>
        <td class="px-4 py-4 text-sm text-gray-600">${issue.recommendation}</td>
      </tr>
    `;
  });
  
  tableHtml += '</tbody></table></div>';
  return tableHtml;
};

// --- KMS KEYS TABLE ---
const renderKmsKeysTable = (keys, title) => {
  if (!keys || keys.length === 0) {
    return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No KMS keys were found.</p></div>';
  }

  let tableHtml = `
    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
      <table class="min-w-full divide-y divide-gray-200">
        <thead class="bg-gray-50">
          <tr>
            <th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Alias</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Key ID</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">State</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rotation</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Manager</th>
            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Key Policy</th>
          </tr>
        </thead>
        <tbody class="bg-white divide-y divide-gray-200">
  `;
  
  keys
    .sort((a, b) => a.Region.localeCompare(b.Region) || a.Aliases.localeCompare(b.Aliases))
    .forEach((k, index) => {
      const isScoped = !!window.scopedResources[k.ARN];
      const rotationBadge = createKmsStatusBadge(k.RotationEnabled, 'rotation');
      const stateBadge = createKmsStatusBadge(k.Status, 'state');
      
      const managerBadge = k.KeyManager === 'CUSTOMER'
        ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">CUSTOMER</span>'
        : '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">AWS</span>';
      
      tableHtml += `
        <tr class="${isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50'}">
          <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${createScopeButton(k.ARN)}</td>
          <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${k.Region}</td>
          <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${k.Aliases}</td>
          <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600 font-mono">${k.KeyId}</td>
          <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${stateBadge}</td>
          <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${rotationBadge}</td>
          <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${managerBadge}</td>
          <td class="px-4 py-4 align-top whitespace-nowrap text-sm">
            <button 
              onclick="openModalWithKmsPolicy(${index})" 
              class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition">
              View Policy
            </button>
          </td>
        </tr>
      `;
    });
  tableHtml += '</tbody></table></div>';
  return tableHtml;
};

// --- EMPTY STATE ---
const createEmptyState = () => `
  <div class="text-center py-16 bg-white rounded-lg">
    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
    </svg>
    <h3 class="mt-2 text-lg font-medium text-[#204071]">KMS & Secrets Manager Data Not Available</h3>
    <p class="mt-1 text-sm text-gray-500">Run a scan to view KMS keys and Secrets Manager data.</p>
  </div>
`;

// --- UTILITY FUNCTIONS ---
const getRiskBadge = (riskScore) => {
  if (riskScore >= 80) {
    return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Critical</span>';
  } else if (riskScore >= 60) {
    return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-orange-100 text-orange-800">High</span>';
  } else if (riskScore >= 40) {
    return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">Medium</span>';
  } else if (riskScore >= 20) {
    return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">Low</span>';
  } else {
    return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Minimal</span>';
  }
};

const getSeverityBadge = (severity) => {
  switch (severity.toLowerCase()) {
    case 'high':
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">High</span>';
    case 'medium':
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">Medium</span>';
    case 'low':
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">Low</span>';
    default:
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">Unknown</span>';
  }
};

const createKmsStatusBadge = (value, type = 'default') => {
  if (type === 'rotation') {
    if (value === 'Enabled') {
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Enabled</span>';
    } else if (value === 'Disabled') {
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Disabled</span>';
    } else {
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">N/A</span>';
    }
  } else if (type === 'state') {
    if (value === 'Enabled') {
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">Enabled</span>';
    } else if (value === 'Disabled') {
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">Disabled</span>';
    } else if (value === 'PendingDeletion') {
      return '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-orange-100 text-orange-800">Pending Deletion</span>';
    } else {
      return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">${value}</span>`;
    }
  } else {
    return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">${value}</span>`;
  }
};

// --- MODAL FUNCTIONS (EXPORTED & GLOBAL FOR INLINE HANDLERS) ---
export const openModalWithKmsPolicy = (keyIndex) => {
  const modal = document.getElementById('details-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalContent = document.getElementById('modal-content');
  const key = window.kmsApiData.results.keys[keyIndex];

  if (!modal || !key || !key.Policy) return;

  modalTitle.textContent = `Key Policy for: ${key.Aliases || key.KeyId}`;
  const formattedPolicy = JSON.stringify(key.Policy, null, 2);

  modalContent.innerHTML = `
    <div class="text-left">
      <pre class="bg-[#204071] text-white text-xs font-mono rounded-md p-3 overflow-x-auto"><code>${formattedPolicy}</code></pre>
    </div>
  `;
  modal.classList.remove('hidden');
};

export const openModalWithSecretDetails = (secretIndex) => {
  const modal = document.getElementById('details-modal');
  const modalTitle = document.getElementById('modal-title');
  const modalContent = document.getElementById('modal-content');
  const secret = window.secretsManagerApiData.results.secrets[secretIndex];

  if (!modal || !secret || secret.Error) return;

  modalTitle.textContent = `Secret Details: ${secret.Name}`;
  
  const rotationRules = secret.RotationRules || {};
  const securityIssues = secret.SecurityIssues || [];
  const rotationAnalysis = secret.RotationAnalysis || {};

  modalContent.innerHTML = `
    <div class="text-left space-y-6">
      <!-- Basic Information -->
      <div class="bg-gray-50 rounded-lg p-4">
        <h4 class="text-lg font-semibold text-gray-800 mb-3">Basic Information</h4>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <span class="text-sm font-medium text-gray-600">Region:</span>
            <p class="text-sm text-gray-800">${secret.Region}</p>
          </div>
          <div>
            <span class="text-sm font-medium text-gray-600">ARN:</span>
            <p class="text-sm text-gray-800 font-mono break-all">${secret.ARN}</p>
          </div>
          <div>
            <span class="text-sm font-medium text-gray-600">Description:</span>
            <p class="text-sm text-gray-800">${secret.Description || 'No description'}</p>
          </div>
          <div>
            <span class="text-sm font-medium text-gray-600">KMS Key:</span>
            <p class="text-sm text-gray-800">${secret.KmsKeyId}</p>
          </div>
          <div>
            <span class="text-sm font-medium text-gray-600">Risk Score:</span>
            <p class="text-sm">${getRiskBadge(secret.RiskScore || 0)}</p>
          </div>
          <div>
            <span class="text-sm font-medium text-gray-600">Created:</span>
            <p class="text-sm text-gray-800">${secret.CreatedDate ? new Date(secret.CreatedDate).toLocaleString() : 'Unknown'}</p>
          </div>
        </div>
      </div>

      <!-- Rotation Configuration -->
      <div class="bg-blue-50 rounded-lg p-4">
        <h4 class="text-lg font-semibold text-gray-800 mb-3">Rotation Configuration</h4>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <span class="text-sm font-medium text-gray-600">Rotation Enabled:</span>
            <p class="text-sm">${secret.RotationEnabled ? 
              '<span class="text-green-600 font-semibold">Yes</span>' : 
              '<span class="text-red-600 font-semibold">No</span>'}</p>
          </div>
          ${secret.RotationLambdaARN ? `
          <div>
            <span class="text-sm font-medium text-gray-600">Lambda Function:</span>
            <p class="text-sm text-gray-800 font-mono break-all">${secret.RotationLambdaARN}</p>
          </div>` : ''}
          ${rotationRules.AutomaticallyAfterDays ? `
          <div>
            <span class="text-sm font-medium text-gray-600">Rotation Interval:</span>
            <p class="text-sm text-gray-800">${rotationRules.AutomaticallyAfterDays} days</p>
          </div>` : ''}
          <div>
            <span class="text-sm font-medium text-gray-600">Last Rotated:</span>
            <p class="text-sm text-gray-800">${secret.LastRotatedDate ? 
              new Date(secret.LastRotatedDate).toLocaleString() : 'Never'}</p>
          </div>
        </div>
        
        ${rotationAnalysis.issues && rotationAnalysis.issues.length > 0 ? `
        <div class="mt-4">
          <h5 class="text-sm font-medium text-red-700 mb-2">Rotation Issues:</h5>
          <ul class="text-sm text-red-600 space-y-1">
            ${rotationAnalysis.issues.map(issue => `<li>• ${issue}</li>`).join('')}
          </ul>
        </div>` : ''}
        
        ${rotationAnalysis.recommendations && rotationAnalysis.recommendations.length > 0 ? `
        <div class="mt-4">
          <h5 class="text-sm font-medium text-blue-700 mb-2">Recommendations:</h5>
          <ul class="text-sm text-blue-600 space-y-1">
            ${rotationAnalysis.recommendations.map(rec => `<li>• ${rec}</li>`).join('')}
          </ul>
        </div>` : ''}
      </div>

      <!-- Security Analysis -->
      ${securityIssues.length > 0 ? `
      <div class="bg-yellow-50 rounded-lg p-4">
        <h4 class="text-lg font-semibold text-gray-800 mb-3">Security Issues</h4>
        <div class="space-y-3">
          ${securityIssues.map(issue => `
            <div class="border-l-4 ${issue.severity === 'high' ? 'border-red-400' : 
                                    issue.severity === 'medium' ? 'border-yellow-400' : 
                                    'border-blue-400'} pl-4">
              <div class="flex justify-between items-start">
                <h5 class="text-sm font-medium text-gray-800">${issue.type.replace('_', ' ').toUpperCase()}</h5>
                ${getSeverityBadge(issue.severity)}
              </div>
              <p class="text-sm text-gray-600 mt-1">${issue.description}</p>
              <p class="text-sm text-blue-600 mt-1"><strong>Recommendation:</strong> ${issue.recommendation}</p>
            </div>
          `).join('')}
        </div>
      </div>` : ''}

      <!-- Resource Policy -->
      ${secret.ResourcePolicy && typeof secret.ResourcePolicy === 'object' ? `
      <div class="bg-gray-50 rounded-lg p-4">
        <h4 class="text-lg font-semibold text-gray-800 mb-3">Resource Policy</h4>
        <pre class="bg-[#204071] text-white text-xs font-mono rounded-md p-3 overflow-x-auto"><code>${JSON.stringify(secret.ResourcePolicy, null, 2)}</code></pre>
      </div>` : ''}

      <!-- Tags -->
      ${secret.Tags && secret.Tags.length > 0 ? `
      <div class="bg-green-50 rounded-lg p-4">
        <h4 class="text-lg font-semibold text-gray-800 mb-3">Tags</h4>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
          ${secret.Tags.map(tag => `
            <div class="bg-white rounded px-3 py-2 border">
              <span class="text-sm font-medium text-gray-600">${tag.Key}:</span>
              <span class="text-sm text-gray-800">${tag.Value}</span>
            </div>
          `).join('')}
        </div>
      </div>` : ''}
    </div>
  `;

  modal.classList.remove('hidden');
};

// expose modal functions for inline onclick handlers
window.openModalWithKmsPolicy = openModalWithKmsPolicy;
window.openModalWithSecretDetails = openModalWithSecretDetails;

const createScopeButton = (arn) => {
  const scopeDetails = window.scopedResources[arn];
  const isScoped = !!scopeDetails;
  const scopeComment = isScoped ? scopeDetails.comment : '';
  
  const scopeIcon = isScoped 
    ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16"><path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>` 
    : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>`;
  
  return `<button onclick="openScopeModal('${arn}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;
};