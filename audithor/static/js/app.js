import { coverageOf, isMigratedCollector, failedCollectionResponse } from './collection.js';
import { html, raw, setHtml, act, installActionDelegation } from './safe_html.js';
/**
 * app.js
 * Fichero principal (el "cerebro") de la lógica de la aplicación AudiThor.
 */

// 1. IMPORTACIONES
import { 
    log, 
    copyToClipboard, 
    handleTabClick, 
    createStatusBadge, 
    createAlarmStateBadge, 
    setupModalControls, 
    setupPagination, 
    renderSecurityHubFindings 
} from '/static/js/utils.js';

import { 
    buildIamView, 
    updateSecurityHubDashboard, 
    openModalWithSsoDetails, 
    openModalWithAccessKeyDetails, 
    openModalWithUserGroups,
    openModalWithUserRoles
} from '/static/js/views/01_iam.js';
import { buildExposureView } from '/static/js/views/02_exposure.js';
import { buildGuarddutyView } from '/static/js/views/03_guardduty.js';
import { buildEcrView } from '/static/js/views/04_ecr.js';
import { buildWafView } from '/static/js/views/05_waf.js';
import { buildCloudtrailView } from '/static/js/views/06_cloudtrail.js';
import { buildCloudwatchView } from '/static/js/views/07_cloudwatch.js';
import { buildInspectorView } from '/static/js/views/08_inspector.js';
import { buildAcmView } from '/static/js/views/09_acm.js';
import { buildComputeView } from '/static/js/views/10_compute.js';
import { buildDatabasesView } from '/static/js/views/11_databases.js';
import { buildKmsSecretsView } from '/static/js/views/12_kms_secrets.js';
import { buildNetworkPoliciesView, openModalWithVpcTags } from '/static/js/views/13_network_policies.js';
import { buildConnectivityView } from '/static/js/views/14_connectivity.js';
import { buildConfigSHView } from '/static/js/views/15_config_sh.js';
import { buildCodePipelineView } from '/static/js/views/18_codepipeline.js';
import { buildInventoryView } from '/static/js/views/21_inventory.js';
import { buildPlaygroundView } from '/static/js/views/16_playground.js';


// Importar las funciones que se usarán en onclick
import { openModalWithTlsDetails, openModalWithResourceMap } from '/static/js/views/02_exposure.js';
import { openModalWithEcrPolicy } from '/static/js/views/04_ecr.js';
import { openModalWithKmsPolicy, openModalWithSecretDetails } from '/static/js/views/12_kms_secrets.js';
import { showCloudtrailEventDetails } from '/static/js/views/06_cloudtrail.js';
import { toggleAlarmDetails } from '/static/js/views/07_cloudwatch.js';
import { openModalWithEc2Tags, openModalWithLambdaTags, openModalWithLambdaRole } from '/static/js/views/10_compute.js';

// Importar iconos
import { SIDEBAR_ICONS } from '/static/js/icons.js';

// 2. ESTADO GLOBAL
window.iamApiData = null;
window.federationApiData = null;
window.accessAnalyzerApiData = null;
window.securityHubApiData = null;
window.exposureApiData = null;
window.guarddutyApiData = null;
window.wafApiData = null;
window.cloudtrailApiData = null;
window.cloudwatchApiData = null;
window.inspectorApiData = null;
window.acmApiData = null;
window.computeApiData = null;
window.ecrApiData = null;
window.databasesApiData = null;
window.networkPoliciesApiData = null;
window.connectivityApiData = null;
window.codepipelineApiData = null;
window.inventoryApiData = null;
window.playgroundApiData = null;
window.configSHApiData = null;
window.configSHStatusApiData = null;
window.kmsApiData = null;
window.allAvailableRegions = [];
window.lastCloudtrailLookupResults = [];
window.scopedResources = {};
window.auditorNotes = [];

// 3. SELECTORES
let views, mainNavLinks, runAnalysisBtn, accessKeyInput, secretKeyInput, sessionTokenInput, loadingSpinner, buttonText, errorMessageDiv, logContainer, clearLogBtn, toggleLogBtn, logPanel;
let landingView, mainAppView, landingRunAnalysisBtn, landingImportResultsBtn, landingAccessKeyInput, landingSecretKeyInput, landingSessionTokenInput, landingLoadingSpinner, landingButtonText, landingErrorMessageDiv;
let hasCompletedInitialScan = false;

// 4. LÓGICA PRINCIPAL
const loadSidebarIcons = () => {
    const sidebarNav = document.getElementById('sidebar-nav');
    if (!sidebarNav) return;

    const navLinks = sidebarNav.querySelectorAll('a[data-view]');
    navLinks.forEach(link => {
        const viewName = link.dataset.view;
        const iconKey = viewName;
        
        if (SIDEBAR_ICONS[iconKey]) {
            const span = link.querySelector('span');
            if (span) {
                const currentText = span.textContent.trim();
                
                // Crear nueva estructura: icono + texto en contenedores separados
                span.replaceChildren();
                
                // Crear contenedor para el icono
                const iconDiv = document.createElement('div');
                setHtml(iconDiv, raw(SIDEBAR_ICONS[iconKey]));
                iconDiv.className = 'flex-shrink-0';
                
                // Crear contenedor para el texto
                const textDiv = document.createElement('div');
                textDiv.textContent = currentText;
                textDiv.className = 'ml-3';
                
                // Añadir ambos al span
                span.appendChild(iconDiv);
                span.appendChild(textDiv);
                
                // Asegurar que el span tenga flex
                span.className = 'flex items-center';
            }
        }
    });
};

// --- NUEVO: FUNCIONES DE GESTIÓN DE SCOPE ---
const SCOPE_STORAGE_KEY = 'audiThorScopedResources';

export const isPlainObject = value => value !== null && typeof value === 'object' && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null);
export const isValidScopeData = value => isPlainObject(value) && Object.values(value).every(entry => isPlainObject(entry));
export const isImportFileSizeAllowed = size => Number.isFinite(size) && size <= 200 * 1024 * 1024;
export const validateImportShape = data => isPlainObject(data) && isPlainObject(data.metadata) && isPlainObject(data.results);
export const playgroundStateFromImport = playground => ({ results: playground?.traceroute || null });

const loadScopedResources = () => {
    const stored = localStorage.getItem(SCOPE_STORAGE_KEY);
    window.scopedResources = stored ? JSON.parse(stored) : {};
    log(`${Object.keys(window.scopedResources).length} recursos marcados cargados desde localStorage.`, 'info');
};

const saveScopedResources = () => {
    localStorage.setItem(SCOPE_STORAGE_KEY, JSON.stringify(window.scopedResources));
};

const setResourceScope = (arn, comment) => {
    const normalizedComment = (comment || '').trim();
    if (!arn) return false;
    if (!normalizedComment) {
        log('Debes indicar un motivo para marcar el recurso en scope.', 'warning');
        return false;
    }

    window.scopedResources[arn] = { comment: normalizedComment };
    log(`Recurso ${arn} marcado como 'in scope'.`, 'success');
    saveScopedResources();
    rerenderCurrentView(); // Función para refrescar la vista actual
    return true;
};


const removeResourceScope = (arn) => {
    if (arn && window.scopedResources[arn]) {
        delete window.scopedResources[arn];
        log(`Resource ${arn} unmarked.`, 'info');
        saveScopedResources();
        rerenderCurrentView();
    } else {
        log('ARN not found in scopedResources. Nothing to remove.', 'warning');
    }
};


const NOTES_STORAGE_KEY = 'audiThorAuditorNotes';

const loadAuditorNotes = () => {
    const stored = localStorage.getItem(NOTES_STORAGE_KEY);
    try {
        window.auditorNotes = stored ? JSON.parse(stored) : [];
        log(`${window.auditorNotes.length} notas del auditor cargadas.`, 'info');
    } catch (error) {
        log(`Error al parsear las notas desde localStorage: ${error.message}. Se reiniciarán las notas.`, 'error');
        console.error("Datos de notas corruptos en localStorage:", stored);
        window.auditorNotes = [];
        localStorage.removeItem(NOTES_STORAGE_KEY);
    }
};


const saveAuditorNotes = () => {
    localStorage.setItem(NOTES_STORAGE_KEY, JSON.stringify(window.auditorNotes));
};

const saveOrUpdateNote = (noteId, noteContent, noteTitle, noteArn, noteControl, view, tab) => {
    if (noteId) {
        // --- Lógica para ACTUALIZAR una nota existente ---
        const noteIndex = window.auditorNotes.findIndex(note => note.id === noteId);
        if (noteIndex > -1) {
            window.auditorNotes[noteIndex].title = noteTitle;
            window.auditorNotes[noteIndex].content = noteContent;
            window.auditorNotes[noteIndex].arn = noteArn;
            window.auditorNotes[noteIndex].controlId = noteControl;
            window.auditorNotes[noteIndex].lastModified = new Date().toISOString();
            log(`Nota con ID ${noteId} actualizada.`, 'success');
        }
    } else {
        // --- Lógica para CREAR una nota nueva (la que ya tenías) ---
        const newNote = {
            id: Date.now(),
            view: view,
            tab: tab,
            timestamp: new Date().toISOString(),
            title: noteTitle,
            arn: noteArn,
            controlId: noteControl,
            content: noteContent
        };
        window.auditorNotes.push(newNote);
        log(`Nota nueva '${noteTitle}' guardada.`, 'success');
    }

    saveAuditorNotes();
    rerenderCurrentView();
};

const openNotesModal = (noteId = null) => {
    const modal = document.getElementById('notes-modal');
    const titleHeader = document.getElementById('notes-modal-title');
    const textarea = document.getElementById('notes-modal-textarea');
    const saveBtn = document.getElementById('notes-modal-save-btn');
    const cancelBtn = document.getElementById('notes-modal-cancel-btn');
    const titleInput = document.getElementById('notes-modal-title-input');
    const arnInput = document.getElementById('notes-modal-arn-input');
    const controlInput = document.getElementById('notes-modal-control-input');

    let noteToEdit = null;

    if (noteId) {
        // --- MODO EDICIÓN ---
        noteToEdit = window.auditorNotes.find(note => note.id === noteId);
        if (!noteToEdit) {
            log(`Error: No se encontró la nota con ID ${noteId}`, 'error');
            return;
        }
        titleHeader.textContent = 'Edit Note';
        titleInput.value = noteToEdit.title;
        arnInput.value = noteToEdit.arn || '';
        controlInput.value = noteToEdit.controlId || '';
        textarea.value = noteToEdit.content;

    } else {
        // --- MODO CREACIÓN ---
        const activeViewLink = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
        const viewText = activeViewLink
            ? ((activeViewLink.querySelector('span')?.textContent || activeViewLink.dataset.view || 'General').trim())
            : 'General';
        titleHeader.textContent = `New Note for: ${viewText}`;
        textarea.value = '';
        titleInput.value = '';
        arnInput.value = '';
        controlInput.value = '';
    }

    const handleSave = () => {
        const noteContent = textarea.value.trim();
        const noteTitle = titleInput.value.trim();
        const noteArn = arnInput.value.trim();
        const noteControl = controlInput.value.trim();
        
        const activeViewLink = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
        const viewName = activeViewLink ? activeViewLink.dataset.view : 'unknown';

        if (noteContent && noteTitle) {
            // Pasamos el ID si estamos editando, o null si estamos creando
            saveOrUpdateNote(noteToEdit ? noteToEdit.id : null, noteContent, noteTitle, noteArn, noteControl, viewName, 'main');
            modal.classList.add('hidden');
        } else {
            alert('Por favor, introduce al menos un título y el contenido de la nota.');
        }
    };

    const newSaveBtn = saveBtn.cloneNode(true);
    saveBtn.parentNode.replaceChild(newSaveBtn, saveBtn);
    newSaveBtn.addEventListener('click', handleSave);

    cancelBtn.addEventListener('click', () => modal.classList.add('hidden'));
    modal.classList.remove('hidden');
    titleInput.focus();
};

const rerenderCurrentView = () => {
    log('Rerendering view(s) to reflect state changes...', 'info');

    const activeLink = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
    if (!activeLink) {
        log('Could not find an active view to rerender.', 'warning');
        return;
    }

    const activeViewName = activeLink.dataset.view;
    const activeSubTab = document.querySelector(`#${activeViewName}-view .tab-link.border-\\[\\#eb3496\\]`);
    const viewRenderers = {
        'iam': buildIamView,
        'exposure': buildExposureView,
        'guardduty': buildGuarddutyView,
        'ecr': buildEcrView,
        'waf': buildWafView,
        'cloudtrail': buildCloudtrailView,
        'cloudwatch': buildCloudwatchView,
        'inspector': buildInspectorView,
        'acm': buildAcmView,
        'compute': buildComputeView,
        'databases': buildDatabasesView,
        'kms-secrets': buildKmsSecretsView,
        'network-policies': buildNetworkPoliciesView,
        'connectivity': buildConnectivityView,
        'config-sh': buildConfigSHView,
        'codepipeline': buildCodePipelineView,
        'auditor-notes': buildAuditorNotesView,
        'inventory': buildInventoryView,
        'playground': buildPlaygroundView
    };

    const renderFunction = viewRenderers[activeViewName];
    if (renderFunction) {
        renderFunction();
        if (activeSubTab) document.querySelector(`[data-tab="${activeSubTab.dataset.tab}"]`)?.click();
    }
};

// Función para abrir y manejar el modal de scope
const openScopeModal = (arn, currentComment = '') => {
    const modal = document.getElementById('scope-modal');
    const title = document.getElementById('scope-modal-title');
    const textarea = document.getElementById('scope-comment-textarea');
    const saveBtn = document.getElementById('scope-modal-save-btn');
    const unscopeBtn = document.getElementById('scope-modal-unscope-btn');
    const closeBtn = document.getElementById('scope-modal-close-btn');

    if (!modal) return;

    title.textContent = `Marcar Recurso: ${arn.split('/').pop()}`;
    try {
        textarea.value = decodeURIComponent(currentComment || '');
    } catch {
        textarea.value = currentComment || '';
    }

    // Limpiar listeners antiguos para evitar ejecuciones múltiples
    const newSaveBtn = saveBtn.cloneNode(true);
    saveBtn.parentNode.replaceChild(newSaveBtn, saveBtn);

    const newUnscopeBtn = unscopeBtn.cloneNode(true);
    unscopeBtn.parentNode.replaceChild(newUnscopeBtn, unscopeBtn);

    newSaveBtn.addEventListener('click', () => {
        const comment = textarea.value.trim();
        if (!comment) {
            alert('Please provide a reason before marking this resource in scope.');
            textarea.focus();
            return;
        }

        modal.classList.add('hidden');
        setResourceScope(arn, comment);
    });

    newUnscopeBtn.addEventListener('click', () => {
        removeResourceScope(arn);
        modal.classList.add('hidden');
    });

    closeBtn.addEventListener('click', () => modal.classList.add('hidden'));

    modal.classList.remove('hidden');
    textarea.focus();
};



const handleMainNavClick = (e) => {
    e.preventDefault();
    const link = e.target.closest('a.main-nav-link');
    if (!link) return;
    
    const targetView = link.dataset.view;
    if (!targetView) return;
    
    // Actualizar navegación activa
    mainNavLinks.forEach(l => {
        l.classList.remove('bg-[#eb3496]');
        l.classList.add('hover:bg-[#1a335a]');
    });
    link.classList.add('bg-[#eb3496]');
    link.classList.remove('hover:bg-[#1a335a]');
    
    // Mostrar vista correspondiente
    views.forEach(v => v.classList.add('hidden'));
    const targetViewElement = document.getElementById(`${targetView}-view`);
    if (targetViewElement) {
        targetViewElement.classList.remove('hidden');
    }
    if (targetView === 'inventory') {
        buildInventoryView();
    }
    if (targetView === 'auditor-notes') {
        buildAuditorNotesView();
    }
};

const setWorkspaceVisibility = (showMainApp) => {
    if (showMainApp) {
        landingView?.classList.add('hidden');
        mainAppView?.classList.remove('hidden');
    } else {
        mainAppView?.classList.add('hidden');
        landingView?.classList.remove('hidden');
    }
};

const syncCredentialsBetweenForms = (source = 'main') => {
    if (source === 'landing') {
        if (accessKeyInput && landingAccessKeyInput) accessKeyInput.value = landingAccessKeyInput.value;
        if (secretKeyInput && landingSecretKeyInput) secretKeyInput.value = landingSecretKeyInput.value;
        if (sessionTokenInput && landingSessionTokenInput) sessionTokenInput.value = landingSessionTokenInput.value;
        return;
    }
    if (landingAccessKeyInput && accessKeyInput) landingAccessKeyInput.value = accessKeyInput.value;
    if (landingSecretKeyInput && secretKeyInput) landingSecretKeyInput.value = secretKeyInput.value;
    if (landingSessionTokenInput && sessionTokenInput) landingSessionTokenInput.value = sessionTokenInput.value;
};

const getScanControls = (source = 'main') => {
    if (source === 'landing') {
        return {
            runBtn: landingRunAnalysisBtn,
            accessInput: landingAccessKeyInput,
            secretInput: landingSecretKeyInput,
            tokenInput: landingSessionTokenInput,
            spinner: landingLoadingSpinner,
            btnText: landingButtonText,
            errorDiv: landingErrorMessageDiv
        };
    }
    return {
        runBtn: runAnalysisBtn,
        accessInput: accessKeyInput,
        secretInput: secretKeyInput,
        tokenInput: sessionTokenInput,
        spinner: loadingSpinner,
        btnText: buttonText,
        errorDiv: errorMessageDiv
    };
};

const activateDefaultViewPostScan = () => {
    document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
    const iamViewToShow = document.getElementById('iam-view');
    if (iamViewToShow) iamViewToShow.classList.remove('hidden');

    const sidebarLinks = document.querySelectorAll('#sidebar-nav a.main-nav-link');
    sidebarLinks.forEach(link => {
        link.classList.remove('bg-[#eb3496]');
        link.classList.add('hover:bg-[#1a335a]');
    });
    const activeIamLink = document.querySelector('#sidebar-nav a[data-view="iam"]');
    if (activeIamLink) {
        activeIamLink.classList.add('bg-[#eb3496]');
        activeIamLink.classList.remove('hover:bg-[#1a335a]');
    }
};

const runAnalysisFromInputs = async (source = 'main') => {
    const controls = getScanControls(source);
    const { runBtn, accessInput, secretInput, tokenInput, spinner, btnText, errorDiv } = controls;

    if (!runBtn || !accessInput || !secretInput || !spinner || !btnText || !errorDiv) return;

    if (source === 'landing') {
        syncCredentialsBetweenForms('landing');
    } else {
        syncCredentialsBetweenForms('main');
    }

    // Resetear estado
    window.iamApiData = null; window.securityHubApiData = null; window.exposureApiData = null; window.guarddutyApiData = null; window.wafApiData = null; window.cloudtrailApiData = null; window.cloudwatchApiData = null; window.inspectorApiData = null; window.acmApiData = null; window.computeApiData = null; window.databasesApiData = null; window.networkPoliciesApiData = null; window.connectivityApiData = null; window.playgroundApiData = null; window.allAvailableRegions = []; window.lastCloudtrailLookupResults = []; window.federationApiData = null; window.configSHApiData = null; window.configSHStatusApiData = null; window.kmsApiData = null; window.ecrApiData = null; window.codepipelineApiData = null; window.secretsManagerApiData = null; window.inventoryApiData = null;
    document.querySelectorAll('.view').forEach(v => v.replaceChildren());
    setHtml(document.getElementById('iam-view'), raw(createInitialEmptyState()));
    
    log('Starting full analysis...', 'info');
    const accessKey = accessInput.value.trim(); 
    const secretKey = secretInput.value.trim(); 
    const sessionToken = tokenInput.value.trim();
    if (!accessKey || !secretKey) { 
        const msg = 'Please enter the Access Key ID and Secret Access Key.'; 
        errorDiv.textContent = msg; 
        errorDiv.classList.remove('hidden'); 
        log(msg, 'error'); 
        return; 
    }
    const payload = { access_key: accessKey, secret_key: secretKey };
    if (sessionToken) { payload.session_token = sessionToken; }
    
    runBtn.disabled = true; 
    spinner.classList.remove('hidden'); 
    btnText.textContent = 'Scanning...'; 
    errorDiv.classList.add('hidden');
    
    try {
        log('Calling all AWS APIs...', 'info');
        window.activeScanId = crypto.randomUUID();
        const scanHeaders = { 'Content-Type': 'application/json', 'X-Scan-Id': window.activeScanId };
        const apiCalls = {
            iam: fetch(window.CONSTANTS.API.RUNS['/api/run-iam-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            accessAnalyzer: fetch(window.CONSTANTS.API.RUNS['/api/run-access-analyzer-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            securityhub: fetch(window.CONSTANTS.API.RUNS['/api/run-securityhub-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            exposure: fetch(window.CONSTANTS.API.RUNS['/api/run-exposure-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            guardduty: fetch(window.CONSTANTS.API.RUNS['/api/run-guardduty-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            waf: fetch(window.CONSTANTS.API.RUNS['/api/run-waf-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            cloudtrail: fetch(window.CONSTANTS.API.RUNS['/api/run-cloudtrail-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            cloudwatch: fetch(window.CONSTANTS.API.RUNS['/api/run-cloudwatch-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            inspector: fetch(window.CONSTANTS.API.RUNS['/api/run-inspector-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            acm: fetch(window.CONSTANTS.API.RUNS['/api/run-acm-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            compute: fetch(window.CONSTANTS.API.RUNS['/api/run-compute-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            ecr: fetch(window.CONSTANTS.API.RUNS['/api/run-ecr-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            databases: fetch(window.CONSTANTS.API.RUNS['/api/run-databases-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            network_policies: fetch(window.CONSTANTS.API.RUNS['/api/run-network-policies-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            federation: fetch(window.CONSTANTS.API.RUNS['/api/run-federation-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            config_sh_status: fetch(window.CONSTANTS.API.RUNS['/api/run-config-sh-status-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            kms: fetch(window.CONSTANTS.API.RUNS['/api/run-kms-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            secrets_manager: fetch(window.CONSTANTS.API.RUNS['/api/run-secrets-manager-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            connectivity: fetch(window.CONSTANTS.API.RUNS['/api/run-connectivity-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            codepipeline: fetch(window.CONSTANTS.API.RUNS['/api/run-codepipeline-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) }),
            inventory: fetch(window.CONSTANTS.API.RUNS['/api/run-inventory-audit'], { method: 'POST', headers: scanHeaders, body: JSON.stringify(payload) })
        };

        const totalTests = Object.keys(apiCalls).length;
        let completedTests = 0;
        log(`Progress: 0% (0/${totalTests})`, 'info');

        const getProgressPercent = () => Math.round((completedTests / totalTests) * 100);
        const testLabels = {
            iam: 'Identity & Access',
            accessAnalyzer: 'Access Analyzer',
            securityhub: 'Security Hub',
            exposure: 'Internet Exposure',
            guardduty: 'GuardDuty',
            waf: 'WAF',
            cloudtrail: 'CloudTrail',
            cloudwatch: 'CloudWatch',
            inspector: 'Inspector',
            acm: 'Certificate Manager',
            compute: 'Compute',
            ecr: 'Elastic Container Registry',
            databases: 'Databases',
            network_policies: 'Network Policies',
            federation: 'Federation',
            config_sh_status: 'Config & Security Hub Status',
            kms: 'KMS',
            secrets_manager: 'Secrets Manager',
            connectivity: 'Connectivity',
            codepipeline: 'CodePipeline',
            inventory: 'Inventory'
        };
        const formatTestLabel = (key) => testLabels[key] || key.replace(/_/g, ' ');
        
        const promises = Object.entries(apiCalls).map(async ([key, promise]) => {
            try { 
                const response = await promise; 
                if (!response.ok) { 
                    const errorData = await response.json(); 
                    throw new Error(errorData.error || `HTTP error! status: ${response.status}`); 
                } 
                const data = await response.json();
                completedTests += 1;
                log(`Progress: ${getProgressPercent()}% (${completedTests}/${totalTests}) - ${formatTestLabel(key)} done`, 'info');
                const coverage = coverageOf(data);
                if (isMigratedCollector(key) && (coverage.status !== 'complete' || !coverage.coverageKnown)) {
                    log(`${formatTestLabel(key)}: ${coverage.status}; review collection coverage`, 'warning');
                }
                return [key, data];
            } catch (error) { 
                log(`Error for API '${key}': ${error.message}`, 'error'); 
                completedTests += 1;
                log(`Progress: ${getProgressPercent()}% (${completedTests}/${totalTests}) - ${formatTestLabel(key)} failed`, 'warning');
                return [key, failedCollectionResponse(key, window.activeScanId)];
            }
        });

        const resolvedPromises = await Promise.all(promises);
        const results = Object.fromEntries(resolvedPromises);

        window.iamApiData = results.iam; 
        window.accessAnalyzerApiData = results.accessAnalyzer; 
        window.securityHubApiData = results.securityhub; 
        window.exposureApiData = results.exposure; 
        window.guarddutyApiData = results.guardduty; 
        window.wafApiData = results.waf; 
        window.cloudtrailApiData = results.cloudtrail; 
        window.cloudwatchApiData = results.cloudwatch; 
        window.inspectorApiData = results.inspector; 
        window.acmApiData = results.acm; 
        window.computeApiData = results.compute;
        window.ecrApiData = results.ecr;
        window.databasesApiData = results.databases; 
        window.networkPoliciesApiData = results.network_policies; 
        window.federationApiData = results.federation;
        window.configSHStatusApiData = results.config_sh_status; 
        window.kmsApiData = results.kms; 
        window.secretsManagerApiData = results.secrets_manager;
        window.connectivityApiData = results.connectivity;
        window.codepipelineApiData = results.codepipeline;
        window.inventoryApiData = results.inventory;
        window.lastAwsAccountId = window.iamApiData?.metadata?.accountId;
        window.regionsIncluded = window.iamApiData?.metadata?.regions || [];
        
        console.log('=== CODEPIPELINE ASSIGNMENT DEBUG ===');
        console.log('results.codepipeline:', results.codepipeline);
        console.log('window.codepipelineApiData after assignment:', window.codepipelineApiData);
        console.log('Has pipelines:', window.codepipelineApiData?.results?.pipelines?.length);
        console.log('=====================================');


        
        if (!window.iamApiData || !window.networkPoliciesApiData) { 
            throw new Error("One or more critical API calls failed. Cannot continue."); 
        }
        
        window.allAvailableRegions = window.networkPoliciesApiData?.results?.all_regions || [];
        log('All data has been received.', 'success');
        
        buildAndRenderAllViews();
        hasCompletedInitialScan = true;
        setWorkspaceVisibility(true);

        log('Activating the Identity & Access view post-scan...', 'info');
        activateDefaultViewPostScan();
    } catch (error) {
        const errorMsg = `Error: ${error.message || 'An unknown error occurred.'}`;
        console.error('Detailed Error:', error);
        errorDiv.textContent = errorMsg;
        errorDiv.classList.remove('hidden');
        log(`${errorMsg}`, 'error');
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Scan Account';
    }
};


const buildAndRenderAllViews = () => {
    const safeRender = (name, fn) => {
        try { fn(); } catch (e) { log(`Error rendering ${name}: ${e.message}`, 'error'); console.error(e); }
    };

    log('Rendering all views…', 'info');
    safeRender('inventory', buildInventoryView);
    safeRender('iam', buildIamView);
    safeRender('exposure', buildExposureView);
    safeRender('guardduty', buildGuarddutyView);
    safeRender('waf', buildWafView);
    safeRender('cloudtrail', buildCloudtrailView);
    safeRender('cloudwatch', buildCloudwatchView);
    safeRender('inspector', buildInspectorView);
    safeRender('acm', buildAcmView);
    safeRender('compute', buildComputeView);
    safeRender('ecr', buildEcrView);
    safeRender('databases', buildDatabasesView);
    safeRender('network-policies', buildNetworkPoliciesView);
    safeRender('config-sh', buildConfigSHView);
    safeRender('codepipeline', buildCodePipelineView);
    safeRender('auditor-notes', buildAuditorNotesView);
    safeRender('playground', buildPlaygroundView);
    safeRender('kms-secrets', buildKmsSecretsView);
    safeRender('connectivity', buildConnectivityView);
    log('Views rendered.', 'success');
};

const buildAuditorNotesView = () => {
    const container = document.getElementById('auditor-notes-view');
    if (!container) return;

    const scopedEntries = Object.entries(window.scopedResources || {});
    const notes = [...(window.auditorNotes || [])].sort((a, b) => {
        const aDate = new Date(a.lastModified || a.timestamp || 0).getTime();
        const bDate = new Date(b.lastModified || b.timestamp || 0).getTime();
        return bDate - aDate;
    });

    const scopedRows = scopedEntries.length
        ? scopedEntries.map(([arn, data]) => html`
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-3 text-xs text-gray-700 font-mono break-all">${arn}</td>
                <td class="px-4 py-3 text-sm text-gray-700 break-words">${data?.comment || ''}</td>
                <td class="px-4 py-3 text-sm text-right whitespace-nowrap">
                    <button ${act('openScopeModal', arn, encodeURIComponent(data?.comment || ''))} class="px-3 py-1.5 bg-blue-100 text-blue-700 rounded-md hover:bg-blue-200 mr-2">Edit</button>
                    <button ${act('removeResourceScope', arn)} class="px-3 py-1.5 bg-gray-100 text-gray-700 rounded-md hover:bg-gray-200">Remove</button>
                </td>
            </tr>
        `)
        : html`<tr><td colspan="3" class="px-4 py-8 text-center text-gray-500">No scoped resources yet.</td></tr>`;

    const noteRows = notes.length
        ? notes.map(note => html`
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-3 text-sm text-gray-700">${note.title || 'Untitled note'}</td>
                <td class="px-4 py-3 text-xs text-gray-600 font-mono break-all">${note.arn || '-'}</td>
                <td class="px-4 py-3 text-sm text-gray-600">${new Date(note.lastModified || note.timestamp).toLocaleString()}</td>
                <td class="px-4 py-3 text-sm text-right whitespace-nowrap">
                    <button ${act('showNoteDetails', note.id)} class="px-3 py-1.5 bg-slate-100 text-slate-700 rounded-md hover:bg-slate-200 mr-2">View</button>
                    <button ${act('openNotesModal', note.id)} class="px-3 py-1.5 bg-blue-100 text-blue-700 rounded-md hover:bg-blue-200 mr-2">Edit</button>
                    <button ${act('deleteAuditorNote', note.id)} class="px-3 py-1.5 bg-red-100 text-red-700 rounded-md hover:bg-red-200">Delete</button>
                </td>
            </tr>
        `)
        : html`<tr><td colspan="4" class="px-4 py-8 text-center text-gray-500">No notes available yet.</td></tr>`;

    setHtml(container, html`
        <header class="flex flex-wrap items-center justify-between gap-3 mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Auditor Notes</h2>
                <p class="text-sm text-gray-500">Centralized workspace for scoped resources and audit notes.</p>
            </div>
            <button id="auditor-new-note-btn" class="bg-[#eb3496] text-white px-4 py-2 rounded-lg font-bold hover:bg-[#d42c86] transition">New Note</button>
        </header>

        <section class="bg-white rounded-xl border border-gray-200 shadow-sm mb-6">
            <div class="px-5 py-4 border-b border-gray-100">
                <h3 class="font-bold text-[#204071]">In-Scope Resources (${scopedEntries.length})</h3>
                <p class="text-xs text-gray-500 mt-1">Each scoped resource requires a reason. You can edit it anytime.</p>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Resource ARN</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reason</th>
                            <th class="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-100">${scopedRows}</tbody>
                </table>
            </div>
        </section>

        <section class="bg-white rounded-xl border border-gray-200 shadow-sm">
            <div class="px-5 py-4 border-b border-gray-100">
                <h3 class="font-bold text-[#204071]">Written Notes (${notes.length})</h3>
                <p class="text-xs text-gray-500 mt-1">Includes manual notes created by the auditor.</p>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Title</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Resource ARN</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Update</th>
                            <th class="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-100">${noteRows}</tbody>
                </table>
            </div>
        </section>
    `);

    const addBtn = document.getElementById('auditor-new-note-btn');
    if (addBtn) {
        addBtn.addEventListener('click', () => openNotesModal());
    }
};

const createInitialEmptyState = () => `<div class="text-center py-16 bg-white rounded-lg">
    <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="mx-auto h-12 w-12 text-gray-400" viewBox="0 0 16 16">
        <path d="M8 16c3.314 0 6-2 6-5.5 0-1.5-.5-4-2.5-6 .25 1.5-1.25 2-1.25 2C11 4 9 .5 6 0c.357 2 .5 4-2 6-1.25 1-2 2.729-2 4.5C2 14 4.686 16 8 16m0-1c-1.657 0-3-1-3-2.75 0-.75.25-2 1.25-3C6.125 10 7 10.5 7 10.5c-.375-1.25.5-3.25 2-3.5-.179 1-.25 2 1 3 .625.5 1 1.364 1 2.25C11 14 9.657 15 8 15"/>
    </svg>
    <h3 class="mt-2 text-lg font-medium text-[#204071]">Scan required</h3>
    <p class="mt-1 text-sm text-gray-500">Complete an account scan to unlock this view.</p>
</div>`;




const exportResultsToJson = () => {
    if (!window.iamApiData) {
        alert("Aviso: Debes ejecutar un análisis primero antes de exportar los resultados.");
        return;
    }

    let scanType = "fast";
    if (window.configSHApiData || (window.inspectorApiData && window.inspectorApiData.results.findings && window.inspectorApiData.results.findings.length > 0)) {
        scanType = "deep";
    }
    
    const accountId = window.iamApiData.metadata.accountId;
    const accountAlias = window.federationApiData?.results?.iam_federation?.account_alias || "NoAlias";
    const timestamp = window.iamApiData.metadata.executionDate;

    const exportData = {
        metadata: {
            accountId: accountId,
            accountAlias: accountAlias,
            analysisTimestamp: timestamp,
            analysisType: scanType,
            exportTimestamp: new Date().toISOString()
        },
        results: {
            iam: window.iamApiData?.results || null,
            federation: window.federationApiData?.results || null,
            accessAnalyzer: window.accessAnalyzerApiData?.results || null,
            securityhub: window.securityHubApiData?.results || null,
            exposure: window.exposureApiData?.results || null,
            guardduty: window.guarddutyApiData?.results || null,
            waf: window.wafApiData?.results || null,
            cloudtrail: window.cloudtrailApiData?.results || null,
            cloudwatch: window.cloudwatchApiData?.results || null,
            inspector: window.inspectorApiData?.results || null,
            acm: window.acmApiData?.results || null,
            compute: window.computeApiData?.results || null,
            ecr: window.ecrApiData?.results || null,
            databases: window.databasesApiData?.results || null,
            networkPolicies: window.networkPoliciesApiData?.results || null,
            configAndSecurityHubStatus: window.configSHStatusApiData?.results || null,
            configAndSecurityHubDeepScan: window.configSHApiData?.results || null,
            kms: window.kmsApiData?.results || null,
            secretsManager: window.secretsManagerApiData?.results || null,
            playground: {
                traceroute: window.playgroundApiData?.results || null
            },
            connectivity: window.connectivityApiData?.results || null,
            codepipeline: window.codepipelineApiData?.results || null,
            inventory: window.inventoryApiData?.results || null,
            audiThorScopeData: window.scopedResources,
            audiThorAuditorNotes: window.auditorNotes || []
        }
    };
    
    const filename = `${accountId}_${accountAlias}_${scanType}.json`;
    const jsonString = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    log(`Results successfully exported to the file: ${filename}`, 'success');
};


const handleJsonImport = (event) => {
    const file = event.target.files[0];
    if (file && !isImportFileSizeAllowed(file.size)) {
        log('Import rejected: file exceeds the 200 MiB size limit.', 'error');
        return;
    }
    if (!file) {
        log('No file selected.', 'info');
        return;
    }

    log(`Loading file: ${file.name}...`, 'info');
    const reader = new FileReader();

    reader.onload = (e) => {
        try {
            const importedData = JSON.parse(e.target.result);

            if (!validateImportShape(importedData)) {
                throw new Error("The JSON file does not have the expected structure. (metadata/results).");
            }

            log(`JSON file parsed successfully. Account: ${importedData.metadata.accountId}`, 'info');

            const results = importedData.results;
            const metadata = { accountId: importedData.metadata.accountId, executionDate: importedData.metadata.analysisTimestamp };

            // Asignar todos los datos globales
            window.iamApiData = results.iam ? { metadata: metadata, results: results.iam } : null;
            window.federationApiData = results.federation ? { metadata: metadata, results: results.federation } : null;
            window.accessAnalyzerApiData = results.accessAnalyzer ? { metadata: metadata, results: results.accessAnalyzer } : null;
            window.securityHubApiData = results.securityhub ? { metadata: metadata, results: results.securityhub } : null;
            window.exposureApiData = results.exposure ? { metadata: metadata, results: results.exposure } : null;
            window.guarddutyApiData = results.guardduty ? { metadata: metadata, results: results.guardduty } : null;
            window.wafApiData = results.waf ? { metadata: metadata, results: results.waf } : null;
            window.cloudtrailApiData = results.cloudtrail ? { metadata: metadata, results: results.cloudtrail } : null;
            window.cloudwatchApiData = results.cloudwatch ? { metadata: metadata, results: results.cloudwatch } : null;
            window.inspectorApiData = results.inspector ? { metadata: metadata, results: results.inspector } : null;
            window.acmApiData = results.acm ? { metadata: metadata, results: results.acm } : null;
            window.computeApiData = results.compute ? { metadata: metadata, results: results.compute } : null;
            window.ecrApiData = results.ecr ? { metadata: metadata, results: results.ecr } : null;
            window.databasesApiData = results.databases ? { metadata: metadata, results: results.databases } : null;
            window.networkPoliciesApiData = results.networkPolicies ? { metadata: metadata, results: results.networkPolicies } : null;
            window.configSHStatusApiData = results.configAndSecurityHubStatus ? { metadata: metadata, results: results.configAndSecurityHubStatus } : null;
            window.configSHApiData = results.configAndSecurityHubDeepScan ? { metadata: metadata, results: results.configAndSecurityHubDeepScan } : null;
            window.kmsApiData = results.kms ? { metadata: metadata, results: results.kms } : null;
            window.secretsManagerApiData = results.secretsManager ? { metadata: metadata, results: results.secretsManager } : null;
            window.connectivityApiData = results.connectivity ? { metadata: metadata, results: results.connectivity } : null;
            window.codepipelineApiData = results.codepipeline ? { metadata: metadata, results: results.codepipeline } : null;
            window.inventoryApiData = results.inventory ? { metadata: metadata, results: results.inventory } : null;
            



            const playgroundImportData = results.playground || {};
            window.playgroundApiData = {
                metadata: metadata,
                ...playgroundStateFromImport(playgroundImportData)
            };
            
            window.allAvailableRegions = window.networkPoliciesApiData?.results?.all_regions || [];

            log('Data imported into the application state.', 'success');
            
            if (isValidScopeData(results.audiThorScopeData)) {
                window.scopedResources = results.audiThorScopeData;
                saveScopedResources(); // Guardarlo en localStorage
                log(`Importados ${Object.keys(window.scopedResources).length} recursos marcados.`, 'success');
            } else {
                if (results.audiThorScopeData !== undefined) log('Ignoring invalid imported scope data.', 'warning');
                window.scopedResources = {}; // Limpiar si el fichero no tiene datos de scope
                saveScopedResources();
            }

            if (results.audiThorAuditorNotes) {
                // Solo carga las notas si existen en el fichero importado.
                window.auditorNotes = results.audiThorAuditorNotes;
                saveAuditorNotes(); 
                log(`Importadas ${window.auditorNotes.length} notas del auditor desde el fichero.`, 'success');
            } else {
                // Si el fichero no tiene notas, LIMPIAR las actuales en lugar de mantenerlas
                window.auditorNotes = [];
                saveAuditorNotes();
                log('Notas del auditor limpiadas al importar nuevo cliente.', 'info');
            }



            // 1. Construir el contenido de todas las vistas en segundo plano
            buildAndRenderAllViews();
            
            // 2. Ejecutar lógicas adicionales que puedan ser necesarias

            // 3. ELIMINADO: Ya no necesitamos llamar buildCloudtrailView() por segunda vez
            // porque ya se ejecuta en buildAndRenderAllViews() y manejará los datos importados

            // 4. Asegurarse de que se muestra la vista correcta
            log('Activating the Identity & Access view post-import...', 'info');
            hasCompletedInitialScan = true;
            setWorkspaceVisibility(true);
            activateDefaultViewPostScan();

        } catch (error) {
            log(`Error importing the JSON file: ${error.message}`, 'error');
            console.error(error);
            errorMessageDiv.textContent = 'Error: El fichero seleccionado no es un JSON válido o tiene un formato incorrecto.';
            errorMessageDiv.classList.remove('hidden');
        }
    };

    reader.onerror = () => {
        log('Error reading the file.', 'error');
        errorMessageDiv.textContent = 'Error: No se pudo leer el fichero seleccionado.';
        errorMessageDiv.classList.remove('hidden');
    };

    reader.readAsText(file);
    event.target.value = '';
};



const populateGeminiRegionFilter = (findings) => {
    const select = document.getElementById('gemini-region-filter');
    if (!select) return;

    const regions = new Set();
    regions.add('all');
    findings.forEach(finding => {
        finding.affected_resources.forEach(res => {
            if (res.region) {
                regions.add(res.region);
            }
        });
    });

    // Clear existing options except "All Regions"
    setHtml(select, html`<option value="all">All Regions</option>`);
    
    const sortedRegions = Array.from(regions).sort();
    sortedRegions.forEach(region => {
        if (region !== 'all') {
            const option = document.createElement('option');
            option.value = region;
            option.textContent = region;
            select.appendChild(option);
        }
    });
};

// app.js

// AÑADE ESTAS DOS NUEVAS FUNCIONES:
const showNoteDetails = (noteId) => {
    const modal = document.getElementById('note-details-modal');
    const titleEl = document.getElementById('note-details-title');
    const contentEl = document.getElementById('note-details-content');
    const closeBtn = document.getElementById('note-details-close-btn');
    const editBtn = document.getElementById('note-details-edit-btn');
    const deleteBtn = document.getElementById('note-details-delete-btn');

    const note = window.auditorNotes.find(n => n.id === noteId);
    if (!note) return;

    titleEl.textContent = note.title;

    const arnHtml = note.arn ? html`
        <div class="mt-2">
            <p class="font-semibold text-gray-700">Recurso Asociado:</p>
            <code class="text-xs text-gray-800 bg-gray-100 p-2 rounded-md block break-all">${note.arn}</code>
        </div>
    ` : '';

    setHtml(contentEl, html`
        <p class="font-semibold text-gray-700">Observaciones:</p>
        <div class="text-gray-800 bg-gray-50 p-3 rounded-md border">${note.content.split('\n').map((line, index) => html`${index ? raw('<br>') : ''}${line}`)}</div>
        ${arnHtml}
        <p class="text-xs text-gray-400 mt-4">Creada: ${new Date(note.timestamp).toLocaleString()}</p>
    `);

    // Limpiamos listeners para evitar duplicados
    const newEditBtn = editBtn.cloneNode(true);
    editBtn.parentNode.replaceChild(newEditBtn, editBtn);
    newEditBtn.addEventListener('click', () => {
        modal.classList.add('hidden'); // Ocultamos el modal de detalles
        openNotesModal(noteId); // Abrimos el modal de edición
    });

    const newDeleteBtn = deleteBtn.cloneNode(true);
    deleteBtn.parentNode.replaceChild(newDeleteBtn, deleteBtn);
    newDeleteBtn.addEventListener('click', () => deleteAuditorNote(noteId));

    closeBtn.addEventListener('click', () => modal.classList.add('hidden')); 
    modal.classList.remove('hidden');
};

const deleteAuditorNote = (noteId) => {
    const confirmation = confirm('¿Estás seguro de que quieres eliminar esta nota? Esta acción no se puede deshacer.');
    if (confirmation) {
        const noteIndex = window.auditorNotes.findIndex(note => note.id === noteId);
        if (noteIndex > -1) {
            window.auditorNotes.splice(noteIndex, 1);
            saveAuditorNotes();
            rerenderCurrentView();
            log(`Nota con ID ${noteId} eliminada.`, 'success');
            
            // Cerramos el modal de detalles si está abierto
            const modal = document.getElementById('note-details-modal');
            if (modal) modal.classList.add('hidden');

        } else {
            log(`Error: No se pudo eliminar la nota con ID ${noteId}`, 'error');
        }
    }
};



// 5. PUNTO DE ENTRADA
document.addEventListener('DOMContentLoaded', () => {
    installActionDelegation();
    landingView = document.getElementById('landing-view');
    mainAppView = document.getElementById('main-app-view');
    landingRunAnalysisBtn = document.getElementById('landing-run-analysis-button');
    landingImportResultsBtn = document.getElementById('landing-import-results-button');
    landingAccessKeyInput = document.getElementById('landing-access-key-input');
    landingSecretKeyInput = document.getElementById('landing-secret-key-input');
    landingSessionTokenInput = document.getElementById('landing-session-token-input');
    landingLoadingSpinner = document.getElementById('landing-loading-spinner');
    landingButtonText = document.getElementById('landing-button-text');
    landingErrorMessageDiv = document.getElementById('landing-error-message');

    // Inicializar selectores
    views = document.querySelectorAll('.view');
    mainNavLinks = document.querySelectorAll('.main-nav-link');
    runAnalysisBtn = document.getElementById('run-analysis-button');
    accessKeyInput = document.getElementById('access-key-input');
    secretKeyInput = document.getElementById('secret-key-input');
    sessionTokenInput = document.getElementById('session-token-input');
    loadingSpinner = document.getElementById('loading-spinner');
    buttonText = document.getElementById('button-text');
    errorMessageDiv = document.getElementById('error-message');
    logContainer = document.getElementById('log-container');
    clearLogBtn = document.getElementById('clear-log-btn');
    toggleLogBtn = document.getElementById('toggle-log-btn');
    logPanel = document.getElementById('log-panel');
    loadScopedResources();
    loadAuditorNotes();

    // Cargar iconos de la barra lateral
    loadSidebarIcons();

    // Configurar navegación principal
    const sidebarNav = document.getElementById('sidebar-nav');
    if (sidebarNav) {
        sidebarNav.addEventListener('click', handleMainNavClick);
    }

    // Configurar botón de notas
const openNotesButton = document.getElementById('open-notes-btn');
if (openNotesButton) {
    openNotesButton.addEventListener('click', () => {
        openNotesModal();
    });
}


    // Configurar botón de análisis
    if (runAnalysisBtn) {
        runAnalysisBtn.addEventListener('click', () => runAnalysisFromInputs('main'));
    }

    if (landingRunAnalysisBtn) {
        landingRunAnalysisBtn.addEventListener('click', () => runAnalysisFromInputs('landing'));
    }

    // Configurar botones de importación/exportación
    const exportBtn = document.getElementById('export-results-button');
    const importBtn = document.getElementById('import-results-button');
    const fileInput = document.getElementById('json-file-input');

    if (exportBtn) {
        exportBtn.addEventListener('click', exportResultsToJson);
    }

    if (importBtn && fileInput) {
        importBtn.addEventListener('click', () => fileInput.click());
        fileInput.addEventListener('change', handleJsonImport);
    }

    if (landingImportResultsBtn && fileInput) {
        landingImportResultsBtn.addEventListener('click', () => fileInput.click());
    }

    // Configurar controles del log
    if (clearLogBtn) {
        clearLogBtn.addEventListener('click', () => {
            if (logContainer) {
                logContainer.replaceChildren();
                // Remover la clase de nuevo log si existe
                if (logPanel) {
                    logPanel.classList.remove('new-log');
                }
            }
        });
    }

    if (toggleLogBtn && logPanel) {
        toggleLogBtn.addEventListener('click', (e) => {
            e.stopPropagation(); // Evitar que se propague al panel
            minimizeLogPanel();
        });

        // Click en el panel flotante para maximizar
        logPanel.addEventListener('click', (e) => {
            if (logPanel.classList.contains('floating')) {
                e.stopPropagation();
                maximizeLogPanel();
            }
        });
    }

    // 3. AÑADE estas dos funciones nuevas después de la sección anterior:

    // Función para minimizar el panel (convertir a flotante)
    function minimizeLogPanel() {
        if (logPanel) {
            logPanel.classList.remove('minimized');
            logPanel.classList.add('floating');
            
            if (toggleLogBtn) {
                toggleLogBtn.textContent = 'Show Log';
            }
            
            log('Event Log minimized to floating button', 'info');
        }
    }

    // Función para maximizar el panel (volver al estado normal)
    function maximizeLogPanel() {
        if (logPanel) {
            logPanel.classList.remove('floating', 'new-log');
            
            if (toggleLogBtn) {
                toggleLogBtn.textContent = 'Minimize';
            }
            
            log('Event Log expanded', 'info');
        }
    }

    // Configurar modal
    setupModalControls();

    // Inicializar vistas vacías
    views.forEach(view => {
        if (view.id !== 'iam-view') {
            setHtml(view, raw(createInitialEmptyState()));
        }
    });

    setWorkspaceVisibility(false);
    minimizeLogPanel();
    
    log('Application initialized successfully.', 'success');
});

// --- SELECTOR VISUAL GLOBAL ---
let selectorMode = false;
let originalStyles = new Map();

window.activateElementSelector = () => {
    if (selectorMode) return; // Ya está activo
    
    selectorMode = true;
    document.body.style.cursor = 'crosshair';
    document.body.classList.add('element-selector-mode');
    
    // Overlay de instrucciones
    const overlay = document.createElement('div');
    overlay.id = 'selector-overlay';
    setHtml(overlay, html`
        <div class="fixed top-4 left-1/2 transform -translate-x-1/2 bg-[#eb3496] text-white px-4 py-2 rounded-lg shadow-lg z-50">
            Click on any element to capture evidence | Press ESC to cancel
        </div>`);
    document.body.appendChild(overlay);
    
    // Event listeners globales
    document.addEventListener('mouseover', highlightElement, true);
    document.addEventListener('mouseout', removeHighlight, true);
    document.addEventListener('click', captureElementOnClick, true);
    document.addEventListener('keydown', handleSelectorKeydown);
};

const highlightElement = (e) => {
    if (!selectorMode) return;
    
    // Guardar estilo original
    originalStyles.set(e.target, {
        outline: e.target.style.outline,
        backgroundColor: e.target.style.backgroundColor
    });
    
    // Aplicar highlight
    e.target.style.outline = '2px solid #eb3496';
    e.target.style.backgroundColor = 'rgba(235, 52, 150, 0.1)';
};

const removeHighlight = (e) => {
    if (!selectorMode) return;
    
    // Restaurar estilo original
    const original = originalStyles.get(e.target);
    if (original) {
        e.target.style.outline = original.outline;
        e.target.style.backgroundColor = original.backgroundColor;
        originalStyles.delete(e.target);
    }
};

const captureElementOnClick = (e) => {
    if (!selectorMode) return;
    
    e.preventDefault();
    e.stopPropagation();
    
    const evidence = extractElementEvidence(e.target);
    deactivateElementSelector();
    openNotesModalWithEvidence(evidence);
};


const deactivateElementSelector = () => {
    selectorMode = false;
    document.body.style.cursor = '';
    document.body.classList.remove('element-selector-mode');
    
    // Limpiar overlay
    const overlay = document.getElementById('selector-overlay');
    if (overlay) overlay.remove();
    
    // IMPORTANTE: Limpiar todos los estilos pendientes ANTES de remover listeners
    originalStyles.forEach((originalStyle, element) => {
        element.style.outline = originalStyle.outline;
        element.style.backgroundColor = originalStyle.backgroundColor;
    });
    originalStyles.clear();
    
    // Remover event listeners
    document.removeEventListener('mouseover', highlightElement, true);
    document.removeEventListener('mouseout', removeHighlight, true);
    document.removeEventListener('click', captureElementOnClick, true);
    document.removeEventListener('keydown', handleSelectorKeydown);
};

const handleSelectorKeydown = (e) => {
    if (e.key === 'Escape') {
        deactivateElementSelector();
    }
};


const extractElementEvidence = (element) => {
    const currentView = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]')?.dataset.view;
    const activeTab = document.querySelector('.tab-link.border-\\[\\#eb3496\\]')?.textContent?.trim();
    
    let evidence = {
        timestamp: new Date().toISOString(),
        section: getCurrentSectionName(),
        subSection: activeTab,
        elementType: 'Unknown Element',
        data: {},
        rawHTML: element.outerHTML.substring(0, 500) // Backup of captured markup
    };
    
    // Detectar automáticamente el tipo de elemento
    const row = element.closest('tr');
    const card = element.closest('.bg-white');
    
    // PATRÓN: Filas de tabla
    if (row && row.closest('tbody')) {
        evidence = {
            ...evidence,
            ...extractTableRowData(row, currentView)
        };
    }
    
    // PATRÓN: Cards/badges
    else if (element.closest('.bg-yellow-200') || element.textContent.includes('VIP')) {
        evidence = {
            ...evidence,
            elementType: 'Privileged User Badge',
            data: { issue: 'Privileged user detected', element: element.textContent.trim() }
        };
    }
    
    // PATRÓN: Status badges
    else if (element.closest('.bg-red-100') || element.textContent.includes('NO')) {
        evidence = {
            ...evidence,
            elementType: 'Security Issue Badge',
            data: { issue: 'Negative security indicator', status: element.textContent.trim() }
        };
    }
    
    return evidence;
};

const extractTableRowData = (row, currentView) => {
    const cells = Array.from(row.querySelectorAll('td')).map(td => td.textContent.trim());
    
    // Mapeo específico por vista
    const extractors = {
        'iam': extractIamUserRow,
        'acm': extractAcmCertRow,
        'compute': extractComputeRow,
        'databases': extractDatabaseRow
    };
    
    const extractor = extractors[currentView] || extractGenericRow;
    return extractor(cells, row);
};

// Agregar después de extractAcmCertRow
const extractComputeRow = (cells, row) => {
    return {
        elementType: 'Compute Resource',
        data: {
            identifier: cells[1],
            region: cells[0],
            status: cells[4] || 'Unknown',
            issue: cells[4]?.includes('stopped') ? 'Instance stopped' : null
        }
    };
};

const extractDatabaseRow = (cells, row) => {
    return {
        elementType: 'Database Resource',
        data: {
            identifier: cells[1],
            region: cells[0],
            status: cells[2],
            issue: cells[3]?.includes('YES') ? 'Publicly accessible' : null
        }
    };
};

const extractGenericRow = (cells, row) => {
    return {
        elementType: 'Table Row',
        data: {
            values: cells,
            cellCount: cells.length
        }
    };
};

const getCurrentSectionName = () => {
    const activeView = document.querySelector('#sidebar-nav a.bg-\\[\\#eb3496\\]');
    return activeView?.querySelector('div:last-child')?.textContent || 'Unknown Section';
};

const openNotesModalWithEvidence = (evidence) => {
    // Reutilizar la función existente que ya tiene todos los event listeners funcionando
    openNotesModal();
    
    // Esperar a que se abra el modal y luego pre-llenar los campos
    setTimeout(() => {
        const titleInput = document.getElementById('notes-modal-title-input');
        const arnInput = document.getElementById('notes-modal-arn-input');
        const textarea = document.getElementById('notes-modal-textarea');
        
        // Pre-llenar con los datos capturados
        titleInput.value = `Issue found: ${evidence.data.issue || evidence.elementType}`;
        arnInput.value = evidence.data.arn || '';
        
        const evidenceText = `EVIDENCE CAPTURED:
Timestamp: ${evidence.timestamp}
Section: ${evidence.section}
Sub-section: ${evidence.subSection || 'Main view'}
Element Type: ${evidence.elementType}

Details:
${JSON.stringify(evidence.data, null, 2)}

Additional Notes:
`;
        
        textarea.value = evidenceText;
        textarea.focus();
        textarea.setSelectionRange(textarea.value.length, textarea.value.length);
    }, 100);
};

const extractIamUserRow = (cells, row) => {
    return {
        elementType: 'IAM User',
        data: {
            username: cells[0]?.replace('VIP', '').trim(),
            passwordEnabled: cells[1],
            mfaEnabled: cells[3]?.includes('NO') ? 'NO MFA' : 'MFA Enabled',
            isPrivileged: row.querySelector('.bg-yellow-200') ? true : false,
            issue: cells[3]?.includes('NO') ? 'MFA not enabled' : null
        }
    };
};

const extractAcmCertRow = (cells, row) => {
    return {
        elementType: 'ACM Certificate',
        data: {
            domain: cells[1],
            region: cells[2],
            status: cells[3],
            expirationDate: cells[6],
            issue: cells[3]?.includes('EXPIRED') ? 'Certificate expired' : null
        }
    };
};


// 6. EXPOSICIÓN DE FUNCIONES GLOBALES
window.openModalWithSsoDetails = openModalWithSsoDetails;
window.openModalWithAccessKeyDetails = openModalWithAccessKeyDetails;
window.openModalWithUserGroups = openModalWithUserGroups;
window.openModalWithEc2Tags = openModalWithEc2Tags;
window.openModalWithLambdaTags = openModalWithLambdaTags;
window.openModalWithTlsDetails = openModalWithTlsDetails;
window.openModalWithResourceMap = openModalWithResourceMap;
window.toggleAlarmDetails = toggleAlarmDetails;
window.showCloudtrailEventDetails = showCloudtrailEventDetails;
window.openModalWithKmsPolicy = openModalWithKmsPolicy;
window.openModalWithLambdaRole = openModalWithLambdaRole;
window.openModalWithEcrPolicy = openModalWithEcrPolicy;
window.copyToClipboard = copyToClipboard;
window.buildCodePipelineView = buildCodePipelineView;
window.openModalWithUserRoles = openModalWithUserRoles;
window.openModalWithSecretDetails = openModalWithSecretDetails;
window.openScopeModal = openScopeModal;
window.removeResourceScope = removeResourceScope;
window.openNotesModal = openNotesModal;
window.showNoteDetails = showNoteDetails;
window.deleteAuditorNote = deleteAuditorNote;
window.openModalWithVpcTags = openModalWithVpcTags;
