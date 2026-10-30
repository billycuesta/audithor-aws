/**
 * 13_network_policies.js
 * Contiene toda la lógica para construir y renderizar la vista de Network Security Policies.
 */

// --- IMPORTACIONES ---
import { handleTabClick, log } from '../utils.js';


// --- FUNCIÓN PRINCIPAL DE LA VISTA (EXPORTADA) ---
export const buildNetworkPoliciesView = (forceTab = null) => {
    console.log('%c[NETWORK VIEW] buildNetworkPoliciesView() has been executed!', 'color: #eb3496; font-weight: bold;');
    const container = document.getElementById('network-policies-view');
    let activeTabData = forceTab;
    if (!activeTabData) {
        const activeTabEl = container.querySelector('#network-policies-tabs .border-\\[\\#eb3496\\]');
        activeTabData = activeTabEl ? activeTabEl.dataset.tab : 'np-summary-content';
    }
    if (!window.networkPoliciesApiData || !window.computeApiData || !window.databasesApiData) {
        container.innerHTML = '<p class="text-center text-gray-500">Network Policies, Compute, or Databases data not available.</p>';
        return;
    }

    const { vpcs, acls, security_groups, subnets, all_regions } = window.networkPoliciesApiData.results;
    const { ec2_instances, lambda_functions } = window.computeApiData.results;
    const { rds_instances, aurora_clusters } = window.databasesApiData.results;
    const nat_gateways = window.networkPoliciesApiData.results.nat_gateways || [];

    const allResources = {
        ec2: ec2_instances, lambda: lambda_functions,
        rds: rds_instances, aurora: aurora_clusters
    };

    container.innerHTML = `
        <h2 class="text-2xl font-bold text-[#204071] mb-2">Network Security Policies</h2>
        <p class="text-sm text-gray-500 mb-6">${window.networkPoliciesApiData.metadata.executionDate}</p>

        <div class="mt-8">
            <div class="border-b border-gray-200">
                <nav id="network-policies-tabs" class="-mb-px flex space-x-8" aria-label="Tabs">
                    <a href="#" data-tab="np-summary-content" class="tab-link whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm border-[#eb3496] text-[#eb3496]">Summary</a>
                    <a href="#" data-tab="np-vpcs-content" class="tab-link whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300">VPCs (${vpcs.length})</a>
                    <a href="#" data-tab="np-acls-content" class="tab-link whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300">Network ACLs (${acls.length})</a>
                    <a href="#" data-tab="np-sgs-content" class="tab-link whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300">Security Groups (${security_groups.length})</a>
                    <a href="#" data-tab="np-detail-content" class="tab-link whitespace-nowrap py-4 px-1 border-b-2 font-medium text-sm border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300">Details</a>
                </nav>
            </div>
            <div id="network-policies-tab-content-container" class="py-6">
                <div id="np-summary-content" class="network-policies-tab-content">
                    <div id="np-summary-cards"></div>
                    <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 mt-8">
                        <div class="flex justify-between items-center mb-4">
                            <h3 class="font-bold text-lg text-[#204071]">Network Diagram</h3>
                            <div class="flex items-center gap-2">
                                <input type="checkbox" id="vpc-diagram-hide-empty-filter" class="h-4 w-4 rounded border-gray-300 text-[#eb3496] focus:ring-[#eb3496]">
                                <label for="vpc-diagram-hide-empty-filter" class="text-sm font-medium text-gray-700">Hide Empty VPCs</label>
                            </div>
                        </div>
                        <div id="np-diagram-container"></div>
                    </div>
                </div>
                <div id="np-vpcs-content" class="network-policies-tab-content hidden"></div>
                <div id="np-acls-content" class="network-policies-tab-content hidden"></div>
                <div id="np-sgs-content" class="network-policies-tab-content hidden"></div>
                <div id="np-detail-content" class="network-policies-tab-content hidden"></div>
            </div>
        </div>
    `;

    const summaryCardsContainer = document.getElementById('np-summary-cards');
    const diagramContainer = document.getElementById('np-diagram-container');
    const vpcsContainer = document.getElementById('np-vpcs-content');
    const aclsContainer = document.getElementById('np-acls-content');
    const sgsContainer = document.getElementById('np-sgs-content');
    const detailContainer = document.getElementById('np-detail-content');

    const applySgFiltersAndRender = () => {
        const selectedRegion = document.getElementById('sg-region-filter').value;
        const hideEmpty = document.getElementById('sg-hide-empty-filter').checked;
        const searchTerm = document.getElementById('sg-text-filter')?.value.toLowerCase().trim() || '';

        let filteredSGs = security_groups.filter(sg => selectedRegion === 'all' || sg.Region === selectedRegion);

        if (searchTerm) {
            filteredSGs = filteredSGs.filter(sg => 
                sg.GroupName.toLowerCase().includes(searchTerm) ||
                sg.GroupId.toLowerCase().includes(searchTerm) ||
                sg.VpcId.toLowerCase().includes(searchTerm)
            );
        }

        if (hideEmpty) {
            filteredSGs = filteredSGs.filter(sg => {
                const ec2Count = allResources.ec2.filter(i => i.Region === sg.Region && i.SecurityGroups.includes(sg.GroupId)).length;
                const lambdaCount = allResources.lambda.filter(l => l.Region === sg.Region && l.VpcConfig?.SecurityGroupIds?.includes(sg.GroupId)).length;
                const rdsCount = allResources.rds.filter(r => r.Region === sg.Region && r.SecurityGroupIds?.includes(sg.GroupId)).length;
                const auroraCount = allResources.aurora.filter(a => a.Region === sg.Region && a.SecurityGroupIds?.includes(sg.GroupId)).length;
                return (ec2Count + lambdaCount + rdsCount + auroraCount) > 0;
            });
        }
        
        sgsContainer.innerHTML = renderSGsTable(filteredSGs, all_regions, selectedRegion, allResources, hideEmpty);
        const textFilterInput = document.getElementById('sg-text-filter');
        if(textFilterInput) textFilterInput.value = searchTerm;

    };

    summaryCardsContainer.innerHTML = createNetworkPoliciesSummaryCardsHtml();
    updateNetworkPoliciesSummaryCards(vpcs, acls, security_groups);
    diagramContainer.innerHTML = renderVpcDiagram(vpcs, subnets, ec2_instances, lambda_functions, rds_instances, aurora_clusters, nat_gateways);
    
    vpcsContainer.innerHTML = renderVPCsTable(vpcs, all_regions, 'all');
    aclsContainer.innerHTML = renderACLsTable(acls, all_regions, 'all');
    sgsContainer.innerHTML = renderSGsTable(security_groups, all_regions, 'all', allResources, false);
    detailContainer.innerHTML = renderNetworkDetailView(all_regions || []);


    const runDetailBtn = document.getElementById('np-run-detail-btn');
        if (runDetailBtn) {
            runDetailBtn.addEventListener('click', runNetworkDetailAnalysis);
        }



const applyVpcDiagramFiltersAndRender = () => {
    const hideEmpty = document.getElementById('vpc-diagram-hide-empty-filter')?.checked || false;
    let vpcsToRender = vpcs;
    if (hideEmpty) {
        vpcsToRender = vpcsToRender.filter(vpc => {
            const hasEc2 = allResources.ec2.some(i => {
                const subnet = subnets.find(s => s.SubnetId === i.SubnetId);
                return subnet?.VpcId === vpc.VpcId;
            });
            const hasLambda = allResources.lambda.some(l => l.VpcConfig?.VpcId === vpc.VpcId);
            const hasRds = allResources.rds.some(r => r.VpcId === vpc.VpcId);
            const hasAurora = allResources.aurora.some(a => a.VpcId === vpc.VpcId);
            const hasNatGw = nat_gateways.some(ng => ng.VpcId === vpc.VpcId); // <-- AÑADIR ESTA LÍNEA
            return hasEc2 || hasLambda || hasRds || hasAurora || hasNatGw ;
        });
    }
    diagramContainer.innerHTML = renderVpcDiagram(vpcsToRender, subnets, ec2_instances, lambda_functions, rds_instances, aurora_clusters, nat_gateways);
};

// Inicializar el diagrama con el filtro predeterminado
applyVpcDiagramFiltersAndRender();

container.addEventListener('change', (e) => {
    const selectedRegion = e.target.value;
    switch (e.target.id) {
        case 'vpc-region-filter':
            vpcsContainer.innerHTML = renderVPCsTable(vpcs.filter(v => selectedRegion === 'all' || v.Region === selectedRegion), all_regions, selectedRegion);
            break;
        case 'acl-region-filter':
            aclsContainer.innerHTML = renderACLsTable(acls.filter(a => selectedRegion === 'all' || a.Region === selectedRegion), all_regions, selectedRegion);
            break;
        case 'sg-region-filter':
        case 'sg-hide-empty-filter':
        case 'sg-text-filter': // Para que funcione al hacer clic fuera
            applySgFiltersAndRender();
            break;
        case 'vpc-diagram-hide-empty-filter':
            applyVpcDiagramFiltersAndRender();
            break;
    }
});

container.addEventListener('input', (e) => {
    // Este listener se encarga del filtrado en tiempo real para la caja de búsqueda
    if (e.target.id === 'sg-text-filter') {
        applySgFiltersAndRender();
    }
});


    
    if (sgsContainer) {
        sgsContainer.addEventListener('click', (e) => {
            const button = e.target.closest('.view-sg-resources-btn');
            if (button) {
                const groupId = button.dataset.groupId;
                const region = button.dataset.region;
                openModalWithAssociatedResources(groupId, region);
            }
        });
    }

    const tabsNav = container.querySelector('#network-policies-tabs');

    // Si hay una pestaña activa que no es Summary, cambiar a ella
    if (activeTabData !== 'np-summary-content') {
        // Quitar estado activo de Summary
        const defaultActiveLink = tabsNav.querySelector('a[data-tab="np-summary-content"]');
        const defaultActiveContent = document.getElementById('np-summary-content');
        if (defaultActiveLink && defaultActiveContent) {
            defaultActiveLink.classList.remove('border-[#eb3496]', 'text-[#eb3496]');
            defaultActiveLink.classList.add('border-transparent', 'text-gray-500');
            defaultActiveContent.classList.add('hidden');
        }

        // Activar la pestaña correcta
        const newActiveLink = tabsNav.querySelector(`a[data-tab="${activeTabData}"]`);
        const newActiveContent = document.getElementById(activeTabData);
        if (newActiveLink && newActiveContent) {
            newActiveLink.classList.add('border-[#eb3496]', 'text-[#eb3496]');
            newActiveLink.classList.remove('border-transparent', 'text-gray-500');
            newActiveContent.classList.remove('hidden');
        }
    }

    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.network-policies-tab-content'));
};


// Reemplaza tu función existente con esta versión mejorada con logs

const openModalWithAssociatedResources = (groupId, region) => {
    // --- LOGS INICIALES ---
    console.log("--- INICIANDO BÚSQUEDA DE RECURSOS ---");
    console.log(`Buscando para SG: ${groupId} en Región: ${region}`);
    
    const { ec2_instances, lambda_functions } = window.computeApiData.results;
    const { rds_instances, aurora_clusters } = window.databasesApiData.results;

    // --- LOGS PARA EC2 (LA PARTE IMPORTANTE) ---
    console.log(`Total de instancias EC2 a revisar: ${ec2_instances.length}`);
    
    const associatedEc2 = ec2_instances.filter(i => {
        // Para cada instancia, hacemos las comprobaciones por separado para poder loguearlas
        const regionMatch = i.Region === region;
        const sgMatch = i.SecurityGroups.includes(groupId);

        // Creamos un grupo de logs para mantener la consola ordenada
        console.groupCollapsed(`Revisando instancia: ${i.InstanceId}`);
            console.log("ID de Instancia:", i.InstanceId);
            console.log("Región de la Instancia:", i.Region);
            console.log("SGs de la Instancia:", i.SecurityGroups); // ¡Clave!
            console.log("--- Comprobaciones ---");
            console.log(`¿Coincide Región? (${i.Region} === ${region}) -> ${regionMatch}`);
            console.log(`¿Incluye SG? (${groupId}) -> ${sgMatch}`);
        console.groupEnd();

        return regionMatch && sgMatch;
    });

    // --- LOG DEL RESULTADO FINAL ---
    console.log("Resultado final (instancias EC2 encontradas):", associatedEc2);

    // Filtrar los otros recursos (sin logs para mantenerlo simple por ahora)
    const associatedLambdas = lambda_functions.filter(l => l.Region === region && l.VpcConfig?.SecurityGroupIds?.includes(groupId));
    const associatedRds = rds_instances.filter(r => r.Region === region && r.SecurityGroupIds?.includes(groupId));
    const associatedAurora = aurora_clusters.filter(c => c.Region === region && c.SecurityGroupIds?.includes(groupId));

    // Construir el HTML para el contenido del modal (sin cambios)
    let modalContentHtml = '<div class="text-left space-y-4">';

    const createResourceList = (title, resources, idField) => {
        let html = `<div><h4 class="font-bold text-md text-[#204071] border-b pb-1 mb-2">${title} (${resources.length})</h4>`;
        if (resources.length > 0) {
            html += '<ul class="list-disc pl-5 space-y-1 text-sm">';
            resources.forEach(res => {
                const name = res.Tags?.Name ? `(${res.Tags.Name})` : '';
                html += `<li><span class="font-mono bg-gray-100 px-1 rounded">${res[idField]}</span> ${name}</li>`;
            });
            html += '</ul>';
        } else {
            html += '<p class="text-sm text-gray-500">No associated resources found.</p>';
        }
        html += '</div>';
        return html;
    };

    modalContentHtml += createResourceList('EC2 Instances', associatedEc2, 'InstanceId');
    modalContentHtml += createResourceList('Lambda Functions', associatedLambdas, 'FunctionName');
    modalContentHtml += createResourceList('RDS Instances', associatedRds, 'DBInstanceIdentifier');
    modalContentHtml += createResourceList('Aurora Clusters', associatedAurora, 'ClusterIdentifier');
    modalContentHtml += '</div>';

    // Abrir el modal (sin cambios)
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');

    modalTitle.textContent = `Associated Resources for ${groupId}`;
    modalContent.innerHTML = modalContentHtml;
    modal.classList.remove('hidden');
};


// --- FUNCIONES INTERNAS DEL MÓDULO (NO SE EXPORTAN) ---

const createNetworkPoliciesSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Total VPCs</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="np-total-vpcs" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v4h10V2a1 1 0 0 0-1-1zm9 6H6v2h7zm0 3H6v2h7zm0 3H6v2h6a1 1 0 0 0 1-1zm-8 2v-2H3v1a1 1 0 0 0 1 1zm-2-3h2v-2H3zm0-3h2V7H3z"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Default VPCs</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="np-default-vpcs" class="text-3xl font-bold text-yellow-600">--</p>
                <div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v4h10V2a1 1 0 0 0-1-1zm9 6H6v2h7zm0 3H6v2h7zm0 3H6v2h6a1 1 0 0 0 1-1zm-8 2v-2H3v1a1 1 0 0 0 1 1zm-2-3h2v-2H3zm0-3h2V7H3z"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Total Network ACLs</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="np-total-acls" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M12 0H4a2 2 0 0 0-2 2v4h12V2a2 2 0 0 0-2-2m2 7H6v2h8zm0 3H6v2h8zm0 3H6v3h6a2 2 0 0 0 2-2zm-9 3v-3H2v1a2 2 0 0 0 2 2zm-3-4h3v-2H2zm0-3h3V7H2z"/></svg></div>
            </div>
        </div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm">
            <div><p class="text-sm text-gray-500">Total Security Groups</p></div>
            <div class="flex justify-between items-end pt-4">
                <p id="np-total-sgs" class="text-3xl font-bold text-[#204071]">--</p>
                <div class="bg-green-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-green-600" viewBox="0 0 16 16"><path d="M12 0H4a2 2 0 0 0-2 2v4h12V2a2 2 0 0 0-2-2m2 7H6v2h8zm0 3H6v2h8zm0 3H6v3h6a2 2 0 0 0 2-2zm-9 3v-3H2v1a2 2 0 0 0 2 2zm-3-4h3v-2H2zm0-3h3V7H2z"/></svg></div>
            </div>
        </div>
    </div>`;

const updateNetworkPoliciesSummaryCards = (vpcs, acls, sgs) => {
    document.getElementById('np-total-vpcs').textContent = vpcs.length;
    document.getElementById('np-default-vpcs').textContent = vpcs.filter(v => v.IsDefault).length;
    document.getElementById('np-total-acls').textContent = acls.length;
    document.getElementById('np-total-sgs').textContent = sgs.length;
};

const renderVPCsTable = (vpcs, allRegions, selectedRegion = 'all') => {
    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');
    const filterControl = `<div class="mb-4 flex items-center gap-2"><label for="vpc-region-filter" class="text-sm font-medium text-gray-700">Filter by Region:</label><select id="vpc-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5"><option value="all">All Regions</option>${regionOptions}</select></div>`;
    if (!vpcs || vpcs.length === 0) return `<div class="bg-white p-6 rounded-xl border border-gray-100">${filterControl}<p class="text-center text-gray-500 py-4">No VPCs matching the selected filters were found.</p></div>`;
    
    let table = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-2 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">CIDR Block</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Is Default</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tags</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    vpcs.sort((a,b) => a.Region.localeCompare(b.Region)).forEach(v => {
        const originalIndex = window.networkPoliciesApiData.results.vpcs.findIndex(orig => orig.VpcId === v.VpcId);
        const tagCount = Object.keys(v.Tags).length;
        
        // Crear botón de tags
        let tagsHtml = '-';
        if (tagCount > 0) {
            tagsHtml = `<button 
                            onclick="openModalWithVpcTags(${originalIndex})" 
                            class="bg-[#204071] text-white px-3 py-1 text-xs font-bold rounded-md hover:bg-[#1a335a] transition whitespace-nowrap">
                            View (${tagCount})
                        </button>`;
        }
        
        // Lógica para scope
        const vpcArn = `arn:aws:ec2:${v.Region}:${window.iamApiData?.metadata?.accountId || 'unknown'}:vpc/${v.VpcId}`;
        const scopeDetails = window.scopedResources[vpcArn];
        const isScoped = !!scopeDetails;
        const rowClass = isScoped ? 'bg-pink-50 hover:bg-pink-100' : 'hover:bg-gray-50';
        const scopeComment = isScoped ? scopeDetails.comment : '';
        const scopeIcon = isScoped 
            ? `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-red-600" viewBox="0 0 16 16"><path d="M7.84 4.1a.178.178 0 0 1 .32 0l.634 1.285a.18.18 0 0 0 .134.098l1.42.206c.145.021.204.2.098.303L9.42 6.993a.18.18 0 0 0-.051.158l.242 1.414a.178.178 0 0 1-.258.187l-1.27-.668a.18.18 0 0 0-.165 0l-1.27.668a.178.178 0 0 1-.257-.187l.242-1.414a.18.18 0 0 0-.05-.158l-1.03-1.001a.178.178 0 0 1 .098-.303l1.42-.206a.18.18 0 0 0 .134-.098z"/><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>` 
            : `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-bookmark-star w-5 h-5 text-gray-400" viewBox="0 0 16 16"><path d="M2 2a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v13.5a.5.5 0 0 1-.777.416L8 13.101l-5.223 2.815A.5.5 0 0 1 2 15.5zm2-1a1 1 0 0 0-1 1v12.566l4.723-2.482a.5.5 0 0 1 .554 0L13 14.566V2a1 1 0 0 0-1-1z"/></svg>`;
        const scopeButton = `<button onclick="openScopeModal('${vpcArn}', '${encodeURIComponent(scopeComment)}')" title="${isScoped ? `Marcado: ${scopeComment}` : 'Marcar este recurso'}" class="p-1 rounded-full hover:bg-gray-200 transition">${scopeIcon}</button>`;

        const isDefault = v.IsDefault ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">YES</span>' : 'NO';
        
        table += `<tr class="${rowClass}">
                    <td class="px-2 py-4 whitespace-nowrap text-sm text-center">${scopeButton}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${v.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${v.VpcId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${v.CidrBlock}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm">${isDefault}</td>
                    <td class="px-4 py-4 text-sm text-gray-600">${tagsHtml}</td>
                </tr>`;
    });
    
    table += '</tbody></table></div>';
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControl}${table}</div>`;
};

const renderACLsTable = (acls, allRegions, selectedRegion = 'all') => {
    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');
    const filterControl = `<div class="mb-4 flex items-center gap-2"><label for="acl-region-filter" class="text-sm font-medium text-gray-700">Filter by Region:</label><select id="acl-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5"><option value="all">All Regions</option>${regionOptions}</select></div>`;
    if (!acls || acls.length === 0) return `<div class="bg-white p-6 rounded-xl border border-gray-100">${filterControl}<p class="text-center text-gray-500 py-4">No Network ACLs matching the selected filters were found.</p></div>`;
    let table = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">ACL ID</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC ID</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Is Default</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tags</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    acls.sort((a,b) => a.Region.localeCompare(b.Region)).forEach(a => {
        const tagsStr = Object.entries(a.Tags).map(([k, val]) => `${k}:${val}`).join(', ') || '-';
        const isDefault = a.IsDefault ? '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">YES</span>' : 'NO';
        table += `<tr class="hover:bg-gray-50"><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${a.Region}</td><td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${a.AclId}</td><td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${a.VpcId}</td><td class="px-4 py-4 whitespace-nowrap text-sm">${isDefault}</td><td class="px-4 py-4 text-sm text-gray-600 break-all">${tagsStr}</td></tr>`;
    });
    table += '</tbody></table></div>';
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControl}${table}</div>`;
};        

const renderSGsTable = (sgs, allRegions, selectedRegion = 'all', allResources, hideEmptyChecked = false) => {
    const regionOptions = allRegions.map(r => `<option value="${r}" ${selectedRegion === r ? 'selected' : ''}>${r}</option>`).join('');
    
    // Se añade el HTML del checkbox al control de filtros.
    const isChecked = hideEmptyChecked ? 'checked' : '';
    const filterControl = `
      <div class="mb-4 flex items-center gap-6">
        <div class="flex items-center gap-2">
          <label for="sg-region-filter" class="text-sm font-medium text-gray-700">Filter by Region:</label>
          <select id="sg-region-filter" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5">
            <option value="all">All Regions</option>${regionOptions}
          </select>
        </div>
        <div class="flex items-center">
          <input id="sg-hide-empty-filter" type="checkbox" ${isChecked} class="h-4 w-4 rounded border-gray-300 text-[#eb3496] focus:ring-[#eb3496]">
          <label for="sg-hide-empty-filter" class="ml-2 text-sm font-medium text-gray-700">Hide SGs with no resources</label>
        </div>
        <div class="flex items-center gap-2">
            <label for="sg-text-filter" class="text-sm font-medium text-gray-700">Search:</label>
            <input type="text" id="sg-text-filter" placeholder="Filter by Name, ID, VPC..." class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block p-1.5 w-64">
        </div>
      </div>`;

    if (!sgs || sgs.length === 0) return `<div class="bg-white p-6 rounded-xl border border-gray-100">${filterControl}<p class="text-center text-gray-500 py-4">No Security Groups matching the selected filters were found.</p></div>`;
    
    let table = '<div class="overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Group ID</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Group Name</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC ID</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Associated Resources</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Description</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    sgs.sort((a,b) => a.Region.localeCompare(b.Region)).forEach(sg => {
        const ec2Count = allResources.ec2.filter(i => i.Region === sg.Region && i.SecurityGroups.includes(sg.GroupId)).length;
        const lambdaCount = allResources.lambda.filter(l => l.Region === sg.Region && l.VpcConfig?.SecurityGroupIds?.includes(sg.GroupId)).length;
        const rdsCount = allResources.rds.filter(r => r.Region === sg.Region && r.SecurityGroupIds?.includes(sg.GroupId)).length;
        const auroraCount = allResources.aurora.filter(a => a.Region === sg.Region && a.SecurityGroupIds?.includes(sg.GroupId)).length;
        const totalCount = ec2Count + lambdaCount + rdsCount + auroraCount;

        let countCellHtml = `<span class="text-gray-500">${totalCount}</span>`;
        if (totalCount > 0) {
            countCellHtml = `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">${totalCount}</span>`;
        }

        const tagsStr = Object.entries(sg.Tags).map(([k, val]) => `${k}:${val}`).join(', ') || '-';
        const actionButton = `<button class="view-sg-resources-btn bg-[#204071] text-white px-2 py-1 rounded-md text-xs hover:bg-[#1a335a]" data-group-id="${sg.GroupId}" data-region="${sg.Region}">View Resources</button>`;
        
        table += `<tr class="hover:bg-gray-50">
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${sg.Region}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800">${sg.GroupId}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 break-all">${sg.GroupName}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${sg.VpcId}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-center">${countCellHtml}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 break-all">${sg.Description}</td>
            <td class="px-4 py-4 whitespace-nowrap text-sm">${actionButton}</td>
        </tr>`;
    });

    table += '</tbody></table></div>';
    return `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">${filterControl}${table}</div>`;
};


const renderVpcDiagram = (vpcs, subnets, instances, lambdas, rdsInstances, auroraClusters, natGateways) => {
    if (!vpcs || vpcs.length === 0) return '<p class="text-center text-gray-500">No VPCs were found to display in the diagram.</p>';
    
    let diagramHtml = '<div class="space-y-8">';

    vpcs.forEach(vpc => {
        // Filtros previos por VPC
        const vpcSubnets = subnets.filter(s => s.VpcId === vpc.VpcId);
        const vpcInstances = instances.filter(i => vpcSubnets.some(s => s.SubnetId === i.SubnetId));
        const vpcLambdas = lambdas.filter(l => l.VpcConfig && l.VpcConfig.VpcId === vpc.VpcId);
        const vpcRds = rdsInstances.filter(r => r.VpcId === vpc.VpcId);
        const vpcAurora = auroraClusters.filter(a => a.VpcId === vpc.VpcId);

        // Separar BBDD por número de subredes
        const singleSubnetRds = vpcRds.filter(r => r.SubnetIds && r.SubnetIds.length === 1);
        const multiSubnetRds = vpcRds.filter(r => r.SubnetIds && r.SubnetIds.length > 1);
        const singleSubnetAurora = vpcAurora.filter(a => a.SubnetIds && a.SubnetIds.length === 1);
        const multiSubnetAurora = vpcAurora.filter(a => a.SubnetIds && a.SubnetIds.length > 1);

        const totalResources = vpcInstances.length + vpcLambdas.length + vpcRds.length + vpcAurora.length;

        diagramHtml += `<div class="bg-white border border-gray-200 rounded-xl shadow-md"><div class="bg-gray-50 p-3 border-b border-gray-200 rounded-t-xl"><h3 class="text-lg font-bold text-[#204071]">${vpc.Tags['Name'] || vpc.VpcId}</h3><p class="text-sm text-gray-500 font-mono">${vpc.Region} | ${vpc.VpcId} | ${vpc.CidrBlock} | ${vpcSubnets.length} subnets | ${totalResources} resources</p></div><div class="p-4">`;
        
        diagramHtml += `<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">`;

        vpcSubnets.sort((a,b) => (a.Tags['Name'] || a.SubnetId).localeCompare(b.Tags['Name'] || b.SubnetId)).forEach(subnet => {
            diagramHtml += `<div class="bg-slate-50 border border-blue-200 rounded-lg p-3 flex flex-col"><div class="border-b border-blue-200 pb-2 mb-3"><p class="font-bold text-sm text-blue-800">${subnet.Tags['Name'] || subnet.SubnetId}</p><p class="text-xs text-gray-500 font-mono">${subnet.CidrBlock}</p></div><div class="space-y-2 flex-grow">`;
            
            // --- CÓDIGO COMPLETO PARA EC2 ---
            const subnetInstances = vpcInstances.filter(i => i.SubnetId === subnet.SubnetId);
            if (subnetInstances.length > 0) {
                subnetInstances.forEach(instance => {
                    const state = instance.State.toLowerCase();
                    let bgColor = (state === 'running') ? 'bg-green-100 border border-green-300' : 'bg-red-100 border border-red-300';
                    const instanceName = instance.Tags['Name'] || instance.InstanceId;
                    diagramHtml += `<div class="${bgColor} p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${instanceName}">${instanceName}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${instance.InstanceType}</span><span>${instance.State}</span></div></div>`;
                });
            }

            // --- CÓDIGO COMPLETO PARA LAMBDA ---
            const subnetLambdas = vpcLambdas.filter(l => l.VpcConfig?.SubnetIds?.includes(subnet.SubnetId));
            if (subnetLambdas.length > 0) {
                subnetLambdas.forEach(lambda => {
                    diagramHtml += `<div class="bg-purple-100 border border-purple-300 p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${lambda.FunctionName}"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="inline-block mr-1" viewBox="0 0 16 16"><path d="M14 1a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H2a1 1 0 0 1-1-1V2a1 1 0 0 1 1-1zM2 0a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V2a2 2 0 0 0-2-2z"/><path d="M6.854 4.646a.5.5 0 0 1 0 .708L4.207 8l2.647 2.646a.5.5 0 0 1-.708.708l-3-3a.5.5 0 0 1 0-.708l3-3a.5.5 0 0 1 .708 0m2.292 0a.5.5 0 0 0 0 .708L11.793 8l-2.647 2.646a.5.5 0 0 0 .708.708l3-3a.5.5 0 0 0 0-.708l-3-3a.5.5 0 0 0-.708 0"/></svg>${lambda.FunctionName}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${lambda.Runtime}</span></div></div>`;
                });
            }

            // --- Lógica para BBDD de subred única ---
            const subnetRds = singleSubnetRds.filter(r => r.SubnetIds[0] === subnet.SubnetId);
            if (subnetRds.length > 0) {
                 subnetRds.forEach(rds => {
                    diagramHtml += `<div class="bg-blue-100 border border-blue-300 p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${rds.DBInstanceIdentifier}"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="inline-block mr-1" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg>${rds.DBInstanceIdentifier}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${rds.Engine}</span></div></div>`;
                });
            }
            const subnetAurora = singleSubnetAurora.filter(c => c.SubnetIds[0] === subnet.SubnetId);
            if (subnetAurora.length > 0) {
                subnetAurora.forEach(aurora => {
                    diagramHtml += `<div class="bg-teal-100 border border-teal-300 p-2 rounded-md text-xs"><p class="font-semibold text-gray-800 truncate" title="${aurora.ClusterIdentifier}"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="inline-block mr-1" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg>${aurora.ClusterIdentifier}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${aurora.Engine}</span></div></div>`;
                });
            }

            const subnetNatGateways = natGateways.filter(nat => nat.SubnetId === subnet.SubnetId);
            if (subnetNatGateways.length > 0) {
                subnetNatGateways.forEach(nat => {
                    const natName = nat.Tags['Name'] || nat.NatGatewayId;
                    diagramHtml += `<div class="bg-orange-100 border border-orange-300 p-2 rounded-md text-xs">
                        <p class="font-semibold text-gray-800 truncate" title="${natName}">🌐 ${natName}</p>
                        <div class="text-gray-600 text-xs">NAT Gateway</div>
                    </div>`;
                });
            }


            if (subnetInstances.length === 0 && subnetLambdas.length === 0 && subnetRds.length === 0 && subnetAurora.length === 0 && subnetNatGateways.length === 0) {
                diagramHtml += '<p class="text-center text-xs text-gray-400 py-4">No resources</p>';
            }


            diagramHtml += `</div></div>`;
        });
        diagramHtml += `</div>`;

        // --- SECCIÓN COMPLETA PARA BBDD MULTI-SUBRED ---
        if (multiSubnetRds.length > 0 || multiSubnetAurora.length > 0) {
            diagramHtml += `<div class="mt-6 pt-4 border-t border-gray-200">
                <h4 class="text-md font-bold text-[#204071] mb-3">Recursos Multi-Subred (Alta Disponibilidad)</h4>
                <div class="flex flex-wrap gap-4">`;
            
            multiSubnetRds.forEach(rds => {
                diagramHtml += `<div class="bg-blue-100 border border-blue-300 p-2 rounded-md text-xs w-48"><p class="font-semibold text-gray-800 truncate" title="${rds.DBInstanceIdentifier}"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="inline-block mr-1" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg>${rds.DBInstanceIdentifier}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${rds.Engine}</span></div></div>`;
            });
            multiSubnetAurora.forEach(aurora => {
                diagramHtml += `<div class="bg-teal-100 border border-teal-300 p-2 rounded-md text-xs w-48"><p class="font-semibold text-gray-800 truncate" title="${aurora.ClusterIdentifier}"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" fill="currentColor" class="inline-block mr-1" viewBox="0 0 16 16"><path d="M4.318 2.687C5.234 2.271 6.536 2 8 2s2.766.27 3.682.687C12.644 3.125 13 3.627 13 4c0 .374-.356.875-1.318 1.313C10.766 5.729 9.464 6 8 6s-2.766-.27-3.682-.687C3.356 4.875 3 4.373 3 4c0-.374.356-.875 1.318-1.313M13 5.698V7c0 .374-.356.875-1.318 1.313C10.766 8.729 9.464 9 8 9s-2.766-.27-3.682-.687C3.356 7.875 3 7.373 3 7V5.698c.271.202.58.378.904.525C4.978 6.711 6.427 7 8 7s3.022-.289 4.096-.777A5 5 0 0 0 13 5.698M14 4c0-1.007-.875-1.755-1.904-2.223C11.022 1.289 9.573 1 8 1s-3.022.289-4.096.777C2.875 2.245 2 2.993 2 4v9c0 1.007.875 1.755 1.904 2.223C4.978 15.71 6.427 16 8 16s3.022-.289 4.096-.777C13.125 14.755 14 14.007 14 13zm-1 4.698V10c0 .374-.356.875-1.318 1.313C10.766 11.729 9.464 12 8 12s-2.766-.27-3.682-.687C3.356 10.875 3 10.373 3 10V8.698c.271.202.58.378.904.525C4.978 9.71 6.427 10 8 10s3.022-.289 4.096-.777A5 5 0 0 0 13 8.698m0 3V13c0 .374-.356.875-1.318 1.313C10.766 14.729 9.464 15 8 15s-2.766-.27-3.682-.687C3.356 13.875 3 13.373 3 13v-1.302c.271.202.58.378.904.525C4.978 12.71 6.427 13 8 13s3.022-.289 4.096-.777c.324-.147.633-.323.904-.525"/></svg>${aurora.ClusterIdentifier}</p><div class="flex justify-between items-center text-gray-600"><span class="font-mono">${aurora.Engine}</span></div></div>`;
            });
            
            diagramHtml += `</div></div>`;
        }
        
        diagramHtml += `</div></div>`;
    });

    diagramHtml += '</div>';
    return diagramHtml;
};



const renderNetworkDetailView = (allRegions) => {
    const regionOptions = allRegions.map(r => `<option value="${r}">${r}</option>`).join('');
    
    return `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h3 class="font-bold text-lg mb-4 text-[#204071]">Get Network Resource Details</h3>
            <p class="text-sm text-gray-600 mb-4">Enter the ID of a Security Group (e.g., sg-xxxx) or a Network ACL (e.g., acl-xxxx) and select its region to view its rules.</p>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4 items-end">
                <div class="lg:col-span-2">
                    <label for="np-resource-id" class="block text-sm font-medium text-gray-700 mb-1">Resource ID (SG or ACL)</label>
                    <input type="text" id="np-resource-id" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="sg-12345678 or acl-12345678">
                </div>
                <div>
                    <label for="np-resource-region" class="block text-sm font-medium text-gray-700 mb-1">Resource Region</label>
                    <select id="np-resource-region" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5">
                        <option value="">Select a Region</option>
                        ${regionOptions}
                    </select>
                </div>
            </div>
            <button id="np-run-detail-btn" class="bg-[#204071] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition flex items-center justify-center space-x-2">
                <span id="np-detail-btn-text">Analyze</span>
                <div id="np-detail-spinner" class="spinner hidden"></div>
            </button>
        </div>
        <div id="np-detail-results-container" class="mt-6"></div>
    `;
};

const runNetworkDetailAnalysis = async () => {
    log('Starting detailed network analysis…', 'info');
    const resourceId = document.getElementById('np-resource-id').value.trim();
    const region = document.getElementById('np-resource-region').value;
    const resultsContainer = document.getElementById('np-detail-results-container');
    resultsContainer.innerHTML = '';

    if (!resourceId || !region) {
        log('Resource ID and region are required.', 'error');
        resultsContainer.innerHTML = '<p class="text-red-600 font-medium">Error: Please enter an ID and select a region.</p>';
        return;
    }

    const runBtn = document.getElementById('np-run-detail-btn');
    const btnText = document.getElementById('np-detail-btn-text');
    const spinner = document.getElementById('np-detail-spinner');
    
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Analyzing...';
    
    // These need to be accessed from the global scope
    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');

    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
        resource_id: resourceId,
        region: region
    };

    try {
        const networkDetailEndpoint = window.API?.RUN_NETWORK_DETAIL || '/api/run-network-detail-audit';
        const response = await fetch(networkDetailEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Unknown server error.');
        }

        log('Detailed analysis completed.', 'success');
        renderNetworkDetailResult(data.results.details_table);

    } catch(e) {
        log(`Error during the detailed analysis: ${e.message}`, 'error');
        resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Analyze';
    }
};

const renderNetworkDetailResult = (tableString) => {
    const container = document.getElementById('np-detail-results-container');
    if (!tableString) {
        container.innerHTML = '<p class="text-gray-500">No results were found.</p>';
        return;
    }
    container.innerHTML = `
        <h3 class="text-xl font-bold text-[#204071] mb-4">Analysis Results</h3>
        <pre class="bg-[#204071] text-white p-4 rounded-lg text-xs font-mono overflow-x-auto">${tableString}</pre>
    `;
};

export const openModalWithVpcTags = (vpcIndex) => {
    const modal = document.getElementById('details-modal');
    const modalTitle = document.getElementById('modal-title');
    const modalContent = document.getElementById('modal-content');
    const vpc = window.networkPoliciesApiData.results.vpcs[vpcIndex];

    if (!modal || !vpc || !vpc.Tags) return;

    modalTitle.textContent = `Tags for VPC: ${vpc.VpcId}`;
    const tags = vpc.Tags;
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
        tagsListHtml = '<p class="text-sm text-gray-500 text-center py-4">This VPC has no tags.</p>';
    }

    modalContent.innerHTML = tagsListHtml;
    modal.classList.remove('hidden');
};
