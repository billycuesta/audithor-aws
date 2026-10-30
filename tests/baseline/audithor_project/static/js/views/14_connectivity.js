/**
 * 14_connectivity.js
 * Contains all the logic for building and rendering the Network Connectivity view.
 */

// --- IMPORTS ---
// This module only needs the handleTabClick utility.
import { handleTabClick } from '../utils.js';

// --- SERVICE DESCRIPTIONS ---
const serviceDescriptions = {
    peering: {
        title: "VPC Peering",
        description: "VPC Peering creates a private network connection between two VPCs, allowing resources to communicate using private IP addresses as if they were within the same network.",
        useCases: "Cross-account communication, multi-region architecture, hybrid cloud connectivity between different environments (dev/prod).",
        auditConsiderations: "Review route tables, security groups, and NACLs to ensure proper network segmentation. Verify that peering connections don't create unintended access paths."
    },
    tgw: {
        title: "Transit Gateway",
        description: "Transit Gateway acts as a central hub that connects VPCs and on-premises networks through a single gateway, simplifying network architecture.",
        useCases: "Hub-and-spoke network topologies, centralized connectivity for multiple VPCs, simplified routing management, on-premises integration.",
        auditConsiderations: "Examine route tables and propagation settings. Verify that network segmentation is maintained and that sensitive environments are properly isolated."
    },
    vpn: {
        title: "VPN Connections",
        description: "Site-to-Site VPN connections provide secure IPsec tunnels between your VPC and on-premises networks or other cloud providers.",
        useCases: "Hybrid cloud connectivity, secure communication with corporate data centers, backup connectivity for Direct Connect, multi-cloud architectures.",
        auditConsiderations: "Verify encryption algorithms, tunnel redundancy, BGP routing, and that customer gateway configurations meet security standards."
    },
    endpoints: {
        title: "VPC Endpoints",
        description: "VPC Endpoints enable private connectivity to AWS services without using internet gateways, NAT devices, or VPN connections.",
        useCases: "Secure access to S3, DynamoDB, and other AWS services, compliance requirements for private connectivity, reducing data transfer costs.",
        auditConsiderations: "Review endpoint policies, ensure proper DNS resolution, verify that traffic doesn't traverse the public internet for sensitive operations."
    },
    natgateways: {
        title: "NAT Gateways",
        description: "NAT Gateways provide Network Address Translation (NAT) services to enable resources in private subnets to access the internet while preventing inbound connections from the internet.",
        useCases: "Outbound internet access for private instances, software updates and patches, API calls to external services, downloading packages and dependencies.",
        auditConsiderations: "Verify that NAT Gateways are placed in public subnets with proper route table configurations. Review associated costs and consider NAT instances for cost optimization. Ensure high availability by deploying across multiple AZs."
    }
};

// --- MAIN VIEW FUNCTION (EXPORTED) ---
// We export the main function so app.js can find and use it.
export const buildConnectivityView = () => {
    const container = document.getElementById('connectivity-view');
    if (!container || !window.connectivityApiData) return;

    const { peering_connections, tgw_attachments, vpn_connections, vpc_endpoints, nat_gateways = [] } = window.connectivityApiData.results;

    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Network Connectivity</h2>
                <p class="text-sm text-gray-500">${window.connectivityApiData.metadata.executionDate}</p>
            </div>
        </header>
        
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Audit Guidance</h3>
            <p class="text-sm text-blue-700">Review network connectivity components to ensure proper segmentation, security controls, and compliance with data flow requirements. Each tab provides specific audit considerations for that service type.</p>
        </div>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="connectivity-tabs">
                <a href="#" data-tab="conn-peering-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">VPC Peering (${peering_connections.length})</a>
                <a href="#" data-tab="conn-tgw-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Transit Gateway (${tgw_attachments.length})</a>
                <a href="#" data-tab="conn-vpn-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">VPN Connections (${vpn_connections.length})</a>
                <a href="#" data-tab="conn-endpoints-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">VPC Endpoints (${vpc_endpoints.length})</a>
                <a href="#" data-tab="conn-natgateways-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">NAT Gateways (${nat_gateways.length})</a>
            </nav>
        </div>
        <div id="connectivity-tab-content-container">
            <div id="conn-peering-content" class="connectivity-tab-content">
                ${renderServiceDescription(serviceDescriptions.peering)}
                ${renderPeeringTable(peering_connections)}
            </div>
            <div id="conn-tgw-content" class="connectivity-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.tgw)}
                ${renderTgwAttachmentsTable(tgw_attachments)}
            </div>
            <div id="conn-vpn-content" class="connectivity-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.vpn)}
                ${renderVpnConnectionsTable(vpn_connections)}
            </div>
            <div id="conn-endpoints-content" class="connectivity-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.endpoints)}
                ${renderVpcEndpointsTable(vpc_endpoints)}
            </div>
            <div id="conn-natgateways-content" class="connectivity-tab-content hidden">
                ${renderServiceDescription(serviceDescriptions.natgateways)}
                ${renderNatGatewaysTable(nat_gateways)}
            </div>
        </div>
    `;
    
    const tabsNav = container.querySelector('#connectivity-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.connectivity-tab-content'));
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

const renderPeeringTable = (connections) => {
    if (!connections || connections.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No VPC Peering connections found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have active VPC Peering connections, which may indicate a simplified network architecture.</p>
                </div>
            </div>
        `;
    }
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Connection ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Requester VPC</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Accepter VPC</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    connections.forEach(c => {
        const requesterInfo = `${c.RequesterVpc.VpcId} (${c.RequesterVpc.OwnerId})`;
        const accepterInfo = `${c.AccepterVpc.VpcId} (${c.AccepterVpc.OwnerId})`;
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${c.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${c.ConnectionId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${requesterInfo}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${accepterInfo}</td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderTgwAttachmentsTable = (attachments) => {
    if (!attachments || attachments.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No Transit Gateway attachments found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not use Transit Gateway for centralized network connectivity.</p>
                </div>
            </div>
        `;
    }
    
     let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Transit Gateway ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Attached VPC</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Attachment ID</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    attachments.forEach(a => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${a.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${a.TransitGatewayId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${a.VpcId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${a.AttachmentId}</td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderVpnConnectionsTable = (connections) => {
    if (!connections || connections.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No VPN connections found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have active site-to-site VPN connections to on-premises networks.</p>
                </div>
            </div>
        `;
    }
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPN Connection ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Customer Gateway ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Associated TGW</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    connections.forEach(c => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${c.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${c.VpnConnectionId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${c.CustomerGatewayId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${c.TransitGatewayId}</td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderVpcEndpointsTable = (endpoints) => {
    if (!endpoints || endpoints.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No VPC Endpoints found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not use VPC Endpoints for private connectivity to AWS services.</p>
                </div>
            </div>
        `;
    }
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Service Name</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    endpoints.forEach(e => {
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${e.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${e.VpcId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${e.EndpointType}</td>
                    <td class="px-4 py-4 text-sm text-gray-600 break-all font-mono">${e.ServiceName}</td>
                </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};

const renderNatGatewaysTable = (natGateways) => {
    if (!natGateways || natGateways.length === 0) {
        return `
            <div class="bg-white p-6 rounded-xl border border-gray-100">
                <div class="text-center">
                    <svg class="mx-auto h-12 w-12 text-gray-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <h3 class="mt-2 text-sm font-medium text-gray-900">No NAT Gateways found</h3>
                    <p class="mt-1 text-sm text-gray-500">This account does not have any NAT Gateways configured for outbound internet connectivity.</p>
                </div>
            </div>
        `;
    }
    
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">NAT Gateway ID</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">VPC</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Subnet</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">State</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Type</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Public IP</th>' +
                '<th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Private IP</th>' +
                '</tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    
    natGateways.forEach(nat => {
        let stateClass = 'bg-gray-100 text-gray-800';
        if (nat.State === 'available') {
            stateClass = 'bg-green-100 text-green-800';
        } else if (nat.State === 'pending' || nat.State === 'deleting') {
            stateClass = 'bg-yellow-100 text-yellow-800';
        } else if (nat.State === 'failed' || nat.State === 'deleted') {
            stateClass = 'bg-red-100 text-red-800';
        }

        const publicIp = nat.NatGatewayAddresses?.find(addr => addr.PublicIp)?.PublicIp || '-';
        const privateIp = nat.NatGatewayAddresses?.find(addr => addr.PrivateIp)?.PrivateIp || '-';

        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600">${nat.Region}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm font-medium text-gray-800 font-mono">${nat.NatGatewayId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${nat.VpcId}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${nat.SubnetId}</td>
                    <td class="px-4 py-4 whitespace-nowrap">
                        <span class="inline-flex px-2 py-1 text-xs font-medium rounded-full ${stateClass}">
                            ${nat.State}
                        </span>
                    </td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 capitalize">${nat.ConnectivityType || 'public'}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${publicIp}</td>
                    <td class="px-4 py-4 whitespace-nowrap text-sm text-gray-600 font-mono">${privateIp}</td>
                </tr>`;
    });
    
    table += '</tbody></table></div>';
    return table;
};