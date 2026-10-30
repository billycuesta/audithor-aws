/**
 * 21_inventory.js
 * Contiene la lógica para la vista de inventario de recursos.
 * AHORA SE CARGA AUTOMÁTICAMENTE CON EL ESCANEO PRINCIPAL.
 */
import { log } from '../utils.js';

export const buildInventoryView = () => {
    const container = document.getElementById('inventory-view');
    if (!container) return;

    if (!window.inventoryApiData || !window.inventoryApiData.results) {
        container.innerHTML = `
            <div class="text-center py-16 bg-white rounded-lg">
                <h3 class="mt-2 text-lg font-medium text-[#204071]">Scan required</h3>
                <p class="mt-1 text-sm text-gray-500">Complete an account scan to unlock this view.</p>
            </div>
        `;
    } else {
        container.innerHTML = renderInventoryTable(window.inventoryApiData.results);
    }




};

const renderInventoryTable = (results) => {
    const resourceNames = {
        'ec2_instances': "EC2 Instances",
        'rds_instances': "RDS Instances",
        's3_buckets': "S3 Buckets",
        'load_balancers': "Load Balancers (ALB/NLB)",
        'lambda_functions': "Lambda Functions",
        'iam_users': "IAM Users",
        'iam_roles': "IAM Roles",
        'iam_policies': "IAM Customer-Managed Policies",
        'vpcs': "VPCs",
        'dynamodb_tables': "DynamoDB Tables",
        'route53_hosted_zones': "Route 53 Hosted Zones",
        'route53_subdomains': "Route 53 Subdomains",
        'ecs_clusters': "ECS Clusters",
        'eks_clusters': "EKS Clusters",
        'cloudfront_distributions': "CloudFront Distributions",
        'documentdb_clusters': "DocumentDB Clusters",
    };

    const summary = results || {};
    let tableRowsHtml = '';

    // 1. Calcula la lista maestra de cabeceras de regiones activas
    const regionCounts = {};
    for (const key in summary) {
        if (summary[key] && summary[key].by_region) {
            for (const region in summary[key].by_region) {
                if (!regionCounts[region]) {
                    regionCounts[region] = 0;
                }
                regionCounts[region] += summary[key].by_region[region];
            }
        }
    }

    const activeRegions = Object.keys(regionCounts).filter(region =>
        region === 'Global' || regionCounts[region] > 0
    );
    const sortedRegionsHeaders = activeRegions.sort((a, b) => {
        if (a === 'Global') return -1; // 'Global' siempre primero
        if (b === 'Global') return 1;
        return regionCounts[b] - regionCounts[a];
    });

    // 2. Construye las filas (tbody) usando esa misma lista de cabeceras
    for (const key in resourceNames) {
        const item = summary[key];
        if (!item) continue;

        // Itera sobre la lista de cabeceras para generar las celdas de datos regionales

        const regionalCells = sortedRegionsHeaders.map(region => {
            const count = (item.by_region && item.by_region[region]) ? item.by_region[region] : 0;

            // --- Lógica para el mapa de calor ---
            
            let cellClasses = 'text-center'; // Centramos el número para mejor visualización
            if (count === 0) {
                cellClasses += ' text-gray-400'; // Color gris para los ceros
            } else if (count > 0 && count < 10) {
                cellClasses += ' bg-sky-100 text-sky-800'; // Color suave para pocos recursos
            } else if (count >= 10 && count < 50) {
                cellClasses += ' bg-sky-300 text-sky-900 font-semibold'; // Color intermedio
            } else if (count >= 50) {
                cellClasses += ' bg-sky-500 text-white font-bold'; // Color intenso para muchos recursos
            }

            return `<td class="px-6 py-4 whitespace-nowrap text-sm font-mono ${cellClasses}">${count}</td>`;
        }).join('');

        tableRowsHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">${resourceNames[key]}</td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600 font-mono font-bold">${item.total}</td>
                ${regionalCells}
            </tr>
        `;
    }

    // 3. Devuelve el HTML final de la tabla completa
    return `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Resource Inventory Summary</h2>
                <p class="text-sm text-gray-500">Total count of key resources and breakdown by region.</p>
            </div>
        </header>
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Resource Type</th>
                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Total</th>
                        ${sortedRegionsHeaders.map(region => `<th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">${region}</th>`).join('')}
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    ${tableRowsHtml}
                </tbody>
            </table>
        </div>
    `;
};
