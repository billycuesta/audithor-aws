/** Coverage diagnostics live inside results so existing JSON exports retain them. */
const migratedCollectors = {
    acm: { certificates: [] },
    inspector: { scan_status: [], findings: [], findingsStatus: 'failed' },
    databases: { rds_instances: [], aurora_clusters: [], dynamodb_tables: [], documentdb_clusters: [] }
};
export const isMigratedCollector = key => Object.hasOwn(migratedCollectors, key);
export const failedCollectionResponse = (key, scanId) => isMigratedCollector(key) ? {
    metadata: {},
    results: {
        ...migratedCollectors[key],
        _collection: { status: 'failed', coverageKnown: false, scanId,
            units: [{ service: key, operation: 'api_request', status: 'failed', category: 'api_error' }] }
    }
} : null;
export const mergeInspectorCoverage = (statusCoverage, findingsCoverage) => ({
    ...findingsCoverage,
    status: statusCoverage?.status === 'complete' ? findingsCoverage?.status : 'partial',
    coverageKnown: Boolean(statusCoverage?.coverageKnown && findingsCoverage?.coverageKnown),
    units: [...(statusCoverage?.units || []), ...(findingsCoverage?.units || [])]
});
export const coverageOf = data => data?.results?._collection || { status: 'unknown', coverageKnown: false, units: [] };
export const coverageIsComplete = data => {
    const coverage = coverageOf(data);
    return coverage.status === 'complete' && coverage.coverageKnown;
};
export const coverageMessage = data => {
    const coverage = coverageOf(data);
    if (coverage.status === 'failed') return 'Collection failed. Resource counts and absence of findings cannot be determined.';
    if (coverage.status === 'partial') return 'Incomplete results. Counts describe collected data only; failed checks remain unknown.';
    if (coverage.status === 'not_applicable') return 'No applicable collection targets. Review the skipped regions and services.';
    if (!coverage.coverageKnown || coverage.status === 'unknown') return 'Coverage unknown. These results do not establish a complete inventory.';
    return 'Collection complete for the planned scope.';
};
export const renderCollectionNotice = (container, data) => {
    if (!container) return;
    container.querySelectorAll('[data-collection-notice]').forEach(el => el.remove());
    const coverage = coverageOf(data);
    const notice = document.createElement('section');
    notice.dataset.collectionNotice = 'true';
    notice.setAttribute('role', 'status');
    notice.className = 'border rounded-lg p-4 mb-4 bg-yellow-50 text-gray-800';
    const heading = document.createElement('p');
    heading.textContent = coverageMessage(data);
    notice.append(heading);
    if (data?.results?.findingsStatus === 'not_run') {
        const pending = document.createElement('p');
        pending.textContent = 'Inspector findings: not run. Run the findings search to assess vulnerabilities.';
        notice.append(pending);
    }
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = `Collection details (${coverage.units.length} operations) · Scan ${coverage.scanId || 'unknown'}`;
    details.append(summary);
    for (const unit of coverage.units) {
        const row = document.createElement('p');
        row.textContent = [unit.service, unit.region, unit.operation, unit.status,
            unit.category, unit.awsCode, unit.resourceId, unit.awsRequestId].filter(Boolean).join(' · ');
        details.append(row);
    }
    notice.append(details);
    container.prepend(notice);
};
export const emptyCollectionMessage = (data, completeMessage) => coverageIsComplete(data)
    ? completeMessage : 'No data collected for this section. Its resource inventory could not be established; review collection details.';
