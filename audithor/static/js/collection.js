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
export const mergeInspectorCoverage = (statusCoverage, findingsCoverage) => {
    const findingsNotApplicable = findingsCoverage?.status === 'not_applicable';
    return {
        ...(findingsNotApplicable ? statusCoverage : findingsCoverage),
        status: statusCoverage?.status === 'complete' && findingsNotApplicable
            ? 'complete'
            : statusCoverage?.status === 'complete' ? findingsCoverage?.status : 'partial',
        coverageKnown: findingsNotApplicable
            ? Boolean(statusCoverage?.coverageKnown)
            : Boolean(statusCoverage?.coverageKnown && findingsCoverage?.coverageKnown),
        units: [...(statusCoverage?.units || []), ...(findingsNotApplicable ? [] : findingsCoverage?.units || [])]
    };
};
export const coverageOf = data => data?.results?._collection || { status: 'unknown', coverageKnown: false, units: [] };
export const coverageIsComplete = data => {
    const coverage = coverageOf(data);
    return coverage.status === 'complete' && coverage.coverageKnown;
};
export const coverageMessage = data => {
    const coverage = coverageOf(data);
    if (coverage.status === 'failed') return 'Collection failed. Resource counts and absence of findings cannot be determined.';
    if (coverage.status === 'partial') return 'Incomplete results. Counts describe collected data only; failed checks remain unknown.';
    if (coverage.status === 'not_applicable') return 'No collection targets apply to this section.';
    if (!coverage.coverageKnown || coverage.status === 'unknown') return 'Coverage unknown. These results do not establish a complete inventory.';
    return 'Collection complete';
};
export const renderCollectionNotice = (container, data) => {
    if (!container) return;
    container.querySelectorAll('[data-collection-notice]').forEach(el => el.remove());
    const coverage = coverageOf(data);
    if (coverage.status === 'complete') return;
    const notice = document.createElement('section');
    notice.dataset.collectionNotice = 'true';
    notice.setAttribute('role', 'status');
    notice.className = coverage.status === 'partial' ? 'border rounded-lg p-4 mb-4 bg-yellow-50 text-gray-800'
        : coverage.status === 'failed' ? 'border rounded-lg p-4 mb-4 bg-red-50 text-red-800'
        : 'text-xs text-gray-500 mb-4';
    const heading = document.createElement('p');
    heading.textContent = coverageMessage(data);
    notice.append(heading);
    if (data?.results?.findingsStatus === 'not_run') {
        const pending = document.createElement('p');
        pending.textContent = 'Inspector findings have not run. Use the deep scan to search for vulnerabilities.';
        notice.append(pending);
    }
    const details = document.createElement('details');
    const summary = document.createElement('summary');
    summary.textContent = `Collection details (${coverage.units.length} operations) · Scan ${coverage.scanId || 'unknown'}`;
    details.append(summary);
    const failedUnits = coverage.units.filter(unit => unit.status === 'failed');
    const otherUnits = coverage.units.filter(unit => unit.status !== 'failed');
    const regionSkips = otherUnits.filter(unit => unit.operation === 'region_selection' && unit.status === 'skipped' && unit.category === 'region_not_enabled');
    const listedUnits = [...failedUnits, ...otherUnits.filter(unit => !(unit.operation === 'region_selection' && unit.status === 'skipped' && unit.category === 'region_not_enabled'))];
    for (const unit of listedUnits) {
        const row = document.createElement('p');
        row.textContent = [unit.service, unit.region, unit.operation, unit.status,
            unit.category, unit.awsCode, unit.resourceId, unit.awsRequestId].filter(Boolean).join(' · ');
        details.append(row);
    }
    if (regionSkips.length) {
        const row = document.createElement('p');
        row.dataset.regionSkipSummary = 'true';
        row.textContent = `${regionSkips.length} regions skipped (not enabled in this account)`;
        details.append(row);
    }
    notice.append(details);
    container.prepend(notice);
};
export const emptyCollectionMessage = (data, completeMessage) => coverageIsComplete(data)
    ? completeMessage : 'No data collected for this section. Its resource inventory could not be established; review collection details.';
