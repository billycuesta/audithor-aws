 /**
 * 07_cloudwatch.js
 * Contains all the logic for building and rendering the CloudWatch & SNS view.
 */

// --- IMPORTS ---
// We import all the utility functions this module needs.
import { handleTabClick, renderSecurityHubFindings, createAlarmStateBadge, log } from '../utils.js';


// --- MAIN VIEW FUNCTION (EXPORTED) ---
// This main function builds the entire view. We export it so app.js can find and use it.
export const buildCloudwatchView = () => {
    const container = document.getElementById('cloudwatch-view');
    if (!window.cloudwatchApiData || !window.securityHubApiData) return;

    const { alarms, topics } = window.cloudwatchApiData.results;
    const cloudwatchFindings = window.securityHubApiData.results.findings.cloudwatchFindings;
    
    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Cloudwatch & SNS</h2>
                <p class="text-sm text-gray-500">${window.cloudwatchApiData.metadata.executionDate}</p>
            </div>
        </header>
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="cloudwatch-tabs">
                <a href="#" data-tab="cw-summary-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Summary</a>
                <a href="#" data-tab="cw-alarms-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Alarms (${alarms.length})</a>
                <a href="#" data-tab="cw-topics-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">SNS Topics (${topics.length})</a>
                <a href="#" data-tab="cw-sh-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Security Hub (${cloudwatchFindings.length})</a>
            </nav>
        </div>
        <div id="cloudwatch-tab-content-container">
            <div id="cw-summary-content" class="cloudwatch-tab-content">${createCloudwatchSummaryCardsHtml()}</div>
            <div id="cw-alarms-content" class="cloudwatch-tab-content hidden">${renderCloudwatchAlarmsTable(alarms)}</div>
            <div id="cw-topics-content" class="cloudwatch-tab-content hidden">${renderCloudwatchTopicsTable(topics)}</div>
            <div id="cw-sh-content" class="cloudwatch-tab-content hidden">${createCloudwatchSecurityHubHtml()}</div>
        </div>`;

    updateCloudwatchSummaryCards(alarms, topics, cloudwatchFindings);
    renderSecurityHubFindings(cloudwatchFindings, 'sh-cloudwatch-findings-container', 'No CloudWatch alarms were found.');
    
    const tabsNav = container.querySelector('#cloudwatch-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.cloudwatch-tab-content'));
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const createCloudwatchSummaryCardsHtml = () => `
    <div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-5 mb-8">
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Total Alarms</p></div><div class="flex justify-between items-end pt-4"><p id="cw-total-alarms" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M8 16a2 2 0 0 0 2-2H6a2 2 0 0 0 2 2M8 1.918l-.797.161A4 4 0 0 0 4 6c0 .628-.134 2.197-.459 3.742-.16.767-.376 1.566-.663 2.258h10.244c-.287-.692-.502-1.49-.663-2.258C12.134 8.197 12 6.628 12 6a4 4 0 0 0-3.203-3.92zM14.22 12c.223.447.481.801.78 1H1c.299-.199.557-.553.78-1C2.68 10.2 3 6.88 3 6c0-2.42 1.72-4.44 4.005-4.901a1 1 0 1 1 1.99 0A5 5 0 0 1 13 6c0 .88.32 4.2 1.22 6"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Alarms in 'ALARM' State</p></div><div class="flex justify-between items-end pt-4"><p id="cw-state-alarms" class="text-3xl font-bold text-red-600">--</p><div class="bg-red-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-red-600" viewBox="0 0 16 16"><path d="M7.938 2.016A.13.13 0 0 1 8.002 2a.13.13 0 0 1 .063.016.15.15 0 0 1 .054.057l6.857 11.667c.036.06.035.124.002.183a.2.2 0 0 1-.054.06.1.1 0 0 1-.066.017H1.146a.1.1 0 0 1-.066-.017.2.2 0 0 1 .002-.183L7.884 2.073a.15.15 0 0 1 .054-.057m1.044-.45a1.13 1.13 0 0 0-1.96 0L.165 13.233c-.457.778.091 1.767.98 1.767h13.713c.889 0 1.438-.99.98-1.767z"/><path d="M7.002 12a1 1 0 1 1 2 0 1 1 0 0 1-2 0M7.1 5.995a.905.905 0 1 1 1.8 0l-.35 3.507a.552.552 0 0 1-1.1 0z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">SNS Topics with Email</p></div><div class="flex justify-between items-end pt-4"><p id="cw-total-topics" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-blue-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-blue-600" viewBox="0 0 16 16"><path d="M15.854.146a.5.5 0 0 1 .11.54l-5.819 14.547a.75.75 0 0 1-1.329.124l-3.178-4.995L.643 7.184a.75.75 0 0 1 .124-1.33L15.314.037a.5.5 0 0 1 .54.11ZM6.636 10.07l2.761 4.338L14.13 2.576zm6.787-8.201L1.591 6.602l4.339 2.76z"/></svg></div></div></div>
        <div class="bg-white border border-gray-100 p-5 rounded-xl shadow-sm flex flex-col justify-between h-full"><div><p class="text-sm text-gray-500">Findings (Crit/High)</p></div><div class="flex justify-between items-end pt-4"><p id="cw-critical-findings" class="text-3xl font-bold text-[#204071]">--</p><div class="bg-orange-100 p-3 rounded-full"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 text-orange-600" viewBox="0 0 16 16"> <path d="M11.742 10.344a6.5 6.5 0 1 0-1.397 1.398h-.001q.044.06.098.115l3.85 3.85a1 1 0 0 0 1.415-1.414l-3.85-3.85a1 1 0 0 0-.115-.1zM12 6.5a5.5 5.5 0 1 1-11 0 5.5 5.5 0 0 1 11 0"/></svg></div></div></div>
    </div>`;

const updateCloudwatchSummaryCards = (alarms, topics, findings) => {
    document.getElementById('cw-total-alarms').textContent = alarms.length;
    document.getElementById('cw-state-alarms').textContent = alarms.filter(a => a.StateValue === 'ALARM').length;
    document.getElementById('cw-total-topics').textContent = topics.length;
    const criticalHighFindings = findings.filter(f => f.Severity?.Label === 'CRITICAL' || f.Severity?.Label === 'HIGH').length;
    document.getElementById('cw-critical-findings').textContent = criticalHighFindings;
};

const createCloudwatchSecurityHubHtml = () => `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100"><h3 class="font-bold text-lg mb-4 text-[#204071]">Active Security Findings (CloudWatch)</h3><div id="sh-cloudwatch-findings-container" class="overflow-x-auto"></div></div>`;

const renderCloudwatchAlarmsTable = (alarms) => {
    if (!alarms || alarms.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No CloudWatch alarms were found.</p></div>';
    
    let table = `<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">State</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Alarm Name</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Metric</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Condition</th>
                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">SNS Actions</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">`;

    alarms.sort((a, b) => a.Region.localeCompare(b.Region) || a.AlarmName.localeCompare(b.AlarmName))
          .forEach((alarm, index) => {
        const metric = `${alarm.Namespace}/${alarm.MetricName}`;
        const condition = `${alarm.ComparisonOperator} ${alarm.Threshold}`;
        const snsActions = alarm.AlarmActions.filter(a => a.includes("arn:aws:sns")).map(arn => arn.split(':').pop()).join(', ') || '-';
        
        table += `
            <tr class="hover:bg-blue-50 cursor-pointer" onclick="toggleAlarmDetails(${index})">
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${alarm.Region}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm">${createAlarmStateBadge(alarm.StateValue)}</td>
                <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${alarm.AlarmName}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${metric}</td>
                <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${condition}</td>
                <td class="px-4 py-4 align-top text-sm text-gray-600 break-words">${snsActions}</td>
            </tr>
            <tr id="cw-alarm-details-${index}" class="hidden">
                <td colspan="6" class="p-0 bg-slate-50">
                    <div class="p-4">
                       <pre class="bg-[#204071] text-white text-xs font-mono rounded-md p-3 overflow-x-auto"></pre>
                    </div>
                </td>
            </tr>
        `;
    });

    table += '</tbody></table></div>';
    return table;
};

export const toggleAlarmDetails = (index) => {
    const detailsRow = document.getElementById(`cw-alarm-details-${index}`);
    if (!detailsRow) return;

    const isHidden = detailsRow.classList.toggle('hidden');

    if (!isHidden && detailsRow.querySelector('pre').textContent === '') {
        log(`Showing details for alarm index ${index}`, 'info');
        const alarmData = window.cloudwatchApiData.results.alarms[index];
        const formattedJson = JSON.stringify(alarmData, null, 2);
        detailsRow.querySelector('pre').textContent = formattedJson;
    }
};

const renderCloudwatchTopicsTable = (topics) => {
    if (!topics || topics.length === 0) return '<div class="bg-white p-6 rounded-xl border border-gray-100"><p class="text-center text-gray-500">No SNS topics with email subscriptions were found.</p></div>';
    let table = '<div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100 overflow-x-auto"><table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Topic ARN</th><th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Subscribed Emails</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">';
    topics.sort((a, b) => a.Region.localeCompare(b.Region) || a.TopicArn.localeCompare(b.TopicArn)).forEach(topic => {
        const emails = topic.Subscriptions.map(s => s.Endpoint).join(', ');
        table += `<tr class="hover:bg-gray-50">
                    <td class="px-4 py-4 align-top whitespace-nowrap text-sm text-gray-600">${topic.Region}</td>
                    <td class="px-4 py-4 align-top text-sm font-medium text-gray-800 break-words">${topic.TopicArn}</td>
                    <td class="px-4 py-4 align-top text-sm text-gray-600 break-words">${emails}</td>
                  </tr>`;
    });
    table += '</tbody></table></div>';
    return table;
};