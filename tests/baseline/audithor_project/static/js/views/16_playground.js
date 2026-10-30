/**
 * 16_playground.js
 * Contains all logic for building and rendering the Playground view with interactive tools.
 */

// --- IMPORTS ---
import { handleTabClick, log } from '../utils.js';


// --- MAIN VIEW FUNCTION (EXPORTED) ---
export const buildPlaygroundView = () => {
    const container = document.getElementById('playground-view');
    container.innerHTML = `
        <header class="flex justify-between items-center mb-6">
            <div>
                <h2 class="text-2xl font-bold text-[#204071]">Playground</h2>
                <p class="text-sm text-gray-500">Interactive Analysis Tools for Security Testing.</p>
            </div>
        </header>
        
        <div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
            <h3 class="text-sm font-semibold text-blue-800 mb-2">Security Testing Guidelines</h3>
            <p class="text-sm text-blue-700">These tools help evaluate network connectivity, SSL/TLS configurations, and IAM permissions. Always ensure you have proper authorization before testing production systems and follow your organization's security testing policies.</p>
        </div>
        
        <div class="border-b border-gray-200 mb-6">
            <nav class="-mb-px flex flex-wrap space-x-6" id="playground-tabs">
                <a href="#" data-tab="pg-tracer-content" class="tab-link py-3 px-1 border-b-2 border-[#eb3496] text-[#eb3496] font-semibold text-sm">Traceroute</a>
                <a href="#" data-tab="pg-sslscan-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">SSL Scan</a>
                <a href="#" data-tab="pg-simulate-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Simulate Policy</a>
                <a href="#" data-tab="pg-lambda-simulate-content" class="tab-link py-3 px-1 border-b-2 border-transparent text-gray-500 hover:text-gray-700 font-medium text-sm">Lambda Simulation</a>
            </nav>
        </div>
        <div id="pg-tracer-content" class="playground-tab-content">
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <h3 class="font-bold text-lg mb-3 text-[#204071]">Network Connectivity Analyzer</h3>
                <div class="bg-gray-50 border border-gray-200 rounded p-3 mb-4">
                    <h4 class="text-sm font-medium text-gray-700 mb-1">What this tool does:</h4>
                    <p class="text-sm text-gray-600 mb-2">Analyzes the complete network path between two AWS resources, checking Security Groups, NACLs, and Route Tables to determine if connectivity is possible.</p>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Security considerations:</h4>
                    <p class="text-sm text-gray-600">Use this to validate network segmentation, identify unintended connectivity paths, and verify that security controls are properly configured.</p>
                </div>
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label for="pg-source-arn" class="block text-sm font-medium text-gray-700 mb-1">Source ARN</label>
                        <input type="text" id="pg-source-arn" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="arn:aws:ec2:region:account:instance/i-...">
                    </div>
                    <div>
                        <label for="pg-target-arn" class="block text-sm font-medium text-gray-700 mb-1">Destination ARN</label>
                        <input type="text" id="pg-target-arn" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="arn:aws:ec2:region:account:instance/i-...">
                    </div>
                </div>
                <button id="pg-run-analysis-btn" class="bg-[#204071] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition flex items-center justify-center space-x-2">
                    <span id="pg-button-text">Analyze Path</span>
                    <div id="pg-loading-spinner" class="spinner hidden"></div>
                </button>
            </div>
            <div id="playground-results-container" class="mt-6"></div>
        </div>
        <div id="pg-sslscan-content" class="playground-tab-content hidden">
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <h3 class="font-bold text-lg mb-3 text-[#204071]">SSL/TLS Security Scanner</h3>
                <div class="bg-gray-50 border border-gray-200 rounded p-3 mb-4">
                    <h4 class="text-sm font-medium text-gray-700 mb-1">What this tool does:</h4>
                    <p class="text-sm text-gray-600 mb-2">Performs comprehensive SSL/TLS analysis including cipher suites, certificate validation, protocol versions, and security vulnerabilities.</p>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Security considerations:</h4>
                    <p class="text-sm text-gray-600">Identify weak ciphers, expired certificates, unsupported protocols, and other SSL/TLS misconfigurations that could expose sensitive data.</p>
                </div>
                <div>
                    <label for="pg-sslscan-target" class="block text-sm font-medium text-gray-700 mb-1">Domain(s) or IP(s)</label>
                    <input type="text" id="pg-sslscan-target" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="e.g.: google.com, github.com, 1.1.1.1">
                </div>
                <button id="pg-run-sslscan-btn" class="bg-[#204071] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition flex items-center justify-center space-x-2 mt-4">
                    <span id="pg-sslscan-btn-text">Scan SSL/TLS</span>
                    <div id="pg-sslscan-spinner" class="spinner hidden"></div>
                </button>
            </div>
            <div id="sslscan-results-container" class="mt-6"></div>
        </div>
        <div id="pg-simulate-content" class="playground-tab-content hidden">
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <h3 class="font-bold text-lg mb-3 text-[#204071]">IAM Policy Simulation</h3>
                <div class="bg-gray-50 border border-gray-200 rounded p-3 mb-4">
                    <h4 class="text-sm font-medium text-gray-700 mb-1">What this tool does:</h4>
                    <p class="text-sm text-gray-600 mb-2">Simulates IAM policy evaluation for specific users and actions, testing both normal conditions and MFA-required scenarios using AWS's policy simulator.</p>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Security considerations:</h4>
                    <p class="text-sm text-gray-600">Verify that users have appropriate permissions, test MFA enforcement, identify overprivileged accounts, and validate that critical actions require proper authentication.</p>
                </div>
                
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label for="pg-username" class="block text-sm font-medium text-gray-700 mb-1">IAM Username</label>
                        <input type="text" id="pg-username" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="admin-user">
                    </div>
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">MFA Context</label>
                        <div class="flex items-center space-x-4 mt-2">
                            <label class="flex items-center">
                                <input type="radio" name="mfa-context" value="without-mfa" class="mr-2" checked>
                                <span class="text-sm">Without MFA</span>
                            </label>
                            <label class="flex items-center">
                                <input type="radio" name="mfa-context" value="with-mfa" class="mr-2">
                                <span class="text-sm">With MFA</span>
                            </label>
                        </div>
                        <p class="text-xs text-gray-500 mt-1">Test if MFA requirements are properly enforced for sensitive operations</p>
                    </div>
                </div>
                
                <div class="mb-4">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Select Actions to Test</label>
                    <div class="grid grid-cols-2 lg:grid-cols-3 gap-2 mb-3">
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="action-checkbox mr-2" value="s3:GetObject"> S3 Read
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="action-checkbox mr-2" value="s3:DeleteBucket"> S3 Delete Bucket
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="action-checkbox mr-2" value="ec2:DescribeInstances"> EC2 Describe
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="action-checkbox mr-2" value="ec2:TerminateInstances"> EC2 Terminate
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="action-checkbox mr-2" value="iam:CreateUser"> IAM Create User
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="action-checkbox mr-2" value="iam:DeleteUser"> IAM Delete User
                        </label>
                    </div>
                    
                    <div>
                        <label for="pg-custom-actions" class="block text-sm font-medium text-gray-700 mb-1">Custom Actions (one per line)</label>
                        <textarea id="pg-custom-actions" rows="3" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="rds:DeleteDBInstance&#10;cloudtrail:StopLogging"></textarea>
                    </div>
                </div>
                
                <button id="pg-run-simulation-btn" class="bg-[#204071] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition flex items-center justify-center space-x-2">
                    <span id="pg-simulation-btn-text">Run Simulation</span>
                    <div id="pg-simulation-spinner" class="spinner hidden"></div>
                </button>
            </div>
            <div id="simulation-results-container" class="mt-6"></div>
        </div>
        <div id="pg-lambda-simulate-content" class="playground-tab-content hidden">
            <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
                <h3 class="font-bold text-lg mb-3 text-[#204071]">Lambda Permission Simulation</h3>
                <div class="bg-gray-50 border border-gray-200 rounded p-3 mb-4">
                    <h4 class="text-sm font-medium text-gray-700 mb-1">What this tool does:</h4>
                    <p class="text-sm text-gray-600 mb-2">Tests what AWS actions a Lambda function can perform through its execution role, helping validate the principle of least privilege.</p>
                    <h4 class="text-sm font-medium text-gray-700 mb-1">Security considerations:</h4>
                    <p class="text-sm text-gray-600">Identify overprivileged Lambda functions, verify that functions can only access required resources, and ensure proper role-based access controls.</p>
                </div>
                
                <div class="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
                    <div>
                        <label for="pg-lambda-name" class="block text-sm font-medium text-gray-700 mb-1">Function Name</label>
                        <input type="text" id="pg-lambda-name" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="my-function">
                    </div>
                    <div>
                        <label for="pg-lambda-region" class="block text-sm font-medium text-gray-700 mb-1">Region</label>
                        <select id="pg-lambda-region" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5">
                            <option value="">Select a region...</option>
                        </select>
                    </div>
                </div>
                
                <div class="mb-4">
                    <label class="block text-sm font-medium text-gray-700 mb-2">Select Actions to Test</label>
                    <div class="grid grid-cols-2 lg:grid-cols-3 gap-2 mb-3">
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="lambda-action-checkbox mr-2" value="s3:GetObject"> S3 Read
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="lambda-action-checkbox mr-2" value="s3:PutObject"> S3 Write
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="lambda-action-checkbox mr-2" value="dynamodb:GetItem"> DynamoDB Read
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="lambda-action-checkbox mr-2" value="dynamodb:PutItem"> DynamoDB Write
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="lambda-action-checkbox mr-2" value="rds:DescribeDBInstances"> RDS Describe
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="lambda-action-checkbox mr-2" value="secretsmanager:GetSecretValue"> Get Secrets
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="lambda-action-checkbox mr-2" value="kms:Decrypt"> KMS Decrypt
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="lambda-action-checkbox mr-2" value="sns:Publish"> SNS Publish
                        </label>
                        <label class="flex items-center text-sm">
                            <input type="checkbox" class="lambda-action-checkbox mr-2" value="sqs:SendMessage"> SQS Send
                        </label>
                    </div>
                    
                    <div>
                        <label for="pg-lambda-custom-actions" class="block text-sm font-medium text-gray-700 mb-1">Custom Actions (one per line)</label>
                        <textarea id="pg-lambda-custom-actions" rows="3" class="bg-gray-50 border border-gray-300 text-[#204071] text-sm rounded-lg focus:ring-[#eb3496] focus:border-[#eb3496] block w-full p-2.5 font-mono" placeholder="logs:CreateLogGroup&#10;logs:CreateLogStream&#10;logs:PutLogEvents"></textarea>
                    </div>
                </div>
                
                <button id="pg-run-lambda-simulation-btn" class="bg-[#204071] text-white px-4 py-2.5 rounded-lg font-bold text-md hover:bg-[#1a335a] transition flex items-center justify-center space-x-2">
                    <span id="pg-lambda-simulation-btn-text">Run Lambda Simulation</span>
                    <div id="pg-lambda-simulation-spinner" class="spinner hidden"></div>
                </button>
            </div>
            <div id="lambda-simulation-results-container" class="mt-6"></div>
        </div>
    `;

    const tabsNav = document.getElementById('playground-tabs');
    if (tabsNav) tabsNav.addEventListener('click', handleTabClick(tabsNav, '.playground-tab-content'));
    
    const runAnalysisBtn = document.getElementById('pg-run-analysis-btn');
    if (runAnalysisBtn) runAnalysisBtn.addEventListener('click', runPlaygroundAnalysis);

    const runSslScanBtn = document.getElementById('pg-run-sslscan-btn');
    if (runSslScanBtn) runSslScanBtn.addEventListener('click', runSslScan);

    const runSimulationBtn = document.getElementById('pg-run-simulation-btn');
    if (runSimulationBtn) runSimulationBtn.addEventListener('click', runSimulation);

    const runLambdaSimulationBtn = document.getElementById('pg-run-lambda-simulation-btn');
    if (runLambdaSimulationBtn) runLambdaSimulationBtn.addEventListener('click', runLambdaSimulation);
    populateLambdaRegionSelect();

    if (window.playgroundApiData?.results) {
        renderPlaygroundResults();
    }
    if (window.playgroundApiData?.sslscan) {
        renderSslScanResults(window.playgroundApiData.sslscan);
    }
};


// --- INTERNAL MODULE FUNCTIONS (NOT EXPORTED) ---

const runPlaygroundAnalysis = async () => {
    log('Starting network path analysis…', 'info');
    const sourceArn = document.getElementById('pg-source-arn').value.trim();
    const targetArn = document.getElementById('pg-target-arn').value.trim();
    const resultsContainer = document.getElementById('playground-results-container');
    resultsContainer.innerHTML = '';

    if (!sourceArn || !targetArn) {
        log('Source and destination ARNs are required.', 'error');
        resultsContainer.innerHTML = '<p class="text-red-600 font-medium">Error: Please enter both ARNs.</p>';
        return;
    }

    const runBtn = document.getElementById('pg-run-analysis-btn');
    const btnText = document.getElementById('pg-button-text');
    const spinner = document.getElementById('pg-loading-spinner');
    
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Analyzing...';
    
    // These need to be accessed from the global scope for credentials
    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');

    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
        source_arn: sourceArn,
        target_arn: targetArn
    };

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout

        const playgroundEndpoint = window.API?.RUN_PLAYGROUND || '/api/run-playground-audit';
        const response = await fetch(playgroundEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        window.playgroundApiData = await response.json();
        
        if (!response.ok) {
            throw new Error(window.playgroundApiData.error || 'Unknown server error.');
        }

        log('Path analysis completed.', 'success');
        renderPlaygroundResults();

    } catch(e) {
        if (e.name === 'AbortError') {
            log('Path analysis timed out after 30 seconds.', 'error');
            resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Timeout Error</h4><p>The analysis took too long to complete. Please check your network connection and try again.</p></div>`;
        } else {
            log(`Path analysis error: ${e.message}`, 'error');
            resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
        }
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Analyze Path';
    }
};

const renderPlaygroundResults = () => {
    if (!window.playgroundApiData?.results) return;
    const container = document.getElementById('playground-results-container');
    const { status, reason, tables, detail_tables } = window.playgroundApiData.results;

    let resultHtml = '';
    if (status === 'REACHABLE') {
        resultHtml = `
            <div class="bg-green-50 text-green-800 p-4 rounded-lg">
                <h4 class="text-lg font-bold flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 mr-2" viewBox="0 0 16 16"><path d="M13.854 3.646a.5.5 0 0 1 0 .708l-7 7a.5.5 0 0 1-.708 0l-3.5-3.5a.5.5 0 1 1 .708-.708L6.5 10.293l6.646-6.647a.5.5 0 0 1 .708 0z"/></svg>
                    Status: REACHABLE
                </h4>
            </div>
        `;
        // Mostrar las tablas de resumen del path solo si es alcanzable
        if(tables && tables.length > 0) {
            tables.forEach(table => {
                resultHtml += `<pre class="bg-[#204071] text-white p-4 rounded-lg text-xs font-mono overflow-x-auto mt-4">${table}</pre>`;
            });
        }
        
    } else { // UNREACHABLE
        resultHtml = `
            <div class="bg-red-50 text-red-800 p-4 rounded-lg">
                <h4 class="text-lg font-bold flex items-center">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="w-6 h-6 mr-2" viewBox="0 0 16 16"><path d="M4.646 4.646a.5.5 0 0 1 .708 0L8 7.293l2.646-2.647a.5.5 0 0 1 .708.708L8.707 8l2.647 2.646a.5.5 0 0 1-.708.708L8 8.707l-2.646 2.647a.5.5 0 0 1-.708-.708L7.293 8 4.646 5.354a.5.5 0 0 1 0-.708z"/></svg>
                    Status: UNREACHABLE
                </h4>
                <p class="mt-2 font-mono text-sm"><b>Reason:</b> ${reason}</p>
            </div>
        `;
    }

    // --- CAMBIO PRINCIPAL ---
    // Este bloque ahora se ejecuta para AMBOS casos: REACHABLE y UNREACHABLE
    if (detail_tables && Object.keys(detail_tables).length > 0) {
        resultHtml += '<h3 class="text-xl font-bold text-[#204071] mt-8 mb-4 border-b pb-2">Details of Involved Resources</h3>';
        for (const resourceId in detail_tables) {
            // Añadimos un pequeño encabezado para cada recurso para mayor claridad
            resultHtml += `<div class="mt-4">
                <p class="text-sm font-semibold text-gray-600 mb-1">Resource: <span class="font-mono text-gray-800">${resourceId}</span></p>
                <pre class="bg-gray-800 text-gray-200 p-4 rounded-lg text-xs font-mono overflow-x-auto">${detail_tables[resourceId]}</pre>
            </div>`;
        }
    }

    container.innerHTML = resultHtml;
};

const renderSslScanResults = (results) => {
    const resultsContainer = document.getElementById('sslscan-results-container');
    if (!results || results.length === 0) {
        resultsContainer.innerHTML = '';
        return;
    }

    let resultsHtml = '';
    results.forEach(result => {
        let resultOutput = '';
        if (result.error) {
            resultOutput = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${result.error}</p></div>`;
        } else if (result.output && result.output.trim() !== '') {
            resultOutput = `<pre class="bg-gray-900 text-white p-4 rounded-lg text-xs font-mono overflow-x-auto">${result.output}</pre>`;
        } else {
            resultOutput = `<div class="bg-yellow-50 text-yellow-700 p-4 rounded-lg"><h4 class="font-bold">Warning</h4><p>The scan finished without returning results for this target.</p></div>`;
        }
        
        resultsHtml += `
            <div class="mb-6">
                <h4 class="font-bold text-lg mb-2 text-[#204071]">Result for: ${result.target}</h4>
                ${resultOutput}
            </div>
        `;
    });
    resultsContainer.innerHTML = resultsHtml;
};

const runSslScan = async () => {
    const targetInput = document.getElementById('pg-sslscan-target');
    const resultsContainer = document.getElementById('sslscan-results-container');
    const runBtn = document.getElementById('pg-run-sslscan-btn');
    const btnText = document.getElementById('pg-sslscan-btn-text');
    const spinner = document.getElementById('pg-sslscan-spinner');
    const target = targetInput.value.trim();
    
    if (!target) {
        resultsContainer.innerHTML = '<p class="text-red-600 font-medium">Please enter one or more comma-separated domains/IPs.</p>';
        return;
    }

    log(`Starting sslscan for: ${target}...`, 'info');
    resultsContainer.innerHTML = '';
    runBtn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Scanning...';

    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 120000); // 2 minute timeout

        const sslscanEndpoint = window.API?.RUN_SSLSCAN || '/api/run-sslscan';
        const response = await fetch(sslscanEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target }),
            signal: controller.signal
        });

        clearTimeout(timeoutId);
        const data = await response.json();
        if (!response.ok && data.error) {
            throw new Error(data.error);
        }
        if (!window.playgroundApiData) window.playgroundApiData = {};
        window.playgroundApiData.sslscan = data.results;
        renderSslScanResults(data.results);
        log(`sslscan completed for: ${target}.`, 'success');
            } catch (e) {
        if (e.name === 'AbortError') {
            log('SSL scan timed out after 2 minutes.', 'error');
            resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Timeout Error</h4><p>The SSL scan took too long to complete. This may be due to network connectivity issues or unresponsive targets.</p></div>`;
        } else {
            log(`sslscan error: ${e.message}`, 'error');
            resultsContainer.innerHTML = `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
        }
    } finally {
        runBtn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Scan SSL/TLS';
    }
};

const runSimulation = async () => {
    const username = document.getElementById('pg-username').value.trim();
    const customActions = document.getElementById('pg-custom-actions').value.trim();
    const mfaContext = document.querySelector('input[name="mfa-context"]:checked').value;
    
    // Collect selected actions
    const selectedActions = Array.from(document.querySelectorAll('.action-checkbox:checked'))
        .map(cb => cb.value);
    
    // Add custom actions
    if (customActions) {
        const customActionsList = customActions.split('\n').map(a => a.trim()).filter(a => a);
        selectedActions.push(...customActionsList);
    }
    
    if (!username || selectedActions.length === 0) {
        document.getElementById('simulation-results-container').innerHTML = 
            '<p class="text-red-600 font-medium">Please enter a username and select at least one action.</p>';
        return;
    }

    // Check credentials
    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');
    
    if (!accessKeyInput.value.trim() || !secretKeyInput.value.trim()) {
        document.getElementById('simulation-results-container').innerHTML = 
            '<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Credentials Required</h4><p>Please enter your AWS credentials in the header before running the simulation.</p></div>';
        return;
    }
    
    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
        username: username,
        actions: selectedActions,
        include_mfa_context: mfaContext === 'with-mfa'  // FIXED: This was inverted
    };
    
    // UI updates
    const btn = document.getElementById('pg-run-simulation-btn');
    const btnText = document.getElementById('pg-simulation-btn-text');
    const spinner = document.getElementById('pg-simulation-spinner');
    
    btn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Simulating...';
    
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
        
        const simulatePolicyEndpoint = window.API?.RUN_SIMULATE_POLICY || '/api/run-simulate-policy';
        const response = await fetch(simulatePolicyEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Simulation failed');
        
        renderSimulationResults(data.results);
        log(`Policy simulation completed for user: ${username}`, 'success');
        
    } catch (e) {
        if (e.name === 'AbortError') {
            log('Simulation timed out after 30 seconds.', 'error');
            document.getElementById('simulation-results-container').innerHTML = 
                `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Timeout Error</h4><p>The simulation took too long to complete. Please check your credentials and network connection.</p></div>`;
        } else {
            log(`Simulation error: ${e.message}`, 'error');
            document.getElementById('simulation-results-container').innerHTML = 
                `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
        }
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Run Simulation';
    }
};

const renderSimulationResults = (results) => {
    const container = document.getElementById('simulation-results-container');
    
    // Determine context label
    const contextText = results.context_applied && results.context_applied.length > 0 ? 'With MFA Context' : 'Without MFA Context';
    
    let resultHtml = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h4 class="font-bold text-lg mb-2 text-[#204071]">Policy Simulation Results</h4>
            <div class="mb-4 p-3 bg-gray-50 rounded">
                <p class="text-sm"><strong>User:</strong> <span class="font-mono">${results.username}</span></p>
                <p class="text-sm"><strong>Context:</strong> ${contextText}</p>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Decision</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Details</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">`;
    
    results.simulation_results.forEach(result => {
        const decisionClass = result.decision === 'allowed' ? 'text-green-800 bg-green-100' : 'text-red-800 bg-red-100';
        let matchedPolicies = 'No matching policies';
        if (result.matched_statements && result.matched_statements.length > 0) {
            const count = result.matched_statements.length;
            matchedPolicies = count === 1 
                ? '1 policy rule matched' 
                : `${count} policy rules matched`;
        }
        
        resultHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-4 text-sm font-mono">${result.action}</td>
                <td class="px-4 py-4 text-sm">
                    <span class="px-2 py-1 text-xs font-semibold rounded-full ${decisionClass}">
                        ${result.decision.toUpperCase()}
                    </span>
                </td>
                <td class="px-4 py-4 text-sm text-gray-600">${matchedPolicies}</td>
            </tr>`;
    });
    
    resultHtml += `</tbody></table></div></div>`;
    container.innerHTML = resultHtml;
};

const runLambdaSimulation = async () => {
    const functionName = document.getElementById('pg-lambda-name').value.trim();
    const region = document.getElementById('pg-lambda-region').value;
    const customActions = document.getElementById('pg-lambda-custom-actions').value.trim();
    
    // Collect selected actions
    const selectedActions = Array.from(document.querySelectorAll('.lambda-action-checkbox:checked'))
        .map(cb => cb.value);
    
    // Add custom actions
    if (customActions) {
        const customActionsList = customActions.split('\n').map(a => a.trim()).filter(a => a);
        selectedActions.push(...customActionsList);
    }
    
    if (!functionName || !region || selectedActions.length === 0) {
        document.getElementById('lambda-simulation-results-container').innerHTML = 
            '<p class="text-red-600 font-medium">Please enter a function name, select a region, and choose at least one action.</p>';
        return;
    }

    // Check credentials
    const accessKeyInput = document.getElementById('access-key-input');
    const secretKeyInput = document.getElementById('secret-key-input');
    const sessionTokenInput = document.getElementById('session-token-input');
    
    if (!accessKeyInput.value.trim() || !secretKeyInput.value.trim()) {
        document.getElementById('lambda-simulation-results-container').innerHTML = 
            '<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Credentials Required</h4><p>Please enter your AWS credentials in the header before running the simulation.</p></div>';
        return;
    }
    
    const payload = {
        access_key: accessKeyInput.value.trim(),
        secret_key: secretKeyInput.value.trim(),
        session_token: sessionTokenInput.value.trim() || null,
        function_name: functionName,
        region: region,
        actions: selectedActions
    };
    
    // UI updates
    const btn = document.getElementById('pg-run-lambda-simulation-btn');
    const btnText = document.getElementById('pg-lambda-simulation-btn-text');
    const spinner = document.getElementById('pg-lambda-simulation-spinner');
    
    btn.disabled = true;
    spinner.classList.remove('hidden');
    btnText.textContent = 'Simulating...';
    
    try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 30000); // 30 second timeout
        
        const simulateLambdaEndpoint = window.API?.RUN_SIMULATE_LAMBDA || '/api/run-simulate-lambda-policy';
        const response = await fetch(simulateLambdaEndpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
            signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Lambda simulation failed');
        
        renderLambdaSimulationResults(data.results);
        log(`Lambda simulation completed for function: ${functionName}`, 'success');
        
    } catch (e) {
        if (e.name === 'AbortError') {
            log('Lambda simulation timed out after 30 seconds.', 'error');
            document.getElementById('lambda-simulation-results-container').innerHTML = 
                `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Timeout Error</h4><p>The simulation took too long to complete. Please check your credentials and network connection.</p></div>`;
        } else {
            log(`Lambda simulation error: ${e.message}`, 'error');
            document.getElementById('lambda-simulation-results-container').innerHTML = 
                `<div class="bg-red-50 text-red-700 p-4 rounded-lg"><h4 class="font-bold">Error</h4><p>${e.message}</p></div>`;
        }
    } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
        btnText.textContent = 'Run Lambda Simulation';
    }
};

const renderLambdaSimulationResults = (results) => {
    const container = document.getElementById('lambda-simulation-results-container');
    
    let resultHtml = `
        <div class="bg-white p-6 rounded-xl shadow-sm border border-gray-100">
            <h4 class="font-bold text-lg mb-2 text-[#204071]">Lambda Permission Analysis</h4>
            <div class="mb-4 p-3 bg-gray-50 rounded">
                <p class="text-sm"><strong>Function:</strong> <span class="font-mono">${results.function_name}</span></p>
                <p class="text-sm"><strong>Execution Role:</strong> <span class="font-mono text-xs">${results.execution_role_arn}</span></p>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-200">
                    <thead class="bg-gray-50">
                        <tr>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Decision</th>
                            <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Risk Level</th>
                        </tr>
                    </thead>
                    <tbody class="bg-white divide-y divide-gray-200">`;
    
    results.simulation_results.forEach(result => {
        const decisionClass = result.decision === 'allowed' ? 'text-green-800 bg-green-100' : 'text-red-800 bg-red-100';
        
        // Assess risk level for allowed actions
        let riskLevel = 'N/A';
        let riskClass = 'text-gray-600';
        if (result.decision === 'allowed') {
            if (result.action.includes('Delete') || result.action.includes('Terminate') || result.action.includes('Put') || result.action.includes('Create')) {
                riskLevel = 'High';
                riskClass = 'text-red-600 font-semibold';
            } else if (result.action.includes('Get') || result.action.includes('List') || result.action.includes('Describe')) {
                riskLevel = 'Low';
                riskClass = 'text-green-600';
            } else {
                riskLevel = 'Medium';
                riskClass = 'text-yellow-600';
            }
        }
        
        resultHtml += `
            <tr class="hover:bg-gray-50">
                <td class="px-4 py-4 text-sm font-mono">${result.action}</td>
                <td class="px-4 py-4 text-sm">
                    <span class="px-2 py-1 text-xs font-semibold rounded-full ${decisionClass}">
                        ${result.decision.toUpperCase()}
                    </span>
                </td>
                <td class="px-4 py-4 text-sm ${riskClass}">${riskLevel}</td>
            </tr>`;
    });
    
    resultHtml += `</tbody></table></div></div>`;
    container.innerHTML = resultHtml;
};

const populateLambdaRegionSelect = () => {
    const select = document.getElementById('pg-lambda-region');
    if (!select || !window.allAvailableRegions) return;
    
    // Clear existing options
    select.innerHTML = '<option value="">Select a region...</option>';
    
    // Populate with all available regions
    window.allAvailableRegions.forEach(region => {
        const option = document.createElement('option');
        option.value = region;
        option.textContent = region;
        select.appendChild(option);
    });
    
    // Set us-east-1 as default if it exists
    if (window.allAvailableRegions.includes('us-east-1')) {
        select.value = 'us-east-1';
    }
};
