/**
 * utils.js
 * Contiene funciones de ayuda y utilidades reutilizables en toda la aplicación.
 */
        
export const copyToClipboard = (element, textToCopy) => {
    navigator.clipboard.writeText(textToCopy).then(() => {
        const originalContent = element.innerHTML;
        element.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-check-lg w-4 h-4 text-green-500" viewBox="0 0 16 16">
                <path d="M12.736 3.97a.733.733 0 0 1 1.047 0c.286.289.29.756.01 1.05L7.88 12.01a.733.733 0 0 1-1.065.02L3.217 8.384a.757.757 0 0 1 0-1.06.733.733 0 0 1 1.047 0l3.052 3.093 5.4-6.425z"/>
            </svg>
            <span class="text-green-500 text-xs font-bold">Copied</span>`;
        setTimeout(() => {
            element.innerHTML = originalContent;
        }, 1500); // Vuelve al estado original después de 1.5 segundos
    }).catch(err => {
        console.error('Error al copiar el ARN: ', err);
        log('Error copying ARN.', 'error');
    });
};

export const log = (message, type = 'info') => {
    // CORRECCIÓN: Buscamos el contenedor del log aquí dentro.
    // Esto hace que la función sea independiente y no dependa de variables externas.
    const logContainer = document.getElementById('log-container');
    if (!logContainer) return;

    const timestamp = new Date().toLocaleTimeString();
    const typeClass = `log-${type}`;
    const typeText = type.toUpperCase();
    const entry = document.createElement('p');
    entry.className = 'log-entry';
    entry.innerHTML = `<span class="font-bold ${typeClass}">[${timestamp} - ${typeText}]</span> ${message}`;
    logContainer.prepend(entry);

    // NUEVO: Efecto de pulso cuando hay nuevos logs y el panel está flotante
    const logPanel = document.getElementById('log-panel');
    if (logPanel && logPanel.classList.contains('floating')) {
        logPanel.classList.add('new-log');
        setTimeout(() => {
            logPanel.classList.remove('new-log');
        }, 3000);
    }
};

export const createStatusBadge = (statusText) => { 
    if (!statusText) { 
        return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">N/A</span>`; 
    } 
    const lowerStatus = statusText.toLowerCase(); 
    if (lowerStatus === 'Enabled' || lowerStatus === 'enabled' || lowerStatus === 'running' || lowerStatus === 'active') { 
        return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">${statusText}</span>`; 
    } 
    if (lowerStatus === 'Disabled' || lowerStatus === 'suspendido' || lowerStatus.includes('error') || lowerStatus === 'not_available' || lowerStatus === 'stopped' || lowerStatus === 'terminated' || lowerStatus === 'shutting-down' || lowerStatus === 'failed') { 
        return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">${statusText}</span>`; 
    } 
    if (lowerStatus === 'pending' || lowerStatus === 'enabling' || lowerStatus === 'stopping') { 
        return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">${statusText}</span>`; 
    } 
    return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">${statusText}</span>`; 
};

export const handleTabClick = (navElement, contentSelector) => (e) => { 
    e.preventDefault(); 
    const link = e.target.closest('a.tab-link'); 
    if (!link) return; 
    navElement.querySelectorAll('a.tab-link').forEach(l => { 
        l.classList.remove('border-[#eb3496]', 'text-[#eb3496]', 'font-semibold'); 
        l.classList.add('border-transparent', 'text-gray-500'); 
    }); 
    link.classList.add('border-[#eb3496]', 'text-[#eb3496]', 'font-semibold'); 
    link.classList.remove('border-transparent', 'text-gray-500'); 
    document.querySelectorAll(contentSelector).forEach(c => c.classList.add('hidden')); 
    const contentElement = document.getElementById(link.dataset.tab); 
    if (contentElement) contentElement.classList.remove('hidden'); 
};
        
export const createAlarmStateBadge = (state) => { 
    if (state === 'ALARM') return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">${state}</span>`; 
    if (state === 'OK') return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">${state}</span>`; 
    return `<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800">${state}</span>`; 
};

export const renderSecurityHubFindings = (findings, containerId, emptyMessage) => { 
    const container = document.getElementById(containerId); 
    if (!container) return; 
    if (!findings || findings.length === 0) { 
        container.innerHTML = `<p class="text-center text-gray-500 py-4">${emptyMessage}</p>`; 
        return; 
    } 
    const severityClasses = { 
        'CRITICAL': 'bg-red-600 text-white', 
        'HIGH': 'bg-orange-500 text-white', 
        'MEDIUM': 'bg-yellow-400 text-black', 
        'LOW': 'bg-blue-500 text-white', 
        'INFORMATIONAL': 'bg-gray-400 text-white' 
    }; 
    let tableHtml = '<table class="min-w-full divide-y divide-gray-200"><thead class="bg-gray-50"><tr><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Region</th><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Name</th><th class="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Resource Type</th></tr></thead><tbody class="bg-white divide-y divide-gray-200">'; 
    findings.forEach(f => { 
        const severity = f.Severity?.Label || 'N/A'; 
        const severityClass = severityClasses[severity] || 'bg-gray-200 text-gray-800'; 
        const region = f.Region || 'N/A'; 
        const title = f.Title || 'Sin título'; 
        const resourceType = f.Resources?.[0]?.Type || 'N/A'; 
        tableHtml += `<tr class="hover:bg-gray-50"><td class="px-4 py-2 whitespace-nowrap"><span class="px-2.5 py-0.5 text-xs font-semibold rounded-full ${severityClass}">${severity}</span></td><td class="px-4 py-2 whitespace-nowrap text-sm text-gray-600">${region}</td><td class="px-4 py-2 text-sm text-gray-800 break-words">${title}</td><td class="px-4 py-2 whitespace-nowrap text-sm text-gray-600">${resourceType}</td></tr>`; 
    }); 
    tableHtml += '</tbody></table>'; 
    container.innerHTML = tableHtml; 
};

export const setupModalControls = () => {
    const modal = document.getElementById('details-modal');
    const closeBtn = document.getElementById('modal-close-btn');
    if (modal && closeBtn) {
        // Cerrar al hacer clic en el botón de cerrar
        closeBtn.addEventListener('click', () => modal.classList.add('hidden'));
        // Cerrar al hacer clic fuera del contenido de la modal (en el fondo oscuro)
        modal.addEventListener('click', (e) => {
            if (e.target.id === 'details-modal') {
                modal.classList.add('hidden');
            }
        });
    }
};

export const setupPagination = (paginationContainer, ulContainer, items, renderPageFunction) => {
    const rowsPerPage = 50; // Mostraremos 50 resultados por página
    if (items.length <= rowsPerPage) {
        renderPageFunction(ulContainer, items, 1, rowsPerPage);
        return; // No se necesita paginación si hay pocos items
    }

    const pageCount = Math.ceil(items.length / rowsPerPage);
    let currentPage = 1;

    const updatePaginationButtons = () => {
        paginationContainer.innerHTML = '';
        
        // Botón "Anterior"
        const prevButton = document.createElement('button');
        prevButton.innerText = '« Prev';
        prevButton.disabled = currentPage === 1;
        prevButton.className = 'px-3 py-1 text-sm rounded-md border border-gray-300 bg-white hover:bg-gray-50 disabled:opacity-50';
        prevButton.addEventListener('click', () => {
            currentPage--;
            renderPageFunction(ulContainer, items, currentPage, rowsPerPage);
            updatePaginationButtons();
        });
        paginationContainer.appendChild(prevButton);

        // Indicador de página
        const pageIndicator = document.createElement('span');
        pageIndicator.innerText = `Pág ${currentPage} of ${pageCount}`;
        pageIndicator.className = 'px-3 py-1 text-sm text-gray-600';
        paginationContainer.appendChild(pageIndicator);
        
        // Botón "Siguiente"
        const nextButton = document.createElement('button');
        nextButton.innerText = 'Next »';
        nextButton.disabled = currentPage === pageCount;
        nextButton.className = 'px-3 py-1 text-sm rounded-md border border-gray-300 bg-white hover:bg-gray-50 disabled:opacity-50';
        nextButton.addEventListener('click', () => {
            currentPage++;
            renderPageFunction(ulContainer, items, currentPage, rowsPerPage);
            updatePaginationButtons();
        });
        paginationContainer.appendChild(nextButton);
    };

    renderPageFunction(ulContainer, items, currentPage, rowsPerPage);
    updatePaginationButtons();
};

// Nueva versión de setupPagination que acepta un objeto de configuración
export const setupPaginationNew = (config) => {
    const { rowsSelector, paginationContainerSelector, rowsPerPage = 15 } = config;
    
    // Verificar que los selectores existen
    const rows = document.querySelectorAll(rowsSelector);
    const paginationContainer = document.getElementById(paginationContainerSelector.replace('#', ''));
    
    if (!rows || rows.length === 0) {
        console.warn('setupPaginationNew: No rows found with selector:', rowsSelector);
        return;
    }
    
    if (!paginationContainer) {
        console.warn('setupPaginationNew: Pagination container not found:', paginationContainerSelector);
        return;
    }

    const totalRows = rows.length;
    
    if (totalRows <= rowsPerPage) {
        // No necesita paginación
        return;
    }

    const pageCount = Math.ceil(totalRows / rowsPerPage);
    let currentPage = 1;

    const showPage = (page) => {
        const startIndex = (page - 1) * rowsPerPage;
        const endIndex = startIndex + rowsPerPage;
        
        rows.forEach((row, index) => {
            if (index >= startIndex && index < endIndex) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    };

    const updatePaginationButtons = () => {
        paginationContainer.innerHTML = '';
        
        if (pageCount <= 1) return;
        
        const paginationDiv = document.createElement('div');
        paginationDiv.className = 'flex items-center justify-between';
        
        // Información de página
        const pageInfo = document.createElement('div');
        pageInfo.className = 'text-sm text-gray-700';
        pageInfo.textContent = `Showing ${((currentPage - 1) * rowsPerPage) + 1} to ${Math.min(currentPage * rowsPerPage, totalRows)} of ${totalRows} results`;
        
        // Controles de navegación
        const nav = document.createElement('div');
        nav.className = 'flex space-x-1';
        
        // Botón anterior
        const prevBtn = document.createElement('button');
        prevBtn.textContent = 'Previous';
        prevBtn.className = `px-3 py-1 text-sm border rounded ${currentPage === 1 ? 'bg-gray-100 text-gray-400 cursor-not-allowed' : 'bg-white text-gray-700 hover:bg-gray-50'}`;
        prevBtn.disabled = currentPage === 1;
        prevBtn.onclick = () => {
            if (currentPage > 1) {
                currentPage--;
                showPage(currentPage);
                updatePaginationButtons();
            }
        };
        
        // Número de página actual
        const pageNum = document.createElement('span');
        pageNum.className = 'px-3 py-1 text-sm bg-[#eb3496] text-white rounded';
        pageNum.textContent = currentPage;
        
        // Botón siguiente
        const nextBtn = document.createElement('button');
        nextBtn.textContent = 'Next';
        nextBtn.className = `px-3 py-1 text-sm border rounded ${currentPage === pageCount ? 'bg-gray-100 text-gray-400 cursor-not-allowed' : 'bg-white text-gray-700 hover:bg-gray-50'}`;
        nextBtn.disabled = currentPage === pageCount;
        nextBtn.onclick = () => {
            if (currentPage < pageCount) {
                currentPage++;
                showPage(currentPage);
                updatePaginationButtons();
            }
        };
        
        nav.appendChild(prevBtn);
        nav.appendChild(pageNum);
        nav.appendChild(nextBtn);
        
        paginationDiv.appendChild(pageInfo);
        paginationDiv.appendChild(nav);
        paginationContainer.appendChild(paginationDiv);
    };

    // Inicializar
    showPage(currentPage);
    updatePaginationButtons();
};