document.addEventListener('DOMContentLoaded', () => {
    // Set current year in footer
    document.getElementById('year').textContent = new Date().getFullYear();

    // DOM element references
    const uploadSection = document.getElementById('upload-section');
    const reportSection = document.getElementById('report-section');
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('apk-upload');
    const fileInfo = document.getElementById('file-info');
    const fileNameSpan = document.getElementById('file-name');
    const analyzeButton = document.getElementById('analyze-button');
    const errorMessage = document.getElementById('error-message');
    const buttonText = document.getElementById('button-text');
    const loader = document.getElementById('loader');

    let selectedFile = null;

    // --- SVG Icons for dynamic injection ---
    const icons = {
        'check-circle': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>',
        'x-circle': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>',
        'help-circle': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"></path><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
        'alert-triangle': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path><line x1="12" y1="9" x2="12" y2="13"></line><line x1="12" y1="17" x2="12.01" y2="17"></line></svg>',
        'file-text': '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>'
    };

    // --- File Handling and UI Updates ---
    const handleFileSelect = (file) => {
        if (file && file.name.toLowerCase().endsWith('.apk')) {
            selectedFile = file;
            fileNameSpan.textContent = file.name;
            fileInfo.classList.remove('hidden');
            analyzeButton.disabled = false;
            hideError();
        } else {
            showError('Invalid file type. Please upload an APK file.');
            resetFileSelection();
        }
    };
    
    const resetFileSelection = () => {
        selectedFile = null;
        fileInput.value = '';
        fileInfo.classList.add('hidden');
        analyzeButton.disabled = true;
    };

    const showError = (message) => {
        errorMessage.textContent = message;
        errorMessage.classList.remove('hidden');
    };

    const hideError = () => {
        errorMessage.classList.add('hidden');
    };
    
    const setIsLoading = (loading) => {
        if (loading) {
            buttonText.textContent = 'Analyzing...';
            loader.classList.remove('hidden');
            analyzeButton.disabled = true;
        } else {
            buttonText.textContent = 'Analyze APK';
            loader.classList.add('hidden');
            analyzeButton.disabled = !selectedFile;
        }
    };

    // --- Event Listeners for File Upload ---
    fileInput.addEventListener('change', (event) => handleFileSelect(event.target.files[0]));
    dropZone.addEventListener('dragenter', (e) => { e.preventDefault(); e.stopPropagation(); dropZone.classList.add('drag-over'); });
    dropZone.addEventListener('dragleave', (e) => { e.preventDefault(); e.stopPropagation(); dropZone.classList.remove('drag-over'); });
    dropZone.addEventListener('dragover', (e) => { e.preventDefault(); e.stopPropagation(); });
    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        e.stopPropagation();
        dropZone.classList.remove('drag-over');
        handleFileSelect(e.dataTransfer.files[0]);
    });
    
    // --- API Call and Report Generation ---
    analyzeButton.addEventListener('click', async () => {
        if (!selectedFile) return showError('Please select an APK file to analyze.');
        
        setIsLoading(true);
        hideError();

        const formData = new FormData();
        formData.append('apk_file', selectedFile);

        try {
            const response = await fetch('/api/analyze', { method: 'POST', body: formData });
            if (!response.ok) {
                const errorData = await response.json().catch(() => ({ error: 'An unknown server error occurred.' }));
                throw new Error(errorData.error || `HTTP error! Status: ${response.status}`);
            }
            const result = await response.json();
            displayReport(result);

        } catch (err) {
            console.error("Analysis Error:", err);
            showError(err.message || 'Failed to analyze the file. Is the server running?');
        } finally {
            setIsLoading(false);
        }
    });
    
    const displayReport = (result) => {
        uploadSection.classList.add('hidden');
        reportSection.innerHTML = ''; // Clear previous report

        // 1. Create Verdict Card
        const verdict = getVerdictCardDetails(result.classification);
        const verdictCard = document.createElement('div');
        verdictCard.className = `verdict-card ${verdict.className}`;
        const verdictIcon = document.createElement('div');
        verdictIcon.innerHTML = verdict.iconSVG;
        verdictIcon.firstElementChild.classList.add('icon-large');
        verdictIcon.firstElementChild.style.color = verdict.color;
        verdictCard.appendChild(verdictIcon);
        const verdictText = document.createElement('div');
        verdictText.innerHTML = `
            <h2>${verdict.title}</h2>
            <p>${verdict.description}</p>
        `;
        verdictCard.appendChild(verdictText);
        reportSection.appendChild(verdictCard);

        // 2. Create App Details Card
        const detailsCard = document.createElement('div');
        detailsCard.className = 'card';
        detailsCard.innerHTML = `
            <h3 class="section-title" style="text-align: left; display: flex; align-items: center; gap: 0.5rem;">
                ${icons['file-text']} App Details
            </h3>
            <div class="details-grid">
                ${createDetailItem('App Label', result.app_label)}
                ${createDetailItem('Package Name', result.package_name)}
                ${createDetailItem('File Hash (SHA256)', result.file_hash, true)}
            </div>
        `;
        reportSection.appendChild(detailsCard);

        // 3. Create Layer Analysis Section
        const layersSection = document.createElement('div');
        layersSection.innerHTML = `<h3 class="section-title">Detailed Layer Analysis</h3>`;
        const layersGrid = document.createElement('div');
        layersGrid.className = 'layer-grid';
        Object.entries(result.layer_results).forEach(([layer, details]) => {
            layersGrid.innerHTML += createLayerCard(layer, details);
        });
        layersSection.appendChild(layersGrid);
        reportSection.appendChild(layersSection);

        // 4. Create Reset Button
        const resetButtonContainer = document.createElement('div');
        resetButtonContainer.style.textAlign = 'center';
        resetButtonContainer.style.paddingTop = '1rem';
        const resetButton = document.createElement('button');
        resetButton.className = 'button reset-button';
        resetButton.textContent = 'Analyze Another APK';
        resetButton.onclick = resetUI;
        resetButtonContainer.appendChild(resetButton);
        reportSection.appendChild(resetButtonContainer);

        reportSection.classList.remove('hidden');
        window.scrollTo({ top: 0, behavior: 'smooth' });
    };
    
    const resetUI = () => {
        reportSection.classList.add('hidden');
        uploadSection.classList.remove('hidden');
        resetFileSelection();
        setIsLoading(false);
    };

    // --- HTML Generation Helper Functions ---
    const getVerdictCardDetails = (classification) => {
        switch (classification) {
            case 'Safe': return { iconSVG: icons['check-circle'], title: "Application is Safe", description: "All critical security checks passed.", className: 'safe', color: 'var(--safe-color)' };
            case 'Fraud': return { iconSVG: icons['x-circle'], title: "Fraudulent Application Detected", description: "This application failed one or more critical security checks.", className: 'fraud', color: 'var(--fraud-color)' };
            default: return { iconSVG: icons['help-circle'], title: "Analysis Result: Unknown", description: "Could not determine the status of the application.", className: 'unknown', color: 'var(--text-secondary)' };
        }
    };

    const createDetailItem = (label, value, isHash = false) => `
        <div class="detail-item">
            <p class="label">${label}</p>
            <p class="value ${isHash ? 'hash' : ''}">${value || 'N/A'}</p>
        </div>
    `;
    
    const createLayerCard = (layer, details) => {
        const statusClass = `status-${details.status.toLowerCase()}`;
        const statusIcon = { passed: icons['check-circle'], failed: icons['x-circle'], warning: icons['alert-triangle'] }[details.status.toLowerCase()] || icons['help-circle'];
        
        return `
            <div class="layer-card ${statusClass}">
                <div class="layer-card-header">
                    <p class="layer-card-title">${layer}</p>
                    <div style="color: var(--${details.status.toLowerCase()}-color)">${statusIcon}</div>
                </div>
                <p class="layer-card-verdict">${details.verdict}</p>
                <div class="layer-card-status status-badge">${details.status}</div>
            </div>
        `;
    };

    // --- Navbar Visibility on Scroll ---
    let lastScroll = window.scrollY;

    window.addEventListener('scroll', () => {
        const navbar = document.querySelector('.navbar');
        const currentScroll = window.scrollY;
        
        if (currentScroll > lastScroll && currentScroll > 50) {
            navbar.classList.add('navbar--hidden');
        } else {
            navbar.classList.remove('navbar--hidden');
        }
        
        lastScroll = currentScroll;
    });
});

    closeBtn.addEventListener('click', () => {
        modal.classList.add('hidden');
    });

    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.classList.add('hidden');
        }
    });

    // --- Navbar Visibility on Scroll ---
    let lastScroll = window.scrollY;

    window.addEventListener('scroll', () => {
        const navbar = document.querySelector('.navbar');
        const currentScroll = window.scrollY;
        
        if (currentScroll > lastScroll && currentScroll > 50) {
            navbar.classList.add('navbar--hidden');
        } else {
            navbar.classList.remove('navbar--hidden');
        }
        
        lastScroll = currentScroll;
    });
