document.addEventListener('DOMContentLoaded', function() {
    const domainForm = document.getElementById('domainForm');
    const dkimCheck = document.getElementById('dkimCheck');
    const selectorContainer = document.getElementById('selectorContainer');
    const resultsCard = document.getElementById('resultsCard');
    const resultsContent = document.getElementById('resultsContent');
    
    // Show/hide DKIM selector based on check type selection
    document.querySelectorAll('input[name="checkType"]').forEach(radio => {
        radio.addEventListener('change', function() {
            selectorContainer.classList.toggle('d-none', this.value !== 'dkim');
        });
    });
    
    // Form submission
    domainForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const domain = document.getElementById('domain').value.trim();
        const checkType = document.querySelector('input[name="checkType"]:checked').value;
        
        // Display loading indicator
        resultsCard.classList.remove('d-none');
        resultsContent.innerHTML = `
            <div class="d-flex justify-content-center">
                <div class="spinner-border loading-spinner" role="status">
                    <span class="visually-hidden">Loading...</span>
                </div>
            </div>
            <p class="text-center mt-3">This may take up to 15 seconds...</p>
        `;
        
        try {
            let url = `/api/${checkType}?domain=${encodeURIComponent(domain)}`;
            
            // Add selector parameter for DKIM checks
            if (checkType === 'dkim') {
                const selector = document.getElementById('selector').value.trim() || 'default';
                url += `&selector=${encodeURIComponent(selector)}`;
            }
                 
            // Set up timeout for fetch
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 30000); // 30-second timeout
            
            const response = await fetch(url, {
                signal: controller.signal
            }).catch(err => {
                if (err.name === 'AbortError') {
                    throw new Error('Request timed out after 30 seconds');
                }
                throw err;
            });
            
            clearTimeout(timeoutId);
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`Server error: ${response.status} ${errorText}`);
            }
            
            const data = await response.json();

            // Display results based on check type
            displayResults(checkType, data);
            
        } catch (error) {
            resultsContent.innerHTML = `
                <div class="alert alert-danger">
                    <h5>Error</h5>
                    <p>${error.message || 'An unexpected error occurred'}</p>
                </div>
            `;
        }
    });
    
    function displayResults(checkType, data) {
        let resultsHTML = '';
        
        switch (checkType) {
            case 'mx':
                if (data.mxRecords && data.mxRecords.length > 0) {
                    resultsHTML = `
                        <h5>MX Records for ${data.domain}</h5>
                        <div class="table-responsive">
                            <table class="table table-bordered table-striped">
                                <thead>
                                    <tr>
                                        <th>Priority</th>
                                        <th>Mail Server</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.mxRecords.map(record => `
                                        <tr>
                                            <td>${record.priority}</td>
                                            <td>${record.exchange}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                    `;
                } else {
                    resultsHTML = `
                        <div class="alert alert-warning">
                            <h5>No MX Records Found</h5>
                            <p>No MX records were found for ${data.domain}</p>
                        </div>
                    `;
                }
                break;
                
            case 'spf':
                if (data.spfRecord && data.spfRecord !== 'No SPF record found') {
                    resultsHTML = `
                        <h5>SPF Record for ${data.domain}</h5>
                        <pre>${data.spfRecord}</pre>
                        <div class="mt-3">
                            <h6>SPF Analysis</h6>
                            <p>${analyzeSPF(data.spfRecord)}</p>
                        </div>
                    `;
                } else {
                    resultsHTML = `
                        <div class="alert alert-warning">
                            <h5>No SPF Record Found</h5>
                            <p>No SPF record was found for ${data.domain}</p>
                        </div>
                    `;
                }
                break;
                
            case 'dkim':
                if (data.dkimRecord && data.dkimRecord !== 'No DKIM record found') {
                    resultsHTML = `
                        <h5>DKIM Record for ${data.selector}._domainkey.${data.domain}</h5>
                        <pre>${data.dkimRecord}</pre>
                    `;
                } else {
                    resultsHTML = `
                        <div class="alert alert-warning">
                            <h5>No DKIM Record Found</h5>
                            <p>No DKIM record was found for ${data.selector}._domainkey.${data.domain}</p>
                        </div>
                    `;
                }
                break;
                
            case 'dmarc':
                if (data.dmarcRecord && data.dmarcRecord !== 'No DMARC record found') {
                    resultsHTML = `
                        <h5>DMARC Record for ${data.domain}</h5>
                        <pre>${data.dmarcRecord}</pre>
                        <div class="mt-3">
                            <h6>DMARC Analysis</h6>
                            <p>${analyzeDMARC(data.dmarcRecord)}</p>
                        </div>
                    `;
                } else {
                    resultsHTML = `
                        <div class="alert alert-warning">
                            <h5>No DMARC Record Found</h5>
                            <p>No DMARC record was found for ${data.domain}</p>
                        </div>
                    `;
                }
                break;
            
            case 'blacklist':
                if (data.blacklists && data.blacklists.length > 0) {
                    resultsHTML = `
                        <h5>Blacklist Check Results for ${data.target}</h5>
                        <p>IP Address: ${data.ipAddress}</p>
                        <div class="mb-3">
                            <span class="badge bg-success">${data.cleanCount} Clean</span>
                            <span class="badge bg-danger">${data.listedCount} Listed</span>
                            ${data.errorCount > 0 ? `<span class="badge bg-warning">${data.errorCount} Errors</span>` : ''}
                        </div>
                        
                        <div class="table-responsive">
                            <table class="table table-bordered table-striped">
                                <thead>
                                    <tr>
                                        <th>Blacklist</th>
                                        <th>Description</th>
                                        <th>Status</th>
                                        <th>Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${data.blacklists.map(item => `
                                        <tr>
                                            <td>${item.blacklist}</td>
                                            <td><small>${item.description || ''}</small></td>
                                            <td>
                                                <span class="badge ${item.listed ? 'bg-danger' : item.listed === false ? 'bg-success' : 'bg-warning'}">
                                                    ${item.status}
                                                </span>
                                            </td>
                                            <td>
                                                ${item.reason ? `<small>${item.reason}</small>` : ''}
                                                ${item.error ? `<small class="text-danger">Error: ${item.error}</small>` : ''}
                                            </td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                        <div class="alert alert-info mt-3">
                            <h6>About Blacklists</h6>
                            <p>Being listed on a blacklist doesn't automatically mean your mail will be blocked, but it may affect deliverability.</p>
                            <p>If you're listed, you can visit the blacklist provider's website to learn about their delisting process.</p>
                        </div>
                    `;
                } else {
                    resultsHTML = `
                        <div class="alert alert-warning">
                            <h5>Blacklist Check Failed</h5>
                            <p>Could not check blacklists for ${data.target}</p>
                            ${data.error ? `<p>Error: ${data.error}</p>` : ''}
                        </div>
                    `;
                }
                break;
                
            case 'dns-records':
                if (data.records && data.records.length > 0) {
                    resultsHTML = `
                        <h5>Extended DNS Records for ${data.domain}</h5>
                        <div class="accordion" id="dnsRecordsAccordion">
                    `;
                    
                    // Loop through each record type
                    data.records.forEach((recordType, index) => {
                        const hasRecords = recordType.records && recordType.records.length > 0;
                        
                        resultsHTML += `
                            <div class="accordion-item">
                                <h2 class="accordion-header" id="heading${recordType.type}">
                                    <button class="accordion-button ${index > 0 ? 'collapsed' : ''}" type="button" 
                                            data-bs-toggle="collapse" data-bs-target="#collapse${recordType.type}" 
                                            aria-expanded="${index === 0 ? 'true' : 'false'}" aria-controls="collapse${recordType.type}">
                                        ${recordType.type} Records
                                        ${!recordType.success ? '<span class="badge bg-danger ms-2">Error</span>' : ''}
                                        ${recordType.success && !hasRecords ? '<span class="badge bg-warning ms-2">Not Found</span>' : ''}
                                    </button>
                                </h2>
                                <div id="collapse${recordType.type}" class="accordion-collapse collapse ${index === 0 ? 'show' : ''}" 
                                     aria-labelledby="heading${recordType.type}" data-bs-parent="#dnsRecordsAccordion">
                                    <div class="accordion-body">
                        `;
                        
                        if (!recordType.success) {
                            resultsHTML += `<div class="alert alert-danger">Error: ${recordType.error}</div>`;
                        } else if (!hasRecords) {
                            resultsHTML += `<div class="alert alert-warning">No ${recordType.type} records found</div>`;
                        } else {
                            if (recordType.type === 'SOA') {
                                // Special handling for SOA record which is an object
                                const soa = recordType.records[0];
                                resultsHTML += `
                                    <table class="table table-bordered">
                                        <tr><th>Primary NS</th><td>${soa.nsname}</td></tr>
                                        <tr><th>Hostmaster</th><td>${soa.hostmaster}</td></tr>
                                        <tr><th>Serial</th><td>${soa.serial}</td></tr>
                                        <tr><th>Refresh</th><td>${soa.refresh}</td></tr>
                                        <tr><th>Retry</th><td>${soa.retry}</td></tr>
                                        <tr><th>Expire</th><td>${soa.expire}</td></tr>
                                        <tr><th>Min TTL</th><td>${soa.minttl}</td></tr>
                                    </table>
                                `;
                            } else if (recordType.type === 'CAA') {
                                // Special handling for CAA records
                                resultsHTML += `
                                    <table class="table table-bordered">
                                        <thead>
                                            <tr>
                                                <th>Flag</th>
                                                <th>Tag</th>
                                                <th>Value</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${recordType.records.map(record => `
                                                <tr>
                                                    <td>${record.critical}</td>
                                                    <td>${record.tag}</td>
                                                    <td>${record.value}</td>
                                                </tr>
                                            `).join('')}
                                        </tbody>
                                    </table>
                                `;
                            } else {
                                // Standard list for other record types
                                resultsHTML += `
                                    <ul class="list-group">
                                        ${recordType.records.map(record => `
                                            <li class="list-group-item">${record}</li>
                                        `).join('')}
                                    </ul>
                                `;
                            }
                        }
                        
                        resultsHTML += `
                                    </div>
                                </div>
                            </div>
                        `;
                    });
                    
                    resultsHTML += `</div>`;
                } else {
                    resultsHTML = `
                        <div class="alert alert-warning">
                            <h5>No DNS Records Found</h5>
                            <p>Could not find DNS records for ${data.domain}</p>
                            ${data.error ? `<p>Error: ${data.error}</p>` : ''}
                        </div>
                    `;
                }
                break;
        }
        
        resultsContent.innerHTML = resultsHTML;
    }
    
    // Basic SPF record analysis
    function analyzeSPF(spfRecord) {
        let analysis = [];
        
        if (spfRecord.includes(' -all')) {
            analysis.push('Policy: <strong>Fail</strong> - All mail not matching this SPF record will be rejected.');
        } else if (spfRecord.includes(' ~all')) {
            analysis.push('Policy: <strong>SoftFail</strong> - Mail not matching this SPF record will be accepted but marked.');
        } else if (spfRecord.includes(' ?all')) {
            analysis.push('Policy: <strong>Neutral</strong> - No policy statement is made.');
        } else if (spfRecord.includes(' +all')) {
            analysis.push('Policy: <strong>Pass</strong> (NOT RECOMMENDED) - All hosts are allowed to send.');
        }
        
        return analysis.join('<br>');
    }
    
    // Basic DMARC record analysis
    function analyzeDMARC(dmarcRecord) {
        let analysis = [];
        
        // Extract policy
        const pMatch = dmarcRecord.match(/p=([^;\s]+)/);
        if (pMatch) {
            const policy = pMatch[1].toLowerCase();
            if (policy === 'none') {
                analysis.push('Policy: <strong>None</strong> - No specific action is requested.');
            } else if (policy === 'quarantine') {
                analysis.push('Policy: <strong>Quarantine</strong> - Messages that fail checks should be treated with suspicion.');
            } else if (policy === 'reject') {
                analysis.push('Policy: <strong>Reject</strong> - Messages that fail checks should be rejected.');
            }
        }
        
        // Extract reporting percentage
        const pctMatch = dmarcRecord.match(/pct=([0-9]+)/);
        if (pctMatch) {
            const pct = parseInt(pctMatch[1]);
            analysis.push(`Percentage: <strong>${pct}%</strong> of messages are subject to filtering.`);
        }
        
        return analysis.join('<br>');
    }
});