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
        `;
        
        try {
            let url = `/api/${checkType}?domain=${encodeURIComponent(domain)}`;
            
            // Add selector parameter for DKIM checks
            if (checkType === 'dkim') {
                const selector = document.getElementById('selector').value.trim() || 'default';
                url += `&selector=${encodeURIComponent(selector)}`;
            }
            
            const response = await fetch(url);
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