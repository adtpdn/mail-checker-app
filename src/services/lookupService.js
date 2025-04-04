// Using Node.js built-in dns module instead of the deprecated npm 'dns' package
const dns = require('node:dns').promises;
const axios = require('axios');

const lookupService = {
  // MX Record Lookup
  async lookupMX(domain) {
    try {
      const mxRecords = await dns.resolveMx(domain);
      return mxRecords.map(record => ({
        priority: record.priority,
        exchange: record.exchange
      }));
    } catch (error) {
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        return [];
      }
      throw new Error(`Failed to lookup MX records: ${error.message}`);
    }
  },
  
  // TXT Record Lookup for SPF
  async lookupTXT(domain, recordType) {
    try {
      const txtRecords = await dns.resolveTxt(domain);
      
      if (recordType === 'spf') {
        // Find SPF record
        const spfRecord = txtRecords.flat().find(record => 
          record.toLowerCase().startsWith('v=spf1')
        );
        return spfRecord || 'No SPF record found';
      }
      
      return txtRecords.flat();
    } catch (error) {
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        return 'No TXT records found';
      }
      throw new Error(`Failed to lookup TXT records: ${error.message}`);
    }
  },
  
  // DKIM Record Lookup
  async lookupDKIM(domain, selector) {
    try {
      const dkimDomain = `${selector}._domainkey.${domain}`;
      const txtRecords = await dns.resolveTxt(dkimDomain);
      
      // Find DKIM record
      const dkimRecord = txtRecords.flat().find(record => 
        record.toLowerCase().includes('v=dkim1')
      );
      
      return dkimRecord || 'No DKIM record found';
    } catch (error) {
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        return 'No DKIM record found';
      }
      throw new Error(`Failed to lookup DKIM record: ${error.message}`);
    }
  },
  
  // DMARC Record Lookup
  async lookupDMARC(domain) {
    try {
      const dmarcDomain = `_dmarc.${domain}`;
      const txtRecords = await dns.resolveTxt(dmarcDomain);
      
      // Find DMARC record
      const dmarcRecord = txtRecords.flat().find(record => 
        record.toLowerCase().startsWith('v=dmarc1')
      );
      
      return dmarcRecord || 'No DMARC record found';
    } catch (error) {
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        return 'No DMARC record found';
      }
      throw new Error(`Failed to lookup DMARC record: ${error.message}`);
    }
  }
};

module.exports = lookupService;