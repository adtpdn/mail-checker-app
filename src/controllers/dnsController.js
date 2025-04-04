const lookupService = require('../services/lookupService');

const dnsController = {
  // MX Record Lookup
  async getMXRecords(req, res) {
    try {
      const { domain } = req.query;
      if (!domain) {
        return res.status(400).json({ error: 'Domain is required' });
      }
      
      const mxRecords = await lookupService.lookupMX(domain);
      return res.status(200).json({ domain, mxRecords });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  },
  
  // SPF Record Lookup
  async getSPFRecord(req, res) {
    try {
      const { domain } = req.query;
      if (!domain) {
        return res.status(400).json({ error: 'Domain is required' });
      }
      
      const spfRecord = await lookupService.lookupTXT(domain, 'spf');
      return res.status(200).json({ domain, spfRecord });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  },
  
  // DKIM Record Lookup
  async getDKIMRecord(req, res) {
    try {
      const { domain, selector } = req.query;
      if (!domain || !selector) {
        return res.status(400).json({ error: 'Domain and selector are required' });
      }
      
      const dkimRecord = await lookupService.lookupDKIM(domain, selector);
      return res.status(200).json({ domain, selector, dkimRecord });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  },
  
  // DMARC Record Lookup
  async getDMARCRecord(req, res) {
    try {
      const { domain } = req.query;
      if (!domain) {
        return res.status(400).json({ error: 'Domain is required' });
      }
      
      const dmarcRecord = await lookupService.lookupDMARC(domain);
      return res.status(200).json({ domain, dmarcRecord });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  },

  // Blacklist Check
  async checkBlacklists(req, res) {
    try {
      const { domain, ip } = req.query;
      
      if (!domain && !ip) {
        return res.status(400).json({ error: 'Domain or IP address is required' });
      }
      
      const target = domain || ip;
      
      // Create a promise that will timeout after 20 seconds
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Operation timed out')), 20000);
      });
      
      // Race the actual operation against the timeout
      const blacklistResults = await Promise.race([
        lookupService.checkBlacklists(target),
        timeoutPromise
      ]);
      
      return res.status(200).json({ target, ...blacklistResults });
    } catch (error) {
      console.error('Error in blacklist check:', error);
      return res.status(500).json({ 
        error: error.message,
        target: req.query.domain || req.query.ip
      });
    }
  },

  // Extended DNS Records
  async getExtendedDNSRecords(req, res) {
    try {
      const { domain } = req.query;
      if (!domain) {
        return res.status(400).json({ error: 'Domain is required' });
      }
      
      // Create a promise that will timeout after 20 seconds
      const timeoutPromise = new Promise((_, reject) => {
        setTimeout(() => reject(new Error('Operation timed out')), 20000);
      });
      
      // Race the actual DNS lookup against the timeout
      const dnsRecords = await Promise.race([
        lookupService.lookupExtendedDNS(domain),
        timeoutPromise
      ]);
      
      return res.status(200).json({ domain, records: dnsRecords });
    } catch (error) {
      console.error('Error in DNS records check:', error);
      return res.status(500).json({ 
        error: error.message,
        domain: req.query.domain
      });
    }
  }

};

module.exports = dnsController;