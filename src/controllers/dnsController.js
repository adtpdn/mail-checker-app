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
      const blacklistResults = await lookupService.checkBlacklists(target);
      return res.status(200).json({ target, ...blacklistResults });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  },

  // Extended DNS Records
  async getExtendedDNSRecords(req, res) {
    try {
      const { domain } = req.query;
      if (!domain) {
        return res.status(400).json({ error: 'Domain is required' });
      }
      
      const dnsRecords = await lookupService.lookupExtendedDNS(domain);
      return res.status(200).json({ domain, records: dnsRecords });
    } catch (error) {
      return res.status(500).json({ error: error.message });
    }
  }

};

module.exports = dnsController;