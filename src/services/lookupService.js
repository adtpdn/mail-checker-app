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
  },

  //   Blacklist Check
  async checkBlacklists(domain) {
    try {
      // First resolve the domain to its IP address
      const addresses = await dns.resolve4(domain);
      const ipAddress = addresses[0]; // Take the first IP if multiple
      
      // List of common DNS blacklists
      const blacklists = [
        'zen.spamhaus.org',
        'bl.spamcop.net',
        'dnsbl.sorbs.net',
        'b.barracudacentral.org',
        'cbl.abuseat.org',
        'dnsbl-1.uceprotect.net',
        'xbl.spamhaus.org',
        'pbl.spamhaus.org',
        'sbl.spamhaus.org',
        'psbl.surriel.com'
      ];
      
      // // Array to store results
      // const results = [];
      
      // Reverse the IP address for blacklist checking
      const reversedIp = ipAddress.split('.').reverse().join('.');
      
      // Check each blacklist in parallel
      const blacklistPromises = blacklists.map(async (blacklist) => {
        const lookupDomain = `${reversedIp}.${blacklist}`;
        try {
          // Try to resolve the IP - if success, it means it's blacklisted
          await dns.resolve(lookupDomain);
          return { blacklist, listed: true, status: 'Listed' };
        } catch (error) {
          // If resolve fails with ENOTFOUND or ENODATA, it means not listed
          if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
            return { blacklist, listed: false, status: 'Clean' };
          }
          // For other errors, mark as error
          return { blacklist, listed: null, status: 'Error checking' };
        }
      });
      
      const results = await Promise.all(blacklistPromises);
      
      return {
        ipAddress,
        blacklists: results,
        listedCount: results.filter(r => r.listed === true).length,
        cleanCount: results.filter(r => r.listed === false).length,
        errorCount: results.filter(r => r.listed === null).length
      };
    } catch (error) {
      throw new Error(`Failed to check blacklists: ${error.message}`);
    }
  },


  // New method for checking additional DNS records
  async lookupExtendedDNS(domain) {
    try {
      // Fetch various types of DNS records
      const recordTypes = ['A', 'AAAA', 'CNAME', 'NS', 'TXT', 'SOA', 'CAA'];
      
      const recordPromises = recordTypes.map(async (type) => {
        try {
          let records;
          switch (type) {
            case 'A':
              records = await dns.resolve4(domain);
              break;
            case 'AAAA':
              records = await dns.resolve6(domain);
              break;
            case 'CNAME':
              records = await dns.resolveCname(domain);
              break;
            case 'NS':
              records = await dns.resolveNs(domain);
              break;
            case 'TXT':
              records = await dns.resolveTxt(domain);
              // Flatten TXT record arrays
              records = records.map(r => r.join(''));
              break;
            case 'SOA':
              records = await dns.resolveSoa(domain);
              // SOA is a single object, convert to array for consistency
              records = [records];
              break;
            case 'CAA':
              try {
                records = await dns.resolveCaa(domain);
              } catch (e) {
                // CAA records may not exist for many domains
                records = [];
              }
              break;
            default:
              records = [];
          }
          return { type, records, success: true };
        } catch (error) {
          if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
            return { type, records: [], success: true, empty: true };
          }
          return { type, success: false, error: error.message };
        }
      });
      
      return await Promise.all(recordPromises);
    } catch (error) {
      throw new Error(`Failed to lookup extended DNS records: ${error.message}`);
    }
  }


};

module.exports = lookupService;