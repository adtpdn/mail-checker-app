// Using Node.js built-in dns module instead of the deprecated npm 'dns' package
const dns = require('node:dns').promises;
const axios = require('axios');
const { promisify } = require('util');
const { exec } = require('child_process');
const execAsync = promisify(exec);

// Set longer timeout for DNS operations
dns.setServers([...dns.getServers()]);
const DEFAULT_TIMEOUT = 10000; // 10 seconds

// Define blacklist information with descriptions
const BLACKLISTS = [
  { 
    host: 'zen.spamhaus.org', 
    description: 'Spamhaus Zen combines SBL, XBL and PBL blocklists',
    responseMap: {
      '127.0.0.2': 'SBL - Spamhaus Maintained',
      '127.0.0.3': 'SBL - CSS - Spamhaus Maintained',
      '127.0.0.4': 'XBL - CBL Detected Address',
      '127.0.0.9': 'SBL - DROP/EDROP Data',
      '127.0.0.10': 'PBL - ISP Maintained',
      '127.0.0.11': 'PBL - Spamhaus Maintained'
    }
  },
  { 
    host: 'bl.spamcop.net', 
    description: 'SpamCop Blocking List',
    responseMap: {
      '127.0.0.2': 'Listed in SpamCop'
    }
  },
  { 
    host: 'dnsbl.sorbs.net', 
    description: 'SORBS Domain Name System Blacklist',
    responseMap: {
      '127.0.0.2': 'HTTP Proxy',
      '127.0.0.3': 'SOCKS Proxy',
      '127.0.0.4': 'MISC Proxy',
      '127.0.0.5': 'SMTP Server',
      '127.0.0.6': 'Possible Spam Source',
      '127.0.0.7': 'Web Server w/ open Relay',
      '127.0.0.8': 'Verified Spam Source',
      '127.0.0.9': 'Mail Server',
      '127.0.0.10': 'Dynamic IP Block',
      '127.0.0.11': 'Bad Config or Dummy',
      '127.0.0.12': 'Verified Open Relay',
      '127.0.0.14': 'Misc Vulnerability'
    }
  },
  { 
    host: 'b.barracudacentral.org', 
    description: 'Barracuda Reputation Block List',
    responseMap: {
      '127.0.0.2': 'Listed in Barracuda'
    }
  },
  { 
    host: 'cbl.abuseat.org', 
    description: 'Composite Blocking List',
    responseMap: {
      '127.0.0.2': 'Listed in CBL'
    }
  },
  { 
    host: 'dnsbl-1.uceprotect.net', 
    description: 'UCEPROTECT Level 1',
    responseMap: {
      '127.0.0.2': 'Listed in UCEPROTECT-1'
    }
  },
  { 
    host: 'xbl.spamhaus.org', 
    description: 'Spamhaus XBL (Exploits Block List)',
    responseMap: {
      '127.0.0.4': 'CBL',
      '127.0.0.5': 'NJABL',
      '127.0.0.6': 'Not Used',
      '127.0.0.7': 'Not Used'
    }
  },
  { 
    host: 'pbl.spamhaus.org', 
    description: 'Spamhaus PBL (Policy Block List)',
    responseMap: {
      '127.0.0.10': 'ISP Maintained',
      '127.0.0.11': 'Spamhaus Maintained'
    }
  },
  { 
    host: 'sbl.spamhaus.org', 
    description: 'Spamhaus SBL (Spamhaus Block List)',
    responseMap: {
      '127.0.0.2': 'SBL',
      '127.0.0.3': 'CSS'
    }
  },
  { 
    host: 'psbl.surriel.com', 
    description: 'Passive Spam Block List',
    responseMap: {
      '127.0.0.2': 'Listed in PSBL'
    }
  }
];

// Add delay function
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

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
  // async checkBlacklists(domain) {
  //   try {
  //     // First resolve the domain to its IP address
  //     const addresses = await dns.resolve4(domain);
  //     const ipAddress = addresses[0]; // Take the first IP if multiple
      
  //     // List of common DNS blacklists
  //     const blacklists = [
  //       'zen.spamhaus.org',
  //       'bl.spamcop.net',
  //       'dnsbl.sorbs.net',
  //       'b.barracudacentral.org',
  //       'cbl.abuseat.org',
  //       'dnsbl-1.uceprotect.net',
  //       'xbl.spamhaus.org',
  //       'pbl.spamhaus.org',
  //       'sbl.spamhaus.org',
  //       'psbl.surriel.com'
  //     ];
      
  //     // // Array to store results
  //     // const results = [];
      
  //     // Reverse the IP address for blacklist checking
  //     const reversedIp = ipAddress.split('.').reverse().join('.');
      
  //     // Check each blacklist in parallel
  //     const blacklistPromises = blacklists.map(async (blacklist) => {
  //       const lookupDomain = `${reversedIp}.${blacklist}`;
  //       try {
  //         // Try to resolve the IP - if success, it means it's blacklisted
  //         await dns.resolve(lookupDomain);
  //         return { blacklist, listed: true, status: 'Listed' };
  //       } catch (error) {
  //         // If resolve fails with ENOTFOUND or ENODATA, it means not listed
  //         if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
  //           return { blacklist, listed: false, status: 'Clean' };
  //         }
  //         // For other errors, mark as error
  //         return { blacklist, listed: null, status: 'Error checking' };
  //       }
  //     });
      
  //     const results = await Promise.all(blacklistPromises);
      
  //     return {
  //       ipAddress,
  //       blacklists: results,
  //       listedCount: results.filter(r => r.listed === true).length,
  //       cleanCount: results.filter(r => r.listed === false).length,
  //       errorCount: results.filter(r => r.listed === null).length
  //     };
  //   } catch (error) {
  //     throw new Error(`Failed to check blacklists: ${error.message}`);
  //   }
  // },

  // Updated method for Blacklist Checking with delays
  async checkBlacklists(domain) {
    try {
      // First resolve the domain to its IP address
      const addresses = await dns.resolve4(domain).catch(err => {
        // If domain doesn't resolve, try to process as IP directly
        const ipPattern = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        if (ipPattern.test(domain)) {
          return [domain];
        }
        throw err;
      });
      
      const ipAddress = addresses[0]; // Take the first IP if multiple
      
      // Reverse the IP address for blacklist checking
      const reversedIp = ipAddress.split('.').reverse().join('.');
      
      // Check each blacklist in parallel (with some delay between requests)
      const blacklistPromises = BLACKLISTS.map(async (blacklistInfo, index) => {
        // Stagger requests to avoid overwhelming DNS servers 
        // Add 300ms delay between each batch of 3 requests
        await delay(Math.floor(index / 3) * 300);
        
        const { host, description, responseMap } = blacklistInfo;
        const lookupDomain = `${reversedIp}.${host}`;
        
        try {
          // Try to resolve the IP - if success, it means it's blacklisted
          const addresses = await dns.resolve(lookupDomain)
            .catch(e => { 
              // Add a retry with delay on first failure
              return delay(500).then(() => dns.resolve(lookupDomain));
            });
          
          // Get the specific reason from the response if available
          let reason = "Listed";
          if (addresses && addresses[0] && responseMap && responseMap[addresses[0]]) {
            reason = responseMap[addresses[0]];
          }
          
          return { 
            blacklist: host, 
            description,
            listed: true, 
            status: 'Listed',
            reason: reason
          };
        } catch (error) {
          // If resolve fails with ENOTFOUND or ENODATA, it means not listed
          if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
            return { 
              blacklist: host,
              description,
              listed: false, 
              status: 'Clean'
            };
          }
          // For timeout or other errors, mark as error
          return { 
            blacklist: host,
            description,
            listed: null, 
            status: 'Error checking',
            error: error.code || error.message
          };
        }
      });
      
      // Add overall timeout to prevent hanging
      const timeoutPromise = delay(15000).then(() => {
        throw new Error('Operation timed out after 15 seconds');
      });
      
      // Wait for all blacklist checks or timeout, whichever comes first
      const results = await Promise.race([
        Promise.all(blacklistPromises),
        timeoutPromise
      ]);
      
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

  // // New method for checking additional DNS records
  // async lookupExtendedDNS(domain) {
  //   try {
  //     // Fetch various types of DNS records
  //     const recordTypes = ['A', 'AAAA', 'CNAME', 'NS', 'TXT', 'SOA', 'CAA'];
      
  //     const recordPromises = recordTypes.map(async (type) => {
  //       try {
  //         let records;
  //         switch (type) {
  //           case 'A':
  //             records = await dns.resolve4(domain);
  //             break;
  //           case 'AAAA':
  //             records = await dns.resolve6(domain);
  //             break;
  //           case 'CNAME':
  //             records = await dns.resolveCname(domain);
  //             break;
  //           case 'NS':
  //             records = await dns.resolveNs(domain);
  //             break;
  //           case 'TXT':
  //             records = await dns.resolveTxt(domain);
  //             // Flatten TXT record arrays
  //             records = records.map(r => r.join(''));
  //             break;
  //           case 'SOA':
  //             records = await dns.resolveSoa(domain);
  //             // SOA is a single object, convert to array for consistency
  //             records = [records];
  //             break;
  //           case 'CAA':
  //             try {
  //               records = await dns.resolveCaa(domain);
  //             } catch (e) {
  //               // CAA records may not exist for many domains
  //               records = [];
  //             }
  //             break;
  //           default:
  //             records = [];
  //         }
  //         return { type, records, success: true };
  //       } catch (error) {
  //         if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
  //           return { type, records: [], success: true, empty: true };
  //         }
  //         return { type, success: false, error: error.message };
  //       }
  //     });
      
  //     return await Promise.all(recordPromises);
  //   } catch (error) {
  //     throw new Error(`Failed to lookup extended DNS records: ${error.message}`);
  //   }
  // }

  // Updated method for checking additional DNS records with better timeout handling
  async lookupExtendedDNS(domain) {
    try {
      // Fetch various types of DNS records
      const recordTypes = ['A', 'AAAA', 'CNAME', 'NS', 'TXT', 'SOA', 'CAA'];
      
      const recordPromises = recordTypes.map(async (type, index) => {
        // Add staggered delays to prevent overwhelming DNS servers
        await delay(index * 200); 
        
        try {
          let records;
          // Set a timeout for each DNS request
          const timeoutPromise = delay(8000).then(() => {
            throw new Error(`Request timed out after 8 seconds`);
          });
          
          const dnsLookupPromise = (async () => {
            switch (type) {
              case 'A':
                return await dns.resolve4(domain);
              case 'AAAA':
                return await dns.resolve6(domain);
              case 'CNAME':
                return await dns.resolveCname(domain);
              case 'NS':
                return await dns.resolveNs(domain);
              case 'TXT':
                const txtRecords = await dns.resolveTxt(domain);
                // Flatten TXT record arrays
                return txtRecords.map(r => r.join(''));
              case 'SOA':
                const soa = await dns.resolveSoa(domain);
                // SOA is a single object, convert to array for consistency
                return [soa];
              case 'CAA':
                try {
                  return await dns.resolveCaa(domain);
                } catch (e) {
                  // CAA records may not exist for many domains
                  if (e.code === 'ENODATA' || e.code === 'ENOTFOUND') {
                    return [];
                  }
                  throw e;
                }
              default:
                return [];
            }
          })();
          
          // Race between the DNS lookup and the timeout
          records = await Promise.race([dnsLookupPromise, timeoutPromise]);
          
          return { 
            type, 
            records, 
            success: true,
            ttl: await this.getTTL(domain, type).catch(() => 'Unknown')
          };
        } catch (error) {
          if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
            return { 
              type, 
              records: [], 
              success: true, 
              empty: true,
              message: 'No records found'
            };
          }
          
          // Add more specific error messages
          let errorMessage = error.message;
          if (error.code === 'ETIMEOUT' || error.message.includes('timed out')) {
            errorMessage = 'Request timed out. The DNS server took too long to respond.';
          }
          
          return { 
            type, 
            success: false, 
            error: errorMessage
          };
        }
      });
      
      return await Promise.all(recordPromises);
    } catch (error) {
      throw new Error(`Failed to lookup extended DNS records: ${error.message}`);
    }
  },

  // Helper method to get TTL values
  async getTTL(domain, recordType) {
    try {
      // This is a simplified approach - for a more accurate TTL, you'd need to use
      // a lower-level DNS library that exposes the TTL values directly
      const command = `dig +nocmd ${domain} ${recordType} +noall +answer`;
      const { stdout } = await execAsync(command).catch(() => ({ stdout: '' }));
      
      // Parse the TTL from the dig output
      const match = stdout.match(/\s+(\d+)\s+IN\s+/);
      return match ? match[1] + ' seconds' : 'Unknown';
    } catch (error) {
      return 'Unknown';
    }
  }

};

module.exports = lookupService;