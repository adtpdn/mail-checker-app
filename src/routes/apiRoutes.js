const express = require('express');
const router = express.Router();
const dnsController = require('../controllers/dnsController');

// MX Records
router.get('/mx', dnsController.getMXRecords);

// SPF Record
router.get('/spf', dnsController.getSPFRecord);

// DKIM Record
router.get('/dkim', dnsController.getDKIMRecord);

// DMARC Record
router.get('/dmarc', dnsController.getDMARCRecord);

// Blacklist Check
router.get('/blacklist', dnsController.checkBlacklists);

// Extended DNS Records
router.get('/dns-records', dnsController.getExtendedDNSRecords);

module.exports = router;