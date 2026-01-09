// api.js
console.log('api.js loaded');
const API_BASE_URL = 'http://localhost:3001/api';

async function fetchData(endpoint, params = {}) {
    try {
        const queryString = new URLSearchParams(params).toString();
        const url = `${API_BASE_URL}${endpoint}?${queryString}`;
        const response = await fetch(url, {
            headers: { 'Content-Type': 'application/json' },
        });
        if (!response.ok) throw new Error(`API request failed: ${response.statusText}`);
        return await response.json();
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

const api = {
    getWhoisInfo: (domain) => fetchData('/whois', { domain }),
    getDnsInfo: (domain) => fetchData('/dns', { domain }),
    getSslInfo: (domain) => fetchData('/ssl', { domain }),
    checkVirusTotal: (url) => fetchData('/virustotal', { url }),
    checkSafeBrowsing: (url) => fetchData('/safebrowsing', { url }),

    getEnrichmentData: async (url) => {
        try {
            const domain = new URL(url).hostname;
            const [whois, dns, ssl, virustotal, safebrowsing] = await Promise.allSettled([
                api.getWhoisInfo(domain),
                api.getDnsInfo(domain),
                api.getSslInfo(domain),
                api.checkVirusTotal(url),
                api.checkSafeBrowsing(url)
            ]);

            return {
                whois: whois.status === 'fulfilled' ? whois.value : { error: whois.reason?.message || 'Failed to fetch WHOIS data' },
                dns: dns.status === 'fulfilled' ? dns.value : { error: dns.reason?.message || 'Failed to fetch DNS data' },
                ssl: ssl.status === 'fulfilled' ? ssl.value : { error: ssl.reason?.message || 'Failed to fetch SSL data' },
                virustotal: virustotal.status === 'fulfilled' ? virustotal.value : { error: virustotal.reason?.message || 'Failed to fetch VirusTotal data' },
                safebrowsing: safebrowsing.status === 'fulfilled' ? safebrowsing.value : { error: safebrowsing.reason?.message || 'Failed to fetch Safe Browsing data' }
            };
        } catch (error) {
            console.error('Error fetching enrichment data:', error);
            throw error;
        }
    }
};