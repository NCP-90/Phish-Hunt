console.log('script.js loaded');
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded');
    // DOM Elements
    const urlInput = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const resultSection = document.getElementById('resultSection');
    const verdictBadge = document.getElementById('verdictBadge');
    const riskScoreElement = document.getElementById('riskScore');
    const scoreFill = document.getElementById('scoreFill');
    const redFlagsList = document.getElementById('redFlagsList');
    const explanationText = document.getElementById('explanationText');
    const recommendationsList = document.getElementById('recommendationsList');
    const attackerIntentList = document.getElementById('attackerIntentList');
    const fingerprintValue = document.getElementById('fingerprintValue');
    const fingerprintDecodedList = document.getElementById('fingerprintDecodedList');
    const confidenceBadge = document.getElementById('confidenceBadge');
    const confidenceText = document.getElementById('confidenceText');
    const urlBreakdownView = document.getElementById('urlBreakdownView');
    const psychologyList = document.getElementById('psychologyList');
    const nextStepsText = document.getElementById('nextStepsText');
    const downloadReportBtn = document.getElementById('downloadReportBtn');
    const educationContent = document.getElementById('educationContent');
    const urlBreakdownPanel = document.getElementById('urlBreakdown');
    const emailSummaryPanel = document.getElementById('emailSummary');
    const emailSummaryContent = document.getElementById('emailSummaryContent');

    // Holds the most recent analysis data for report generation
    let latestAnalysis = null;

    // Configuration
    const config = {
        suspiciousKeywords: [
            'login', 'signin', 'sign-in', 'log-in', 'account', 'verify', 
            'banking', 'paypal', 'ebay', 'amazon', 'netflix', 'credit', 
            'password', 'update', 'security', 'alert', 'urgent', 'action',
            'suspended', 'verify', 'confirm', 'secure', 'billing', 'invoice'
        ],
        suspiciousTlds: ['.tk', '.ml', '.ga', '.cf', '.pw', '.gq', '.xyz', '.top', '.club'],
        maxUrlLength: 75,
        maxSubdomains: 2
    };

    // Keywords used to infer attacker intent (educational / explainability)
    const intentKeywords = {
        urgency: ['urgent', 'immediately', 'now', 'action', 'alert', 'warning', 'suspended', 'limited', 'expires'],
        login: ['login', 'sign in', 'signin', 'password', 'verify', 'account', 'authentication'],
        payment: ['pay', 'payment', 'invoice', 'billing', 'bank', 'credit', 'card', 'refund'],
        brand: ['paypal', 'amazon', 'netflix', 'microsoft', 'apple', 'google', 'facebook', 'instagram']
    };

    // Event Listeners
    // Mode controls (URL vs Email)
    const modeUrlBtn = document.getElementById('modeUrlBtn');
    const modeEmailBtn = document.getElementById('modeEmailBtn');
    const emailInput = document.getElementById('emailInput');
    const emailLabel = document.getElementById('emailLabel');
    const urlLabel = document.getElementById('urlLabel');
    let currentMode = 'url';

    // Debug: Check if elements exist
    console.log('Mode buttons found:', { modeUrlBtn: !!modeUrlBtn, modeEmailBtn: !!modeEmailBtn });

    function setMode(mode) {
        currentMode = mode;
        if (mode === 'email') {
            modeUrlBtn.classList.remove('active');
            modeEmailBtn.classList.add('active');
            modeUrlBtn.setAttribute('aria-selected', 'false');
            modeEmailBtn.setAttribute('aria-selected', 'true');
            urlLabel.classList.add('hidden');
            urlInput.classList.add('hidden');
            emailInput.classList.remove('hidden');
            emailLabel.classList.remove('hidden');
        } else {
            modeEmailBtn.classList.remove('active');
            modeUrlBtn.classList.add('active');
            modeEmailBtn.setAttribute('aria-selected', 'false');
            modeUrlBtn.setAttribute('aria-selected', 'true');
            urlLabel.classList.remove('hidden');
            urlInput.classList.remove('hidden');
            emailInput.classList.add('hidden');
            emailLabel.classList.add('hidden');
        }
    }

    if (modeUrlBtn) modeUrlBtn.addEventListener('click', () => setMode('url'));
    if (modeEmailBtn) modeEmailBtn.addEventListener('click', () => setMode('email'));

    // Main scan button: choose behavior by mode
    scanBtn.addEventListener('click', () => {
        console.log('Scan button clicked! mode=', currentMode);
        if (currentMode === 'email') analyzeEmail(); else analyzeUrl();
    });

    // Enter key on URL input
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && currentMode === 'url') analyzeUrl();
    });

    // Ctrl+Enter on email input triggers scan
    emailInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) analyzeEmail();
    });

    /**
     * Main function to analyze the URL
     */
    function analyzeUrl() {
        console.log('analyzeUrl called');
        const url = urlInput.value.trim();
        console.log('URL to analyze:', url);
        const userTypedHttps = /^https:\/\//i.test(url);
        
        // Basic validation
        if (!url) {
            showError('Please enter a URL to analyze');
            return;
        }

        // Reset UI
        resetResults();
        
        try {
            // Parse and validate URL
            // We default to https for parsing convenience, but we DO NOT treat it as secure
            // unless the user actually typed https:// (educational rule).
            const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
            const domain = urlObj.hostname;
            
            // Run all checks
            const checks = runSecurityChecks(url, urlObj, domain, userTypedHttps);
            const riskScore = calculateRiskScore(checks);
            
            // Display results
            displayResults(checks, riskScore, domain);
            
        } catch (error) {
            showError('Invalid URL format. Please enter a valid URL.');
            console.error('URL Analysis Error:', error);
        }
    }

    /**
     * Run all security checks on the URL
     */
    function runSecurityChecks(url, urlObj, domain, userTypedHttps) {
        const urlText = `${urlObj.hostname}${urlObj.pathname}${urlObj.search}`.toLowerCase();

        return {
            // Educational rule: only count HTTPS if the user actually provided an https URL.
            hasHttps: Boolean(userTypedHttps),
            isLongUrl: checkUrlLength(url),
            hasSuspiciousKeywords: checkSuspiciousKeywords(url),
            hasIpAddress: checkForIpAddress(domain),
            hasSuspiciousTld: checkSuspiciousTld(domain),
            hasManySubdomains: checkSubdomains(domain),
            hasUrlShortener: checkUrlShortener(domain),
            hasSpecialChars: checkSpecialChars(url),

            // Explainability signals (used for attacker intent + fingerprint)
            hasUrgencyLanguage: checkAnyKeyword(urlText, intentKeywords.urgency),
            hasLoginLure: checkAnyKeyword(urlText, intentKeywords.login),
            hasPaymentLure: checkAnyKeyword(urlText, intentKeywords.payment),
            hasBrandImpersonation: checkAnyKeyword(urlText, intentKeywords.brand),
            looksLikeNewOrUntrustedDomain: checkNewDomainHeuristic(domain)
        };
    }

    /**
     * Utility: safe keyword check
     * (No regex injection risk because keywords are controlled by us)
     */
    function checkAnyKeyword(text, keywords) {
        return keywords.some((k) => text.includes(k));
    }

    /**
     * Individual security check functions
     */
    function checkUrlLength(url) {
        return url.length > config.maxUrlLength;
    }

    function checkSuspiciousKeywords(url) {
        const lowerUrl = url.toLowerCase();
        return config.suspiciousKeywords.some(keyword => 
            lowerUrl.includes(keyword)
        );
    }

    function checkForIpAddress(domain) {
        // Simple IP address regex (IPv4)
        const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        return ipRegex.test(domain);
    }

    function checkSuspiciousTld(domain) {
        const tld = domain.substring(domain.lastIndexOf('.'));
        return config.suspiciousTlds.includes(tld.toLowerCase());
    }

    /**
     * Heuristic-only (offline) guess for "new/untrusted" domains.
     * We cannot do WHOIS without network, so we use structural signals often seen in phishing.
     */
    function checkNewDomainHeuristic(domain) {
        const lower = domain.toLowerCase();

        // Punycode is often used to mimic real brands with look-alike characters
        if (lower.includes('xn--')) return true;

        // Too many digits in the domain is a common pattern
        const digits = (lower.match(/\d/g) || []).length;
        const letters = (lower.match(/[a-z]/g) || []).length;
        const total = digits + letters;
        if (total > 0 && digits / total >= 0.35) return true;

        // Excessive hyphens often indicate brand-squatting
        const hyphens = (lower.match(/-/g) || []).length;
        if (hyphens >= 3) return true;

        // If TLD is already suspicious, treat it as higher distrust
        if (checkSuspiciousTld(lower)) return true;

        return false;
    }

    function checkSubdomains(domain) {
        const subdomains = domain.split('.').length - 2; // -2 for TLD and main domain
        return subdomains > config.maxSubdomains;
    }

    function checkUrlShortener(domain) {
        const shorteners = [
            'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
            'adf.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rebrand.ly', 't2m.io'
        ];
        return shorteners.some(shortener => domain.includes(shortener));
    }

    function checkSpecialChars(url) {
        // Check for excessive special characters that might indicate obfuscation
        const specialChars = url.match(/[^a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=]/g) || [];
        return specialChars.length > 5; // Arbitrary threshold
    }

    /**
     * Calculate risk score based on checks
     */
    function calculateRiskScore(checks) {
        let score = 0;
        
        // Weighted scoring (improved weights)
        if (!checks.hasHttps) score += 25; // Critical for security
        if (checks.hasIpAddress) score += 35; // High indicator
        if (checks.hasSuspiciousTld) score += 30; // Very suspicious
        if (checks.looksLikeNewOrUntrustedDomain) score += 25; // Domain trust matters
        if (checks.hasSuspiciousKeywords) score += 20; // Phishing language
        if (checks.hasManySubdomains) score += 18; // Suspicious structure
        if (checks.hasUrlShortener) score += 22; // Hides destination
        if (checks.isLongUrl) score += 12; // Obfuscation
        if (checks.hasSpecialChars) score += 12; // Unusual encoding
        
        return Math.min(score, 100); // Cap at 100
    }

    /**
     * Analyze pasted email content and produce educational analysis.
     */
    function analyzeEmail() {
        console.log('analyzeEmail called');
        const raw = emailInput.value || '';
        const text = raw.trim();
        if (!text) {
            showError('Please paste the email text to analyze');
            return;
        }

        // Reset UI
        resetResults();

        // Basic header parsing (best-effort, offline)
        const fromMatch = text.match(/^From:\s*(.+)$/im);
        const subjectMatch = text.match(/^Subject:\s*(.+)$/im);
        const fromRaw = fromMatch ? fromMatch[1].trim() : '';
        const subject = subjectMatch ? subjectMatch[1].trim() : '(no subject)';

        // Extract name and email if present: "Name <email@domain>"
        let senderName = '';
        let senderEmail = '';
        if (fromRaw) {
            const m = fromRaw.match(/^(.*)<([^>]+)>$/);
            if (m) {
                senderName = m[1].replace(/"/g, '').trim();
                senderEmail = m[2].trim();
            } else if (fromRaw.includes('@')) {
                senderEmail = fromRaw.trim();
            } else {
                senderName = fromRaw.trim();
            }
        }

        const lower = text.toLowerCase();

        // Keyword lists
        const urgencyKW = intentKeywords.urgency;
        const credentialKW = ['verify', 'login', 'reset password', 'change password', 'confirm your account', 'update your account', 'enter your password'];
        const authorityKW = ['it department', 'human resources', 'hr', 'it', 'admin', 'administrator', 'security team'];
        const secrecyKW = ['do not share', 'confidential', 'private', 'do not forward', 'strictly confidential'];
        const paymentKW = intentKeywords.payment;
        const brandKW = intentKeywords.brand;
        const freeDomains = ['gmail.com','yahoo.com','hotmail.com','outlook.com','live.com'];

        // Indicators
        const hasUrgency = checkAnyKeyword(lower, urgencyKW);
        const hasCredentialRequest = checkAnyKeyword(lower, credentialKW);
        const hasAuthorityTone = checkAnyKeyword(lower, authorityKW);
        const hasSecrecyRequest = checkAnyKeyword(lower, secrecyKW);
        const hasPaymentMention = checkAnyKeyword(lower, paymentKW);
        const hasBrandMention = checkAnyKeyword(lower, brandKW);
        const hasLink = /https?:\/\//i.test(text) || /www\./i.test(text);
        const hasAttachmentMention = /attachment|attached|see attached/i.test(text) || /\.pdf\b|\.docx?\b|\.xls\b/i.test(text);
        const genericSender = (!senderName && senderEmail) || (senderName && senderName.toLowerCase().includes('support')) || (!senderEmail && !senderName);
        const senderDomain = senderEmail.includes('@') ? senderEmail.split('@').pop().toLowerCase() : '';
        const senderFromFreeDomain = senderDomain && freeDomains.includes(senderDomain);

        // Build checks object compatible with some existing helpers
        const checks = {
            hasUrgencyLanguage: hasUrgency,
            hasLoginLure: hasCredentialRequest,
            hasPaymentLure: hasPaymentMention,
            hasBrandImpersonation: hasBrandMention,
            hasIpAddress: false,
            looksLikeNewOrUntrustedDomain: senderFromFreeDomain,
            isLongUrl: false,
            hasSpecialChars: false,
            hasManySubdomains: false
        };

        // Risk scoring (weights from spec)
        let score = 0;
        if (hasUrgency) score += 20; // urgency
        if (hasCredentialRequest) score += 30; // credential theft attempts
        if (hasBrandMention) score += 30; // brand impersonation
        if (hasLink) score += 25; // suspicious link in email
        if (genericSender) score += 15; // generic sender identity
        // minor penalties
        if (hasAuthorityTone) score += 8;
        if (hasSecrecyRequest) score += 8;
        if (hasAttachmentMention) score += 6;

        const riskScore = Math.min(score, 100);

        // Verdict thresholds
        let verdict = 'Safe';
        if (riskScore <= 20) verdict = 'Safe';
        else if (riskScore <= 60) verdict = 'Suspicious';
        else verdict = 'Malicious';

        // Fingerprint codes
        const codes = [];
        if (hasUrgency) codes.push('URG');
        if (hasAuthorityTone) codes.push('AUTH');
        if (hasCredentialRequest) codes.push('CRED');
        if (hasBrandMention) codes.push('BRND');
        if (hasLink) codes.push('LINK');
        if (hasSecrecyRequest) codes.push('SECR');
        if (codes.length >= 3) codes.push('MULTI');
        const fingerprint = codes.length ? codes.join('-') : 'NONE';
        const fingerprintMeanings = {
            URG: 'Urgent or pressure language to rush the recipient',
            AUTH: 'Uses authority or organizational tone to influence trust',
            CRED: 'Attempts to collect credentials or authentication details',
            BRND: 'Mentions a well-known brand or service to appear legitimate',
            LINK: 'Contains one or more embedded links that may be suspicious',
            SECR: 'Requests secrecy or asks the recipient not to share information',
            MULTI: 'Multiple phishing techniques combined in the same message'
        };

        // Attacker intent mapping (email-focused)
        const intents = [];
        if (hasUrgency) intents.push('Cause panic or rushed decisions');
        if (hasCredentialRequest) intents.push('Harvest login credentials or account access');
        if (hasPaymentMention) intents.push('Trick recipient into making a payment or transfer');
        if (hasAuthorityTone) intents.push('Exploit perceived authority to gain trust and compliance');
        if (intents.length === 0) intents.push('No clear attacker intent signals detected from the email alone');

        // Build detected indicators list (human readable)
        const detectedIndicators = [];
        if (hasUrgency) detectedIndicators.push('Urgent or time-sensitive language');
        if (hasCredentialRequest) detectedIndicators.push('Request to verify/login or provide credentials');
        if (hasBrandMention) detectedIndicators.push('Mentions a known brand or service');
        if (hasLink) detectedIndicators.push('Contains links (may hide destination)');
        if (genericSender) detectedIndicators.push('Generic or vague sender identity');
        if (senderFromFreeDomain) detectedIndicators.push('Sender appears to use a free email provider');
        if (hasSecrecyRequest) detectedIndicators.push('Asks to keep the message confidential');
        if (hasAttachmentMention) detectedIndicators.push('Mentions attachments or files');
        if (detectedIndicators.length === 0) detectedIndicators.push('No obvious indicators detected in the email');

        // Confidence estimation
        const strongSignals = countTruthy([hasCredentialRequest, hasUrgency, hasBrandMention, hasLink]);
        let confidenceLevel = 'Low';
        let confidenceExplanation = 'Low confidence because only a few weak indicators were found.';
        if (riskScore > 60 || strongSignals >= 3) {
            confidenceLevel = 'High';
            confidenceExplanation = 'High confidence due to multiple strong phishing indicators.';
        } else if (riskScore > 20) {
            confidenceLevel = 'Medium';
            confidenceExplanation = 'Medium confidence because several suspicious signs were detected.';
        }

        // Prepare analysis object
        latestAnalysis = {
            type: 'email',
            subject: subject,
            from: fromRaw || '(unknown)',
            url: '(email)',
            verdict: verdict,
            risk_score: riskScore,
            confidence: confidenceLevel,
            confidence_explanation: confidenceExplanation,
            detected_indicators: detectedIndicators,
            attacker_intent: intents,
            phishing_fingerprint: fingerprint,
            fingerprint_meaning: fingerprintMeanings,
            recommended_action: verdict === 'Malicious' ? 'Do not interact with this email. Do not click links or open attachments. Verify sender via another channel.' : 'If unsure, verify sender and avoid clicking links or entering credentials.',
            educational_takeaway: 'This email was analyzed with heuristic, offline methods for educational purposes. Take a cautious approach and verify directly with the organization when in doubt.'
        };

        // Display in UI
        displayEmailResults(latestAnalysis, checks);

        // Enable report download
        if (downloadReportBtn) {
            downloadReportBtn.classList.remove('hidden');
            downloadReportBtn.setAttribute('aria-hidden', 'false');
        }
    }

    /**
     * Populate UI panels using email analysis object
     */
    function displayEmailResults(analysis, checks) {
        // Show/hide panels based on analysis type
        urlBreakdownPanel.classList.add('hidden');
        emailSummaryPanel.classList.remove('hidden');

        // Score and verdict
        riskScoreElement.textContent = analysis.risk_score;
        scoreFill.style.width = `${analysis.risk_score}%`;

        let bgColor, textColor;
        if (analysis.risk_score <= 20) {
            bgColor = 'var(--success)'; textColor = 'white';
        } else if (analysis.risk_score <= 60) {
            bgColor = 'var(--warning)'; textColor = 'black';
        } else { bgColor = 'var(--danger)'; textColor = 'white'; }

        verdictBadge.textContent = analysis.verdict;
        verdictBadge.style.backgroundColor = bgColor;
        verdictBadge.style.color = textColor;
        scoreFill.style.backgroundColor = bgColor;

        // Email summary
        emailSummaryContent.innerHTML = `
            <p><strong>Subject:</strong> ${analysis.subject || '(no subject)'}</p>
            <p><strong>From:</strong> ${analysis.from || '(unknown sender)'}</p>
        `;

        // Red flags
        redFlagsList.innerHTML = '';
        analysis.detected_indicators.forEach(i => addRedFlag(i));

        // Attacker intent
        attackerIntentList.innerHTML = '';
        analysis.attacker_intent.forEach(i => {
            const li = document.createElement('li'); li.textContent = i; attackerIntentList.appendChild(li);
        });

        // Fingerprint
        fingerprintValue.textContent = analysis.phishing_fingerprint || '—';
        fingerprintDecodedList.innerHTML = '';
        Object.keys(analysis.fingerprint_meaning || {}).forEach(code => {
            const li = document.createElement('li'); li.textContent = `${code} → ${analysis.fingerprint_meaning[code]}`; fingerprintDecodedList.appendChild(li);
        });

        // Confidence
        confidenceBadge.textContent = analysis.confidence || '—';
        confidenceText.textContent = analysis.confidence_explanation || '';

        // Explanation and recommendations
        explanationText.textContent = analysis.recommended_action || 'Verify sender before interacting with the email.';
        recommendationsList.innerHTML = '';
        const recs = analysis.verdict === 'Malicious' 
            ? ['Do not open links or attachments', 'Mark as spam/phishing', 'Report to organization if needed']
            : analysis.verdict === 'Suspicious'
            ? ['Verify sender independently', 'Do not click links', 'Do not enter credentials']
            : ['Be cautious even if link appears safe', 'Verify sender before responding'];
        recs.forEach(rec => addRecommendation(rec));

        // Psychology / educational
        psychologyList.innerHTML = '';
        const take = analysis.educational_takeaway || '';
        const p1 = document.createElement('li'); p1.textContent = take; psychologyList.appendChild(p1);

        // Generate email-specific education tips
        generateEmailEducationTips(checks);

        // Show results
        resultSection.classList.remove('hidden'); resultSection.classList.add('visible'); resultSection.scrollIntoView({ behavior: 'smooth' });
    }

    /**
     * Generate educational tips for email analysis
     */
    function generateEmailEducationTips(checks) {
        educationContent.innerHTML = '';
        const tips = [];

        if (checks.hasUrgencyLanguage) {
            tips.push({
                title: 'Phishing creates false urgency',
                text: 'Scammers use pressure tactics ("act now", "verify immediately", "account suspended") to bypass your critical thinking. Real organizations rarely rush you.'
            });
        }

        if (checks.hasLoginLure) {
            tips.push({
                title: 'Legitimate companies don\'t ask for passwords via email',
                text: 'No real bank, email provider, or service will ask you to "verify" or "update" your password in an email. This is always a phishing attempt.'
            });
        }

        if (checks.hasBrandImpersonation) {
            tips.push({
                title: 'Check the sender email domain',
                text: 'If an email claims to be from PayPal but comes from paypal-security@gmail.com or similar, it\'s fake. Verify by checking official websites or calling directly.'
            });
        }

        if (checks.hasLink) {
            tips.push({
                title: 'Hover over links before clicking',
                text: 'In email clients, hover over links to see the real destination without clicking. If it doesn\'t match the text or expected domain, don\'t click it.'
            });
        }

        tips.push({
            title: 'Trust, but verify independently',
            text: 'If an email claims to be from your bank or important service, contact them directly using official contact info. Never use details from the suspicious email.'
        });

        tips.push({
            title: 'Forward phishing emails to the real organization',
            text: 'Most banks and services have a way to report phishing. Check their official website for a phishing@company.com address and forward the email there.'
        });

        // Render tips (show top 3)
        const topTips = tips.slice(0, 3);
        topTips.forEach(tip => {
            const div = document.createElement('div');
            div.className = 'education-item';
            div.innerHTML = `<strong>${tip.title}:</strong> ${tip.text}`;
            educationContent.appendChild(div);
        });
    }

    /**
     * Display analysis results
     */
    function displayResults(checks, riskScore, domain) {
        // Set risk score
        riskScoreElement.textContent = riskScore;
        scoreFill.style.width = `${riskScore}%`;
        
        // Determine risk level and set colors
        let riskLevel, bgColor, textColor;
        
        if (riskScore <= 20) {
            riskLevel = 'Safe';
            bgColor = 'var(--success)';
            textColor = 'white';
        } else if (riskScore <= 60) {
            riskLevel = 'Suspicious';
            bgColor = 'var(--warning)';
            textColor = 'black';
        } else {
            riskLevel = 'Malicious';
            bgColor = 'var(--danger)';
            textColor = 'white';
        }
        
        // Update verdict badge
        verdictBadge.textContent = riskLevel;
        verdictBadge.style.backgroundColor = bgColor;
        verdictBadge.style.color = textColor;
        
        // Update score bar color
        scoreFill.style.backgroundColor = bgColor;
        
        // Generate red flags list
        generateRedFlagsList(checks);

        // Attacker intent + fingerprint (educational features)
        const attackerIntents = generateAttackerIntent(checks);
        const fingerprintData = generateFingerprint(checks);

        // New: confidence + next steps + URL breakdown + psychology
        generateConfidence(riskScore, checks);
        generateNextSteps(riskScore);
        generateUrlBreakdown(urlInput.value.trim(), checks);
        generateEducationTips(checks);
        generatePsychology(riskScore, checks);
        
        // Generate explanation and recommendations
        generateExplanation(riskLevel, checks, domain);
        generateRecommendations(riskLevel, checks);
        
        // Show results
        resultSection.classList.remove('hidden');
        resultSection.classList.add('visible');
        resultSection.scrollIntoView({ behavior: 'smooth' });

        // Build a structured analysis object for report generation
        const detectedIndicators = buildDetectedIndicators(checks);
        const psychologyTexts = readListTexts(psychologyList);

        latestAnalysis = {
            url: urlInput.value.trim(),
            verdict: riskLevel,
            risk_score: riskScore,
            confidence: confidenceBadge.textContent || '—',
            confidence_explanation: confidenceText.textContent || '',
            detected_indicators: detectedIndicators,
            attacker_intent: attackerIntents,
            phishing_fingerprint: fingerprintData && fingerprintData.pattern ? fingerprintData.pattern : '—',
            fingerprint_meaning: fingerprintData && fingerprintData.meanings ? fingerprintData.meanings : {},
            recommended_action: nextStepsText.textContent || '',
            educational_takeaway: psychologyTexts.join(' ')
        };

        // Enable download button after scan
        if (downloadReportBtn) {
            downloadReportBtn.classList.remove('hidden');
            downloadReportBtn.setAttribute('aria-hidden', 'false');
        }
    }

    /**
     * Feature 1: Attacker Intent Explainer
     * Maps detected signals to human-friendly attacker goals.
     */
    function generateAttackerIntent(checks) {
        attackerIntentList.innerHTML = '';

        const intents = [];

        if (checks.hasUrgencyLanguage) {
            intents.push('Create urgency so you act without thinking');
        }

        if (checks.hasLoginLure) {
            intents.push('Trick you into entering your login details');
        }

        if (checks.hasPaymentLure) {
            intents.push('Push you toward a payment, charge, or fake refund');
        }

        if (checks.hasBrandImpersonation) {
            intents.push('Pretend to be a well-known brand to gain your trust');
        }

        if (checks.hasIpAddress || checks.hasSpecialChars || checks.isLongUrl) {
            intents.push('Hide their identity using a confusing or suspicious website address');
        }

        // If multiple signals fire, provide a gentle high-confidence summary
        const signalCount = countTruthy([
            checks.hasUrgencyLanguage,
            checks.hasLoginLure,
            checks.hasPaymentLure,
            checks.hasBrandImpersonation,
            checks.hasIpAddress,
            checks.looksLikeNewOrUntrustedDomain,
            checks.isLongUrl
        ]);

        if (signalCount >= 3) {
            intents.unshift('Combine multiple tricks to increase the chance you fall for it');
        }

        // Show 1–3 bullets (simple + elder-friendly)
        const topIntents = intents.slice(0, 3);
        if (topIntents.length === 0) {
            topIntents.push('No clear attacker intent signals detected from the URL alone');
        }

        topIntents.forEach((text) => {
            const li = document.createElement('li');
            li.textContent = text;
            attackerIntentList.appendChild(li);
        });

        // Return intents for report generation
        return topIntents;
    }

    function countTruthy(arr) {
        return arr.reduce((acc, v) => acc + (v ? 1 : 0), 0);
    }

    /**
     * Feature 2: Phishing Pattern Fingerprint
     * Generates a compact pattern string + decoded meaning.
     */
    function generateFingerprint(checks) {
        const codes = [];

        // Map checks -> detection codes
        if (checks.hasIpAddress) codes.push('IP');
        if (checks.looksLikeNewOrUntrustedDomain) codes.push('NEWDOM');
        if (checks.hasBrandImpersonation) codes.push('BRND');
        if (checks.hasPaymentLure) codes.push('PAY');
        if (checks.hasLoginLure) codes.push('LGN');
        if (checks.hasUrgencyLanguage) codes.push('URG');
        if (checks.isLongUrl || checks.hasSpecialChars || checks.hasManySubdomains) codes.push('LDOM');

        // MULTI indicates multiple phishing indicators combined
        if (codes.length >= 3) codes.push('MULTI');

        // Order by severity / risk (highest first)
        const severityOrder = ['IP', 'NEWDOM', 'BRND', 'PAY', 'LGN', 'URG', 'LDOM', 'MULTI'];
        const ordered = severityOrder.filter((c) => codes.includes(c));

        const pattern = ordered.length ? ordered.join('-') : 'NONE';
        fingerprintValue.textContent = pattern;

        // Decoded meanings (mandatory)
        fingerprintDecodedList.innerHTML = '';
        const meanings = {
            URG: 'Creates urgency or pressure language to rush the recipient into action',
            LGN: 'Attempts to steal login credentials or authentication details via fake forms',
            PAY: 'Tries to trigger a payment, financial transaction, or fake refund',
            IP: 'Uses a numeric IP address to hide identity and avoid domain reputation checks',
            LDOM: 'Uses a long, confusing, or obfuscated address to hide the real destination',
            NEWDOM: 'Website domain appears newly created or untrusted (heuristic analysis)',
            BRND: 'Impersonates or references a well-known brand to exploit trust',
            MULTI: 'Combines multiple phishing techniques in one attack (higher risk)',
            AUTH: 'Uses authority tone (IT, HR, admin) to influence compliance',
            CRED: 'Requests credential entry or account verification',
            LINK: 'Contains embedded links that may lead to malicious sites',
            SECR: 'Requests secrecy or tells recipient not to share the message'
        };

        if (ordered.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No fingerprint codes were triggered for this URL.';
            fingerprintDecodedList.appendChild(li);
            return;
        }

        ordered.forEach((code) => {
            const li = document.createElement('li');
            li.textContent = `${code} → ${meanings[code]}`;
            fingerprintDecodedList.appendChild(li);
        });

        // Return fingerprint data for report generation
        return { pattern, meanings };
    }

    /**
     * Feature 3: Risk Confidence Explanation
     * Based on risk score thresholds, provide a simple confidence label + reason.
     */
    function generateConfidence(riskScore, checks) {
        let level = 'Low';
        let reason = 'Low confidence because the URL shows few phishing indicators.';

        const strongSignals = countTruthy([
            checks.hasIpAddress,
            checks.looksLikeNewOrUntrustedDomain,
            checks.hasBrandImpersonation,
            checks.hasLoginLure,
            checks.hasPaymentLure,
            checks.hasUrgencyLanguage
        ]);

        if (riskScore <= 20) {
            level = 'Low';
            reason = 'Low confidence. Few phishing indicators detected. This does not mean the URL is completely safe—always verify legitimate organizations before sharing personal data.';
        } else if (riskScore <= 60) {
            level = 'Medium';
            reason = strongSignals >= 2
                ? 'Medium confidence. Multiple warning signs detected. Exercise caution and verify sender/destination independently.'
                : 'Medium confidence. Some suspicious patterns detected. Verify with the official organization before proceeding.';
        } else {
            level = 'High';
            reason = strongSignals >= 3
                ? 'High confidence in phishing risk. Multiple strong indicators present. Avoid interacting with this URL and report it if possible.'
                : 'High confidence in phishing risk. Strong indicators detected. Do not click links or enter credentials.';
        }

        confidenceBadge.textContent = level;

        // Gentle color hint (no fear-mongering)
        if (level === 'Low') {
            confidenceBadge.style.backgroundColor = 'var(--soft-safe)';
            confidenceBadge.style.borderColor = 'rgba(47, 133, 90, 0.25)';
        } else if (level === 'Medium') {
            confidenceBadge.style.backgroundColor = 'var(--soft-warn)';
            confidenceBadge.style.borderColor = 'rgba(180, 83, 9, 0.25)';
        } else {
            confidenceBadge.style.backgroundColor = 'var(--soft-danger)';
            confidenceBadge.style.borderColor = 'rgba(185, 28, 28, 0.25)';
        }

        confidenceText.textContent = reason;
    }

    /**
     * Feature 4: What you should do next (summary)
     */
    function generateNextSteps(riskScore) {
        if (riskScore <= 20) {
            nextStepsText.textContent = 'This link appears safe, but always stay cautious online.';
        } else if (riskScore <= 60) {
            nextStepsText.textContent = 'Do not click. Verify the link from an official source before proceeding.';
        } else {
            nextStepsText.textContent = 'Do not open this link. Close the page and report it if possible.';
        }
    }

    /**
     * Feature 5: URL Anatomy Visualizer
     * Break URL into protocol / domain / path and highlight suspicious-looking parts.
     */
    function generateUrlBreakdown(rawInput, checks) {
        urlBreakdownView.innerHTML = '';

        const raw = (rawInput || '').trim();
        if (!raw) return;

        let urlObj;
        try {
            urlObj = new URL(raw.startsWith('http') ? raw : `https://${raw}`);
        } catch {
            // If parsing fails, avoid rendering anything confusing.
            return;
        }

        const protocolRaw = /^https:\/\//i.test(raw) ? 'https' : (/^http:\/\//i.test(raw) ? 'http' : 'missing');
        const protocolClass = protocolRaw === 'https' ? 'safe' : 'warning';
        addUrlPart('Protocol', protocolRaw, protocolClass);

        const domain = urlObj.hostname;
        const domainClass = (checks.hasIpAddress || checks.looksLikeNewOrUntrustedDomain) ? 'suspicious' : 'safe';
        addUrlPart('Domain', domain, domainClass);

        const path = (urlObj.pathname || '/');
        const pathClass = (checks.isLongUrl || checks.hasSpecialChars || checks.hasManySubdomains) ? 'warning' : 'safe';
        addUrlPart('Path', path, pathClass);

        const query = (urlObj.search || '');
        if (query) {
            const queryClass = checks.hasSpecialChars ? 'warning' : 'safe';
            addUrlPart('Query', query, queryClass);
        }

        // Highlight brand-like or lure keywords (educational)
        const highlights = [];
        if (checks.hasBrandImpersonation) highlights.push('Brand-like words');
        if (checks.hasLoginLure) highlights.push('Login/account words');
        if (checks.hasPaymentLure) highlights.push('Payment/billing words');
        if (checks.hasUrgencyLanguage) highlights.push('Urgency words');

        if (highlights.length) {
            addUrlPart('Highlights', highlights.join(', '), 'warning');
        }

        function addUrlPart(name, value, typeClass) {
            const el = document.createElement('div');
            el.className = `url-part ${typeClass}`;

            const nameEl = document.createElement('span');
            nameEl.className = 'url-part-name';
            nameEl.textContent = `${name}:`;

            const valueEl = document.createElement('span');
            valueEl.className = 'url-part-value';
            valueEl.textContent = value;

            el.appendChild(nameEl);
            el.appendChild(valueEl);
            urlBreakdownView.appendChild(el);
        }
    }

    /**
     * Feature 6: Why people fall for this (psychology)
     * Calm, empathetic, pattern-based explanations.
     */
    function generatePsychology(riskScore, checks) {
        psychologyList.innerHTML = '';

        const reasons = [];

        if (checks.hasBrandImpersonation) {
            reasons.push('It looks familiar because it mentions a well-known brand. Scammers exploit your trust in familiar names.');
        }

        if (checks.hasUrgencyLanguage) {
            reasons.push('It creates urgency ("act now", "limited time"), which makes people skip safety checks. Real organizations rarely force immediate action.');
        }

        if (checks.hasLoginLure) {
            reasons.push('It asks for login or password entry, which many people do routinely. Phishers rely on habit and autopilot behavior.');
        }

        if (checks.isLongUrl || checks.hasSpecialChars || checks.hasManySubdomains) {
            reasons.push('The URL is confusing and long on purpose, making the malicious destination hard to notice at a glance.');
        }

        if (checks.hasUrlShortener) {
            reasons.push('Short links hide the real destination until you click. This keeps you from verifying before acting.');
        }

        if (!checks.hasHttps) {
            reasons.push('Missing HTTPS (the lock icon) is often overlooked, especially on mobile. Your data travels unencrypted to untrusted servers.');
        }

        // Ensure 1–3 items, calm tone
        const unique = Array.from(new Set(reasons));
        const top = unique.slice(0, 3);

        if (top.length === 0) {
            top.push(riskScore <= 20
                ? 'Even safe-looking links can be used in scams. Critical thinking and a moment to verify always helps.'
                : 'Scams work because one small detail is missed. Taking a moment to verify can prevent mistakes.');
        }

        top.forEach((text) => {
            const li = document.createElement('li');
            li.textContent = text;
            psychologyList.appendChild(li);
        });
    }

    /**
     * Generate list of detected red flags
     */
    function generateRedFlagsList(checks) {
        redFlagsList.innerHTML = '';
        
        if (!checks.hasHttps) {
            addRedFlag('🔓 No HTTPS - Connection is not encrypted');
        }
        
        if (checks.isLongUrl) {
            addRedFlag('📏 Long URL - Could be hiding the real destination');
        }
        
        if (checks.hasSuspiciousKeywords) {
            addRedFlag('⚠️ Contains suspicious keywords');
        }
        
        if (checks.hasIpAddress) {
            addRedFlag('🔢 Uses IP address instead of domain name');
        }
        
        if (checks.hasSuspiciousTld) {
            addRedFlag('🌐 Suspicious top-level domain (TLD)');
        }
        
        if (checks.hasManySubdomains) {
            addRedFlag('🔗 Multiple subdomains - Could be a trick');
        }
        
        if (checks.hasUrlShortener) {
            addRedFlag('✂️ Uses URL shortener - Hides the real destination');
        }
        
        if (checks.hasSpecialChars) {
            addRedFlag('#️⃣ Contains unusual special characters');
        }
        
        if (redFlagsList.children.length === 0) {
            addRedFlag('✅ No obvious red flags detected');
        }
    }
    
    function addRedFlag(text) {
        const li = document.createElement('li');
        li.textContent = text;
        redFlagsList.appendChild(li);
    }

    /**
     * Generate explanation text based on risk level and checks
     */
    function generateExplanation(riskLevel, checks, domain) {
        let explanation = '';
        
        if (riskLevel === 'Safe') {
            explanation = `The domain ${domain} shows few phishing indicators in our analysis. `;
            explanation += 'However, this checker analyzes URL patterns only. ';
            explanation += 'Always verify websites before entering sensitive data, and be cautious of emails even if links appear legitimate.';
        } 
        else if (riskLevel === 'Suspicious') {
            explanation = `The domain ${domain} displays multiple warning signs. `;
            
            const warnings = [];
            if (!checks.hasHttps) warnings.push('unencrypted connection (no HTTPS)');
            if (checks.hasSuspiciousKeywords) warnings.push('phishing-related keywords');
            if (checks.hasUrlShortener) warnings.push('a URL shortener hiding the destination');
            
            if (warnings.length) {
                explanation += `We detected: ${warnings.join(', ')}. `;
            }
            
            explanation += 'Verify this site independently before sharing personal or financial information.';
        } 
        else { // Malicious
            explanation = `⚠️ HIGH RISK: The domain ${domain} shows multiple strong phishing indicators. `;
            
            const reasons = [];
            if (checks.hasIpAddress) reasons.push('uses an IP address instead of a domain');
            if (checks.hasSuspiciousTld) reasons.push('has a high-risk top-level domain');
            if (checks.hasSuspiciousKeywords) reasons.push('contains phishing keywords');
            
            if (reasons.length) {
                explanation += `Red flags: ${reasons.join(', ')}. `;
            }
            
            explanation += 'We strongly recommend not visiting this URL or entering any personal information.';
        }
        
        explanationText.textContent = explanation;
    }

    /**
     * Generate recommendations based on risk level
     */
    function generateRecommendations(riskLevel, checks) {
        recommendationsList.innerHTML = '';
        
        if (riskLevel === 'Safe') {
            addRecommendation('✅ This URL appears relatively safe, but always stay vigilant');
            addRecommendation('🔒 Check for the lock icon in your browser\'s address bar before entering any data');
            addRecommendation('👀 Look for spelling errors or unusual design on the page itself');
            addRecommendation('📧 Be skeptical of unexpected emails even if the link seems safe');
        } 
        else if (riskLevel === 'Suspicious') {
            addRecommendation('⚠️ Do NOT enter personal or financial information on this site');
            addRecommendation('🔍 Verify by visiting the official website directly or calling the organization');
            addRecommendation('📧 If this came via email, contact the sender through official channels (not by reply)');
            addRecommendation('🚫 Consider not visiting this website at all');
            addRecommendation('📱 If you already clicked it, monitor your accounts for suspicious activity');
        } 
        else { // Malicious
            addRecommendation('🚫 DO NOT VISIT THIS WEBSITE OR CLICK ANY LINKS');
            addRecommendation('❌ Do not download files or enter any personal information');
            addRecommendation('🛡️ If you received this via email, mark it as spam or phishing');
            addRecommendation('🔒 Use a password manager to generate unique passwords (harder to crack)');
            addRecommendation('📱 Enable two-factor authentication on all important accounts');
            addRecommendation('💻 Run a security scan on your device to ensure you didn\'t visit it');
        }
        
        // Universal security recommendations
        addRecommendation('💡 Keep your browser, OS, and antivirus software up to date');
        addRecommendation('🌐 Use browser security extensions that warn about phishing sites');
        addRecommendation('🔐 Create strong, unique passwords for each online account');
    }
    
    function addRecommendation(text) {
        const li = document.createElement('li');
        li.textContent = text;
        recommendationsList.appendChild(li);
    }

    /**
     * Generate educational tips and training content
     */
    function generateEducationTips(checks) {
        educationContent.innerHTML = '';
        const tips = [];

        // General phishing tips
        if (!checks.hasHttps) {
            tips.push({
                title: 'Always check for HTTPS',
                text: 'HTTPS encrypts your connection. Look for a lock icon in the address bar. Without it, your data could be intercepted by attackers.'
            });
        }

        if (checks.hasSuspiciousKeywords) {
            tips.push({
                title: 'Phishing loves urgency',
                text: 'Scammers create fake urgency ("act now", "verify immediately") to make you skip your safety checks. Real organizations rarely rush you to provide sensitive info.'
            });
        }

        if (checks.hasUrlShortener) {
            tips.push({
                title: 'Avoid shortened links in emails',
                text: 'URL shorteners hide the real destination. Hover over links (don\'t click!) to see where they really go. Better yet, verify by visiting the official website directly.'
            });
        }

        if (checks.hasSuspiciousTld) {
            tips.push({
                title: 'Watch out for uncommon domains',
                text: 'TLDs like .tk, .ml, .ga are cheap and often used by attackers. Legitimate companies usually use common TLDs (.com, .org, .net, etc.).'
            });
        }

        if (checks.hasManySubdomains) {
            tips.push({
                title: 'Too many subdomains = red flag',
                text: 'Legitimate sites rarely have 3+ subdomains. Attackers use this to hide the real domain: example.bank.secure.com looks official but isn\'t.'
            });
        }

        if (checks.hasIpAddress) {
            tips.push({
                title: 'Real sites use domain names',
                text: 'Visiting a website by IP address (e.g., 192.168.1.1) is extremely rare. Legitimate companies always use readable domain names.'
            });
        }

        // Always include these core tips
        if (tips.length === 0 || checks.hasSuspiciousKeywords) {
            tips.push({
                title: 'Verify sender identity',
                text: 'Check the sender\'s email domain. If an email claims to be from your bank but comes from gmail.com, it\'s fake. Use contact info from official websites, not the email.'
            });
        }

        tips.push({
            title: 'Multi-factor authentication saves you',
            text: 'Even if your password is stolen, 2FA (two-factor authentication) prevents attackers from accessing your account. Enable it on important accounts.'
        });

        tips.push({
            title: 'When in doubt, verify directly',
            text: 'Call the organization using a number from their official website or statement. Never use contact info from a suspicious email.'
        });

        // Render tips (show top 3)
        const topTips = tips.slice(0, 3);
        topTips.forEach(tip => {
            const div = document.createElement('div');
            div.className = 'education-item';
            div.innerHTML = `<strong>${tip.title}:</strong> ${tip.text}`;
            educationContent.appendChild(div);
        });
    }

    /**
     * Reset the results section
     */
    function resetResults() {
        resultSection.classList.add('hidden');
        resultSection.classList.remove('visible');
        scoreFill.style.width = '0%';
        redFlagsList.innerHTML = '';
        attackerIntentList.innerHTML = '';
        fingerprintDecodedList.innerHTML = '';
        fingerprintValue.textContent = '—';
        confidenceBadge.textContent = '—';
        confidenceBadge.style.backgroundColor = '';
        confidenceBadge.style.borderColor = '';
        confidenceText.textContent = '';
        urlBreakdownView.innerHTML = '';
        psychologyList.innerHTML = '';
        nextStepsText.textContent = '';
        educationContent.innerHTML = '';
        emailSummaryContent.innerHTML = '';
        if (downloadReportBtn) {
            downloadReportBtn.classList.add('hidden');
            downloadReportBtn.setAttribute('aria-hidden', 'true');
        }
        latestAnalysis = null;
        // Reset panels visibility
        urlBreakdownPanel.classList.remove('hidden');
        emailSummaryPanel.classList.add('hidden');
    }

    /**
     * Show error message
     */
    function showError(message) {
        alert(message); // Simple alert for demo purposes
    }
    
    // Helper: build human-readable detected indicators
    function buildDetectedIndicators(checks) {
        const items = [];
        if (!checks.hasHttps) items.push('No HTTPS (connection not encrypted)');
        if (checks.isLongUrl) items.push('Long URL that may hide the destination');
        if (checks.hasSuspiciousKeywords) items.push('Contains suspicious keywords (e.g., login, verify)');
        if (checks.hasIpAddress) items.push('Uses an IP address instead of a domain');
        if (checks.hasSuspiciousTld) items.push('Suspicious top-level domain (TLD)');
        if (checks.hasManySubdomains) items.push('Multiple subdomains (possible trick)');
        if (checks.hasUrlShortener) items.push('Uses a URL shortener');
        if (checks.hasSpecialChars) items.push('Unusual special characters in the URL');
        if (items.length === 0) items.push('No obvious indicators detected in the URL');
        return items;
    }

    function readListTexts(listElement) {
        const texts = [];
        if (!listElement) return texts;
        Array.from(listElement.querySelectorAll('li')).forEach(li => {
            if (li.textContent && li.textContent.trim()) texts.push(li.textContent.trim());
        });
        return texts;
    }

    /**
     * Generate a Markdown report string from analysis data.
     */
    function generateMarkdownReport(analysis) {
        if (!analysis) return '# PhishHunt – Phishing Analysis Report\n\n_No analysis data available._';

        const lines = [];
        lines.push('# PhishHunt – Phishing Analysis Report');
        lines.push('');

        // Analysis type (URL or Email)
        if (analysis.type === 'email') {
            lines.push('**Analysis Type:** Email Phishing Analysis');
            lines.push('');
            lines.push('## 1. Executive Summary');
        } else {
            lines.push('## 1. Executive Summary');
        }
        lines.push('');
        if (analysis.type === 'email') {
            lines.push(`- **Subject:** ${analysis.subject || '—'}`);
            lines.push(`- **From:** ${analysis.from || '—'}`);
        } else {
            lines.push(`- **URL:** ${analysis.url || '—'}`);
        }
        lines.push(`- **Verdict:** ${analysis.verdict || '—'}`);
        lines.push(`- **Risk score:** ${analysis.risk_score != null ? analysis.risk_score : '—'}`);
        lines.push('');
        lines.push(analysis.educational_takeaway || 'The analysis identifies signals in the URL and provides guidance.');
        lines.push('');

        lines.push('## 2. Risk Assessment');
        lines.push('');
        lines.push(`- **Verdict:** ${analysis.verdict || '—'}`);
        lines.push(`- **Risk Score:** ${analysis.risk_score != null ? analysis.risk_score : '—'} (0–100)`);
        lines.push(`- **Detection Confidence:** ${analysis.confidence || '—'}`);
        if (analysis.confidence_explanation) lines.push(`- **Confidence Explanation:** ${analysis.confidence_explanation}`);
        lines.push('');

        lines.push('## 3. Detected Phishing Indicators');
        lines.push('');
        if (Array.isArray(analysis.detected_indicators) && analysis.detected_indicators.length) {
            analysis.detected_indicators.forEach(item => lines.push(`- ${item}`));
        } else {
            lines.push('- None detected from the URL alone');
        }
        lines.push('');

        lines.push('## 4. Attacker Intent Analysis');
        lines.push('');
        if (Array.isArray(analysis.attacker_intent) && analysis.attacker_intent.length) {
            analysis.attacker_intent.forEach(item => lines.push(`- ${item}`));
        } else {
            lines.push('- No clear attacker intent detected from the URL alone');
        }
        lines.push('');

        lines.push('## 5. Phishing Pattern Fingerprint Explanation');
        lines.push('');
        lines.push(`- **Pattern:** ${analysis.phishing_fingerprint || '—'}`);
        lines.push('');
        if (analysis.fingerprint_meaning && Object.keys(analysis.fingerprint_meaning).length) {
            Object.keys(analysis.fingerprint_meaning).forEach(code => {
                const meaning = analysis.fingerprint_meaning[code];
                lines.push(`- **${code}**: ${meaning}`);
            });
        } else {
            lines.push('- No fingerprint meanings available');
        }
        lines.push('');

        lines.push('## 6. Confidence Level Explanation');
        lines.push('');
        lines.push(`- **Confidence:** ${analysis.confidence || '—'}`);
        if (analysis.confidence_explanation) lines.push(`- ${analysis.confidence_explanation}`);
        lines.push('');

        lines.push('## 7. Recommended User Actions');
        lines.push('');
        if (analysis.recommended_action) {
            lines.push(`- ${analysis.recommended_action}`);
        } else {
            lines.push('- Verify the link using an independent source before interacting with it.');
            lines.push('- Do not enter credentials or payment details on sites you do not trust.');
        }
        lines.push('');

        lines.push('## 8. Educational Takeaway');
        lines.push('');
        if (analysis.educational_takeaway) {
            lines.push(analysis.educational_takeaway);
        } else {
            lines.push('This analysis provides heuristics-based, educational guidance. It is not a replacement for professional threat analysis.');
        }

        return lines.join('\n');
    }

    // Attach download handler for the report button
    if (downloadReportBtn) {
        downloadReportBtn.addEventListener('click', () => {
            if (!latestAnalysis) {
                showError('No analysis available to export. Run a scan first.');
                return;
            }
            try {
                const md = generateMarkdownReport(latestAnalysis);
                const blob = new Blob([md], { type: 'text/markdown' });
                const u = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = u;
                a.download = 'phishhunt-report.md';
                document.body.appendChild(a);
                a.click();
                a.remove();
                setTimeout(() => URL.revokeObjectURL(u), 1500);
            } catch (err) {
                console.error('Report generation failed:', err);
                showError('Failed to generate report. See console for details.');
            }
        });
    }
    // Reference to the online toggle switch
const onlineToggle = document.getElementById('onlineToggle');
const onlineIntelligenceSection = document.getElementById('onlineIntelligence');
const onlineStatus = document.getElementById('onlineStatus');
const onlineResults = document.getElementById('onlineResults');

// Debug: Check if elements exist
console.log('Online elements found:', {
    onlineToggle: !!onlineToggle,
    onlineIntelligenceSection: !!onlineIntelligenceSection,
    onlineStatus: !!onlineStatus,
    onlineResults: !!onlineResults
});

// Check if API module is loaded
if (typeof api === 'undefined') {
    console.error('API module not loaded. Please ensure api.js is loaded correctly.');
} else {
    console.log('API module loaded successfully');
}

// Function to display enrichment data
function displayEnrichmentData(data) {
    onlineResults.innerHTML = '';

    const createSection = (title, content) => {
        const section = document.createElement('div');
        section.className = 'enrichment-section';
        section.innerHTML = `
            <h4>${title}</h4>
            <div class="enrichment-content">
                ${content}
            </div>
        `;
        return section;
    };

    const formatData = (data) => {
        if (data.error) {
            return `<div class="error">${data.error}</div>`;
        }
        return `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    };

    if (data.whois) {
        onlineResults.appendChild(createSection('WHOIS Information', formatData(data.whois)));
    }
    if (data.dns) {
        onlineResults.appendChild(createSection('DNS Records', formatData(data.dns)));
    }
    if (data.ssl) {
        onlineResults.appendChild(createSection('SSL/TLS Certificate', formatData(data.ssl)));
    }
    if (data.virustotal) {
        onlineResults.appendChild(createSection('VirusTotal Report', formatData(data.virustotal)));
    }
    if (data.safebrowsing) {
        onlineResults.appendChild(createSection('Safe Browsing', formatData(data.safebrowsing)));
    }

    onlineResults.classList.add('visible');
}

// Save the original analyzeUrl function
const originalAnalyzeUrl = analyzeUrl;

// Override the analyzeUrl function to include online enrichment
analyzeUrl = async function() {
    const result = await originalAnalyzeUrl.apply(this, arguments);
    
    // Debug: Check if online mode is enabled
    console.log('Online toggle checked:', onlineToggle ? onlineToggle.checked : 'toggle not found');
    
    // If online mode is enabled, fetch enrichment data
    if (onlineToggle && onlineToggle.checked) {
        const urlInput = document.getElementById('urlInput').value.trim();
        if (urlInput) {
            onlineIntelligenceSection.classList.remove('hidden');
            onlineStatus.innerHTML = '<div class="loading-spinner"></div><p>Fetching online intelligence data...</p>';
            onlineResults.innerHTML = '';
            
            try {
                // Check if API is available
                if (typeof api === 'undefined') {
                    throw new Error('API module not loaded');
                }
                const enrichmentData = await api.getEnrichmentData(urlInput);
                displayEnrichmentData(enrichmentData);
                onlineStatus.innerHTML = '';
            } catch (error) {
                console.error('Error fetching enrichment data:', error);
                onlineStatus.innerHTML = `
                    <div class="error-icon">⚠️</div>
                    <p>Failed to load online intelligence data. Please check your connection and try again.</p>
                `;
            }
        }
    }
    
    return result;
};

// Add event listener for the online toggle
if (onlineToggle) {
    onlineToggle.addEventListener('change', () => {
        console.log('Toggle changed, checked:', onlineToggle.checked);
        if (!onlineToggle.checked) {
            onlineIntelligenceSection.classList.add('hidden');
        } else if (document.getElementById('urlInput').value.trim()) {
            // If there's a URL in the input, re-run analysis with online mode
            console.log('Re-running analysis with online mode');
            analyzeUrl();
        }
    });
} else {
    console.error('Online toggle element not found!');
}

// Test API connection
const testApiBtn = document.getElementById('testApiBtn');
if (testApiBtn) {
    testApiBtn.addEventListener('click', async () => {
        console.log('Testing API connection...');
        try {
            const response = await fetch('http://localhost:3001/api/whois?domain=google.com');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            console.log('API Test Success:', data);
            alert('API connection successful! Check console for details.');
        } catch (error) {
            console.error('API Test Failed:', error);
            alert('API connection failed. Check console for error details.');
        }
    });
}
});
