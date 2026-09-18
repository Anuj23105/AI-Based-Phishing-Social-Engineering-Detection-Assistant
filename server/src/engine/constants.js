/**
 * PhishGuard AI — detection knowledge base.
 *
 * Everything the engine "knows" about brands, infrastructure abuse patterns and
 * social-engineering language lives here so it can be reviewed and extended
 * without touching detection logic.
 */

/* ------------------------------------------------------------------------- *
 * Brand intelligence
 * Used for impersonation / typosquatting detection. `domains` are the official
 * registrable domains; anything that looks like the brand but resolves
 * elsewhere is a strong phishing signal.
 * ------------------------------------------------------------------------- */
export const BRANDS = [
  { name: 'Google', keywords: ['google', 'gmail', 'google drive', 'google docs'], domains: ['google.com', 'gmail.com', 'googlemail.com', 'google.co.in', 'youtube.com'] },
  { name: 'Microsoft', keywords: ['microsoft', 'outlook', 'office365', 'office 365', 'onedrive', 'sharepoint', 'windows'], domains: ['microsoft.com', 'outlook.com', 'live.com', 'office.com', 'microsoftonline.com', 'sharepoint.com', 'hotmail.com'] },
  { name: 'Apple', keywords: ['apple', 'icloud', 'apple id', 'appleid', 'itunes'], domains: ['apple.com', 'icloud.com'] },
  { name: 'Amazon', keywords: ['amazon', 'aws', 'prime video'], domains: ['amazon.com', 'amazon.in', 'aws.amazon.com', 'amazonaws.com'] },
  { name: 'Facebook / Meta', keywords: ['facebook', 'meta', 'instagram', 'whatsapp'], domains: ['facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com', 'fb.com'] },
  { name: 'Netflix', keywords: ['netflix'], domains: ['netflix.com'] },
  { name: 'PayPal', keywords: ['paypal'], domains: ['paypal.com'] },
  { name: 'LinkedIn', keywords: ['linkedin'], domains: ['linkedin.com'] },
  { name: 'DHL', keywords: ['dhl'], domains: ['dhl.com'] },
  { name: 'FedEx', keywords: ['fedex'], domains: ['fedex.com'] },
  { name: 'India Post', keywords: ['india post', 'indiapost'], domains: ['indiapost.gov.in'] },
  { name: 'Blue Dart', keywords: ['bluedart', 'blue dart'], domains: ['bluedart.com'] },
  { name: 'State Bank of India', keywords: ['sbi', 'state bank', 'yono', 'onlinesbi'], domains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com'] },
  { name: 'HDFC Bank', keywords: ['hdfc'], domains: ['hdfcbank.com'] },
  { name: 'ICICI Bank', keywords: ['icici'], domains: ['icicibank.com'] },
  { name: 'Axis Bank', keywords: ['axis bank', 'axisbank'], domains: ['axisbank.com'] },
  { name: 'Kotak Mahindra Bank', keywords: ['kotak'], domains: ['kotak.com'] },
  { name: 'Punjab National Bank', keywords: ['pnb', 'punjab national'], domains: ['pnbindia.in'] },
  { name: 'Paytm', keywords: ['paytm'], domains: ['paytm.com', 'paytmbank.com'] },
  { name: 'PhonePe', keywords: ['phonepe'], domains: ['phonepe.com'] },
  { name: 'Google Pay / UPI', keywords: ['google pay', 'gpay', 'upi', 'npci', 'bhim'], domains: ['pay.google.com', 'npci.org.in', 'bhimupi.org.in'] },
  { name: 'Income Tax Department (India)', keywords: ['income tax', 'incometax', 'itr refund', 'cbdt'], domains: ['incometax.gov.in', 'incometaxindia.gov.in'] },
  { name: 'GST / CBIC', keywords: ['gst', 'gstn', 'cbic'], domains: ['gst.gov.in'] },
  { name: 'UIDAI / Aadhaar', keywords: ['aadhaar', 'aadhar', 'uidai'], domains: ['uidai.gov.in'] },
  { name: 'EPFO', keywords: ['epfo', 'provident fund', 'uan'], domains: ['epfindia.gov.in'] },
  { name: 'IRCTC', keywords: ['irctc'], domains: ['irctc.co.in'] },
  { name: 'Flipkart', keywords: ['flipkart'], domains: ['flipkart.com'] },
  { name: 'Myntra', keywords: ['myntra'], domains: ['myntra.com'] },
  { name: 'Swiggy', keywords: ['swiggy'], domains: ['swiggy.com'] },
  { name: 'Zomato', keywords: ['zomato'], domains: ['zomato.com'] },
  { name: 'Reserve Bank of India', keywords: ['rbi', 'reserve bank'], domains: ['rbi.org.in'] },
  { name: 'Binance', keywords: ['binance'], domains: ['binance.com'] },
  { name: 'Coinbase', keywords: ['coinbase'], domains: ['coinbase.com'] },
  { name: 'WazirX', keywords: ['wazirx'], domains: ['wazirx.com'] },
  { name: 'Steam', keywords: ['steam', 'steamcommunity'], domains: ['steampowered.com', 'steamcommunity.com'] },
  { name: 'GitHub', keywords: ['github'], domains: ['github.com'] },
  { name: 'DocuSign', keywords: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
  { name: 'Zoom', keywords: ['zoom meeting', 'zoom.us'], domains: ['zoom.us'] },
  { name: 'Telegram', keywords: ['telegram'], domains: ['telegram.org', 't.me'] },
  { name: 'Uber', keywords: ['uber'], domains: ['uber.com'] },
  { name: 'Ola', keywords: ['olacabs', 'ola cabs'], domains: ['olacabs.com'] },
  { name: 'Airtel', keywords: ['airtel'], domains: ['airtel.in'] },
  { name: 'Jio', keywords: ['jio', 'reliance jio'], domains: ['jio.com'] },
  { name: 'Vodafone Idea', keywords: ['vodafone', ' vi '], domains: ['myvi.in'] },
  { name: 'BSNL', keywords: ['bsnl'], domains: ['bsnl.co.in'] }
];

/** Fast lookup of every official brand domain. */
export const OFFICIAL_DOMAINS = new Set(BRANDS.flatMap((b) => b.domains));

/**
 * High-reputation domains. Presence of one of these as the *registrable* domain
 * dampens the score — this is the main lever protecting the <10% false-positive
 * target for real corporate mail.
 */
export const TRUSTED_DOMAINS = new Set([
  ...OFFICIAL_DOMAINS,
  'wikipedia.org', 'stackoverflow.com', 'stackexchange.com', 'mozilla.org', 'w3.org',
  'nic.in', 'gov.in', 'mygov.in', 'digilocker.gov.in', 'india.gov.in', 'sih.gov.in',
  'npmjs.com', 'nodejs.org', 'python.org', 'developer.mozilla.org', 'cloudflare.com',
  'atlassian.com', 'slack.com', 'notion.so', 'figma.com', 'dropbox.com', 'adobe.com',
  'ieee.org', 'acm.org', 'coursera.org', 'udemy.com', 'nptel.ac.in', 'aicte-india.org'
]);

/** Consumer webmail providers — a "corporate" sender here is suspicious. */
export const FREE_MAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.in', 'ymail.com', 'rediffmail.com',
  'hotmail.com', 'outlook.com', 'live.com', 'aol.com', 'gmx.com', 'mail.com',
  'zoho.com', 'yandex.com', 'protonmail.com', 'proton.me', 'icloud.com', 'inbox.lv'
]);

/** Throwaway mail services frequently used by fraudsters. */
export const DISPOSABLE_MAIL_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'sharklasers.com', '10minutemail.com', 'tempmail.com',
  'temp-mail.org', 'yopmail.com', 'trashmail.com', 'dispostable.com', 'getnada.com',
  'throwawaymail.com', 'maildrop.cc', 'fakeinbox.com', 'mailnesia.com', 'moakt.com'
]);

/** URL shorteners hide the true destination. */
export const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly',
  'bit.do', 'cutt.ly', 'shorte.st', 'rb.gy', 'rebrand.ly', 'tiny.cc', 'lnkd.in',
  'shorturl.at', 'urlz.fr', 'v.gd', 'x.co', 'clck.ru', 'soo.gd', 's2r.co', 'qps.ru',
  'trib.al', 'zpr.io', 'shrtco.de', 'gg.gg', 'me2.do', 'chilp.it', 'clicky.me',
  'linktr.ee', 'rebrandly.com', 'short.gy', 'tny.im', 'urlis.net', 'kutt.it'
]);

/** TLDs with very high abuse-to-legitimate ratios (cheap or free registration). */
export const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'xyz', 'club', 'work', 'click', 'link', 'live',
  'buzz', 'rest', 'fit', 'surf', 'cam', 'monster', 'quest', 'cyou', 'icu', 'zip', 'mov',
  'country', 'kim', 'review', 'date', 'wang', 'loan', 'racing', 'stream', 'download',
  'bid', 'trade', 'party', 'gdn', 'mom', 'lol', 'pw', 'cc', 'su', 'ru.com', 'sbs',
  'autos', 'boats', 'bar', 'best', 'casa', 'cfd', 'shop.ru'
]);

/**
 * Hosting / tunnelling / paste platforms with free subdomains. Legitimate on
 * their own, but a *login form for a bank* hosted here is a red flag.
 */
export const FREE_HOSTING_HOSTS = [
  'blogspot.com', 'wordpress.com', 'weebly.com', 'wixsite.com', 'webnode.page', 'jimdofree.com',
  '000webhostapp.com', 'infinityfreeapp.com', 'epizy.com', 'byethost.com', 'hostinger.site',
  'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'r2.dev',
  'firebaseapp.com', 'web.app', 'glitch.me', 'repl.co', 'replit.dev', 'herokuapp.com',
  'ngrok.io', 'ngrok-free.app', 'trycloudflare.com', 'loca.lt', 'serveo.net', 'localtunnel.me',
  'duckdns.org', 'no-ip.org', 'ddns.net', 'hopto.org', 'zapto.org', 'sytes.net',
  'sites.google.com', 'forms.gle', 'docs.google.com/forms', 'formspree.io', 'jotform.com',
  'typeform.com', 'surveyheart.com', 'pastebin.com', 'anotepad.com', 'telegra.ph',
  'ipfs.io', 'dweb.link', 'cloudfront.net', 'blob.core.windows.net', 's3.amazonaws.com',
  'godaddysites.com', 'square.site', 'canva.site', 'notion.site', 'framer.website'
];

/** Second-level suffixes so `co.uk`, `gov.in`, ... are parsed correctly. */
export const MULTI_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in', 'gov.in', 'nic.in', 'ac.in', 'edu.in', 'res.in', 'mil.in',
  'com.au', 'net.au', 'org.au', 'gov.au', 'edu.au',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'co.za', 'org.za', 'gov.za', 'com.sg', 'com.my', 'com.ph', 'com.pk', 'com.bd', 'com.np',
  'co.nz', 'org.nz', 'govt.nz', 'com.tr', 'com.mx', 'com.ar', 'com.co', 'com.pe',
  'co.kr', 'or.kr', 'go.kr', 'com.hk', 'com.tw', 'co.il', 'co.th', 'in.th',
  'com.sa', 'com.eg', 'com.ng', 'co.ke', 'com.gh', 'com.ua', 'com.ru', 'org.ru',
  'com.vn', 'com.ua', 'co.id', 'or.id', 'go.id', 'ac.id', 'sch.id'
]);

/** Cyrillic / Greek / accented look-alikes used in homograph attacks. */
export const HOMOGLYPHS = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', х: 'x', у: 'y', і: 'i', ѕ: 's', ԁ: 'd', һ: 'h',
  ν: 'v', ο: 'o', ρ: 'p', τ: 't', α: 'a', ε: 'e', ι: 'i', κ: 'k', μ: 'm', ѵ: 'v',
  à: 'a', á: 'a', â: 'a', ä: 'a', å: 'a', ã: 'a', è: 'e', é: 'e', ê: 'e', ë: 'e',
  ì: 'i', í: 'i', î: 'i', ï: 'i', ò: 'o', ó: 'o', ô: 'o', ö: 'o', õ: 'o', ø: 'o',
  ù: 'u', ú: 'u', û: 'u', ü: 'u', ç: 'c', ñ: 'n', ý: 'y', ł: 'l', ĺ: 'l', ǀ: 'l',
  ẹ: 'e', ọ: 'o', ạ: 'a', ḅ: 'b', ḍ: 'd', ṇ: 'n', ṣ: 's', ṭ: 't', '\u0131': 'i'
};

/** Leet-speak normalisation so `p4yp4l` / `acc0unt` still match. */
export const LEET_MAP = { '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', $: 's', '@': 'a', '!': 'i', '|': 'l', '¡': 'i' };

/** File extensions that should never arrive as a "document" link. */
export const DANGEROUS_EXTENSIONS = [
  'exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
  'msi', 'msp', 'hta', 'cpl', 'jar', 'apk', 'dmg', 'iso', 'img', 'lnk', 'ps1', 'reg',
  'ace', 'cab', 'docm', 'xlsm', 'pptm', 'dotm', 'xlam', 'svg', 'html', 'htm', 'shtml', 'chm'
];

/** Parameter names commonly used for open redirects. */
export const REDIRECT_PARAMS = ['url', 'redirect', 'redirect_uri', 'redirecturl', 'return', 'returnurl', 'next', 'continue', 'dest', 'destination', 'goto', 'target', 'r', 'u', 'link', 'out', 'forward', 'redir'];

/** Parameter names that leak or pre-fill identity — typical of phishing kits. */
export const IDENTITY_PARAMS = ['email', 'mail', 'user', 'username', 'userid', 'login', 'account', 'acct', 'card', 'cardno', 'cvv', 'pin', 'otp', 'password', 'passwd', 'pwd', 'token', 'aadhaar', 'pan', 'ifsc', 'upi', 'vpa', 'mobile', 'phone'];

/* ------------------------------------------------------------------------- *
 * Social-engineering tactic library
 *
 * Each tactic is a named manipulation technique with weighted patterns.
 * `weight` is the contribution of the tactic when at least one pattern hits;
 * additional distinct hits inside a tactic add `repeatWeight` (with a cap),
 * so a message screaming five urgency phrases scores above one that says
 * "please respond soon".
 * ------------------------------------------------------------------------- */
export const TACTICS = [
  {
    id: 'urgency',
    label: 'Artificial urgency / deadline pressure',
    category: 'social-engineering',
    weight: 13,
    repeatWeight: 4,
    cap: 25,
    why: 'Attackers impose a deadline so you act before you can verify anything.',
    patterns: [
      // A deadline only counts as pressure when something is demanded or
      // threatened alongside it. Without this guard, "your cab is arriving in
      // 3 minutes" and "web check-in opens 48 hours before departure" were
      // being read as urgency tactics.
      /\b(within|in)\s+\d{1,2}\s*(hours?|hrs?|minutes?|mins?|days?)\b[^.!?]{0,70}\b(or\b|otherwise|else\b|to avoid|verify|confirm|update|pay|click|respond|reply|submit|suspend|block|deactivat|clos|terminat|cancel|expire|delet|penalt|legal)/i,
      /\b(verify|confirm|update|pay|click|respond|reply|submit|act|complete|renew|claim)\b[^.!?]{0,50}\b(within|in|before)\s+\d{1,2}\s*(hours?|hrs?|minutes?|mins?|days?)\b/i,
      /\b(immediate(ly)?|urgent(ly)?|right away|as soon as possible|asap|at once|without delay)\b/i,
      /\b(act|respond|reply|confirm|verify|update|click|pay|redeem)\s+(now|immediately|today|fast|quickly|at once)\b/i,
      /\b(last|final)\s+(chance|warning|reminder|notice|opportunity)\b/i,
      // Short horizons only: "expires in 14 days" is a normal corporate notice.
      /\b(expires?|expiring|expired|valid (only )?(for|till|until))\s+(today|tonight|tomorrow|soon|in\s+\d{1,2}\s*(minutes?|mins?|hours?|hrs?))/i,
      /\b(time[-\s]?sensitive|limited time|hurry|don'?t delay|before it'?s too late|only \d+ (left|remaining))\b/i,
      /\b(within|in)\s+(24|48|72)\s*(hours?|hrs?)\b[^.!?]{0,60}\b(or|otherwise|to avoid|verify|confirm|update|pay|suspend|block|deactivat|clos)/i,
      // Threat first, deadline second: "your account will be suspended within 24
      // hours". The horizon is restricted to hours or 1-3 days so that a genuine
      // "your password expires in 14 days" notice does not read as pressure.
      /\b(suspend|block|deactivat|disabl|terminat|clos|lock|freez|restrict|expir|delet|cancel|forfeit|disconnect|remov)\w*\b[^.!?]{0,45}\b(within|in)\s+(\d{1,2}\s*(hours?|hrs?|minutes?|mins?)|[1-3]\s*days?)\b/i
    ]
  },
  {
    id: 'fear',
    label: 'Fear / threat of loss',
    category: 'social-engineering',
    weight: 15,
    repeatWeight: 5,
    cap: 28,
    why: 'Threatening to close, block or fine you triggers panic and short-circuits judgement.',
    patterns: [
      /\b(suspend(ed|ing)?|block(ed|ing)?|deactivat(e|ed|ion)|disabl(e|ed)|disconnect(ed|ion)?|terminat(e|ed|ion)|clos(e|ed|ure)|lock(ed)?|freez(e|ing|ed)|restrict(ed|ion)|withheld|laps(e|ed)|dormant|removed)\b[^.!?]{0,40}\b(account|card|profile|access|service|number|sim|wallet|policy|connection|meter|result|marksheet|admission)\b/i,
      /\b(account|card|sim|policy|connection|meter|number)\b[^.!?]{0,30}\b(will be|shall be|is going to be)\b[^.!?]{0,25}\b(disconnect|remov|cancel|withheld|forfeit)/i,
      /\b(account|card|sim|kyc|wallet|profile)\b[^.!?]{0,40}\b(will be|shall be|is going to be|about to be)\b[^.!?]{0,20}\b(suspend|block|deactivat|clos|terminat|lock|freez|expire)/i,
      /\b(unauthorized|unusual|suspicious|unrecognized)\s+(login|sign[-\s]?in|access|activity|transaction|attempt|device)\b/i,
      /\b(legal action|police|court|arrest|fir|cyber cell|lawsuit|penalty|fine|prosecut)/i,
      /\b(you (will|may) lose|permanent(ly)? (delet|los|clos)|data will be (erased|deleted)|avoid (suspension|deactivation|penalty))/i,
      /\b(virus|malware|trojan|infected|hacked|compromised|breach)\b/i,
      /\b(failed|declined|rejected)\s+(payment|transaction|delivery|attempt)\b/i
    ]
  },
  {
    id: 'authority',
    label: 'Authority impersonation',
    category: 'social-engineering',
    weight: 12,
    repeatWeight: 4,
    cap: 22,
    why: 'Pretending to be a bank, government body or your boss borrows trust the sender has not earned.',
    patterns: [
      /\b(this is|i am|on behalf of)\s+(the\s+)?(ceo|cfo|coo|md|managing director|director|manager|hr|head of|principal|dean|chairman)/i,
      /\b(income tax|it department|gst|cbdt|cbic|uidai|aadhaar|epfo|rbi|reserve bank|npci|trai|police|cyber (cell|crime)|customs|court)\b[^.!?]{0,50}\b(notice|action|verify|update|payment|penalty|department|officer)\b/i,
      // Genuine IT helpdesks and fraud teams exist, so the role only counts when
      // it is attached to a demand. "contact the IT helpdesk on the number in the
      // staff directory" is advice, not impersonation.
      /\b(security team|fraud (department|team)|compliance (team|department)|account (security|services) team|it (support|helpdesk|department))\b[^.!?]{0,60}\b(requires?|require|needs?|asks?|request(s|ing)?|has (detected|blocked|flagged)|contact us|call us|reply|verify|confirm|click|share|provide|submit)/i,
      /\b(i am|this is|calling from|on behalf of)\b[^.!?]{0,30}\b(security team|fraud (department|team)|customer (care|support)|helpdesk|bank)\b/i,
      /\b(official (notice|communication|warning)|government of india|ministry of)\b/i,
      /\b(your (bank|branch) manager|bank official|authorized (officer|representative))\b/i
    ]
  },
  {
    id: 'credential-request',
    label: 'Credential / sensitive data harvesting',
    category: 'credential-theft',
    weight: 20,
    repeatWeight: 6,
    cap: 34,
    why: 'No legitimate organisation asks for passwords, full card numbers, OTPs, PINs or Aadhaar over a message.',
    patterns: [
      // The verb group accepts inflections (share/shares/shared/sharing) because
      // "complete onboarding by sharing your Aadhaar" is the same request as
      // "share your Aadhaar". The negative lookbehinds keep genuine warnings
      // ("do not share this OTP with anyone") from being read as a request.
      /(?<!\bnot )(?<!\bnever )(?<!\bnot to )(?<!\bdont )\b(enter|provide|submit|confirm|share|send|update|re-?enter|validate|verify|reply with|revert with|fill in|furnish|disclose|quote)(?:s|d|ed|ing)?\b[^.!?]{0,45}\b(password|passcode|pin|otp|one[-\s]?time (password|code)|cvv|card (number|details)|credit card|debit card|net ?banking|user ?id|username|login (details|credentials)|credentials|aadhaar|aadhar|pan (number|card)|ifsc|upi (pin|id)|account (number|details)|cancelled cheque|date of birth|mother'?s maiden)/i,
      // "forward the code you just received" — account takeover by proxy.
      /\b(forward|send|share|tell|read out|give)(?:s|d|ed|ing)?\b[^.!?]{0,35}\b(\d\s*digit\s*)?(code|otp|password|pin)\b[^.!?]{0,30}\b(you (just )?received|sent to (you|your)|on your (phone|mobile)|so i can|to complete|to confirm)/i,
      /\b(password|otp|cvv|pin|mpin|upi pin)\b[^.!?]{0,25}\b(expire|expired|reset|change|required|needed|verify|confirm)\b/i,
      /\b(verify|confirm|update|re-?activate|reactivate|restore|revalidate|re-?register)(?:s|d|ed|ing)?\b[^.!?]{0,30}\b(your )?(account|identity|kyc|profile|details|information|billing|payment method|user ?id|net ?banking)\b/i,
      // "scan the QR code to receive money" — UPI collect-request inversion:
      // scanning a QR never credits you, it authorises a debit.
      /\b(scan)(?:s|ned|ning)?\b[^.!?]{0,30}\bqr\b[^.!?]{0,40}\b(receive|get|claim|collect|credit|refund|cashback|money|amount)/i,
      /\b(enter|share|confirm)(?:s|d|ed|ing)?\s+(your\s+)?upi\s*pin\b/i,
      /\b(log ?in|sign ?in)\b[^.!?]{0,30}\b(to (verify|confirm|restore|avoid|update)|immediately|here|below|using the link)/i,
      /\b(do not share|never share)\b[^.!?]{0,20}\bthis (otp|code)\b[^.!?]{0,30}\b(except|with us|to confirm)/i,
      /\b(kyc)\b[^.!?]{0,30}\b(pending|update|expire|incomplete|verification)\b/i,
      /\b(scan (this|the) qr|qr code to (receive|get|claim))/i
    ]
  },
  {
    id: 'reward',
    label: 'Prize / reward / lottery bait',
    category: 'social-engineering',
    weight: 16,
    repeatWeight: 5,
    cap: 28,
    why: 'Unexpected winnings and free gifts are bait to collect your data or an advance "fee".',
    patterns: [
      /\b(congratulations?|congrats|you'?ve been (selected|chosen)|you are (a )?(lucky )?winner|you have won|winner of)\b/i,
      /\b(lottery|jackpot|lucky draw|prize|sweepstake|raffle|bonanza|scratch card|spin (the )?wheel)\b/i,
      /\b(free|complimentary)\s+(gift|prize|iphone|laptop|voucher|coupon|recharge|data|cashback|reward|holiday|trip)\b/i,
      /\b(claim|redeem|collect)\b[^.!?]{0,25}\b(your )?(prize|reward|gift|cashback|refund|bonus|points|voucher)\b/i,
      /\b(gift card|amazon voucher|google play code|itunes card)\b/i,
      // "credited" deliberately excluded: "Rs. 82,400 has been credited to your
      // account" is the most ordinary bank SMS there is.
      /\b(cash ?prize|₹\s?\d{2,}[,\d]*\s*(lakh|crore)?|rs\.?\s?\d{2,}[,\d]*|\$\s?\d{3,})\b[^.!?]{0,30}\b(won|winning|prize|reward|jackpot|lucky draw)\b/i,
      /\b(you are eligible|eligibility confirmed)\b[^.!?]{0,30}\b(refund|reward|loan|subsidy|scheme)\b/i
    ]
  },
  {
    id: 'financial-fraud',
    label: 'Payment / money movement request',
    category: 'financial-fraud',
    weight: 17,
    repeatWeight: 5,
    cap: 30,
    why: 'Requests to pay a fee, move funds or change bank details are how the money actually leaves.',
    patterns: [
      /\b(pay|transfer|deposit|remit|send)(?:s|ing)?\b[^.!?]{0,35}\b(fee|charge|amount|tax|duty|customs|processing|registration|security deposit|advance|penalty|fine|premium|dues|instal?ment|emi|challan|bill)\b/i,
      // "pay again using the new UPI ID / account below" — payment redirection.
      /\b(pay|transfer|send)(?:s|ing)?\b[^.!?]{0,30}\b(again|now|immediately)?\b[^.!?]{0,25}\b(new|updated|different|below|following)\s+(upi\s*(id|address)?|account|vpa|number|beneficiary|qr)/i,
      /\b(wire transfer|bank transfer|neft|rtgs|imps|swift)\b[^.!?]{0,40}\b(urgent|today|immediately|asap|confidential)/i,
      /\b(change|update|new)\b[^.!?]{0,25}\b(bank (account|details)|account (number|details)|payment (details|instructions)|beneficiary)\b/i,
      /\b(outstanding|pending|overdue|unpaid)\s+(invoice|payment|bill|dues|amount)\b/i,
      /\b(bitcoin|btc|usdt|crypto|ethereum|binance|trust wallet|seed phrase|private key)\b/i,
      /\b(gift ?cards?|google play|steam wallet)\b[^.!?]{0,30}\b(buy|purchase|send (me|us)|code)\b/i,
      /\b(refund|reversal)\b[^.!?]{0,30}\b(processed|initiated|claim|pending)\b[^.!?]{0,40}\b(details|link|form|account)\b/i,
      // "20 percent monthly returns" is written as often as "20% returns".
      /\b(double your|guaranteed\s+(\d+\s*(%|percent)\s*)?(return|profit|income)|risk[-\s]?free\s+(investment|return|profit)|\d{2,}\s*(%|percent)\s*(monthly|weekly|daily|per month)?\s*(return|profit|income|interest))/i,
      /\b(\d{2,}\s*(%|percent)\s*(return|profit)|assured returns|fixed daily (income|profit)|trading signals?)\b/i,
      /\b(loan)\b[^.!?]{0,30}\b(approved|pre-?approved|instant|without documents|no cibil)\b/i
    ]
  },
  {
    id: 'tech-support',
    label: 'Fake technical support',
    category: 'social-engineering',
    weight: 15,
    repeatWeight: 5,
    cap: 26,
    why: 'Fake support agents want remote control of your device or your one-time codes.',
    patterns: [
      /\b(call|contact|dial|whatsapp)\b[^.!?]{0,30}\b(support|helpline|customer care|toll[-\s]?free|technician|agent)\b/i,
      /\b(microsoft|windows|apple|google)\s+(support|technician|security|help ?desk)\b/i,
      /\b(install|download|run|sideload)(?:s|ed|ing)?\b[^.!?]{0,35}\b(anydesk|teamviewer|quicksupport|remote (access|desktop)|screen (share|sharing)|support tool)\b/i,
      // Sideloaded APKs are the primary Android banking-malware vector in India.
      /\b(install|download|update)(?:s|ed|ing)?\b[^.!?]{0,40}\b(apk|\.apk|app from (the )?link|new (secure )?app|updated app|mobile app)\b/i,
      /\b(your (computer|pc|device|phone) (is|has been) (infected|hacked|compromised|at risk))\b/i,
      /\b(license|subscription|antivirus|warranty)\b[^.!?]{0,30}\b(expired|expiring|renew|auto[-\s]?renew(ed|al)?|charged)\b/i,
      /\b(error code|virus alert|security alert)\s*[:#]?\s*[a-z0-9-]{3,}/i
    ]
  },
  {
    id: 'job-scam',
    label: 'Fake job / work-from-home offer',
    category: 'social-engineering',
    weight: 14,
    repeatWeight: 4,
    cap: 24,
    why: 'Fake recruiters collect documents and "registration fees", or launder money through you.',
    patterns: [
      /\b(work from home|part[-\s]?time job|earn (₹|rs\.?|\$)?\s?\d[\d,]*\s*(per|\/)\s*(day|hour|week|month))\b/i,
      /\b(job|position|offer letter|placement|internship)\b[^.!?]{0,40}\b(selected|shortlisted|confirmed|no interview|without interview|direct joining)\b/i,
      /\b(registration|security|training|processing)\s+(fee|charge|amount|deposit)\b/i,
      /\b(daily payout|instant payment|easy (task|money)|just \d+ hours? (a|per) day)\b/i,
      /\b(like|subscribe|review)\b[^.!?]{0,25}\b(task|videos?|products?|hotels?)\b[^.!?]{0,25}\b(earn|paid|commission|₹|rs\.?)/i,
      /\b(send (your )?(resume|cv|documents|aadhaar|pan)\b[^.!?]{0,30}\b(whatsapp|telegram))/i
    ]
  },
  {
    id: 'emotional',
    label: 'Emotional manipulation / romance or charity bait',
    category: 'social-engineering',
    weight: 12,
    repeatWeight: 4,
    cap: 20,
    why: 'Sympathy, affection or guilt are used to lower your defences before the ask.',
    patterns: [
      /\b(i (really )?(need|trust) (your help|your assistance|you to help|only you)|only you can help|please help me|i have no one else|you are my last hope)\b/i,
      /\b(dying|hospital|surgery|accident|cancer|orphan|widow|refugee|earthquake|flood relief)\b[^.!?]{0,50}\b(donat|help|fund|money|transfer|support)\b/i,
      /\b(my (dear|love|darling|honey)|god bless you|beloved (friend|one)|dearest one)\b/i,
      /\b(inheritance|next of kin|unclaimed (funds|estate)|late (mr|mrs|dr)\.?\s+\w+)\b/i,
      /\b(keep this (confidential|between us|a secret)|do not (tell|inform) (anyone|anybody)|strictly confidential)\b/i,
      /\b(i am (stuck|stranded)|lost my (wallet|phone|passport))\b/i
    ]
  },
  {
    id: 'link-lure',
    label: 'Vague "click here" link lure',
    category: 'content',
    weight: 9,
    repeatWeight: 3,
    cap: 15,
    why: 'Hiding the destination behind vague text stops you from seeing where you are really going.',
    patterns: [
      /\b(click|tap|press)\s+(here|the link|below|on the link|this link)\b/i,
      /\b(follow|open|use)\s+(this|the)\s+(link|url|attachment)\b/i,
      /\b(track (it|your (order|package|shipment)) here)\b/i,
      // A colon only signals a call to action when a link actually follows it.
      // "Delivery update: your parcel is delayed" was matching before this guard.
      /\b(login|log in|sign in|verify|update|claim|download|pay)\s*(?::|->|=>|➡|👉)\s*(?=https?:\/\/|www\.)/i,
      /\b(link (below|above)|see (the )?attachment|view (document|invoice|statement))\b/i
    ]
  },
  {
    id: 'impersonal',
    label: 'Impersonal or inconsistent addressing',
    category: 'content',
    weight: 7,
    repeatWeight: 2,
    cap: 11,
    why: 'Real providers usually know your name; mass phishing does not.',
    patterns: [
      /\b(dear (customer|user|client|sir\/madam|sir or madam|account holder|valued (customer|member)|member|friend|beneficiary|winner|applicant))\b/i,
      /\b(attention:?\s*(customer|user|account holder))\b/i,
      /\b(undisclosed[-\s]?recipients?|to whom it may concern)\b/i
    ]
  },
  {
    id: 'channel-switch',
    label: 'Push to an unmonitored channel',
    category: 'social-engineering',
    weight: 11,
    repeatWeight: 4,
    cap: 18,
    why: 'Moving you to WhatsApp or Telegram removes logging, filters and any paper trail.',
    patterns: [
      /\b(contact|message|reach|ping|chat|dm)\b[^.!?]{0,25}\b(on\s+)?(whats\s?app|whatsapp|telegram|signal|wechat)\b/i,
      /\b(wa\.me|t\.me|api\.whatsapp\.com|chat\.whatsapp\.com)\b/i,
      /\b(reply (with|to this)|revert on)\b[^.!?]{0,20}\b(personal|private|alternate)\s+(number|email|id)\b/i,
      /\b(do not (reply|respond) (to|on) (this )?(email|official))\b/i
    ]
  },
  {
    id: 'secrecy',
    label: 'Secrecy and bypass-the-process pressure',
    category: 'social-engineering',
    weight: 12,
    repeatWeight: 4,
    cap: 18,
    why: 'Asking you to skip verification or keep quiet is designed to defeat your organisation\'s controls.',
    patterns: [
      /\b(don'?t|do not)\s+(tell|inform|discuss|involve|contact)\b[^.!?]{0,30}\b(anyone|team|finance|accounts|manager|colleague|it)\b/i,
      /\b(bypass|skip|ignore)\b[^.!?]{0,25}\b(process|procedure|approval|verification|policy)\b/i,
      /\b(i'?m (in a meeting|travelling|on a flight|unavailable)|can'?t (talk|call) (right )?now)\b[^.!?]{0,60}\b(so|please|need you to)\b/i,
      /\b(handle this (personally|discreetly|quietly)|strictly (confidential|between us))\b/i
    ]
  },
  {
    id: 'bec',
    label: 'Business Email Compromise pattern',
    category: 'bec',
    weight: 18,
    repeatWeight: 5,
    cap: 28,
    why: 'A "leadership" request for an urgent, quiet payment or data dump is the classic BEC playbook.',
    patterns: [
      /\b(are you (at your desk|available|free)\??)\b/i,
      /\b(need (you|your help) (to|with))\b[^.!?]{0,40}\b(payment|transfer|invoice|vendor|wire|gift cards?|payroll|w-?2|employee (data|details))\b/i,
      /\b(vendor|supplier|beneficiary|company|our|accounts?( department)?)\b[^.!?]{0,35}\b(bank|banks|account|payment)\b[^.!?]{0,30}\b(chang(e|ed|ing)|updat(e|ed)|switch(ed)?|new)\b/i,
      /\b(bank|banking|account) details?\b[^.!?]{0,25}\b(have|has|was|were|are)?\s*(chang(e|ed)|updat(e|ed)|new)\b/i,
      /\b(use|note)\s+(the\s+)?(new|updated|revised|attached)\s+(bank|account|beneficiary|payment)\s*(details?|instructions?)?/i,
      /\b(process (this|the) (payment|invoice|transfer))\b[^.!?]{0,30}\b(today|urgently|immediately|before)\b/i,
      /\b(sent from my (i|I)phone)\b[\s\S]{0,80}\b(payment|transfer|urgent)\b/i,
      /\b(payroll|salary)\s+(details|account|update)\b/i
    ]
  },
  {
    id: 'delivery-lure',
    label: 'Delivery / logistics pretext',
    category: 'content',
    weight: 10,
    repeatWeight: 3,
    cap: 16,
    why: 'Almost everyone is waiting for a parcel, which makes this the most reused pretext there is.',
    patterns: [
      /\b(package|parcel|shipment|consignment|courier|delivery)\b[^.!?]{0,40}\b(delayed|held|pending|failed|on hold|customs|address|reschedul|undelivered|attempt)\b/i,
      /\b(customs (duty|clearance|fee)|shipping (fee|charge)|redelivery)\b/i,
      /\b(tracking (number|id|code))\b[^.!?]{0,30}\b(click|link|update|confirm)\b/i,
      /\b(confirm your (delivery )?address)\b/i
    ]
  },
  {
    id: 'account-alert',
    label: 'Unsolicited security alert',
    category: 'content',
    weight: 10,
    repeatWeight: 3,
    cap: 16,
    why: 'Fake "we noticed a new sign-in" alerts push you to a look-alike login page.',
    patterns: [
      /\b(we (noticed|detected|found)|there (was|has been))\b[^.!?]{0,40}\b(sign[-\s]?in|login|access|activity|transaction|attempt|device|location)\b/i,
      /\b(new device|unknown device|new location|different (device|ip))\b[^.!?]{0,30}\b(sign|login|access)/i,
      /\b(if this (wasn'?t|was not) you)\b/i,
      /\b(password (was )?(changed|reset)|recovery (email|phone) (changed|added))\b/i,
      /\b(review (this )?activity|secure your account (now|immediately))\b/i
    ]
  }
];

/* ------------------------------------------------------------------------- *
 * Recommendation library — mapped from the dominant signal categories.
 * ------------------------------------------------------------------------- */
export const RECOMMENDATIONS = {
  'credential-theft': [
    'Do not enter any password, OTP, PIN, CVV or Aadhaar/PAN details from this message.',
    'If you already entered credentials, change that password now and enable two-factor authentication.'
  ],
  'financial-fraud': [
    'Do not make any payment or transfer based on this message.',
    'Confirm bank or payment detail changes by calling a known, previously used number — never a number from the message.'
  ],
  bec: [
    'Verify the request out-of-band: call the colleague or executive on a number you already have.',
    'Follow your organisation\'s payment approval process even if the sender says it is urgent or confidential.'
  ],
  url: [
    'Do not click the link. Type the official website address into your browser manually instead.',
    'Hover over links to read the real destination before clicking, and be sceptical of shortened links.'
  ],
  domain: [
    'Check the sender domain character by character — look-alike domains differ by one or two letters.',
    'Reach the organisation through its official app or a bookmarked website, not through this message.'
  ],
  sender: [
    'Verify the sender independently using contact details from the organisation\'s official website.',
    'Treat a reply-to address that differs from the sender address as a strong warning sign.'
  ],
  'social-engineering': [
    'Slow down. Urgency, fear and secrecy are pressure tactics, not evidence of a real deadline.',
    'When in doubt, contact the organisation directly through an official channel before doing anything.'
  ],
  page: [
    'Never submit credentials on a page you reached from a message or advertisement.',
    'Close the page and navigate to the service yourself if you genuinely need to log in.'
  ],
  content: [
    'Do not open attachments or links you were not expecting, even if the sender looks familiar.',
    'Ask the sender to confirm through a second channel before acting on the request.'
  ],
  general: [
    'Report the message as phishing in your mail or messaging app, then delete it.',
    'Block the sender so follow-up attempts do not reach you.'
  ],
  safe: [
    'No strong phishing indicators were found, but stay alert if the message asks for money or credentials.',
    'When a message involves payments or credentials, verify through an official channel regardless of how it looks.'
  ]
};

/** Category display names used by the explanation engine. */
export const CATEGORY_LABELS = {
  url: 'Link & URL structure',
  domain: 'Domain & brand impersonation',
  sender: 'Sender authenticity',
  'social-engineering': 'Social engineering tactics',
  'credential-theft': 'Credential harvesting',
  'financial-fraud': 'Financial fraud',
  bec: 'Business Email Compromise',
  page: 'Website / login page behaviour',
  content: 'Message content & structure',
  intel: 'Threat intelligence',
  ml: 'Machine-learning classifier',
  ai: 'AI language model assessment',
  positive: 'Trust indicators'
};

/** Awareness tips surfaced in the UI training module. */
export const AWARENESS_TIPS = [
  { id: 'tip-otp', title: 'An OTP is a password', body: 'No bank, wallet, delivery agent or government office ever needs your OTP. Anyone asking for it is trying to complete a transaction as you.' },
  { id: 'tip-domain', title: 'Read domains right to left', body: 'In secure-sbi.login-verify.co, the real owner is login-verify.co, not SBI. The part just before the final dot is what matters.' },
  { id: 'tip-urgency', title: 'Urgency is the attack', body: 'Deadlines of 24 hours, threats of suspension and "final warning" wording exist to stop you from checking. Real providers give you time.' },
  { id: 'tip-channel', title: 'Verify on a channel you chose', body: 'Call the number printed on your card or the official app, never the number inside the suspicious message.' },
  { id: 'tip-attachment', title: 'Unexpected attachments are hostile until proven otherwise', body: 'Invoices, "delivery slips" and resumes in .html, .zip, .apk or macro-enabled Office files are a common malware carrier.' },
  { id: 'tip-lookalike', title: 'HTTPS is not a safety badge', body: 'A padlock only means the connection is encrypted. Phishing sites get free certificates too.' },
  { id: 'tip-bec', title: 'Bank detail changes need a phone call', body: 'Any email changing vendor or payroll bank details must be confirmed by voice with a known contact before payment.' },
  { id: 'tip-report', title: 'Reporting protects others', body: 'In India you can report cyber fraud at cybercrime.gov.in or helpline 1930, ideally within the first hours of a financial loss.' }
];
