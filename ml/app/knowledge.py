"""
Domain knowledge shared by the featurisers, the corpus generator and the API.

This is deliberately a compact mirror of the Node rule engine's constants: the
ML tier needs the same notion of "which domains are real" to build features
such as *edit distance to the nearest brand domain*, but it stays independent so
the two tiers can be trained, deployed and reasoned about separately.
"""

from __future__ import annotations

# --------------------------------------------------------------------------- #
# Brands and their genuine registrable domains
# --------------------------------------------------------------------------- #
BRAND_DOMAINS: dict[str, list[str]] = {
    "google": ["google.com", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com", "microsoftonline.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.in", "amazonaws.com"],
    "facebook": ["facebook.com", "instagram.com", "whatsapp.com", "meta.com"],
    "netflix": ["netflix.com"],
    "paypal": ["paypal.com"],
    "linkedin": ["linkedin.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "bluedart": ["bluedart.com"],
    "indiapost": ["indiapost.gov.in"],
    "sbi": ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc": ["hdfcbank.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotak.com"],
    "pnb": ["pnbindia.in"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "npci": ["npci.org.in"],
    "incometax": ["incometax.gov.in"],
    "gst": ["gst.gov.in"],
    "uidai": ["uidai.gov.in"],
    "epfo": ["epfindia.gov.in"],
    "irctc": ["irctc.co.in"],
    "flipkart": ["flipkart.com"],
    "myntra": ["myntra.com"],
    "swiggy": ["swiggy.com"],
    "zomato": ["zomato.com"],
    "rbi": ["rbi.org.in"],
    "binance": ["binance.com"],
    "coinbase": ["coinbase.com"],
    "wazirx": ["wazirx.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "github": ["github.com"],
    "docusign": ["docusign.com"],
    "zoom": ["zoom.us"],
    "uber": ["uber.com"],
    "airtel": ["airtel.in"],
    "jio": ["jio.com"],
    "bsnl": ["bsnl.co.in"],
}

OFFICIAL_DOMAINS: set[str] = {d for domains in BRAND_DOMAINS.values() for d in domains}

# Brand label (the part before the public suffix) -> brand key.
BRAND_LABELS: dict[str, str] = {}
for _brand, _domains in BRAND_DOMAINS.items():
    BRAND_LABELS[_brand] = _brand
    for _d in _domains:
        BRAND_LABELS[_d.split(".")[0]] = _brand

TRUSTED_EXTRA: set[str] = {
    "wikipedia.org", "stackoverflow.com", "nodejs.org", "python.org", "cloudflare.com",
    "slack.com", "notion.so", "figma.com", "dropbox.com", "adobe.com", "atlassian.com",
    "nic.in", "gov.in", "mygov.in", "digilocker.gov.in", "nptel.ac.in", "coursera.org",
    "udemy.com", "ieee.org", "acm.org", "zoho.com", "razorpay.com", "cleartax.in",
}

TRUSTED_DOMAINS: set[str] = OFFICIAL_DOMAINS | TRUSTED_EXTRA

SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "club", "work", "click", "link", "buzz",
    "rest", "fit", "surf", "cam", "monster", "quest", "cyou", "icu", "zip", "mov", "sbs",
    "country", "kim", "review", "date", "wang", "loan", "racing", "stream", "download",
    "bid", "trade", "party", "gdn", "mom", "lol", "pw", "cc", "casa", "cfd", "autos", "bar",
}

COMMON_TLDS: set[str] = {
    "com", "org", "net", "in", "co.in", "gov.in", "ac.in", "edu", "io", "co", "co.uk",
    "us", "ca", "au", "de", "fr", "jp", "sg", "info", "biz", "gov", "mil", "int", "app", "dev",
}

URL_SHORTENERS: set[str] = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "cutt.ly", "rb.gy", "rebrand.ly", "tiny.cc", "shorturl.at", "v.gd", "clck.ru",
    "gg.gg", "shrtco.de", "t.me", "wa.me", "linktr.ee", "short.gy", "kutt.it", "bit.do",
}

FREE_HOSTING_SUFFIXES: tuple[str, ...] = (
    "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "webnode.page",
    "000webhostapp.com", "epizy.com", "byethost.com", "github.io", "gitlab.io",
    "netlify.app", "vercel.app", "pages.dev", "workers.dev", "r2.dev", "firebaseapp.com",
    "web.app", "glitch.me", "repl.co", "replit.dev", "herokuapp.com", "ngrok-free.app",
    "trycloudflare.com", "loca.lt", "duckdns.org", "ddns.net", "no-ip.org", "hopto.org",
    "sites.google.com", "forms.gle", "jotform.com", "typeform.com", "formspree.io",
    "telegra.ph", "pastebin.com", "canva.site", "notion.site", "square.site",
)

MULTI_PART_SUFFIXES: set[str] = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "net.in", "org.in", "gov.in", "nic.in",
    "ac.in", "edu.in", "res.in", "com.au", "net.au", "gov.au", "co.jp", "or.jp", "com.br",
    "com.cn", "co.za", "com.sg", "com.my", "com.ph", "com.pk", "com.bd", "com.np", "co.nz",
    "com.tr", "com.mx", "co.kr", "com.hk", "com.tw", "co.il", "co.th", "com.sa", "co.id",
}

# Words that phishing kits bake into paths and subdomains.
CREDENTIAL_URL_WORDS: tuple[str, ...] = (
    "login", "signin", "logon", "account", "verify", "verification", "validate", "secure",
    "security", "update", "confirm", "auth", "password", "credential", "recover", "unlock",
    "reactivate", "suspended", "billing", "payment", "wallet", "netbanking", "banking",
    "kyc", "aadhaar", "pan", "upi", "otp", "webscr", "session", "token", "invoice",
    "refund", "claim", "reward", "gift", "prize", "winner", "bonus", "customer",
)

REDIRECT_PARAMS: tuple[str, ...] = (
    "url", "redirect", "redirect_uri", "return", "returnurl", "next", "continue", "dest",
    "destination", "goto", "target", "link", "out", "forward", "redir", "r", "u",
)

IDENTITY_PARAMS: tuple[str, ...] = (
    "email", "mail", "user", "username", "userid", "login", "account", "acct", "card",
    "cardno", "cvv", "pin", "otp", "password", "pwd", "token", "aadhaar", "pan", "ifsc",
    "upi", "vpa", "mobile", "phone", "id",
)

# Extensions that execute code or carry macros. A link ending in one of these is
# a strong signal on its own.
EXECUTABLE_EXTENSIONS: tuple[str, ...] = (
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse", "wsf", "wsh",
    "msi", "msp", "hta", "cpl", "jar", "apk", "dmg", "iso", "img", "lnk", "ps1", "reg",
    "docm", "xlsm", "pptm", "dotm", "xlam", "chm",
)

# Archives and standalone web pages: used by phishing kits for offline login
# clones, but also completely normal on documentation and download sites.
# Kept as a separate, weaker feature so that ``docs.python.org/.../urllib.parse.html``
# is not scored like ``invoice.exe`` — that exact case was a false positive
# before the split.
ARCHIVE_WEB_EXTENSIONS: tuple[str, ...] = ("zip", "rar", "7z", "ace", "cab", "html", "htm", "shtml", "svg")

DANGEROUS_EXTENSIONS: tuple[str, ...] = EXECUTABLE_EXTENSIONS + ARCHIVE_WEB_EXTENSIONS

HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ѕ": "s", "ԁ": "d", "һ": "h", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "α": "a",
    "ε": "e", "ι": "i", "κ": "k", "μ": "m", "à": "a", "á": "a", "â": "a", "ä": "a",
    "å": "a", "ã": "a", "è": "e", "é": "e", "ê": "e", "ë": "e", "ì": "i", "í": "i",
    "î": "i", "ï": "i", "ò": "o", "ó": "o", "ô": "o", "ö": "o", "õ": "o", "ø": "o",
    "ù": "u", "ú": "u", "û": "u", "ü": "u", "ç": "c", "ñ": "n", "ý": "y", "ł": "l",
}

LEET_MAP: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "$": "s", "@": "a", "!": "i", "|": "l",
}


def registrable_domain(host: str) -> str:
    """eTLD+1 using the curated multi-part suffix list."""
    host = (host or "").lower().strip().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    parts = [p for p in host.split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def public_suffix(host: str) -> str:
    """Public suffix of a host, aware of two-part suffixes such as ``co.in``."""
    rd = registrable_domain(host)
    parts = rd.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(parts[-2:])
    return parts[-1] if parts else ""


def domain_label(host: str) -> str:
    """The registrable domain without its public suffix."""
    rd = registrable_domain(host)
    suffix = public_suffix(host)
    if suffix and rd.endswith("." + suffix):
        return rd[: -(len(suffix) + 1)]
    return rd
