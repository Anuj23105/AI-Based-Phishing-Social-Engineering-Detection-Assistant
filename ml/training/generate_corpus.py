"""
Training corpus generator for PhishGuard AI.

Why generated data?
-------------------
Public phishing corpora (Enron/Nazario/PhishTank/Kaggle mixes) cannot be
redistributed inside a project repository, and the popular ones are dominated by
2000s-era English spam that misses UPI, Aadhaar, KYC, OTP and courier pretexts
that dominate Indian phishing today. This script instead composes a labelled
corpus from templates, slot banks and surface-level noise, which gives:

* balanced classes and reproducible runs (fixed seed);
* coverage of the tactic taxonomy the product claims to detect;
* hard negatives on purpose — genuine OTP alerts, genuine "new sign-in"
  notices, genuine courier updates and real password resets sit in the *legit*
  class, because those are exactly the messages a naive classifier flags.

The honest caveat: metrics measured on a held-out split of generated data
describe how well the model separates *these* distributions, not live traffic.
Both training scripts accept ``--data`` so a real CSV can be dropped in without
touching any other code. See the README for the swap-in instructions.

Usage
-----
    python training/generate_corpus.py --messages 7000 --urls 9000
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import DATA_DIR, RANDOM_SEED  # noqa: E402
from app.knowledge import BRAND_DOMAINS, SUSPICIOUS_TLDS  # noqa: E402

# --------------------------------------------------------------------------- #
# Slot banks
# --------------------------------------------------------------------------- #
BANKS = ["SBI", "HDFC Bank", "ICICI Bank", "Axis Bank", "Kotak Bank", "Punjab National Bank",
         "Bank of Baroda", "Canara Bank", "IndusInd Bank", "Yes Bank", "Union Bank"]
WALLETS = ["Paytm", "PhonePe", "Google Pay", "Amazon Pay", "Mobikwik", "BHIM UPI"]
COURIERS = ["Blue Dart", "DTDC", "India Post", "Delhivery", "DHL", "FedEx", "Ekart", "Amazon Logistics"]
SHOPS = ["Amazon", "Flipkart", "Myntra", "Ajio", "Nykaa", "Croma", "Reliance Digital"]
TECH = ["Microsoft", "Google", "Apple", "Netflix", "LinkedIn", "Instagram", "Facebook", "WhatsApp", "Zoom", "GitHub"]
GOVT = ["Income Tax Department", "GST Department", "UIDAI", "EPFO", "RBI", "Regional Transport Office", "Municipal Corporation"]
TELECOM = ["Airtel", "Jio", "Vi", "BSNL"]
CRYPTO = ["Binance", "WazirX", "CoinDCX", "Coinbase"]

FIRST_NAMES = ["Anuj", "Priya", "Rahul", "Sneha", "Vikram", "Aisha", "Rohit", "Kavya", "Arjun", "Meera",
               "Karan", "Divya", "Suresh", "Neha", "Amit", "Pooja", "Nikhil", "Ananya", "Sanjay", "Ritu",
               "Faisal", "Ishaan", "Tanya", "Manish", "Shreya", "Deepak", "Farhan", "Lakshmi", "Gaurav", "Nisha"]
LAST_NAMES = ["Sharma", "Verma", "Patel", "Reddy", "Nair", "Iyer", "Gupta", "Singh", "Khan", "Bose",
              "Menon", "Kulkarni", "Joshi", "Chatterjee", "Desai", "Rao", "Mehta", "Pillai", "Dutta", "Kapoor"]
COMPANIES = ["Nexora Systems", "Trilok Industries", "Vertex Labs", "BlueOrbit Technologies", "Sahyadri Textiles",
             "Anantam Consulting", "Quantum Edge Pvt Ltd", "Sunrise Logistics", "Pragati Motors", "Zentra Analytics"]
JOB_TITLES = ["Data Entry Executive", "Customer Support Associate", "Content Reviewer", "Marketing Intern",
              "Backend Developer", "Business Analyst", "Field Sales Officer", "Product Tester"]
CITIES = ["Mumbai", "Pune", "Bengaluru", "Hyderabad", "Chennai", "Delhi", "Kolkata", "Ahmedabad", "Jaipur", "Kochi",
          "Indore", "Lucknow", "Nagpur", "Surat", "Bhopal"]
DEPARTMENTS = ["Finance", "Human Resources", "IT Support", "Payroll", "Procurement", "Operations", "Admin"]

AMOUNTS_SMALL = ["Rs. 199", "Rs. 499", "Rs. 899", "Rs. 1,250", "Rs. 2,340", "Rs. 3,499", "Rs. 4,999", "Rs. 7,850"]
AMOUNTS_LARGE = ["Rs. 25,000", "Rs. 48,500", "Rs. 1,20,000", "Rs. 2,50,000", "Rs. 5,00,000", "Rs. 12,00,000",
                 "Rs. 25 lakh", "Rs. 1 crore", "$4,500", "$18,750"]
PRIZES = ["Rs. 25 lakh", "Rs. 10,00,000", "a brand new iPhone 15 Pro", "a Tata Nexon EV", "Rs. 50,000 cashback",
          "a MacBook Air", "Rs. 5,000 Amazon voucher", "an all-expenses-paid trip to Dubai"]
DEADLINES = ["24 hours", "48 hours", "12 hours", "6 hours", "72 hours", "today", "tonight", "the next 2 hours",
             "the end of the day", "3 working days"]
TRACKING = ["BD{n8}", "IN{n9}", "AWB{n10}", "SF{n8}IN", "EK{n11}", "1Z{n9}"]
CODES = ["{n6}", "{n4}", "{n8}"]
DATES = ["12 March", "3 April", "27 June", "8 August", "19 September", "2 November", "15 January", "30 December"]
TIMES = ["10:30 AM", "2:15 PM", "6:45 PM", "11:20 PM", "9:00 AM", "4:30 PM"]
DEVICES = ["Windows PC in {city}", "iPhone in {city}", "Android device in {city}", "Linux machine", "iPad in {city}",
           "Chrome browser on Windows"]
CARD_LAST4 = ["{n4}"]

PHISH_SUBDOMAIN_WORDS = ["secure", "verify", "account", "login", "update", "online", "service", "support", "help",
                         "auth", "id", "portal", "care", "alert", "kyc", "billing", "signin", "myaccount"]
PHISH_PATH_WORDS = ["login", "signin", "verify", "account/update", "secure/confirm", "kyc-update", "auth/validate",
                    "customer/verify", "billing/update", "unlock", "reactivate", "session/renew", "claim/reward",
                    "wallet/verify", "netbanking/login", "id/confirm", "otp/validate", "payment/pending"]
LEGIT_PATH_WORDS = ["help", "support/articles", "orders", "account/settings", "products", "blog/2026/03",
                    "careers", "about-us", "docs/getting-started", "pricing", "contact", "search", "faq",
                    "news/press-release", "downloads", "status", "community/threads"]
RANDOM_TLDS = sorted(SUSPICIOUS_TLDS)
BENIGN_TLDS = ["com", "in", "co.in", "org", "net", "io", "ac.in", "gov.in", "app", "dev", "co"]
GENERIC_LEGIT_DOMAINS = ["thehindu.com", "indianexpress.com", "moneycontrol.com", "geeksforgeeks.org",
                         "stackoverflow.com", "medium.com", "dev.to", "wikipedia.org", "nptel.ac.in",
                         "iitb.ac.in", "vit.ac.in", "razorpay.com", "zerodha.com", "cleartax.in", "practo.com",
                         "makemytrip.com", "redbus.in", "bookmyshow.com", "hackerrank.com", "leetcode.com"]

SHORTENER_DOMAINS = ["bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co", "shorturl.at", "gg.gg", "v.gd"]
FREE_HOSTS = ["000webhostapp.com", "weebly.com", "blogspot.com", "netlify.app", "vercel.app", "pages.dev",
              "web.app", "firebaseapp.com", "glitch.me", "repl.co", "herokuapp.com", "ngrok-free.app",
              "duckdns.org", "sites.google.com", "jotform.com", "wixsite.com", "github.io"]


def _rand_digits(n: int) -> str:
    return "".join(random.choice("0123456789") for _ in range(n))


def _rand_token(length: int, alphabet: str = "abcdefghijklmnopqrstuvwxyz0123456789") -> str:
    return "".join(random.choice(alphabet) for _ in range(length))


def _fill_numbers(value: str) -> str:
    """Expand ``{n6}`` style placeholders into random digit runs."""
    out = value
    while "{n" in out:
        start = out.index("{n")
        end = out.index("}", start)
        count = int(out[start + 2:end])
        out = out[:start] + _rand_digits(count) + out[end + 1:]
    return out


# --------------------------------------------------------------------------- #
# URL builders
# --------------------------------------------------------------------------- #
def _typosquat(label: str) -> str:
    """Produce a plausible one-or-two character mutation of a brand label."""
    if len(label) < 4:
        return label + "s"
    mode = random.choice(["swap", "drop", "double", "replace", "insert", "hyphen", "homoglyph"])
    i = random.randrange(1, len(label) - 1)
    if mode == "swap":
        chars = list(label)
        chars[i], chars[i + 1] = chars[i + 1], chars[i]
        return "".join(chars)
    if mode == "drop":
        return label[:i] + label[i + 1:]
    if mode == "double":
        return label[:i] + label[i] + label[i:]
    if mode == "replace":
        near = {"a": "e", "e": "a", "i": "1", "l": "1", "o": "0", "s": "5", "m": "rn", "n": "m", "c": "k",
                "g": "q", "t": "7", "b": "6", "u": "v", "y": "i"}
        ch = label[i]
        return label[:i] + near.get(ch, random.choice("aeiou")) + label[i + 1:]
    if mode == "insert":
        return label[:i] + random.choice("aeioulnrst") + label[i:]
    if mode == "hyphen":
        return label[:i] + "-" + label[i:]
    homo = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "p": "\u0440", "c": "\u0441", "i": "\u0456"}
    for idx, ch in enumerate(label):
        if ch in homo:
            return label[:idx] + homo[ch] + label[idx + 1:]
    return label + "-secure"


def make_phishing_url() -> str:
    brand_key = random.choice(list(BRAND_DOMAINS.keys()))
    brand_domain = random.choice(BRAND_DOMAINS[brand_key])
    label = brand_domain.split(".")[0]
    kind = random.choices(
        ["typosquat", "brand_subdomain", "brand_prefix", "ip_host", "shortener", "free_host",
         "credential_path", "random_domain", "punycode", "redirect", "download", "userinfo", "deep_sub"],
        weights=[16, 14, 14, 7, 8, 11, 8, 6, 3, 4, 4, 2, 3],
    )[0]
    scheme = random.choices(["http", "https"], weights=[6, 4])[0]
    path = random.choice(PHISH_PATH_WORDS)
    tld = random.choice(RANDOM_TLDS) if random.random() < 0.55 else random.choice(["com", "net", "info", "online", "site"])
    query = ""
    if random.random() < 0.45:
        key = random.choice(["email", "user", "id", "token", "session", "acc", "mobile", "ref"])
        val = random.choice([
            f"{_rand_token(random.randint(6, 10))}%40{random.choice(['gmail.com', 'yahoo.com', 'outlook.com'])}",
            _rand_token(random.randint(18, 44)),
            _rand_digits(random.randint(8, 12)),
        ])
        query = f"?{key}={val}"

    if kind == "typosquat":
        host = f"{'www.' if random.random() < 0.4 else ''}{_typosquat(label)}.{random.choice(['com', 'net', 'co', 'in'] + RANDOM_TLDS[:12])}"
    elif kind == "brand_subdomain":
        host = f"{label}.{random.choice(PHISH_SUBDOMAIN_WORDS)}-{_rand_token(random.randint(4, 8))}.{tld}"
    elif kind == "brand_prefix":
        joiner = random.choice(["-", "", "-", "."])
        host = f"{label}{joiner}{random.choice(PHISH_SUBDOMAIN_WORDS)}{random.choice(['', '-' + random.choice(PHISH_SUBDOMAIN_WORDS)])}.{tld}"
    elif kind == "ip_host":
        host = f"{random.randint(3, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        if random.random() < 0.3:
            host += f":{random.choice([8080, 8000, 8443, 3000, 7777])}"
        path = f"{label}/{path}"
    elif kind == "shortener":
        return f"https://{random.choice(SHORTENER_DOMAINS)}/{_rand_token(random.randint(5, 8), 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789')}"
    elif kind == "free_host":
        host = f"{label}-{random.choice(PHISH_SUBDOMAIN_WORDS)}{random.choice(['', _rand_digits(2)])}.{random.choice(FREE_HOSTS)}"
    elif kind == "credential_path":
        host = f"{_rand_token(random.randint(6, 12))}.{tld}"
        path = f"{label}/{random.choice(PHISH_PATH_WORDS)}"
    elif kind == "punycode":
        host = f"xn--{_rand_token(random.randint(6, 11))}-{_rand_token(3)}.{random.choice(['com', 'net'] + RANDOM_TLDS[:8])}"
        path = f"{label}/{path}"
    elif kind == "redirect":
        host = f"{random.choice(PHISH_SUBDOMAIN_WORDS)}-{_rand_token(6)}.{tld}"
        query = f"?redirect=https%3A%2F%2F{label}-{random.choice(PHISH_SUBDOMAIN_WORDS)}.{random.choice(RANDOM_TLDS)}%2Flogin"
    elif kind == "download":
        host = f"{label}{random.choice(['-', ''])}{random.choice(['docs', 'invoice', 'files', 'update'])}.{tld}"
        path = f"{random.choice(['invoice', 'statement', 'document', 'receipt', 'update'])}-{_rand_digits(5)}.{random.choice(['exe', 'apk', 'zip', 'html', 'scr', 'jar', 'docm'])}"
        query = ""
    elif kind == "userinfo":
        host = f"{label}.com@{_rand_token(random.randint(6, 10))}.{random.choice(RANDOM_TLDS)}"
    else:  # deep_sub
        host = f"{label}.{random.choice(PHISH_SUBDOMAIN_WORDS)}.{random.choice(PHISH_SUBDOMAIN_WORDS)}.{_rand_token(6)}.{tld}"

    return f"{scheme}://{host}/{path}{query}".replace("//" + host + "//", "//" + host + "/")


def make_legit_url() -> str:
    if random.random() < 0.55:
        brand_key = random.choice(list(BRAND_DOMAINS.keys()))
        domain = random.choice(BRAND_DOMAINS[brand_key])
    else:
        domain = random.choice(GENERIC_LEGIT_DOMAINS)

    host = ("www." if random.random() < 0.45 else "") + domain
    if random.random() < 0.18:
        host = random.choice(["support", "help", "accounts", "docs", "blog", "careers", "status", "m"]) + "." + domain

    path_choice = random.random()
    if path_choice < 0.15:
        path = ""
    elif path_choice < 0.75:
        path = random.choice(LEGIT_PATH_WORDS)
        if random.random() < 0.35:
            path += "/" + random.choice([
                _rand_token(random.randint(4, 9), "abcdefghijklmnopqrstuvwxyz-"),
                _rand_digits(random.randint(4, 7)),
                random.choice(["overview", "details", "how-to-reset-password", "shipping-policy", "invoice"]),
            ])
    else:
        path = "/".join([
            random.choice(LEGIT_PATH_WORDS),
            random.choice(["2026", "guides", "reference", "in-en", "topics"]),
            _rand_token(random.randint(5, 10), "abcdefghijklmnopqrstuvwxyz-"),
        ])

    # Documentation and download sites legitimately end in .html, .pdf or .zip.
    # Without these examples the model treats any file extension as hostile.
    if path and random.random() < 0.14:
        path += "." + random.choice(["html", "htm", "pdf", "aspx", "php", "jsp", "zip", "csv", "json", "xml"])

    query = ""
    if random.random() < 0.25:
        key = random.choice(["q", "page", "ref", "utm_source", "lang", "sort", "category", "id"])
        val = random.choice(["1", "2", "newsletter", "en-in", "latest", _rand_token(6), _rand_digits(4)])
        query = f"?{key}={val}"

    scheme = "https" if random.random() < 0.94 else "http"
    return f"{scheme}://{host}/{path}{query}".replace("/?", "?") if path else f"{scheme}://{host}{('/' + query) if query else '/'}"


# --------------------------------------------------------------------------- #
# Message templates
# --------------------------------------------------------------------------- #
PHISH_TEMPLATES: list[tuple[str, str]] = [
    # ---- banking / account suspension -----------------------------------
    ("bank", "Dear Customer, your {bank} account will be suspended within {deadline}. Please verify your identity immediately at {url} to avoid deactivation."),
    ("bank", "URGENT: Your {bank} net banking access has been temporarily blocked due to incomplete KYC. Update your KYC now: {url}"),
    ("bank", "{bank} Alert: Unusual login detected on your account from {device}. If this was not you, secure your account here {url}"),
    ("bank", "Your debit card ending {card4} has been deactivated for security reasons. Re-activate by confirming your card details at {url}"),
    ("bank", "Dear user, your account statement could not be delivered. Kindly re-confirm your registered mobile number and net banking password at {url}"),
    ("bank", "{bank}: Your account has been credited with {amount} in error. Reverse the transaction within {deadline} by logging in at {url} or legal action will follow."),
    ("bank", "Final reminder: Your {bank} account KYC expires {deadline}. Failure to update will result in permanent account closure. Update: {url}"),
    ("bank", "Security Notice from {bank}: {amount} was debited from your account. If you did not authorise this, cancel the transaction immediately at {url}"),
    ("bank", "Your {bank} internet banking password expires today. Reset it now using the secure link {url} to keep your account active."),
    ("bank", "ATTENTION {bank} customer! Your account is under review for suspicious activity. Submit your account number, PIN and registered email at {url} within {deadline}."),

    # ---- UPI / wallet ----------------------------------------------------
    ("upi", "Your {wallet} KYC is pending. Complete verification within {deadline} or your wallet balance of {amount} will be frozen. Verify: {url}"),
    ("upi", "You have received {amount} in your {wallet} wallet. Accept the payment by entering your UPI PIN here: {url}"),
    ("upi", "{wallet} refund of {amount} is pending. Scan the QR code or click {url} and enter your UPI PIN to receive the amount."),
    ("upi", "Dear user, your UPI ID will be deactivated by NPCI within {deadline}. Re-register your VPA immediately at {url}"),
    ("upi", "Payment request of {amount} pending approval. Approve now by confirming your {wallet} PIN at {url}"),

    # ---- delivery / courier ---------------------------------------------
    ("delivery", "{courier}: Your parcel {tracking} is held at our facility due to an incomplete address. Update your delivery details here {url}"),
    ("delivery", "Your package could not be delivered. Customs duty of {small_amount} is pending. Pay now to release your shipment: {url}"),
    ("delivery", "{courier} Notice: Delivery attempt failed for shipment {tracking}. Reschedule within {deadline} or the parcel will be returned: {url}"),
    ("delivery", "Your order is out for delivery but the shipping address is unclear. Confirm your address and pay {small_amount} redelivery fee at {url}"),
    ("delivery", "Parcel on hold! {courier} requires address confirmation for {tracking}. Verify here {url}"),

    # ---- prize / lottery ------------------------------------------------
    ("prize", "Congratulations! You have won {prize} in the {shop} anniversary lucky draw. Claim your prize within {deadline} at {url}"),
    ("prize", "Dear winner, your mobile number has been selected for {prize}. Send your name, address and bank account details to claim."),
    ("prize", "You are today's lucky winner of {prize}! Pay a small processing fee of {small_amount} to release your reward: {url}"),
    ("prize", "CONGRATULATIONS!!! Your number won {prize} in the {telecom} customer bonanza. Reply with your Aadhaar and bank details to claim now."),
    ("prize", "{shop} Spin & Win: You have won {prize}. Claim before {deadline}, only 2 gifts left! {url}"),
    ("prize", "Your KBC lottery ticket has won {prize}. Contact our claim officer on WhatsApp immediately to process your winnings."),

    # ---- job scams ------------------------------------------------------
    ("job", "Hi, we found your resume. {company} is hiring {job} for work from home, salary {amount} per month, no interview required. Register at {url} with a refundable fee of {small_amount}."),
    ("job", "Congratulations, you are shortlisted for {job} at {company}. Pay a registration fee of {small_amount} to confirm your offer letter: {url}"),
    ("job", "Part time job available! Earn {small_amount} daily by liking videos, only 1 hour work. Contact us on WhatsApp to start today."),
    ("job", "Dear candidate, your offer letter for {job} is ready. Share your Aadhaar, PAN and bank account details on WhatsApp to complete onboarding."),
    ("job", "Work from home opportunity: complete simple hotel review tasks and earn {amount} weekly. Join our Telegram group: {url}"),

    # ---- tech support ---------------------------------------------------
    ("techsupport", "Microsoft Security Alert: your computer is infected with 3 viruses. Call our certified technician on {phone} immediately or your files will be deleted."),
    ("techsupport", "Your {tech} subscription auto-renewal of {amount} has been processed. To cancel this charge, call {phone} within {deadline}."),
    ("techsupport", "Warning: unusual activity detected on your device. Install our support tool from {url} so our engineer can fix the problem remotely."),
    ("techsupport", "Your antivirus licence expired {deadline} ago and your data is at risk. Renew now at {url} to stay protected."),
    ("techsupport", "ERROR CODE 0x{code}: Windows Defender has blocked access to your system. Contact support at {phone} to unlock your PC."),

    # ---- BEC / invoice fraud --------------------------------------------
    ("bec", "Hi {name}, are you at your desk? I need you to process an urgent transfer of {amount} to a new vendor today. Keep this confidential until it is done. Sent from my iPhone"),
    ("bec", "{name}, please update the bank account details for {company} in our records. The new account is provided below. Process the pending invoice of {amount} immediately."),
    ("bec", "Dear {department} team, our supplier has changed their beneficiary bank account. Kindly remit the outstanding payment of {amount} to the new account today. Do not discuss this with anyone else."),
    ("bec", "Hello, I am in a meeting and cannot talk right now. I need you to purchase {small_amount} worth of gift cards for a client and send me the codes urgently."),
    ("bec", "Please find attached the revised invoice {tracking} for {amount}. Note our updated banking details and process payment before {deadline} to avoid service interruption. {url}"),
    ("bec", "{name}, kindly share the payroll details and salary account numbers of all employees. This is required urgently for an audit. Treat as strictly confidential."),

    # ---- government / tax -----------------------------------------------
    ("govt", "{govt} Notice: Your income tax refund of {amount} is approved. Submit your bank account and IFSC details at {url} within {deadline} to receive the refund."),
    ("govt", "Your Aadhaar has been linked to a suspicious transaction. Verify your Aadhaar number and OTP at {url} or your Aadhaar will be suspended."),
    ("govt", "{govt}: A penalty notice has been issued against your PAN. Pay {amount} within {deadline} to avoid prosecution. Payment link: {url}"),
    ("govt", "EPFO Alert: Your PF withdrawal of {amount} is on hold. Update your UAN KYC with Aadhaar and bank details here {url}"),
    ("govt", "Traffic violation challan of {small_amount} pending against your vehicle. Pay online within {deadline} to avoid court summons: {url}"),

    # ---- credential harvesting on tech accounts -------------------------
    ("credential", "{tech} security alert: someone signed in to your account from a {device}. If this wasn't you, verify your identity now: {url}"),
    ("credential", "Your {tech} password will expire in {deadline}. Click {url} to keep your current password and avoid losing access to your mailbox."),
    ("credential", "Your mailbox storage is full and incoming messages are being rejected. Re-validate your email account here to restore delivery: {url}"),
    ("credential", "{tech} Notice: your account has been flagged for a policy violation and will be permanently deleted. Appeal within {deadline} at {url}"),
    ("credential", "Shared document: {name} has shared \"Q4 Payroll Review\" with you. Sign in with your work email to view the file: {url}"),
    ("credential", "Your {tech} subscription payment failed. Update your billing information within {deadline} to avoid cancellation: {url}"),

    # ---- crypto / investment --------------------------------------------
    ("crypto", "{crypto} Alert: your withdrawal request of {amount} is pending confirmation. Verify your wallet by entering your seed phrase at {url}"),
    ("crypto", "Guaranteed 20% monthly returns on crypto investment, risk free. Start with just {small_amount} today. Join our Telegram channel for signals."),
    ("crypto", "Double your Bitcoin in 24 hours! Send BTC to the address below and receive twice the amount instantly. Limited slots available."),
    ("crypto", "Your {crypto} account has been restricted due to unusual activity. Complete identity verification within {deadline}: {url}"),

    # ---- romance / emotional / charity ----------------------------------
    ("emotional", "My dear friend, I am {name}, a widow diagnosed with cancer. I wish to donate {amount} to charity through you. Please reply with your bank details. Keep this confidential."),
    ("emotional", "Hello dearest one, I am stranded in {city} and lost my wallet. Please help me with {small_amount}, I will return it as soon as I reach home."),
    ("emotional", "I am the next of kin to an unclaimed estate of {amount} left by late Mr. {surname}. Contact me privately to share this inheritance. Strictly confidential."),
    ("emotional", "Urgent help needed! My daughter's surgery costs {amount} and we are short of funds. Please donate through the link and God bless you: {url}"),

    # ---- telecom / subscription -----------------------------------------
    ("telecom", "{telecom}: Your SIM will be deactivated within {deadline} as your e-KYC is incomplete. Re-verify your SIM now: {url}"),
    ("telecom", "Your {telecom} number has won a free 5G upgrade with {prize}. Claim your gift by confirming your details at {url}"),
    ("telecom", "Dear customer, your mobile number will be disconnected today under new TRAI rules. Call {phone} immediately to keep your number active."),
    ("telecom", "Your {tech} account will be closed for non-payment of {small_amount}. Pay now to continue your subscription: {url}"),

    # ---- shopping / refund ----------------------------------------------
    ("shopping", "{shop}: Your order of {small_amount} could not be processed. Update your payment method within {deadline} or the order will be cancelled: {url}"),
    ("shopping", "Refund of {small_amount} for your cancelled {shop} order is pending. Claim the refund by entering your card details here: {url}"),
    ("shopping", "Your {shop} account has been suspended after multiple failed logins. Restore access immediately: {url}"),
    ("shopping", "Congratulations, your {shop} loyalty points worth {small_amount} expire {deadline}. Redeem instantly at {url}"),

    # ---- deliberately subtle: no threats, no shouting, no deadline -------
    # These exist so the model cannot equate "phishing" with "alarming words".
    ("bec", "Hi {name}, quick one - can you confirm the bank details we have on file for {company}? I want to release the payment of {amount} before I leave today."),
    ("bec", "Hello {name}, I have approved the invoice from {company}. Their accounts team says the old account is closed, so please use the details in the attachment for this payment."),
    ("credential", "{name} shared a document with you: \"{department} Budget FY26\". Sign in to view it: {url}"),
    ("credential", "You have one new voicemail message of 47 seconds. Listen online: {url}"),
    ("credential", "A document is waiting for your signature. Review and sign: {url}"),
    ("delivery", "Address confirmation required for parcel {tracking}. {url}"),
    ("shopping", "Your invoice for {small_amount} is attached. View statement: {url}"),
    ("job", "Hi {name}, I came across your profile and I think you would be a good fit for a {job} role at {company}. Are you open to a conversation? You can register your interest here: {url}"),

    # ---- attack families that dominate Indian fraud reporting ------------
    # Added after the gold set exposed gaps: voice-phishing scripts delivered
    # over chat, QR collect-request fraud, sideloaded APK banking malware and
    # chain-forwarded charity appeals. See the README note on evaluation bias.
    ("vishing", "This is {name} calling from the {bank} fraud department. We have detected a fraudulent transaction of {amount} on your account. To block it, please share the OTP you just received."),
    ("vishing", "Sir, I am from {wallet} customer care. Your account shows a pending refund of {small_amount}. Please tell me the 6 digit code sent to your phone so I can process it."),
    ("vishing", "Madam, your {bank} account will be closed today. I am your branch manager, please confirm your card number and the CVV printed on the back so I can stop the closure."),
    ("qr-fraud", "Scan this QR code to receive your {small_amount} cashback from {wallet}. Offer valid for the next 30 minutes only."),
    ("qr-fraud", "To collect the refund of {small_amount}, scan the QR code below and enter your UPI PIN. The amount will be credited instantly."),
    ("malware", "Your mobile banking app version is outdated and unsafe. Install the updated APK from the link below to continue using net banking: {url}"),
    ("malware", "{bank} has launched a new secure app. Download and install it from {url} within {deadline}, the old app will stop working."),
    ("charity", "Urgent appeal: floods in our district have displaced 4,000 families. Donate any amount through the UPI ID below and God will bless you. Please forward this message to 10 groups."),
    ("charity", "A child needs an urgent operation costing {amount}. Every rupee helps. Send to the number below and share with as many groups as you can."),
    ("grooming", "Hi, sorry to bother you, I got your number from a mutual contact. I run a small crypto trading group and my students made 38 percent last month. Would you like free signals for one week?"),
    ("grooming", "Hello, is this {name}? I think I have the wrong number, but you seem nice. I am an investment analyst in {city}, do you trade at all?"),
    ("bank", "Your bank account has been marked dormant. To reactivate it, log in through the link and re-enter your registered mobile number, date of birth and net banking password: {url}"),
    ("bank", "We overcharged you {small_amount} on your last transaction. To receive the refund, confirm your card number and CVV on our secure refund page: {url}"),
    ("reward", "Your credit card reward points worth {small_amount} expire tonight. Redeem them now by verifying your card and the OTP sent to your phone."),
    ("utility-fraud", "Your electricity connection will be disconnected tonight at {time} because your previous bill was not updated. Contact our officer on {phone} immediately to avoid disconnection."),
    ("utility-fraud", "Dear consumer, your electricity bill of {small_amount} is unpaid and the meter will be removed today. Pay now on {phone} through the officer to avoid disconnection."),
]

LEGIT_TEMPLATES: list[tuple[str, str]] = [
    # ---- genuine transactional codes (hard negatives) -------------------
    ("otp", "{code} is your OTP to log in to your {bank} account. Valid for 10 minutes. Do not share this OTP with anyone. -{bank}"),
    ("otp", "Use OTP {code} to complete your {wallet} transaction of {small_amount}. Never share your OTP with anyone, including {wallet} staff."),
    ("otp", "Your verification code is {code}. It expires in 5 minutes. If you did not request this code, you can safely ignore this message."),
    ("otp", "{code} is your one time password for {shop} login. Do not share it with anyone."),
    ("otp", "Your {tech} verification code is {code}. Never share this code with anyone. If you did not request it, please secure your account from your settings page."),

    # ---- genuine bank statements / transaction alerts -------------------
    ("bank", "Dear customer, {small_amount} has been debited from your {bank} account ending {card4} on {date} at {time} towards a UPI payment. Available balance is {amount}."),
    ("bank", "{bank}: Your salary of {amount} has been credited to your account ending {card4} on {date}. View details in the mobile app."),
    ("bank", "Your {bank} credit card statement for {date} is ready. Total due {small_amount}, minimum due {small_amount}. Please pay by the due date to avoid charges."),
    ("bank", "Thank you for banking with {bank}. Your fixed deposit of {amount} has been booked for 24 months at 7.1% per annum. Reference number {tracking}."),
    ("bank", "{bank} reminder: your credit card payment of {small_amount} is due on {date}. You can pay through the {bank} app or net banking."),
    ("bank", "Your cheque number {code} for {small_amount} has been cleared from your {bank} account on {date}."),

    # ---- genuine security notices (hard negatives) ----------------------
    ("security", "New sign-in to your {tech} account from a {device} on {date}. If this was you, no action is needed. You can review your recent activity from your account settings."),
    ("security", "Your {tech} password was changed successfully on {date} at {time}. If you did not make this change, please reset your password from the app."),
    ("security", "Two-factor authentication was enabled on your {tech} account. Recovery codes are available in your security settings."),
    ("security", "We are writing to let you know that we updated our privacy policy on {date}. No action is required from you. You can read the full policy in the help centre."),

    # ---- genuine delivery updates (hard negatives) ----------------------
    ("delivery", "Your {shop} order {tracking} has been shipped via {courier} and will arrive by {date}. Track it in the {shop} app under My Orders."),
    ("delivery", "{courier}: Shipment {tracking} is out for delivery today and will reach you between {time} and {time}. Our delivery partner will call you."),
    ("delivery", "Your {shop} order {tracking} was delivered on {date} at {time}. Rate your experience in the app."),
    ("delivery", "Your return for order {tracking} has been picked up. The refund of {small_amount} will be credited to your original payment method in 3 to 5 business days."),
    ("delivery", "Delivery update: your parcel {tracking} is delayed due to heavy rain in {city} and will now arrive by {date}. We are sorry for the inconvenience."),

    # ---- workplace / internal mail --------------------------------------
    ("work", "Hi {name}, sharing the minutes of today's sprint review. Action items are assigned in the tracker and the next review is on {date} at {time}. Regards, {surname}"),
    ("work", "Team, the {department} monthly report has been uploaded to the shared drive. Please add your comments before {date}."),
    ("work", "Hi {name}, could you review my pull request when you get a chance? I have addressed the comments on the caching layer and added tests."),
    ("work", "Reminder: the {department} town hall is scheduled for {date} at {time} in the {city} office. Joining details are in the calendar invite."),
    ("work", "Hello {name}, please find the approved purchase order attached. The vendor has been informed and delivery is expected by {date}."),
    ("work", "{company} HR announcement: the appraisal cycle opens on {date}. Please complete your self assessment in the HR portal before the deadline."),
    ("work", "Hi {surname}, the client has approved the proposal. I will schedule a kickoff call on {date} and share the agenda in advance."),
    ("work", "Hi {name}, I have moved our one-on-one from {time} to {time} because of a conflict. Let me know if that works for you."),

    # ---- legitimate service / product mail -----------------------------
    ("service", "Your {tech} subscription renews on {date} for {small_amount}. You can review or cancel your plan any time from your account settings. Manage preferences or unsubscribe below."),
    ("service", "Thanks for signing up for {company}. Your workspace is ready at {url}. Our getting started guide walks you through the first steps."),
    ("service", "Invoice {tracking} for {small_amount} is attached for the billing period ending {date}. Payment has already been collected from your saved card. No action is needed."),
    ("service", "Your monthly usage report is ready. You used 62% of your plan this cycle. View the breakdown in your dashboard at {url}. Unsubscribe from usage emails in preferences."),
    ("service", "We have received your support request {tracking} about login issues. Our team will respond within one business day. You can add details by replying to this email."),
    ("service", "Your ticket {tracking} has been resolved. If the issue reappears, reply to this email and we will reopen it. Thank you for your patience."),
    ("service", "Your {shop} order {tracking} for {small_amount} is confirmed. Expected delivery is {date}. Invoice is available in your account under Orders."),

    # ---- education / community -----------------------------------------
    ("education", "Dear student, the semester examination timetable for {date} has been published on the college portal. Please check your registered subjects and report any discrepancy to the exam cell."),
    ("education", "Registration for the {city} hackathon closes on {date}. Team size is 4 to 6 members. Details and rules are available at {url}."),
    ("education", "Your certificate for the Machine Learning course is ready. You can download it from your dashboard at {url}."),
    ("education", "The guest lecture on network security has been rescheduled to {date} at {time} in Seminar Hall 2. Attendance is optional."),
    ("education", "Library notice: the book you borrowed is due for return on {date}. You can renew it once from the library portal."),

    # ---- travel / bookings ---------------------------------------------
    ("travel", "Your train ticket is confirmed. PNR {tracking}, coach B4, seat 32, departing {city} on {date} at {time}. Carry a valid photo ID during the journey."),
    ("travel", "Booking confirmed: 2 seats for the {time} show on {date} in {city}. Show this message or the QR code in the app at the entrance."),
    ("travel", "Your flight from {city} scheduled on {date} at {time} is on time. Web check-in opens 48 hours before departure in the app."),
    ("travel", "Your cab is arriving in 3 minutes. Driver {name}, vehicle number MH 12 {code}. Fare estimate {small_amount}."),
    ("travel", "Your hotel booking in {city} for {date} is confirmed. Check-in is from {time}. The booking reference is {tracking}."),

    # ---- utilities / genuine payment reminders -------------------------
    ("utility", "Your electricity bill of {small_amount} for the billing period ending {date} is generated. Due date is {date}. Pay through the official app or authorised centres."),
    ("utility", "{telecom}: Your monthly plan of {small_amount} has been renewed successfully. Your next billing date is {date}. Data balance is 45 GB."),
    ("utility", "Your gas connection service request {tracking} has been registered. A technician will visit on {date} between {time} and {time}."),
    ("utility", "Your insurance premium of {small_amount} for policy {tracking} was received on {date}. The renewal receipt is available in your account."),

    # ---- personal / social ---------------------------------------------
    ("personal", "Hey {name}, are we still meeting at {time} tomorrow? I can reach the {city} cafe a little early if that helps."),
    ("personal", "Happy birthday {name}! Hope you have a great year ahead. Let us plan dinner this weekend."),
    ("personal", "Hi, I have sent you the photos from the trip on the shared album. Let me know if you want the raw files as well."),
    ("personal", "{name}, thanks for helping with the move yesterday. I owe you a coffee. See you at practice on {date}."),
    ("personal", "Please remind me to submit the form before {date}. I keep forgetting and the portal closes at {time}."),

    # ---- newsletters ---------------------------------------------------
    ("newsletter", "This week in technology: three articles on distributed systems, a deep dive into vector databases and a reader Q&A. Read online at {url}. Unsubscribe any time from the link in the footer."),
    ("newsletter", "Weekly digest: 4 pull requests merged, 2 issues closed and 1 release published in repositories you follow. Manage your notification preferences in settings."),
    ("newsletter", "{shop} weekend picks: monsoon essentials, kitchen appliances and a curated deals section. Prices valid till {date}. You are receiving this because you subscribed to updates."),
    ("newsletter", "Your monthly reading summary is here: 6 articles read, 2 saved for later and a new recommendation list based on your interests. Unsubscribe in one click."),

    # ---- deliberately alarming but genuine (hard negatives) --------------
    # Real service mail talks about failed payments, blocked sign-ins and
    # expiring passwords too. If the model treats that vocabulary as proof of
    # phishing, the false-positive target is unreachable.
    ("security", "We detected a sign-in attempt from a new device and blocked it. No action is needed unless you do not recognise the attempt. You can review active devices in your account settings."),
    ("security", "Reminder: your work password expires in 14 days. You can change it from the company portal at {url} or by pressing Ctrl+Alt+Del on your work laptop."),
    ("security", "Your account was locked after five incorrect password attempts and will unlock automatically in 30 minutes. If this was not you, contact the IT helpdesk on the number in the staff directory."),
    ("bank", "For your security, {bank} will never ask for your OTP, PIN, CVV or password over a call, SMS or email. Report suspicious messages to the helpline printed on your card."),
    ("bank", "Your {bank} account will be temporarily unavailable on {date} between {time} and {time} for scheduled maintenance. No action is required from you."),
    ("bank", "We could not process the standing instruction of {small_amount} on your account ending {card4} due to insufficient balance. The bank will retry on {date}."),
    ("service", "Your subscription payment of {small_amount} failed. Please update your card in the app when convenient; we will retry automatically in three days."),
    ("service", "Your account will be scheduled for deletion in 30 days because it has been inactive. Sign in from the app if you would like to keep it."),
    ("utility", "Your {telecom} bill of {small_amount} is overdue. Services may be restricted after {date}. You can pay from the official app or any authorised store."),
    ("delivery", "Delivery of parcel {tracking} failed because nobody was available. The courier will attempt delivery again on {date}. You can also collect it from the {city} hub."),
]

# Decorations are deliberately drawn from the SAME banks for both classes.
# An earlier version gave phishing its own greetings, sign-offs and emoji, and
# the classifier scored a perfect 1.000 by learning "hi" => legitimate. Sharing
# the surface furniture forces the signal to come from the message body.
GREETINGS = ["", "", "", "Dear Customer, ", "Dear User, ", "Hi {name}, ", "Hello {name}, ", "Dear {name}, ",
             "Hi, ", "Attention: ", "IMPORTANT: ", "Dear Sir/Madam, ", "Dear valued customer, ",
             "Notice: ", "Hello, ", "Dear {department} team, "]
SIGNOFFS = ["", "", "", " Team Security.", " Customer Care.", " - Support Team", " Thank you.",
            " This is an automated message, do not reply.", " Regards, Verification Department.",
            " Regards, {name} {surname}", " Thanks, {name}", " - {company} Support",
            " Best regards, {department} Team", " Do not reply to this automated message.",
            " Sent from my iPhone", " -{bank}"]
EMOJI = ["", "", "", "", " 🎁", " ⚠️", " 🔴", " ✅", " 💰", " 🚨", " 📦", " 🙏", " 🎉", " 📩"]
LINK_INTROS = ["More details: ", "", "Link: ", "See ", "Visit ", "Details here: ", "Open ", ""]


def _slot_values() -> dict[str, str]:
    name = random.choice(FIRST_NAMES)
    return {
        "bank": random.choice(BANKS),
        "wallet": random.choice(WALLETS),
        "courier": random.choice(COURIERS),
        "shop": random.choice(SHOPS),
        "tech": random.choice(TECH),
        "govt": random.choice(GOVT),
        "telecom": random.choice(TELECOM),
        "crypto": random.choice(CRYPTO),
        "name": name,
        "surname": random.choice(LAST_NAMES),
        "company": random.choice(COMPANIES),
        "job": random.choice(JOB_TITLES),
        "city": random.choice(CITIES),
        "department": random.choice(DEPARTMENTS),
        "amount": random.choice(AMOUNTS_LARGE),
        "small_amount": random.choice(AMOUNTS_SMALL),
        "prize": random.choice(PRIZES),
        "deadline": random.choice(DEADLINES),
        "tracking": _fill_numbers(random.choice(TRACKING)),
        "code": _fill_numbers(random.choice(CODES)),
        "date": random.choice(DATES),
        "time": random.choice(TIMES),
        "card4": _rand_digits(4),
        "phone": random.choice([f"+91 {_rand_digits(10)}", f"1800-{_rand_digits(3)}-{_rand_digits(4)}",
                                f"0{_rand_digits(3)}-{_rand_digits(7)}"]),
        "device": random.choice(DEVICES).format(city=random.choice(CITIES)),
    }


def _apply_noise(text: str) -> str:
    """Surface-level variation so the model cannot key on template artefacts."""
    if random.random() < 0.12:
        text = text.upper()
    elif random.random() < 0.08:
        text = text.lower()
    if random.random() < 0.10:
        text = text.replace(".", "!", 1)
    if random.random() < 0.08:
        words = text.split()
        if len(words) > 6:
            i = random.randrange(len(words))
            w = words[i]
            if len(w) > 4:
                j = random.randrange(1, len(w) - 1)
                words[i] = w[:j] + w[j + 1:]
            text = " ".join(words)
    if random.random() < 0.07:
        text = text.replace("  ", " ") + random.choice(["!!", "!!!", "..", " ..."])
    return text


def render_message(label: int) -> tuple[str, str]:
    templates = PHISH_TEMPLATES if label == 1 else LEGIT_TEMPLATES
    category, template = random.choice(templates)
    slots = _slot_values()

    body = template
    if "{url}" in body:
        body = body.replace("{url}", make_phishing_url() if label == 1 else make_legit_url())
    body = body.format(**slots)

    greeting = random.choice(GREETINGS).format(**slots)
    signoff = random.choice(SIGNOFFS).format(**slots)
    emoji = random.choice(EMOJI) if random.random() < 0.3 else ""

    # Links are attached to both classes with the same phrasing and a similar
    # rate, so "contains a link" cannot become a shortcut for the label. What
    # differs is the *kind* of link, which is exactly what should be learned.
    if "{url}" not in template and random.random() < 0.22:
        body = f"{body} {random.choice(LINK_INTROS)}{make_phishing_url() if label == 1 else make_legit_url()}".replace("  ", " ")

    text = f"{greeting}{body}{signoff}{emoji}".strip()
    return _apply_noise(text), category


def build_message_corpus(count: int) -> list[tuple[str, int, str, str]]:
    rows: list[tuple[str, int, str, str]] = []
    seen: set[str] = set()
    attempts = 0
    target_each = count // 2
    counts = {0: 0, 1: 0}
    while (counts[0] < target_each or counts[1] < target_each) and attempts < count * 40:
        attempts += 1
        label = 1 if counts[1] <= counts[0] else 0
        text, category = render_message(label)
        key = text.lower().strip()
        if key in seen or len(key) < 20:
            continue
        seen.add(key)
        counts[label] += 1
        channel = "sms" if len(text) < 200 else "email"
        rows.append((text, label, category, channel))
    random.shuffle(rows)
    return rows


def build_url_corpus(count: int) -> list[tuple[str, int, str]]:
    rows: list[tuple[str, int, str]] = []
    seen: set[str] = set()
    attempts = 0
    target_each = count // 2
    counts = {0: 0, 1: 0}
    while (counts[0] < target_each or counts[1] < target_each) and attempts < count * 40:
        attempts += 1
        label = 1 if counts[1] <= counts[0] else 0
        url = make_phishing_url() if label == 1 else make_legit_url()
        if url in seen:
            continue
        seen.add(url)
        counts[label] += 1
        rows.append((url, label, "phishing" if label else "legitimate"))
    random.shuffle(rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate the PhishGuard training corpus")
    parser.add_argument("--messages", type=int, default=7000, help="number of messages (balanced)")
    parser.add_argument("--urls", type=int, default=9000, help="number of URLs (balanced)")
    parser.add_argument("--seed", type=int, default=RANDOM_SEED)
    parser.add_argument("--out", type=Path, default=DATA_DIR)
    args = parser.parse_args()

    random.seed(args.seed)
    args.out.mkdir(parents=True, exist_ok=True)

    messages = build_message_corpus(args.messages)
    urls = build_url_corpus(args.urls)

    message_path = args.out / "messages.csv"
    with message_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["text", "label", "category", "channel"])
        writer.writerows(messages)

    url_path = args.out / "urls.csv"
    with url_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label", "kind"])
        writer.writerows(urls)

    phish_msgs = sum(1 for r in messages if r[1] == 1)
    phish_urls = sum(1 for r in urls if r[1] == 1)
    print(f"messages : {len(messages):>6}  ({phish_msgs} phishing / {len(messages) - phish_msgs} legitimate)  -> {message_path}")
    print(f"urls     : {len(urls):>6}  ({phish_urls} phishing / {len(urls) - phish_urls} legitimate)  -> {url_path}")
    categories = {}
    for _, label, category, _ in messages:
        categories.setdefault(category, [0, 0])[label] += 1
    print("\nmessage categories (legit/phish):")
    for category, (legit, phish) in sorted(categories.items()):
        print(f"  {category:<12} {legit:>5} / {phish:>5}")


if __name__ == "__main__":
    main()
