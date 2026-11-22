with open(r"C:\Projects\cyber-security-awareness-platform\backend\reports\ml\phishing_hybrid_independent_evaluation\compphish_pilot\page.html", encoding="utf-8") as f:
    text = f.read()

import re
matches = re.findall(r'https?://[^\s"\'<>]+', text)
print("Total URLs in page.html:", len(matches))
relevant = [u for u in set(matches) if any(k in u.lower() for k in ["download", "file", "api", "fmbs4kp9wz", "elsevier"])]
for u in sorted(relevant):
    print(" ", u)
