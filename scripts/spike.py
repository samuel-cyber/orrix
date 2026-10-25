"""Orrix sandbox spike. UNTESTED against PayPal. Sandbox only.
Setup:  pip install requests python-dotenv
.env (git-ignored) must contain:
  PAYPAL_CLIENT_ID=...
  PAYPAL_CLIENT_SECRET=...
Usage:
  python spike.py token
  python spike.py list
  python spike.py get <DISPUTE_ID>
  python spike.py evidence <DISPUTE_ID> <CARRIER> <TRACKING_NUMBER>
  python spike.py get <DISPUTE_ID>      # run again: is the evidence visible?
"""
import json, os, sys, requests
from dotenv import load_dotenv
load_dotenv()
BASE = "https://api-m.sandbox.paypal.com"   # sandbox only, never live

def token():
    r = requests.post(f"{BASE}/v1/oauth2/token",
        auth=(os.environ["PAYPAL_CLIENT_ID"], os.environ["PAYPAL_CLIENT_SECRET"]),
        data={"grant_type": "client_credentials"}, timeout=30)
    print("token status", r.status_code)
    if r.status_code != 200:
        print(r.text); sys.exit(1)
    j = r.json()
    print("scopes:", j.get("scope"))   # tells us whether any dispute scope is present
    return j["access_token"]

def hdr(t): return {"Authorization": f"Bearer {t}"}

def show(r):
    print("status", r.status_code, "| debug id:", r.headers.get("Paypal-Debug-Id"))
    try: print(json.dumps(r.json(), indent=2))
    except Exception: print(r.text)

cmd = sys.argv[1] if len(sys.argv) > 1 else "token"
t = token()
if cmd == "list":
    show(requests.get(f"{BASE}/v1/customer/disputes", headers=hdr(t), timeout=30))
elif cmd == "get":
    show(requests.get(f"{BASE}/v1/customer/disputes/{sys.argv[2]}", headers=hdr(t), timeout=30))
elif cmd == "evidence":
    did, carrier, num = sys.argv[2:5]
    body = {"evidences": [{
        "evidence_type": "PROOF_OF_FULFILLMENT",
        "evidence_info": {"tracking_info": [{"carrier_name": carrier, "tracking_number": num}]},
        "notes": "Spike test: tracking submitted via API."}]}
    r = requests.post(f"{BASE}/v1/customer/disputes/{did}/provide-evidence",
        headers=hdr(t), files={"input": (None, json.dumps(body), "application/json")}, timeout=60)
    show(r)
