#!/usr/bin/env python3
"""Send one short prompt to the local Strata server.

Used only for the dry-run demonstration: while this request is in flight the
sleep monitor should report `strata: inference active` and hold the countdown.

    python3 tools/send_strata_prompt.py [path/to/strata-*.json]
"""
import argparse
import json
import time
import urllib.request

ap = argparse.ArgumentParser(description="Send short prompts to the local Strata server (demo).")
ap.add_argument("--config", default="/srv/strata/Strata/strata-iq2_xs.json")
ap.add_argument("--count", type=int, default=1, help="how many requests")
ap.add_argument("--gap", type=float, default=2.0, help="seconds between requests")
ap.add_argument("--max-tokens", type=int, default=200)
ap.add_argument("--prompt", default="Count from 1 to 40, comma separated, nothing else.")
args = ap.parse_args()

cfg = json.load(open(args.config))
key = cfg.get("api_key") or ""
url = f"http://{cfg.get('host', '127.0.0.1')}:{cfg.get('port', 8080)}/v1/chat/completions"
failed = 0
for i in range(1, args.count + 1):
    body = {"model": cfg.get("model_name"),
            "messages": [{"role": "user", "content": args.prompt}],
            "max_tokens": args.max_tokens, "temperature": 0}
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + key},
    )
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            data = json.loads(r.read().decode())
        text = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        print(f"[{i}/{args.count}] ok in {time.time() - t0:.1f}s: {text[:60]!r}", flush=True)
    except Exception as e:  # noqa: BLE001
        failed += 1
        print(f"[{i}/{args.count}] failed after {time.time() - t0:.1f}s: {type(e).__name__}: {e}", flush=True)
    if i < args.count:
        time.sleep(args.gap)
raise SystemExit(1 if failed else 0)
