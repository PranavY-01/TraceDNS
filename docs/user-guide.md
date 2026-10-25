# TraceDNS User Guide

Welcome! This guide explains what TraceDNS does, why it matters, and how to read its results. No programming knowledge is needed.

---

## What is TraceDNS?

Every domain name (like `example.com`) has public settings stored in the **DNS**, the internet's address book. Some of these settings tell the world where the website lives. Others tell email servers **which messages claiming to come from that domain are genuine**.

TraceDNS reads those public settings and gives you a clear report:

- what records the domain has,
- whether its email-protection settings are present and correctly written,
- and what to do if something needs attention.

Each result shows the exact setting it was based on, so you can see for yourself why TraceDNS said what it said.

## Why does this matter?

Criminals often send emails that *pretend* to come from a trusted company or school. This is called **spoofing**, and it's a common start to phishing scams.

Three settings help email providers spot these fakes:

| Setting | In plain words | An everyday comparison |
|---|---|---|
| **SPF** | A list of the servers allowed to send email for the domain | A guest list at the door |
| **DKIM** | A digital signature on outgoing email, checked using a public key in DNS | A wax seal on a letter |
| **DMARC** | Instructions for what to do with mail that fails the checks: let it through, mark it as suspicious, or reject it | The house rules for anyone not on the list |

When these settings are missing or mistyped, the protection quietly stops working. TraceDNS helps you notice.

## What TraceDNS checks

- **Address and server records**: where the website and mail servers are (A, AAAA, MX, NS, and TXT records).
- **SPF**: whether exactly one SPF record exists, whether it is written correctly, and how strictly it treats unknown senders.
- **DMARC**: whether a DMARC record exists, whether it is written correctly under the current standard (RFC 9989, published 2026), and which policy it sets.
- **DKIM** (optional): whether a DKIM key is published for a *selector* you name, and whether the key is usable and strong enough. A selector is the label of a particular key.

TraceDNS only **reads public information**, the same way any email server does. It does not log in to anything, change anything, or probe for weaknesses.

---

## Getting started

You need **Python 3.11 or newer** installed. Then, in a terminal (PowerShell on Windows, Terminal on macOS or Linux):

**1. Download TraceDNS**

```
git clone https://github.com/PranavY-01/TraceDNS.git
cd TraceDNS
```

**2. Create a private workspace for it**

Windows:

```
python -m venv .venv
.venv\Scripts\Activate.ps1
```

macOS / Linux:

```
python3 -m venv .venv
source .venv/bin/activate
```

**3. Install it**

```
python -m pip install -e .
```

**4. Check it works**

```
tracedns --version
```

You should see `TraceDNS 1.1.0`.

> Next time, you only need to repeat the "activate" line from step 2 before using TraceDNS.

---

## Your first scan

Type `tracedns` on its own to see the welcome screen and a simple menu, or scan a domain directly:

```
tracedns scan example.com
```

TraceDNS shows its progress step by step, then prints:

1. **A table of DNS records**: what the domain publishes.
2. **Assessment cards**: one card per result, each with an explanation, the evidence, and a recommendation.
3. **A summary**: totals at a glance.

### Other things you can try

| What you want | What to type |
|---|---|
| Also check a DKIM key | `tracedns scan example.com --dkim-selector selector1` |
| Only look up records, without the email checks | `tracedns scan example.com --checks none` |
| Only certain record types | `tracedns scan example.com --record A,MX` |
| Save the results to a file | `tracedns scan example.com --json my-report.json` |
| Ask a specific DNS service, such as Cloudflare's | `tracedns scan example.com --nameserver 1.1.1.1` |
| See all options | `tracedns scan --help` |

**Where do I find a DKIM selector?** Open an email sent from the domain and view its full headers ("Show original" or "View source" in most mail apps). Find the line starting `DKIM-Signature` and look for `s=`. The word after it is the selector.

---

## Reading the results

### The result cards

Every card has a label in its top-left corner:

| Label | What it means |
|---|---|
| **PASS** | The basic checks found no problems. |
| **HIGH** | A serious gap. For example, the domain's settings say *anyone* may send email for it. |
| **MEDIUM** | Important protection is missing or broken. For example, there is no DMARC record, or there are two conflicting SPF records. |
| **LOW** | Works, but could be stronger, or a small part is written incorrectly. |
| **INFO** | An observation, often a deliberate choice. Worth knowing, nothing urgent. |
| **ERROR** | TraceDNS couldn't get an answer (for example, the network was slow). This says nothing about the domain itself. Try again. |
| **INCONCLUSIVE** | There wasn't enough information to decide. For example, the domain doesn't exist. |
| **SKIPPED** | The check needed something you didn't provide, such as a DKIM selector. |

Each card also includes:

- **Evidence**: the exact record or answer the result is based on.
- **Recommendation**: a suggested next step.

### The summary

At the bottom, the summary shows:

- **Status**: `completed` means every lookup got an answer. `partial` or `failed` means some lookups didn't, so the picture is incomplete.
- **How many results** passed, needed attention, or couldn't be checked.
- **Severity totals**, from high to info.

## Common results explained

| You see | What it means | What people usually do |
|---|---|---|
| *No SPF record published* | Nothing tells email providers which servers may send for this domain. | Publish an SPF record listing the domain's email services. |
| *Multiple SPF records published* | Two SPF records conflict, so email providers ignore both. | Merge them into one. |
| *SPF policy permits all senders* | The record says every server on the internet is allowed. | Change the ending from `+all` to `-all` or `~all`. |
| *No DMARC record published* | Email providers have no instructions for handling fake mail. | Add a DMARC record, often starting with monitoring (`p=none`). |
| *DMARC policy is monitoring-only* | Fake mail is reported, but not blocked yet. | A normal first stage. Tighten it once reports look healthy. |
| *SPF record exceeds the 10 DNS-lookup limit* | The record points to so many other services that email providers give up checking it. | Remove services you no longer use, or list server addresses directly. |
| *DMARC record uses tags removed by RFC 9989* | The record contains settings (such as `pct`) that the current DMARC standard has retired. | Remove them; use `t=y` to trial a policy instead. |
| *No DKIM record found for the selector* | Nothing is published under that selector name. | Double-check the selector. The domain may use a different one. |
| *DKIM key is revoked* | The key under that selector has been deliberately switched off. | Fine if it's retired. Otherwise, publish the current key. |
| *DKIM RSA key is shorter than 2048 bits* | The signing key is older and weaker than today's recommendation. | Ask your email provider for a 2048-bit key. |

## Good to know

- **TraceDNS reports what is published, not what happens.** It can tell you a policy is set up. It cannot tell you whether a specific email was delivered, or whether a domain has ever been misused.
- **A clean report isn't a guarantee.** TraceDNS performs *basic* checks. It doesn't follow every chain of settings, and it only checks the DKIM selector you give it.
- **Results can change.** DNS settings are updated over time, and different networks can briefly see different answers.
- **Your results stay with you.** Lookups go through your normal internet connection, just like visiting a website. The results aren't uploaded anywhere, and saved reports stay on your computer.

## Using TraceDNS responsibly

Please only check domains that **you own or have permission to assess**. TraceDNS is intended for learning, for looking after your own domains, and for authorized security work.

## Questions

**Is TraceDNS free?** Yes. It is open source under the MIT License.

**Does it change anything on the domain?** No. It only reads public DNS information.

**Why did a check say ERROR?** The lookup didn't get a reply in time, usually because of network trouble. Run the scan again. If it keeps happening, try `--timeout 10` to allow more time.

**Can I use the results in a report?** Yes. Use `--json my-report.json` to save a structured copy you can keep or share.

**Where can I learn more?** The [README](../README.md) has the full feature list. The [architecture notes](architecture.md) and the [developer demo guide](demo-guide.md) go into the technical details.
