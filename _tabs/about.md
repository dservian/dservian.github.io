---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

Sysadmin moving into SOC analyst work. This blog is where I publish what I learn doing it.

The main lab is a T-Pot honeypot running on Proxmox, exposed to the internet and pulling in roughly 100k attack events a day across Cowrie, Dionaea, Honeytrap, and Suricata. Posts here pick at that data, build detections from it, and occasionally wander into malware triage or lab-build write-ups.

A few things I try to stick to:

- Every claim has an artifact behind it — a log line, a query, a hash, a screenshot.
- Time windows in UTC, ISO-8601. Sample sizes stated. Confidence calibrated.
- Defender lens. Attacker behavior is interesting because it tells me what to detect.
- IoCs defanged, internals sanitized, no naming individuals.
- If a post is useful to a working SOC analyst, it is doing its job.

If a post is useful to a working SOC analyst, it is doing its job.

> **AI assistance disclosure.** Posts on this site are drafted in collaboration with an AI assistant (Anthropic's Claude). The lab, configuration choices, data, and analysis are mine. The AI is used for structuring, editing, and tightening prose against a style guide I maintain. All technical claims, log excerpts, and screenshots are reviewed and verified by me before publication.
{: .prompt-info }
