# Responsible use

logindesk logs in to websites and signs up for them **for one person, the user running it, from their own machine**. It is not a tool for operating accounts at scale.

## You agree to

- Follow each website's terms of service. Some sites forbid automated access or automated signups; on those sites, don't use logindesk.
- Use logindesk only for accounts that are yours, or that you are authorised to operate.
- Approve each action yourself. The approval popup is the point where you decide.

## The project will not accept

Contributions, issues or feature requests whose purpose is to:
- create accounts in bulk, or rotate identities to evade limits;
- solve, bypass or outsource CAPTCHAs, Turnstile or other bot checks;
- evade a site's automation detection (stealth or fingerprint spoofing);
- remove or weaken the approval step, the site blocklist or the rate limits in official builds;
- operate accounts belonging to other people without their consent.

## Safe defaults in official builds

- Every login, signup, form submit and secret capture needs a fresh approval that names the asking agent.
- A CAPTCHA, SMS code or unknown page is handed to you in the visible browser window. logindesk never solves it.
- Terms-of-service and marketing checkboxes are never ticked for you.
- A site blocklist and a daily signup limit (at most 10) ship turned on.

logindesk is open source, so a fork can remove these defaults. Only official builds from this repository's release channel promise them.

## No warranty

logindesk is provided under the Apache-2.0 licence, without warranty of any kind. You are responsible for how you use it.
