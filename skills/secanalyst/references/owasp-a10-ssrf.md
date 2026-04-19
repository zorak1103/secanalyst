# A10 — Server-Side Request Forgery (SSRF)

## Problem

SSRF flaws occur whenever a web application fetches a remote resource without validating the user-supplied URL. An attacker can coerce the application to send a crafted request to an unexpected destination — even behind firewalls, VPNs, or network ACLs that would block external access.

Common manifestations:
- Fetching URLs supplied directly by users (`req.query.url`, `req.body.url`, `params[:url]`).
- Image/PDF preview services that fetch remote content and render it.
- Webhook registration that allows any URL.
- Server fetches `metadata.internal` cloud provider metadata endpoints (AWS `169.254.169.254`, GCP `metadata.google.internal`, Azure `169.254.169.254`).
- URL parsing bypasses via `http://attacker.com@internal.host/` or redirect chains.

## Prevention

1. Validate and sanitize all client-supplied input data including URLs.
2. Enforce URL allowlists: only permit expected schemes (https only), expected domains, and expected port ranges.
3. Do not send raw responses from server-side fetches directly to clients.
4. Disable HTTP redirects in the fetch client, or re-validate the redirect destination.
5. Use network segmentation and firewall rules to prevent the server from reaching internal services it shouldn't need.
6. On cloud deployments, require `Metadata-Flavor: Google` or IMDSv2 tokens so the metadata service is not accessible with a plain GET.

## Typical Attack Scenarios

- **Cloud metadata exfiltration**: Attacker supplies `url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` to a webhook or image-preview endpoint. The server fetches the AWS IAM role credentials and returns them in the response.
- **Internal service scan**: Attacker iterates `url=http://10.0.0.1:8080` through `10.0.0.254:8080` to map internal services. Response timing or body differences reveal which hosts are alive.
- **Blind SSRF via DNS**: Attacker supplies a URL pointing to a DNS callback service. The server resolves the domain, leaking the internal IP address in the DNS lookup.

## Detection Patterns (Grep)

Look for server-side HTTP fetch calls where the URL comes from user input:

- HTTP client calls (`fetch(`, `axios.get(`, `requests.get(`, `http.Get(`, `URI.create(`) where the first argument references a request parameter, query string, or body field
- Webhook URL storage without validation: database columns or config fields named `webhook_url`, `callback_url`, `redirect_url` being used directly in HTTP client calls without an allowlist check
- `url.parse(` or `new URL(` followed immediately by an HTTP request without domain validation
- Missing blocklist for private IP ranges: `127.0.0.1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
