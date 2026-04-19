# A08 — Software and Data Integrity Failures

## Problem

Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. This includes insecure deserialization, unsigned software updates, and CI/CD pipeline compromise.

Common manifestations:
- Deserializing arbitrary class instances from untrusted sources (Java `ObjectInputStream`, Python native serialization, Ruby `Marshal`, PHP `unserialize`).
- Using plugins, libraries, or modules from untrusted repositories.
- An application that is auto-updated without sufficient integrity verification.
- CI/CD pipeline allows code or configuration injection from external contributors.
- Object serialization format (XML, JSON, YAML) used with libraries that execute embedded logic.

## Prevention

1. Use digital signatures or similar mechanisms to verify software or data is from the expected source and hasn't been altered.
2. Ensure libraries and dependencies are consuming trusted repositories.
3. Use software supply chain security tools (e.g., OWASP CycloneDX) to verify that components don't contain known vulnerabilities.
4. Review code and configuration changes before incorporating them in pipelines.
5. Avoid deserializing arbitrary class instances from untrusted data; use allowlists of accepted classes or safer data formats (JSON with schema).
6. Use cryptographic signing for all serialized data that crosses a trust boundary.

## Typical Attack Scenarios

- A Java application deserializes a cookie value using the native Java serialization API. An attacker crafts a gadget chain targeting a library already on the classpath (e.g., Apache Commons Collections) to achieve remote code execution through deserialization.
- A Python app deserializes cached objects stored in Redis using an unsafe binary serialization format. The Redis instance is exposed; an attacker writes a malicious payload that executes arbitrary commands on deserialization.
- A build pipeline downloads a dependency from npm without a lockfile. An attacker publishes a malicious version of a transitive dependency (supply-chain attack). The pipeline builds and ships the compromised code.

## Detection Patterns

- Usages of native deserialization APIs on user-controlled data:
  - Java: `ObjectInputStream`, `readObject()` receiving data from HTTP requests or external queues
  - Python: Unsafe binary deserialization or `yaml.load(` without specifying `Loader=yaml.SafeLoader`
  - Ruby: `Marshal.load(` on untrusted input
  - PHP: `unserialize(` on user-supplied strings
- CI/CD workflow files (`*.yml` in `.github/workflows/`, `.gitlab-ci.yml`) that use `pull_request_target` with untrusted code execution
- Missing `integrity` hash attributes on `<script>` tags (Subresource Integrity)
- npm `package.json` without a corresponding `package-lock.json` (lockfile absent = no integrity pinning)
