# A03 — Injection

## Problem

Injection flaws occur when hostile data is sent to an interpreter as part of a command or query. Attackers can use injection to manipulate the interpreter into executing unintended commands or accessing data without authorization. This category covers SQL injection, OS command injection, LDAP injection, and arbitrary code execution via dynamic evaluation.

### SQL Injection

User-controlled input concatenated into SQL query strings without parameterization.

```python
# Vulnerable — string concatenation
query = "SELECT * FROM users WHERE email = '" + user_input + "'"
cursor.execute(query)

# Safe — parameterized query
cursor.execute("SELECT * FROM users WHERE email = %s", (user_input,))
```

### OS Command Injection

User-controlled input passed to a shell via `shell=True` or string-building with `os.system`.

```python
# Vulnerable
import os
os.system("ping " + host)            # shell-interprets host value
import subprocess
subprocess.run("ls " + path, shell=True)

# Safe — pass an argument list, no shell involved
subprocess.run(["ping", "-c", "1", host])
subprocess.run(["ls", path])
```

### Arbitrary Code Execution via Dynamic Evaluation

Using `eval()`, `exec()`, or equivalent (Ruby `eval`, PHP `eval`, JS dynamic evaluation) on user-controlled input.

```javascript
// Vulnerable — evaluates arbitrary user-supplied expression
eval(req.query.expr);

// Safe — use a fixed allowlist instead
const OPS = { add: (a, b) => a + b, mul: (a, b) => a * b };
const fn = OPS[req.query.op];
if (!fn) throw new Error("Invalid operation");
```

## Prevention

1. Use parameterized queries / prepared statements for all database interactions.
2. Use ORMs with parameter binding (SQLAlchemy, Hibernate, GORM) correctly — avoid raw query concatenation even within ORMs.
3. Pass argument arrays to subprocess functions; never use `shell=True` with user-controlled data.
4. Avoid `eval`/`exec` on user input entirely; validate against strict allowlists for dynamic dispatch.
5. Apply least-privilege to database accounts (read-only where sufficient, no DDL for application users).

## Typical Attack Scenarios

- **SQLi**: `email = '' OR '1'='1'` — the `WHERE` clause always evaluates true, returning all rows.
- **Blind SQLi**: `' AND (SELECT SUBSTRING(password,1,1) FROM users LIMIT 1)='a'` — boolean-based side channel leaks schema and data one character at a time.
- **OS command injection**: `host=127.0.0.1; cat /etc/passwd` — semicolon terminates the ping command and a second command executes.
- **Template injection**: `{{7*7}}` in a user-supplied template name evaluates server-side, confirming SSTI — escalatable to remote code execution.

## Detection Patterns

Look for the following patterns when scanning source code. These are described as text to avoid confusing scanners; translate to regex as needed.

**SQL concatenation indicators:**
- String quotes followed by `+` adjacent to request/param/body/input/user variable references
- `cursor.execute(` calls where the first argument contains string concatenation rather than a placeholder
- ORM `.raw(` or `.execute(` calls with interpolated variables

**Shell injection indicators:**
- `subprocess.run` / `subprocess.call` / `subprocess.Popen` with `shell=True` alongside untrusted variable input
- `os.system(` calls where the argument is not a string literal
- `os.popen(` or similar with non-literal arguments

**Dynamic eval indicators:**
- `eval(` where the argument references a request/query/body/input/user variable
- `exec(` with non-literal source
- Dynamic function construction from string input

**LDAP injection indicators:**
- LDAP filter strings concatenated with user-controlled values (look for `ldap` in combination with `+` and request variables)
