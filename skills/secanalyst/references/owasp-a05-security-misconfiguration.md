# A05 — Security Misconfiguration

## Problem

Security misconfiguration is the most commonly seen issue. This is commonly a result of insecure default configurations, incomplete or ad-hoc configurations, open cloud storage, misconfigured HTTP headers, or verbose error messages containing sensitive information.

Common manifestations:
- Default credentials left unchanged (admin/admin, admin/password).
- Debug mode or verbose stack traces enabled in production.
- Unnecessary features, ports, services, or accounts enabled (e.g., default admin consoles exposed).
- Missing security headers: `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, `X-Content-Type-Options`.
- S3 buckets or GCS buckets with public read/write access.
- Directory listing enabled on web server.
- Default exception handlers exposing internal paths, library versions, or database schemas.

## Prevention

1. Establish a repeatable hardening process: minimal install, disable unused features, change default credentials.
2. Use security headers middleware in every web framework (Helmet.js for Node, Django's `SECURE_*` settings, Spring Security headers).
3. Run automated config review tools as part of CI (e.g., `tfsec`, `checkov` for IaC).
4. Separate development and production configuration — debug mode must be disabled in prod environments.
5. Log configuration changes and review cloud resource policies regularly.
6. Return generic error messages to end users; log full details server-side only.

## Typical Attack Scenarios

- An attacker navigates to `/actuator/env` on a Spring Boot app and reads all environment variables including database passwords because the Actuator endpoints were not secured.
- A default Django `DEBUG=True` setting in production causes full stack traces (including source code context and local variable values) to be returned to the browser on any exception.
- An S3 bucket named `mybucket-backups` has `ListBucket` and `GetObject` permissions for `*`, exposing all backups to the public.

## Detection Patterns (Grep)

Search for these in configuration files, environment files, and framework-specific settings:

- `DEBUG = True` or `DEBUG=true` in Python settings files outside of test directories
- `app.debug = True` in Flask
- `RAILS_ENV=development` in production deployment configs
- HTTP header middleware absent from Express apps (look for apps without `helmet`)
- Spring Boot `management.endpoints.web.exposure.include=*` in application properties
- AWS bucket policies containing `"Principal": "*"` with `Allow` effect
- Generic catch-all exception handlers that return full error objects to the HTTP response
