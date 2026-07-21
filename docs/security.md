# Security notes

DigitDojo Shield is a host-based mitigation tool and must be deployed with the same care as other privileged infrastructure components.

## Hardening practices

- The configuration loader validates required settings, rejects unsafe IPs, and rejects path traversal and malformed bind addresses.
- The API requires a shared token, enforces request-body limits, and uses a tighter client-key based rate limiter.
- The installer writes files with conservative permissions and backs up existing configuration.
- The service is intended for Linux systems and should be operated with least-privilege access.

## Operational guidance

- Prefer a dedicated service account for the daemon when running in a larger environment.
- Rotate API tokens regularly.
- Review logs under /var/log/digitdojo-shield.
- Keep the host kernel and networking stack patched.
