# FLAW147 — Security group 0.0.0.0/0 ingress

**Severity:** high · **Tag:** security · CWE-284

## What
A security group that allows ingress from 0.0.0.0/0 exposes the service to the entire internet. Legitimate for public HTTP/HTTPS load balancers; almost never correct for SSH, databases, admin consoles, or internal services. Restrict to a known CIDR, or a load-balancer security group.

## Fix
See the rule description and the detector at `src/rules/tf_wide_ingress.cr`.
