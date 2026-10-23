# php-2026-rce

This verified response pack covers CVE-2026-109618 and CVE-2026-109619 using the fixed versions published by the PHP project on October 21, 2026.

It deliberately returns `unknown` for PHP 8.1 and older, distribution backports, unversioned artifacts, and unsupported lines unless explicit evidence is supplied. It does not claim that interim configuration mitigations make an installation safe.

## Synthetic fixtures

- `fixtures/affected`: PHP 8.4.26 source and running workload evidence.
- `fixtures/fixed`: PHP 8.4.27 source and running workload evidence.
- `fixtures/drift`: fixed source with an affected running workload.

No exploit, vulnerable binary, or live target is included.

