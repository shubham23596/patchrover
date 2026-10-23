# litellm-1.107.0-compromise

This provisional response pack covers the October 21, 2026 LiteLLM release-pipeline compromise. It evaluates package versions, image tags, and exact published image digests without downloading or executing affected artifacts.

The pack is intentionally provisional because the upstream investigation is ongoing. It expires quickly and must be reviewed, updated, re-signed, or revoked as authoritative information changes.

Two published image identifiers were available only as prefixes in the source excerpt. They are deliberately excluded until authoritative full values are available. Version and tag matches remain affected, and exact digest matching is used only for the fully published digest.

## Synthetic fixtures

- `fixtures/affected`: exact affected Python version and running digest metadata.
- `fixtures/fixed`: explicitly safe version and a synthetic replacement digest.
- `fixtures/drift`: fixed source pin with the affected running digest.

The fixtures contain no package wheel, image layer, executable code, credentials, indicators copied from a real host, exploit, or malware.

