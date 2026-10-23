import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';

const [version, output, ...artifacts] = process.argv.slice(2);
if (!version || !output || artifacts.length === 0) {
  throw new Error('usage: node generate-release-sbom.mjs <version> <output> <artifact...>');
}

const sha256 = (path) => createHash('sha256').update(readFileSync(path)).digest('hex');
const namespaceSeed = artifacts.map(sha256).join('');
const namespace = createHash('sha256').update(namespaceSeed).digest('hex');
const created = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

const document = {
  spdxVersion: 'SPDX-2.3',
  dataLicense: 'CC0-1.0',
  SPDXID: 'SPDXRef-DOCUMENT',
  name: `PatchRover ${version} release artifacts`,
  documentNamespace: `https://patchrover.dev/spdx/${version}/${namespace}`,
  creationInfo: {
    created,
    creators: ['Tool: PatchRover-release-sbom/1']
  },
  packages: [{
    name: 'patchrover',
    SPDXID: 'SPDXRef-Package-PatchRover',
    versionInfo: version,
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    licenseConcluded: 'Apache-2.0',
    licenseDeclared: 'Apache-2.0',
    copyrightText: 'NOASSERTION',
    externalRefs: [{
      referenceCategory: 'PACKAGE-MANAGER',
      referenceType: 'purl',
      referenceLocator: `pkg:golang/github.com/shubham23596/patchrover@${version.replace(/^v/, '')}`
    }]
  }],
  files: artifacts.map((path, index) => ({
    fileName: basename(path),
    SPDXID: `SPDXRef-Artifact-${index + 1}`,
    checksums: [{ algorithm: 'SHA256', checksumValue: sha256(path) }],
    licenseConcluded: 'NOASSERTION',
    copyrightText: 'NOASSERTION'
  })),
  relationships: artifacts.map((_, index) => ({
    spdxElementId: 'SPDXRef-Package-PatchRover',
    relationshipType: 'CONTAINS',
    relatedSpdxElement: `SPDXRef-Artifact-${index + 1}`
  }))
};

writeFileSync(output, `${JSON.stringify(document, null, 2)}\n`, { mode: 0o644 });
