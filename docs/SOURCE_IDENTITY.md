# Source identity

The original frozen candidate commit is `133211a2efe88a1403e3d80d6e83007248936359`.
The supplemental package commit is `6c1f71767df24af188fe75900f4ecbc5bd8c9c69`.
The recorded result commit is `cbdc97bbae8ecab66e9008a6622152741c31cb85`.
These identifiers describe provenance; the original research repository is not needed for using this public source.

`SOURCE_PROVENANCE.json` maps every preserved file to its source path and SHA256.
Fourteen algorithm, RTL, and gate sources are copied without byte changes.
The supplemental worker `cases.py` is also copied without byte changes.
`provenance/upstream_source_manifest.json` preserves the original source manifest for comparison.
Files listed there but omitted here are not required by the selected runtime and validation entry.

The two public packaging files inside frozen/ have new identities:

- `verify_source.py` identifies itself as a public packaging verifier.
- `manifest.json` pins the selected files instead of the original complete delivery package.

The verifier retains the original syntax, hash-chain, and storage arithmetic checks.
The preserved run_cloud.py calls its unchanged verify() interface.
Documentation, summary exports, reproduction helpers, and CI are new public-release files.
They do not replace the frozen algorithm implementation.

Original screenshots, operational logs, queues, chat instructions, tool downloads, and research history are omitted.
Validation-only baseline helpers remain because the original development gate imports them.
No target-device or official-acceptance result is added by packaging.

For a report citation, use a fixed commit or the `v1r4-source` release.
The publication record outside the repository records the final public commit and downloaded archive checks.
