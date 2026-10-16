# Source artifact

Start with README.md and docs/SOURCE_IDENTITY.md.
The sole candidate is frozen/reference.py with its matching RTL.
Treat frozen/ and cases.py as pinned sources.
Make any algorithm revision in a separately identified version.
Do not overwrite recorded evidence or remove known failures.
The read-only check is python -B tools/verify_release.py.
Run algorithm reproduction, RTL, and proof tools on native Linux.
Do not start a large experiment campaign during a routine source review.
Self-built software tests are not official acceptance or physical-device measurements.
