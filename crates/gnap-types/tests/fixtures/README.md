# Packaged test vectors

These files are package-local copies of the repository's canonical fixtures:

- [vectors/deserialization.json](https://github.com/davlgd/gnap/blob/main/vectors/deserialization.json)

They keep tests and examples usable outside a workspace checkout. The package
asset check verifies byte-for-byte equality with the canonical sources. Change
the source and its copies together; do not invent independent fixture variants.
