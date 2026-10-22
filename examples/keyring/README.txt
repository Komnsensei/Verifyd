VERIFYD EXAMPLE KEYRING (VERIFY-ONLY)
=====================================
These are public key records, and the `active` pointer, for the receipts shipped
in examples/. They let you verify those receipts:

    node bin/verifyd.cjs verify "examples/paper.verifyd-receipt.json" --keyring examples/keyring
    node bin/verifyd.cjs verify "examples/Quantum Information Holography and the Born Rule.verifyd-receipt.json" --keyring examples/keyring

There is deliberately no private key here. The key that signed the examples was
generated for this purpose and discarded, so this directory can verify but not
sign. `verifyd audit --keyring examples/keyring` will fail with
PRIVATE_KEY_MISSING, which is the intended behavior.

The receipts are regenerated with the current engine when the policy checks or
receipt format change, and the public half of the new key is committed here
without its private half. Their signatures therefore prove only that the shipped
bytes are unmodified since generation.

To sign your own receipts, create your own keyring: `verifyd keys init`.
Do not treat these example keys as any kind of trust anchor for your own work;
they only prove the shipped files are unmodified since they were generated.
