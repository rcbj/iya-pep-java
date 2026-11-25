# iya-pep-java

The shared embedded PEP package (`iya-pep`, `com.iyasec:iya-pep`) for the Java authentication libraries. The design and decisions are on rcbj/iya-sts#1206, decisions D1–D4. This is the Java counterpart of `iya-pep-rust`.

- **It knows no sign-in protocol.** A library adapts its own identity into the package's subject, verifies its SET stream, and checks that the PEP key differs from its own keys. The package exposes its key's JWK thumbprint for that check.
- **`sts-xacml` in iya-sts is the reference engine.** The local engine must give the same decision on every case of the versioned conformance corpus (rcbj/iya-sts#2024), pinned in `src/test/resources/corpus/`. Never edit the corpus. A newer one is taken deliberately: update `PROVENANCE.md` and the two constants in the corpus test.
- **Both modes give one answer.** `authzen` maps an evaluation through the realm's catalogue exactly as the service does, held to `src/test/resources/authzen/authzen_cases.json`. A catalogue-undeclared subject property is never sent, so `central` pulls the catalogue too.
- **Fail closed, and every failure is a 403.** With no policy held, the service unreachable or answering badly in `central` mode, or a fault while deciding, the answer is `Unavailable`, never a Permit. `Decision.httpStatus()` is 200 for a Permit and 403 for everything else. A failed evaluation or heartbeat drops `central`'s cached Permits until the service answers again. An Indeterminate over a missing attribute is a Deny; over a processing or syntax error, `Unavailable`. A Permit carrying an obligation the host did not declare is a Deny.
- **The engine's public types are a contract** with `local` and `authzen` (`com.iyasec.pep.engine`).
- **Tests run in the container:** `docker build --target test .`. Do not run Maven on the host. Bytecode is 17. The image is `maven:3.9-eclipse-temurin-26`.
- **Commits:** author `rcbjBlueMars <9321971+rcbjBlueMars@users.noreply.github.com>`, no Co-Authored-By trailer.
- **Branches:** work lands on `develop`. `main` is the released branch. There is no publish workflow yet. Add one, as in `oidc-caep-risc-java`, with the first release. Do not merge to `main` until that release is intended: a later library that depends on a published coordinate cannot take a git pin the way the Rust crates did.
