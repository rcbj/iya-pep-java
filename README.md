# iya-pep

The [iya-sts](https://github.com/rcbj/iya-sts) remote Policy Enforcement Point, embedded in a Java application.

It is the shared PEP for the Java authentication libraries: [`oidc-caep-risc`](https://github.com/rcbj/oidc-caep-risc-java), [`saml2-sp`](https://github.com/rcbj/saml2-sp-java), [`wsfed-caep`](https://github.com/rcbj/wsfed-caep-java) and [`gnap-caep-risc`](https://github.com/rcbj/gnap-caep-risc-java). Each library depends on it and enables it from its own configuration, so an application does not normally use this package directly. The design is in [iya-sts #1206](https://github.com/rcbj/iya-sts/issues/1206). The Rust counterpart is [`iya-pep-rust`](https://github.com/rcbj/iya-pep-rust).

## Modes

- **`central`:** every decision is an AuthZEN evaluation (`POST /access/v1/evaluation`) at iya-sts. An optional Permit cache (`permitCacheMs`, at most 60 s) is off by default.
- **`local`:** a lightweight XACML 3.0 engine decides in process. It holds only the bound application's policies (`GET /xacml/pep/policies?scope=bound-application`) and the realm's AuthZEN catalogue. It refreshes them when a `pep-policies-changed` Shared Signals event arrives, at `fallbackPollMs` (5 minutes) otherwise, or at `pollIntervalMs` (15 s) when the host has no signal stream.

Both modes take the same AuthZEN-shaped request and give the same answer. `local` maps an evaluation through the catalogue exactly as the service does, and its engine is held to the service's conformance corpus.

## Use

```java
PepConfig config = new PepConfig("pep-orders", Mode.LOCAL, "/etc/app/pep-key.pem",
        "https://sts.example/realm/shop", "orders");
Pep pep = Pep.create(config);
pep.start();

Subject subject = Subject.user("alice", claims);
Decision decision = pep.decide(subject, Access.of("read", "order", "42"));
int status = decision.httpStatus(); // 200 for a Permit, 403 for anything else

pep.onPolicyEvent(eventPayload);
```

- **The subject** is a claims map the host library builds from its own sign-in. Only the claims the realm's catalogue declares are sent, because the service refuses an evaluation that names any other.
- **`decide` never fails, and every failure is a 403.** No policy held yet, a service that cannot be reached or answers badly, an engine fault, or a failure while deciding is `Unavailable`, never a Permit. `Decision.httpStatus()` is 403 for it as for a Deny (200 only for a Permit).
- **A cached Permit does not outlive an outage.** In `central` mode with `permitCacheMs`, a failed evaluation or a failed heartbeat drops every cached Permit, and none is served until the service answers an evaluation again.
- **Obligations:** a Permit carries only obligations of the types named in `supportedObligations`. Anything else turns the Permit into a Deny.

## The PEP's credential

The PEP has a key of its own: EC P-256, or RSA of 2048 bits or more. With it, the PEP signs an RFC 7523 self-assertion through the `sts-remote-pep` client and gets a DPoP-bound token for each audience: `xacml:pep`, `xacml:pep-audit` and `authzen:evaluate`.

The key is certified, and the PEP bound to its application, with iya-sts's `issue-pep-credential`. `keyThumbprint()` lets the host library refuse a configuration where the PEP's key is one of its own. `reloadKey()` reads a rotated key at once; otherwise the file is checked every 30 s.

## Configuration

`PepConfig.fromJson` reads a library's `pep` section. Members and defaults match the Rust package: `name` and `assertionKey` are required, `mode` defaults to `local`, `clientId` defaults to `sts-remote-pep`, `pollIntervalMs` 15000, `fallbackPollMs` 300000, `heartbeatIntervalMs` 30000, `decisionRecords` true, `permitCacheMs` 0, `signals` false, `timeoutMs` 10000. An unknown member is refused.

## Tests

```sh
docker build --target test .
```

Do not run Maven on the host. Bytecode is 17. The image is `maven:3.9-eclipse-temurin-26`.

## License

MIT, in `LICENSE`. `src/test/resources/corpus/oasis/` is Apache-2.0 (`LICENSES/Apache-2.0.txt`). `src/test/resources/corpus/PROVENANCE.md` says why.
