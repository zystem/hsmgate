# Documentation

What hsmgate is, and a one-minute try: [the README](../README.md). The rest, by what you want to do.

## I want to know whether it fits
- [faq.md](faq.md): the questions people ask (hardware, restarts, a lost card, replicas, limits, Kubernetes)
- [architecture.md](architecture.md): the parts and how a call goes through them
- [threat-model.md](threat-model.md): what it protects, from whom, and what it does not
- [compliance.md](compliance.md): FIPS 140-3 mode of the crypto module, algorithms, what is and is not claimed
- [roadmap.md](roadmap.md): what is next, and what was considered and not done

## I install and run it
- **[production.md](production.md): the checklist before it holds real keys** (token, PIN, policy, certificates, network, audit, software, drills)
- [Helm chart](../deploy/helm/hsmgate/README.md) (Kubernetes, software token, for tests and pilots), [systemd unit and Docker](../deploy/), [building.md](building.md)
- [operations.md](operations.md): certificates (`hsmgate ca`), unlock, reload, rotation, spare card, lost card, Docker
- [tokens/smartcard-hsm.md](tokens/smartcard-hsm.md): the SmartCard-HSM
- [cli.md](cli.md): every command and flag (generated from the program, kept equal to it by a test)
- [configuration.md](configuration.md): **every setting and its default**; the smallest file is [deploy/hsmgate.minimal.yaml](../deploy/hsmgate.minimal.yaml), a larger one for a card [deploy/hsmgate.example.yaml](../deploy/hsmgate.example.yaml)
- [audit-log.md](audit-log.md): the audit line, every result word, questions it answers, rotation and shipping
- [key-management.md](key-management.md): keys, versions, changing the algorithms
- [upgrading.md](upgrading.md), [supported-versions.md](supported-versions.md), [verifying-releases.md](verifying-releases.md)

## It does not work
- [troubleshooting.md](troubleshooting.md): a message, what it means, what to do

## I connect a client
- [guides/clients.md](guides/clients.md): recipes (the command line, `curl`, OpenBao, Kubernetes)
- [specs/](specs/README.md): the Transit API ([transit.md](specs/transit.md), [openapi.yaml](../api/openapi.yaml)), Kubernetes KMS v2, the KMS-JSON, gRPC and REST faces, the sealed format
- [guides/kubernetes-pod-secrets.md](guides/kubernetes-pod-secrets.md), [guides/kms-json-clients.md](guides/kms-json-clients.md)

## I check how it is made
- [security-requirements.md](security-requirements.md), [assurance-case.md](assurance-case.md), [security-policies.md](security-policies.md), [long-running-checks.md](long-running-checks.md)
- [transit-face.md](transit-face.md): the design, and what was tried (the "Verified" sections say what was run)
- Records, in date order: [audit-2026-10.md](audit-2026-10.md), [audit-self-2026-10-21.md](audit-self-2026-10-21.md), [audit-response-2026-10-21.md](audit-response-2026-10-21.md), [security-audit-2026-10-21/](security-audit-2026-10-21/), [review.md](review.md); the plan: [project-plan.md](project-plan.md)

## I contribute
- [CONTRIBUTING](../CONTRIBUTING.md), [GOVERNANCE](../GOVERNANCE.md), [releasing.md](releasing.md), [SECURITY](../SECURITY.md), [CODE OF CONDUCT](../CODE_OF_CONDUCT.md)

## What kind of page is it

Pages are written as one of four kinds ([Diátaxis](https://diataxis.fr/)), and a page that mixes them is split when it grows: a reader who looks something up does not want to be taught, and one who is learning does not want a table of every flag.

| Kind | Answers | Pages |
|---|---|---|
| **Tutorial** (learn by doing) | "Show me it works" | [README, "Try it in a minute"](../README.md#try-it-in-a-minute-no-hardware-nothing-to-prepare) |
| **How-to** (do a task) | "How do I ...?" | [production.md](production.md), [operations.md](operations.md), [troubleshooting.md](troubleshooting.md), [guides/](guides/clients.md), [the Helm chart](../deploy/helm/hsmgate/README.md), [upgrading.md](upgrading.md), [verifying-releases.md](verifying-releases.md), [building.md](building.md), [releasing.md](releasing.md) |
| **Reference** (look it up) | "What exactly does X do, and what is its default?" | [cli.md](cli.md), [configuration.md](configuration.md), [audit-log.md](audit-log.md), [specs/](specs/README.md), [openapi.yaml](../api/openapi.yaml) ([as a Swagger page](../api/index.html)), [supported-versions.md](supported-versions.md) |
| **Explanation** (understand why) | "Why is it like this? Is it right for me?" | [faq.md](faq.md), [architecture.md](architecture.md), [threat-model.md](threat-model.md), [compliance.md](compliance.md), [key-management.md](key-management.md), [transit-face.md](transit-face.md), [security-requirements.md](security-requirements.md), [assurance-case.md](assurance-case.md), [roadmap.md](roadmap.md) |

How these pages are written, for someone who adds one: [writing-docs.md](writing-docs.md).
