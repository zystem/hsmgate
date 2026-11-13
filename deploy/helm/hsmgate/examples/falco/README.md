# hsmgate audit into Falco

Falco can check the audit lines of hsmgate with rules (a refused call, a locked token, an unlock attempt). The way in is the `collector` plugin (an HTTP POST listener) and the `json` plugin (reads the fields).

| File | What it is |
|---|---|
| [falco.yaml](falco.yaml) | Falco configuration: no kernel driver, the plugins `collector` and `json`, the rules file |
| [hsmgate_rules.yaml](hsmgate_rules.yaml) | three rules over the fields of [docs/audit-log.md](../../../../docs/audit-log.md) |
| [networkpolicy.yaml](networkpolicy.yaml) | lets only the hsmgate pods reach the collector port (it has no authentication) |
| [vector.yaml](vector.yaml) | Vector: reads the audit file and POSTs every line on its own to the collector |
| [../vector-sidecar-values.yaml](../vector-sidecar-values.yaml) | chart values that run that Vector as a sidecar (`extraContainers`, `extraVolumes`) |

## What was run (2026-11-13, on one machine, in Docker; not in a cluster)

Falco 0.45.2 (`falcosecurity/falco`, with `engine.kind: nodriver` and `HOST_ROOT=/`), the plugins `collector` and `json` from `falcoctl artifact install collector json`, and the three rules.

- One line in one POST: the rule fires and prints the client, key, operation and result.
- **Several lines in one POST, or a JSON array: no event, no error.** The collector takes one JSON object per request.
- Vector 0.61.0 (`timberio/vector:0.61.0-alpine`) with [vector.yaml](vector.yaml) and six lines in an audit file: the lines `forbidden`, `unauthenticated` and `locked` each gave one alert, the `ok` ones none.
- The Fluent Bit sidecar of the chart (`fluentbit.enabled`) was run and reads the file and sends it to an HTTP output, but it **joins lines into one request** (an `[OUTPUT] http` has no "one record per request"), so it does not feed this collector. Use Vector, or send from Fluent Bit to a store (VictoriaLogs, Loki, Elasticsearch) and keep Falco out of it.
- **Not run:** the Falco Helm chart (put the same `load_plugins`, `plugins` and `rules_files` in its values), a cluster, a NetworkPolicy to the port 54827, a high rate of lines.

The collector has no authentication: anyone who can reach the port can send a fake audit line to Falco. Keep it inside the cluster and limit it with a NetworkPolicy ([networkpolicy.yaml](networkpolicy.yaml); not run).
