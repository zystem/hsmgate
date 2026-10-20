#!/usr/bin/env bash
# Kubernetes KMS v2 against a real kube-apiserver: hsmgate (software key) + vault-kubernetes-kms on a single-node k3s host, as systemd units.
# Run AS ROOT ON THE K3S NODE. It changes the node: read the steps, run `backup` first, and use it on a test cluster.
#
#   tools/k3s-kms-test.sh preflight          read-only: k3s state, an existing secrets encryption, conflicts
#   tools/k3s-kms-test.sh backup             copies /etc/rancher/k3s and the encryption config to /var/backups/k3s-kms-<time>  (BACKUP_DB=1: the datastore too, k3s is stopped briefly)
#   HSMGATE_BIN=... PLUGIN_BIN=... tools/k3s-kms-test.sh install     binaries, certificates, software key, configuration, two units
#   tools/k3s-kms-test.sh enable             EncryptionConfiguration (kms v2 first, identity second), k3s drop-in, RESTART of k3s
#   tools/k3s-kms-test.sh verify             a Secret is stored as a KMS envelope; health of the KMS provider
#   tools/k3s-kms-test.sh rotate             a second key version in hsmgate (reload), a new Secret is written after the apiserver saw the new key_id
#   tools/k3s-kms-test.sh outage             stops hsmgate for 30 s: the provider must fail its health check and Secret writes must fail, then recover
#   tools/k3s-kms-test.sh disable            identity first, restart, REWRITE every Secret, then remove the provider and the units
#
# Why `disable` rewrites the Secrets: anything written while the provider was first is stored under it and is unreadable without the plug-in.
# The software key is for a test: the cluster's Secrets are sealed under a key in a file on the same node.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root on the k3s node" >&2; exit 1; }

D=/opt/hsmgate-test
SOCK_DIR=/run/hsmgate-kms
SOCK="$SOCK_DIR/kms.sock"
PORT=18443
ENCCFG=/var/lib/rancher/k3s/server/kms-encryption-config.yaml
DROPIN=/etc/rancher/k3s/config.yaml.d/90-hsmgate-kms.yaml
KC="k3s kubectl"
DB=/var/lib/rancher/k3s/server/db

say() { printf '\n== %s\n' "$*"; }

wait_api() {
  for _ in $(seq 1 90); do
    $KC get nodes >/dev/null 2>&1 && return 0
    sleep 2
  done
  echo "the API did not come back in 3 minutes" >&2
  return 1
}

hg() { curl -s --cacert "$D/certs/ca.pem" --cert "$D/certs/kms.pem" --key "$D/certs/kms.key" "https://127.0.0.1:$PORT$1"; }

preflight() {
  say "k3s"; k3s --version | head -1; systemctl is-active k3s || true
  say "existing secrets encryption (a conflict if enabled)"
  if [ -f /var/lib/rancher/k3s/server/cred/encryption-config.json ]; then
    echo "PRESENT: /var/lib/rancher/k3s/server/cred/encryption-config.json"; k3s secrets-encrypt status 2>&1 | head -8 || true
  else
    echo "none"
  fi
  say "k3s config"; ls -la /etc/rancher/k3s /etc/rancher/k3s/config.yaml.d 2>&1 | head -20 || true
  grep -rn "encryption-provider-config\|secrets-encryption" /etc/rancher/k3s 2>/dev/null || echo "no encryption flags in /etc/rancher/k3s"
  say "datastore"; ls -la "$DB" 2>&1 | head || true
  say "tools"; for t in openssl curl systemctl; do if command -v $t >/dev/null; then echo "$t ok"; else echo "$t MISSING"; fi; done
  say "ports and sockets"
  if ss -ltn 2>/dev/null | grep -q ":$PORT "; then echo "port $PORT is taken"; else echo "port $PORT free"; fi
  ls "$SOCK_DIR" 2>&1 | head -2 || true
}

backup() {
  B=/var/backups/k3s-kms-$(date +%Y%m%d-%H%M%S); mkdir -p "$B"; chmod 700 "$B"
  cp -a /etc/rancher/k3s "$B/etc-rancher-k3s"
  if [ -f /var/lib/rancher/k3s/server/cred/encryption-config.json ]; then cp -a /var/lib/rancher/k3s/server/cred/encryption-config.json "$B/"; fi
  if [ "${BACKUP_DB:-0}" = 1 ]; then
    systemctl stop k3s; cp -a "$DB" "$B/db"; systemctl start k3s; wait_api; echo "datastore copied (k3s was stopped for it)"
  else
    echo "datastore NOT copied (BACKUP_DB=1 stops k3s briefly and copies it)"
  fi
  echo "$B" > /var/backups/k3s-kms-last; echo "backup: $B"; ls -la "$B"
}

write_config() { # $1 = number of key versions (1 or 2)
  if [ "$1" = 2 ] && [ ! -f $D/k2.hex ]; then openssl rand -hex 32 | tr -d '\n' > $D/k2.hex; chmod 600 $D/k2.hex; fi
  local keys="m: $D/k1.hex" versions="{token: soft, label: m}"
  if [ "$1" = 2 ]; then keys="m: $D/k1.hex, m2: $D/k2.hex"; versions="{token: soft, label: m}, {token: soft, label: m2}"; fi
  {
    echo "listen: 127.0.0.1:$PORT"
    echo "tls: {cert: $D/certs/srv.pem, key: $D/certs/srv.key, client_ca: $D/certs/ca.pem}"
    echo "audit: {file: $D/audit.log}"
    echo "tokens: [{name: soft, type: soft, keys: {$keys}}]"
    echo "keys:"
    echo "  k8s-etcd: {versions: [$versions], aad: {mode: fixed, fixed: \"k8s-kms/v1|k8s-etcd\"}}"
    echo "clients:"
    echo "  - {name: kube-kms, identity: {cn: kube-kms}, keys: {k8s-etcd: {ops: [encrypt, decrypt], per_minute: 600}}}"
  } > $D/hsmgate.yaml
  chmod 600 $D/hsmgate.yaml
}

mkcert() { # name cn extfile-content   (in the current directory)
  openssl ecparam -name prime256v1 -genkey -noout -out "$1.key" 2>/dev/null
  openssl req -new -key "$1.key" -subj "/CN=$2" -out "$1.csr" 2>/dev/null
  printf '%s\n' "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days 30 -extfile "$1.ext" -out "$1.pem" 2>/dev/null
  rm -f "$1.csr" "$1.ext"
}

install_units() {
  {
    echo "[Unit]"; echo "Description=hsmgate (test, software key)"; echo "After=network.target"
    echo "[Service]"; echo "ExecStart=$D/hsmgate serve -config $D/hsmgate.yaml"; echo 'ExecReload=/bin/kill -HUP $MAINPID'; echo "Restart=on-failure"
    echo "[Install]"; echo "WantedBy=multi-user.target"
  } > /etc/systemd/system/hsmgate-test.service
  {
    echo "[Unit]"; echo "Description=vault-kubernetes-kms against hsmgate (test)"; echo "After=hsmgate-test.service"; echo "Requires=hsmgate-test.service"
    echo "[Service]"
    echo "Environment=VAULT_CACERT=$D/certs/ca.pem VAULT_CLIENT_CERT=$D/certs/kms.pem VAULT_CLIENT_KEY=$D/certs/kms.key"
    echo "ExecStartPre=/bin/mkdir -p $SOCK_DIR"
    echo "ExecStart=$D/vault-kubernetes-kms -auth-method token -token unused -vault-address https://127.0.0.1:$PORT -transit-mount transit -transit-key k8s-etcd -socket unix://$SOCK -force-socket-overwrite -health-port 18444"
    echo "Restart=on-failure"
    echo "[Install]"; echo "WantedBy=multi-user.target"
  } > /etc/systemd/system/vkk-test.service
}

install() {
  : "${HSMGATE_BIN:?path of the hsmgate binary}" "${PLUGIN_BIN:?path of the vault-kubernetes-kms binary}"
  mkdir -p $D/certs; chmod 700 $D
  install -m 0755 "$HSMGATE_BIN" $D/hsmgate; install -m 0755 "$PLUGIN_BIN" $D/vault-kubernetes-kms
  (
    cd $D/certs
    openssl ecparam -name prime256v1 -genkey -noout -out ca.key 2>/dev/null
    openssl req -x509 -new -key ca.key -subj "/CN=hsmgate-test-ca" -days 30 -out ca.pem 2>/dev/null
    mkcert srv hsmgate "$(printf 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth')"
    mkcert kms kube-kms "extendedKeyUsage=clientAuth"
    chmod 600 ./*.key
  )
  if [ ! -f $D/k1.hex ]; then openssl rand -hex 32 | tr -d '\n' > $D/k1.hex; chmod 600 $D/k1.hex; fi
  write_config 1
  install_units
  systemctl daemon-reload; systemctl enable --now hsmgate-test.service; sleep 2; systemctl enable --now vkk-test.service; sleep 3
  say "units"; systemctl is-active hsmgate-test vkk-test
  ls -la "$SOCK" || { journalctl -u vkk-test -n 15 --no-pager; exit 1; }
  say "hsmgate answers the plug-in's client certificate"; hg /v1/transit/keys/k8s-etcd | head -c 300; echo
}

enc_config() { # $1 = kms-first | identity-first
  local kms="- kms: {apiVersion: v2, name: hsmgate, endpoint: \"unix://$SOCK\", timeout: 10s}" idn="- identity: {}" first second
  if [ "$1" = kms-first ]; then first=$kms; second=$idn; else first=$idn; second=$kms; fi
  {
    echo "apiVersion: apiserver.config.k8s.io/v1"; echo "kind: EncryptionConfiguration"
    echo "resources:"; echo "  - resources: [secrets]"; echo "    providers:"; echo "      $first"; echo "      $second"
  } > $ENCCFG
  chmod 600 $ENCCFG
}

enable() {
  [ -S "$SOCK" ] || { echo "no plug-in socket $SOCK: run install first" >&2; exit 1; }
  if [ -f /var/lib/rancher/k3s/server/cred/encryption-config.json ]; then echo "k3s secrets-encryption is on: this would conflict. Stop." >&2; exit 1; fi
  enc_config kms-first
  mkdir -p /etc/rancher/k3s/config.yaml.d
  printf 'kube-apiserver-arg+:\n  - "encryption-provider-config=%s"\n' "$ENCCFG" > $DROPIN
  say "restarting k3s (the API is down for about a minute; running pods keep running)"
  systemctl restart k3s; wait_api; $KC get nodes
}

verify() {
  say "provider health"; $KC get --raw='/healthz?verbose' 2>&1 | grep -i "kms" || echo "no kms line in /healthz?verbose"
  $KC create namespace kms-test --dry-run=client -o yaml | $KC apply -f - >/dev/null
  n=kms-probe-$(date +%s); $KC -n kms-test create secret generic "$n" --from-literal=plain="ThisIsPlainText-$$" >/dev/null
  say "read back through the API"; $KC -n kms-test get secret "$n" -o jsonpath='{.data.plain}' | base64 -d; echo
  say "what is stored in the datastore"
  # shellcheck disable=SC2086
  if grep -aq "ThisIsPlainText-$$" $DB/state.db* 2>/dev/null; then echo "FAIL: the plaintext is in the datastore"; exit 1; else echo "the plaintext is not in the datastore"; fi
  # shellcheck disable=SC2086
  if grep -aq "k8s:enc:kms:v2:hsmgate" $DB/state.db* 2>/dev/null; then echo "OK: a 'k8s:enc:kms:v2:hsmgate' envelope is stored"; else echo "no KMS envelope found (check the apiserver log)"; exit 1; fi
  say "hsmgate audit (last lines)"; tail -4 $D/audit.log | cut -c1-200
}

rotate() {
  write_config 2; systemctl reload hsmgate-test; sleep 2
  say "key versions now"; hg /v1/transit/keys/k8s-etcd | grep -o '"latest_version":[0-9]*' || true
  echo "waiting 75 s: the apiserver polls the plug-in's Status about once a minute"; sleep 75
  n=kms-rot-$(date +%s); $KC -n kms-test create secret generic "$n" --from-literal=plain="rotated-$$" >/dev/null
  $KC -n kms-test get secret "$n" -o jsonpath='{.data.plain}' | base64 -d; echo
  say "the Secrets written under the first key still open"; $KC -n kms-test get secrets -o name
  say "hsmgate audit (last lines)"; tail -6 $D/audit.log | cut -c1-200
}

outage() {
  say "stopping hsmgate for 30 s"; systemctl stop hsmgate-test; sleep 20
  say "provider health while it is down"; $KC get --raw='/healthz?verbose' 2>&1 | grep -i "kms" || true
  say "a Secret write while it is down (must fail)"
  if $KC -n kms-test create secret generic kms-outage --from-literal=a=b 2>&1; then echo "UNEXPECTED: the write worked"; $KC -n kms-test delete secret kms-outage; else echo "failed as expected"; fi
  systemctl start hsmgate-test; sleep 3; systemctl restart vkk-test; sleep 15
  say "after the restart"; $KC get --raw='/healthz?verbose' 2>&1 | grep -i "kms" || true
  $KC -n kms-test create secret generic kms-after-outage --from-literal=a=b && echo "writes work again"
}

disable() {
  [ -f "$DROPIN" ] || echo "(drop-in not there)"
  enc_config identity-first; systemctl restart k3s; wait_api
  say "rewriting every Secret so that none stays under the provider"
  $KC get secrets -A -o json | $KC replace -f - >/dev/null
  rm -f "$DROPIN" "$ENCCFG"; systemctl restart k3s; wait_api; $KC get nodes
  say "stopping the units"
  systemctl disable --now vkk-test hsmgate-test
  rm -f /etc/systemd/system/vkk-test.service /etc/systemd/system/hsmgate-test.service; systemctl daemon-reload
  $KC delete namespace kms-test --ignore-not-found >/dev/null
  echo "done; $D is left for you to remove"
}

case "${1:-}" in
  preflight) preflight ;;
  backup) backup ;;
  install) install ;;
  enable) enable ;;
  verify) verify ;;
  rotate) rotate ;;
  outage) outage ;;
  disable) disable ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
