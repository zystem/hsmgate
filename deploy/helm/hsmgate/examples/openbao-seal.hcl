# The seal stanza of OpenBao (auto-unseal through hsmgate). Mount the Secret of the client certificate (<release>-client-openbao made by the chart, or openbao-client-tls of cert-manager.yaml: tls.crt, tls.key, ca.crt)
# into the OpenBao pod at /openbao/tls. hsmgate answers the Transit API of Vault/OpenBao; the key is `openbao-unseal` of values-openbao.yaml.
seal "transit" {
  address         = "https://hsmgate.hsmgate.svc:8443"   # <fullname>.<namespace>.svc: a name in the certificate of the service
  mount_path      = "transit/"                          # the path of the API is /v1/transit/encrypt/<key_name>
  key_name        = "openbao-unseal"
  tls_ca_cert     = "/openbao/tls/ca.crt"
  tls_client_cert = "/openbao/tls/tls.crt"
  tls_client_key  = "/openbao/tls/tls.key"
  # hsmgate takes no token (it decides by the client certificate) and ignores one; if OpenBao asks for a token, give it any value (BAO_TOKEN=unused)
}
