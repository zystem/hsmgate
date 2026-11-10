# The seal stanza of OpenBao (auto-unseal through hsmgate), for OpenBao in ANOTHER cluster than hsmgate: the address is the Ingress of hsmgate
# (ingress.host; the Ingress passes the TLS through to hsmgate, port 443). In the same cluster use https://hsmgate.hsmgate.svc:8443 instead.
# The files are the Secret of the client certificate, mounted at /openbao/userconfig/hsmgate-client-openbao/ by `server.extraVolumes` of the OpenBao
# chart (openbao-helm-values.yaml). hsmgate answers the Transit API of Vault/OpenBao; the key is `openbao-unseal` of values-openbao.yaml.
seal "transit" {
  address         = "https://hsmgate.example.com"
  mount_path      = "transit/"                          # the path of the API is /v1/transit/encrypt/<key_name>
  key_name        = "openbao-unseal"
  tls_ca_cert     = "/openbao/userconfig/hsmgate-client-openbao/ca.crt"
  tls_client_cert = "/openbao/userconfig/hsmgate-client-openbao/tls.crt"
  tls_client_key  = "/openbao/userconfig/hsmgate-client-openbao/tls.key"
  # hsmgate takes no token (it decides by the client certificate) and ignores one; if OpenBao asks for a token, give it any value (BAO_TOKEN=unused)
}
