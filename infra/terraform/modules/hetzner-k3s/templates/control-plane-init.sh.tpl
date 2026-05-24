#cloud-config
package_update: true
packages:
  - curl
  - open-iscsi
runcmd:
  - |
    %{ if version_env != "" ~}
    export ${version_env}
    %{ endif ~}
    K3S_TOKEN="${token}"
    %{ if index == 0 ~}
    K3S_INSTALL=https://get.k3s.io
    sh -c "$(wget -qO- $K3S_INSTALL)" -- server \
      --cluster-init \
      --token "$K3S_TOKEN" \
      --tls-san "${cluster}-cp-0" \
      --disable traefik
    %{ else ~}
    K3S_INSTALL=https://get.k3s.io
    sh -c "$(wget -qO- $K3S_INSTALL)" -- server \
      --server "https://${cluster}-cp-0:6443" \
      --token "$K3S_TOKEN" \
      --disable traefik
    %{ endif ~}
