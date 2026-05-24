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
    K3S_INSTALL=https://get.k3s.io
    sh -c "$(wget -qO- $K3S_INSTALL)" -- agent \
      --server "https://${cp0_ip}:6443" \
      --token "$K3S_TOKEN"
