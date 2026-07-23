# kube-ssh

kube-ssh 为 Kubernetes Pod 提供统一的 SSH 访问入口。安装后，使用 Access 资源选择允许访问的 Pod，并通过 SSH 公钥授权用户。

## 对外访问地址

安装时填写 `kubeSsh.advertiseAddresses`，地址必须是用户能够访问的 `host:port`：

```yaml
kubeSsh:
  advertiseAddresses:
    - ssh.example.com:2222
```

可以配置多个地址。可用地址会发布到 Access 状态，供平台展示 SSH 连接信息。

## 多网关

默认网关只处理未指定 `gatewayClassName` 的 Access。需要为不同网络入口部署独立网关时，设置网关类名：

```yaml
kubeSsh:
  gatewayClassName: default-gateway
  advertiseAddresses:
    - ssh-a.example.com:2222
    - ssh-b.example.com:2222
```

Access 中的 `spec.gatewayClassName` 必须与网关类名完全一致。同一类名的网关副本应配置相同的对外访问地址。

## Service

Service 默认为 `NodePort`，端口为 `30022`。可根据集群网络环境选择 `ClusterIP`、`NodePort` 或 `LoadBalancer`。`advertiseAddresses` 应填写用户实际访问的地址，而不是仅在集群内部可用的 Service 地址。

## SSH 主机密钥

Chart 会自动生成 Ed25519 主机密钥并保存到 Secret，Pod 重启和升级不会改变 SSH 指纹。如需复用统一管理的密钥，可设置 `kubeSsh.hostKey.existingSecret`；Secret 中必须包含 `kubeSsh.hostKey.secretKey` 指定的键。运维也可以通过 `kubeSsh.hostKey.privateKey` 直接传入私钥。优先级依次为 `existingSecret`、`privateKey`、自动生成。设置 `kubeSsh.hostKey.autoGenerate=false` 可禁用主机密钥管理，由网关使用临时密钥。静态 `deploy/install.yaml` 会主动使用该配置，避免向所有用户分发同一私钥。

## Node 数据面

设置 `kubeSsh.backend.mode=node` 后，Chart 会在每个 Linux 节点部署
`kube-ssh-node`。SSH 大流量从网关通过 mTLS 直连目标节点的 `10443`
端口，再由 Node 组件使用 CRI v1 streaming 连接容器；apiserver 仅承载 Pod
查询/监听、Access 策略、Secret 监听和 SubjectAccessReview。Node 组件不可用时
会直接失败，不会回退到 `pods/exec` 或 `pods/portforward`。

Chart 默认只读挂载宿主机 `/run` 目录，Node 进程会依次探测常见的
containerd、CRI-O、K3s、K0s 和 cri-dockerd socket，并使用第一个就绪的
CRI v1 endpoint。可以通过 `kubeSsh.node.runtimeEndpoints` 指定有序的
`unix:///...` 列表覆盖自动探测。网关必须能访问所有节点 HostIP 的 Node
流端口。

`kubeSsh.node.tls.existingSecret` 为空时，Chart 会生成并保留一套发布级
mTLS Secret。使用已有 PKI 时，将 `existingSecret` 设置为已有 Secret 的名称；
该标准 TLS Secret 必须包含 `ca.crt`、`tls.crt`、`tls.key`，Node 服务端与
Gateway 客户端共用这套证书；证书 SAN 必须覆盖配置的 Node server name，
common name 必须与 `kubeSsh.node.expectedClientName` 一致。Node 进程会动态
加载挂载文件中的服务端证书和客户端 CA，轮换后新连接无需重启 DaemonSet
即可使用新凭据。
