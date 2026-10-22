# Recording the demos

The GIFs in the main README are rendered with [vhs](https://github.com/charmbracelet/vhs)
against a disposable kind cluster with planted problems.

```bash
kind create cluster --name kupre-demo --image kindest/node:v1.36.4 --kubeconfig /tmp/demo/kubeconfig
kubectl --kubeconfig /tmp/demo/kubeconfig config rename-context kind-kupre-demo demo
kubectl --kubeconfig /tmp/demo/kubeconfig apply -f docs/demo/fixtures.yaml
mkdir -p /tmp/demo/bin && go build -o /tmp/demo/bin/kupre ./cmd/kupre

vhs docs/demo/tui.tape
vhs docs/demo/cli.tape
```
