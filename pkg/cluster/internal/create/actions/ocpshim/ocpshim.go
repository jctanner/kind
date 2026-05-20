/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ocpshim

import (
	"bytes"
	"fmt"
	"time"

	"sigs.k8s.io/kind/pkg/cluster/internal/create/actions"
	"sigs.k8s.io/kind/pkg/cluster/nodes"
	"sigs.k8s.io/kind/pkg/cluster/nodeutils"
	"sigs.k8s.io/kind/pkg/errors"

	"go.yaml.in/yaml/v3"
)

type action struct{}

// NewAction returns a new action for configuring the OCP API shim
func NewAction() actions.Action {
	return &action{}
}

const wellKnownJSON = `{
  "issuer": "https://oauth-openshift.apps.ocp-sim.test",
  "authorization_endpoint": "https://oauth-openshift.apps.ocp-sim.test/oauth/authorize",
  "token_endpoint": "https://oauth-openshift.apps.ocp-sim.test/oauth/token",
  "scopes_supported": ["user:check-access","user:full","user:info","user:list-projects"],
  "response_types_supported": ["code","token"],
  "grant_types_supported": ["authorization_code","implicit"],
  "code_challenge_methods_supported": ["plain","S256"]
}`

// Execute runs the action
func (a *action) Execute(ctx *actions.ActionContext) error {
	ctx.Status.Start("Configuring OCP API shim 🔧")
	defer ctx.Status.End(false)

	allNodes, err := ctx.Nodes()
	if err != nil {
		return err
	}

	node, err := nodeutils.BootstrapControlPlaneNode(allNodes)
	if err != nil {
		return err
	}

	// write the well-known discovery JSON
	if err := nodeutils.WriteFile(node, "/etc/kubernetes/ocp-shim/well-known.json", wellKnownJSON); err != nil {
		return errors.Wrap(err, "failed to write well-known.json")
	}

	// read the kube-apiserver static pod manifest
	var raw bytes.Buffer
	if err := node.Command("cat", "/etc/kubernetes/manifests/kube-apiserver.yaml").SetStdout(&raw).Run(); err != nil {
		return errors.Wrap(err, "failed to read kube-apiserver manifest")
	}

	patched, err := patchManifest(raw.Bytes())
	if err != nil {
		return errors.Wrap(err, "failed to patch kube-apiserver manifest")
	}

	// write the patched manifest back
	if err := nodeutils.WriteFile(node, "/etc/kubernetes/manifests/kube-apiserver.yaml", string(patched)); err != nil {
		return errors.Wrap(err, "failed to write patched kube-apiserver manifest")
	}

	// wait for the API server to come back
	ctx.Logger.V(0).Info("Waiting for API server to restart with OCP shim...")
	if err := waitForAPIServer(node); err != nil {
		return errors.Wrap(err, "API server did not recover after OCP shim patching")
	}

	ctx.Status.End(true)
	return nil
}

func waitForAPIServer(node nodes.Node) error {
	backoff := 2 * time.Second
	for i := 0; i < 30; i++ {
		if i > 0 {
			time.Sleep(backoff)
			if backoff < 10*time.Second {
				backoff *= 2
			}
		}
		err := node.Command(
			"kubectl", "--kubeconfig=/etc/kubernetes/admin.conf",
			"get", "--raw", "/healthz",
		).Run()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("timed out waiting for API server health")
}

func patchManifest(data []byte) ([]byte, error) {
	var pod yaml.Node
	if err := yaml.Unmarshal(data, &pod); err != nil {
		return nil, errors.Wrap(err, "failed to parse kube-apiserver manifest")
	}

	// The yaml.Node tree for a document is: Document -> Mapping
	if pod.Kind != yaml.DocumentNode || len(pod.Content) == 0 {
		return nil, fmt.Errorf("unexpected YAML structure")
	}
	root := pod.Content[0] // the top-level mapping

	// patch --secure-port and probe ports in the kube-apiserver container
	spec := findMapValue(root, "spec")
	if spec == nil {
		return nil, fmt.Errorf("no spec in manifest")
	}
	containers := findMapValue(spec, "containers")
	if containers == nil {
		return nil, fmt.Errorf("no containers in spec")
	}

	var apiContainer *yaml.Node
	for _, c := range containers.Content {
		name := findMapValue(c, "name")
		if name != nil && name.Value == "kube-apiserver" {
			apiContainer = c
			break
		}
	}
	if apiContainer == nil {
		return nil, fmt.Errorf("kube-apiserver container not found")
	}

	// patch command args: --secure-port=6443 -> --secure-port=16443
	command := findMapValue(apiContainer, "command")
	if command != nil {
		for _, arg := range command.Content {
			if arg.Value == "--secure-port=6443" {
				arg.Value = "--secure-port=16443"
			}
		}
	}

	// patch probe ports
	for _, probeName := range []string{"livenessProbe", "readinessProbe", "startupProbe"} {
		probe := findMapValue(apiContainer, probeName)
		if probe == nil {
			continue
		}
		httpGet := findMapValue(probe, "httpGet")
		if httpGet == nil {
			continue
		}
		port := findMapValue(httpGet, "port")
		if port != nil && port.Value == "6443" {
			port.Value = "16443"
		}
	}

	// add the ocp-shim volume to the pod spec
	volumes := findMapValue(spec, "volumes")
	if volumes == nil {
		return nil, fmt.Errorf("no volumes in spec")
	}

	var ocpShimConfigVolume yaml.Node
	if err := yaml.Unmarshal([]byte(`name: ocp-shim-config
hostPath:
  path: /etc/kubernetes/ocp-shim
  type: DirectoryOrCreate`), &ocpShimConfigVolume); err != nil {
		return nil, err
	}
	volumes.Content = append(volumes.Content, ocpShimConfigVolume.Content[0])

	var ocpShimBinVolume yaml.Node
	if err := yaml.Unmarshal([]byte(`name: ocp-shim-bin
hostPath:
  path: /usr/local/bin/ocp-shim
  type: File`), &ocpShimBinVolume); err != nil {
		return nil, err
	}
	volumes.Content = append(volumes.Content, ocpShimBinVolume.Content[0])

	// build the sidecar container node
	sidecarYAML := `name: ocp-shim
image: ""
command:
  - /ocp-shim
  - --listen=:6443
  - --upstream=https://localhost:16443
  - --tls-cert-file=/etc/kubernetes/pki/apiserver.crt
  - --tls-key-file=/etc/kubernetes/pki/apiserver.key
  - --client-ca-file=/etc/kubernetes/pki/ca.crt
  - --proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt
  - --proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key
  - --well-known-file=/etc/kubernetes/ocp-shim/well-known.json
  - --oidc-issuer-url=https://localhost:9443
  - --oauth-userinfo-url=https://localhost:9443/oauth/userinfo
ports:
  - containerPort: 6443
    hostPort: 6443
    protocol: TCP
volumeMounts:
  - name: ocp-shim-bin
    mountPath: /ocp-shim
    readOnly: true
  - name: k8s-certs
    mountPath: /etc/kubernetes/pki
    readOnly: true
  - name: ocp-shim-config
    mountPath: /etc/kubernetes/ocp-shim
    readOnly: true
resources:
  requests:
    cpu: 10m
    memory: 16Mi`

	var sidecar yaml.Node
	if err := yaml.Unmarshal([]byte(sidecarYAML), &sidecar); err != nil {
		return nil, err
	}

	// copy the image from the kube-apiserver container so the sidecar uses the same node image
	// (ocp-shim binary is baked into the node image, but the container spec needs an image field)
	apiImage := findMapValue(apiContainer, "image")
	sidecarImage := findMapValue(sidecar.Content[0], "image")
	if apiImage != nil && sidecarImage != nil {
		sidecarImage.Value = apiImage.Value
	}

	containers.Content = append(containers.Content, sidecar.Content[0])

	// also remove the hostPort on the kube-apiserver container's port 6443,
	// since the shim now owns that port
	ports := findMapValue(apiContainer, "ports")
	if ports != nil {
		for _, portEntry := range ports.Content {
			cp := findMapValue(portEntry, "containerPort")
			if cp != nil && cp.Value == "6443" {
				// change containerPort to 16443 to match the new --secure-port
				cp.Value = "16443"
				hp := findMapValue(portEntry, "hostPort")
				if hp != nil {
					// remove hostPort by setting to 0 (or we could remove the key)
					// actually, just remove the whole hostPort mapping
					removeMapKey(portEntry, "hostPort")
				}
			}
		}
	}

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&pod); err != nil {
		return nil, errors.Wrap(err, "failed to encode patched manifest")
	}
	return out.Bytes(), nil
}

func findMapValue(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func removeMapKey(node *yaml.Node, key string) {
	if node.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i < len(node.Content)-1; i += 2 {
		if node.Content[i].Value == key {
			node.Content = append(node.Content[:i], node.Content[i+2:]...)
			return
		}
	}
}
