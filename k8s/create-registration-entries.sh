#/bin/bash


# Create spire-server entries to spire-agent, frontend, frontend-2 and backend.

set -e

bb=$(tput bold)
nn=$(tput sgr0)

register() {
    kubectl exec -n spire spire-server-0 -c spire-server -- /opt/spire/bin/spire-server entry create $@
}

echo "${bb}Creating registration entry for the node...${nn}"
register \
    -node  \
    -spiffeID spiffe://example.org/ns/spire/sa/spire-agent \
    -selector k8s_sat:cluster:demo-cluster \
    -selector k8s_sat:agent_ns:spire \
    -selector k8s_sat:agent_sa:spire-agent

echo "${bb}Creating registration entry for the backend - envoy...${nn}"
register \
    -parentID spiffe://example.org/ns/spire/sa/spire-agent \
    -spiffeID spiffe://example.org/ns/default/sa/default/backend \
    -selector k8s:ns:default \
    -selector k8s:sa:default \
    -selector k8s:pod-label:app:backend \
    -selector k8s:container-name:envoy

echo "${bb}Creating registration entry for the frontend - envoy...${nn}"
register \
    -parentID spiffe://example.org/ns/spire/sa/spire-agent \
    -spiffeID spiffe://example.org/ns/default/sa/default/frontend \
    -selector k8s:ns:default \
    -selector k8s:sa:default \
    -selector k8s:pod-label:app:frontend \
    -selector k8s:container-name:envoy

echo "${bb}Creating registration entry for the frontend - envoy...${nn}"
register \
    -parentID spiffe://example.org/ns/spire/sa/spire-agent \
    -spiffeID spiffe://example.org/ns/default/sa/default/frontend-2 \
    -selector k8s:ns:default \
    -selector k8s:sa:default \
    -selector k8s:pod-label:app:frontend-2 \
    -selector k8s:container-name:envoy

echo "${bb}Listing created registration entries...${nn}"
kubectl exec -n spire spire-server-0 -- /opt/spire/bin/spire-server entry show

kubectl apply -f /spire-tutorials/k8s/quickstart/client-deployment.yaml
