# Introduction
This scripts aims to start a k8s environment to run SPIRE (startk8s.sh) and implement the envoy-X509 example from spire-tutorials repo.

# Prereqs:
- Docker and Docker-compose
- Minikube
- If running in a VM, its also necessary to install socat (apt install socat) and make port-forward to the desired pod: 
    kubectl port-forward --address localhost,<host ip> pod/<frontend name> 3000:3000

# Details:
  
- startk8s.sh: Start minikube and all SPIRE components.
- create-registration-entries.sh: Interact with spire-server, creating the necessary SPIFFE-IDs to run the envoy-X509 example.  
- teardown.sh: Stop and delete everything.
  
# Refs:  
  https://spiffe.io/docs/latest/try/getting-started-k8s/
  https://github.com/spiffe/spire-tutorials/blob/master/.travis.yml
  https://github.com/spiffe/spire-tutorials/tree/master/k8s/envoy-x509
  
