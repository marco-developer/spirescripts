# Introduction
These scripts aims to start a k8s environment to run SPIRE (startk8s.sh) and implement the envoy-X509 example from spire-tutorials repo.

# Prereqs:
- Docker and Docker-compose
- Minikube
- If running in a VM, its also necessary to install socat (apt install socat) and make port-forward to the desired pod: 
    kubectl port-forward --address localhost,host_ip pod/frontend_name 3000:3000

# Details:
  
- startk8s.sh: Start minikube and all SPIRE components.
- create-registration-entries.sh: Interact with spire-server, creating the necessary SPIFFE-IDs to run the envoy-X509 example.
- After the execution of _kubectl apply -k k8s/._ command and port-forward (if necessary), point to IP:3000 to connect to backend through frontend, using mTLS. The same can be done pointing to IP:3002, and in this case the connection will be stablished using frontend-2.
- teardown.sh: Stop and delete everything.
  
# Refs:  
  https://spiffe.io/docs/latest/try/getting-started-k8s/  
  https://github.com/spiffe/spire-tutorials/blob/master/.travis.yml  
  https://github.com/spiffe/spire-tutorials/tree/master/k8s/envoy-x509  
  
