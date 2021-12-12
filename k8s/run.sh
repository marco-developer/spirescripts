#/bin/bash


cd /spire-tutorials/k8s/envoy-x509

kubectl apply -k k8s/.
sleep 3
kubectl get pods

echo "run kubectl port-forward --address localhost,192.168.0.5 pod/<podname> 3000:3000"
echo "run kubectl port-forward --address localhost,192.168.0.5 pod/<podname> 3002:3002"