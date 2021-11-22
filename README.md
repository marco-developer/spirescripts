# Intro
Scripts related to HPE/USP SPIRE DA-SVID project.

# Prereqs
- Docker, docker-compose  
- spire repo  

# Details

k8s folder: Scripts to start SPIRE in minikube and run Envoy/X509 SPIRE sample.  

Basic scripts:  
- preinstall.sh: Executes the basic installation steps.  
- server_menu.sh: A simple command line interface menu to a local implementation of SPIRE Server.  
  Copy server_menu.sh to spire dir, _chmod +x server_menu.sh_ and execute it.  

Step 0:
- google_oauth.sh: Tool to interact and retrieve a Google OAuth Token.  
- okta_access_token.sh: Tool to interact and retrieve an OKTA OAuth Token.  

Step 2:
- oauth2jwt.sh: Receives an Okta oauth JWT, introspects it and then save results in file or generate a new JWT based on selected claims.  
- jwt_gen.sh: shellscript that generates a JWT based on oauth claims.  

