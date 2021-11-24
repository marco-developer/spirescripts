#!/bin/bash

# Receives an Okta oauth JWT and introspect it
# usage:
# ./okta2jwt.sh <OAuth token>

oauthtoken=$1

# Okta client configuration
# This configuration is load from okta.conf file.
# This file shoud contain one line in the format: <oktadomain,clientid,clientsecret>
oktaconf=$(cat ../2-Translate-JWT/okta.conf)
arrcredentials=(${oktaconf//,/ })
oktadomain="${arrcredentials[0]}"
clientid="${arrcredentials[1]}"
clientsecret="${arrcredentials[2]}"

tokeninfo=$(curl --request POST --user $clientid:$clientsecret \
https://$oktadomain/oauth2/v1/introspect \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode token=$oauthtoken)

# Example of token introspection results
# echo $tokeninfo
# {
#     "active":true,
#     "scope":"openid email groups",
#     "username":"mmarques@larc.usp.br",
#     "exp":1637710878,
#     "iat":1637707278,
#     "sub":"mmarques@larc.usp.br",
#     "aud":"https://dev-39567105.okta.com",
#     "iss":"https://dev-39567105.okta.com",
#     "jti":"AT.Rj9-dSRAry6GkVHxarGq5W9tOZWygOMfnkmFkr3DjuY",
#     "token_type":"Bearer",
#     "client_id":"0oa2rwsdfyQwPVQpL5d7",
#     "uid":"00u2rsgj32bcfCKbF5d7"
# }

read userid < <(echo $tokeninfo | jq -r '.uid')
read scope < <(echo $tokeninfo | jq -r '.scope')
read exp < <(echo $tokeninfo | jq -r '.exp')

# # Debug:
# echo "Userid: $userid"
# echo "scope: $scope"
# echo "exp: $exp"

# Uses jwt_gen script to generate the DA-SVID (JWT). 
# jwt_gen.sh <issuer> <sub> <scp> <exp>
../2-Translate-JWT/jwt_gen.sh spiffe://example.org/host spiffe://example.org/mob_backend spiffe://example.org/$userid "$scope" $exp

# with tokeninfo we can proceed with SVID creation using its claims, like:
    
    # read ttl < <(echo $tokeninfo | jq -r '.expires_in')

    # spire-server entry create \
    #     -parentID spiffe://example.org/host \
    #     -ttl $ttl \
    #     -spiffeID spiffe://example.org/$userid \
    #     -selector $selector

