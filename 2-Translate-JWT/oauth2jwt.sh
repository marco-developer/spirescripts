#!/bin/bash
# Receives an Okta oauth JWT and introspect it
# usage:
# ./oauth2jwt.sh <token>

oauthtoken=$1

# Okta client configuration
clientid=''
clientsecret=''
oktadomain=''

tokeninfo=$(curl --request POST --user $clientid:$clientsecret \
https://$oktadomain/oauth2/v1/introspect \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode token=$oauthtoken)

read userid < <(echo $tokeninfo | jq -r '.uid')
read scope < <(echo $tokeninfo | jq -r '.scope')

# Uses jwt_gen script to generate the JWT. 
# jwt_gen.sh <issuer> <sub> <dpr>
./jwt_gen.sh spiffe://example.org/host spiffe://example.org/$userid $scope 

# with tokeninfo we can proceed with SVID creation using its claims, like:
    
    # read userid < <(echo $tokeninfo | jq -r '.user_id')
    # read ttl < <(echo $tokeninfo | jq -r '.expires_in')

    # spire-server entry create \
    #     -parentID spiffe://example.org/host \
    #     -ttl $ttl \
    #     -spiffeID spiffe://example.org/$userid \
    #     -selector $selector
