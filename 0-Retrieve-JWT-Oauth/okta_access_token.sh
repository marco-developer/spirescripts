#! /usr/bin/bash

# A shell script which originally demonstrates how to get an OpenID Connect id_token from from Okta using the OAuth 2.0 "Implicit Flow"
# Modified to retrieve an OpenID Connect access_token
# Original Author: Joel Franusic <joel.franusic@okta.com>
# Modified By: Marco Marques <mmarques@larc.usp.br>
# 
# Copyright © 2016, Okta, Inc.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Usage: sudo ./okta_access_token.sh -b base_url -c client_id -o origin
# Requires a credentials.txt file containing Okta username:password :-/

curl="curl"
jq="jq"

# Add credentials.txt file to avoid passing credentials in command line or inserting it in the script.
# credentials.txt format: username,password
credentials=$(cat credentials.txt)
arrcredentials=(${credentials//,/ })
username="${arrcredentials[0]}"
password="${arrcredentials[1]}"

# Okta Domain
base_url=""

# Client ID
client_id=""

# Okta Sign-in redirect URIs. Ex: http://localhost:8080/callback
origin=""

verbose=0

while getopts ":b:c:o:u:p:v" OPTION
do
    case $OPTION in
    b)
        base_url="$OPTARG"
    ;;
    c)
        client_id="$OPTARG"
    ;;
    o)
        origin="$OPTARG"
    ;;
    v)
        verbose=0
    ;;
    [?])
        echo "Usage: $0 -b base_url -c client_id -o origin" >&2
        echo ""
        echo "Example:"
        echo "$0 -b 'https://example.okta.com' -c aBCdEf0GhiJkLMno1pq2 -o 'https://example.net/your_application'"
        echo ""
        echo "Also requires credentials.txt file containing username:password"
        exit 1
    ;;
    esac
done

redirect_uri=$(curl --silent --output /dev/null --write-out %{url_effective} --get --data-urlencode "$origin" "" | cut -d '?' -f 2)
if [ $verbose -eq 1 ]; then
    echo "Redirect URI: '${redirect_uri}'"
fi

rv=$(curl --silent "${base_url}/api/v1/authn" \
          -H "Origin: ${origin}" \
          -H 'Content-Type: application/json' \
          -H 'Accept: application/json' \
          --data-binary $(printf '{"username":"%s","password":"%s"}' $username $password) )
session_token=$(echo $rv | jq -r .sessionToken )
if [ $verbose -eq 1 ]; then
    echo "First curl: '${rv}'"
fi
if [ $verbose -eq 1 ]; then
    echo "Session token: '${session_token}'"
fi

url=$(printf "%s/oauth2/v1/authorize?sessionToken=%s&client_id=%s&scope=openid+email+groups&response_type=token&response_mode=fragment&nonce=%s&redirect_uri=%s&state=%s" \
      $base_url \
      $session_token \
      $client_id \
      "staticNonce" \
      $redirect_uri \
      "staticState")
if [ $verbose -eq 1 ]; then
    echo "Here is the URL: '${url}'"
fi

rv=$(curl --silent -v $url 2>&1)
if [ $verbose -eq 1 ]; then
    echo "Here is the return value: "
    echo $rv
fi

access_token=$(echo "$rv" | egrep -o '^< location: .*access_token=[[:alnum:]_\.\-]*' | cut -d \= -f 2)

echo "1 to save token in file or 2 to generate JWT:"
read fileorjwt
if [ $fileorjwt -eq 1 ]; then
    # Save access token in file
    echo $access_token > oktatoken.txt
else if [ $fileorjwt -eq 2 ]; then
    # OR.... advance to the next step: oauth2jwt.sh
    ./oauth2jwt.sh $access_token
    fi
fi
