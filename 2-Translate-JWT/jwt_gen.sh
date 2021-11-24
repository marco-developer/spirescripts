#!/usr/bin/env bash

# REF: https://willhaley.com/blog/generate-jwt-with-bash/
#
# JWT Encoder Bash Script
#

# Usage:
#   jwt_gen <issuer> <sub> <scope> <exp>

base64_encode()
{
    declare input=${1:-$(</dev/stdin)}
    # Use `tr` to URL encode the output from base64.
    printf '%s' "${input}" | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n'
}

json() {
    declare input=${1:-$(</dev/stdin)}
    printf '%s' "${input}" | jq -c .
}

hmacsha256_sign()
{
    declare input=${1:-$(</dev/stdin)}
    printf '%s' "${input}" | openssl dgst -binary -sha256 -hmac "${secret}"
}


##### MAM: ??? #####
# This function is planned to be called by Asserting Workload. 
# Then, the secret used in JWT creation can be its private key?
secret='hardsecret'


# Header fields
#
# JWT claims in DA-SVID project:
#
# (iss) issuer = SPIFFE ID of the workload that generated the DA-SVID (Asserting workload)
# (exp) expiration time =  as small as is reasonably possible. Maybe equals to oauth token ttl?
# (aat) asserted at = the time at which the assertion made in the DA-SVID was verified by the Asserting Workload
# (sub) subject = the identity about which the assertion is being made. Subject workload's SPIFFE ID.
# (dpr) delegated principal = it is the sub claim in oauth token? The scope?

# "iss": "spiffe://example.org/host", (Asserting workload)
# "aat": JWT generation timestamp,
# "sub": "spiffe://example.org/mob_backend", (Subject workload)
# "dpr": spiffe://example.org/100416421704833135369, (Principal)
# "scp": "email openid" (Scope)

header='{
    "typ": "JWT",
    "alg": "HS256",
    "kid": "0001",
    "iss": "'$1'", 
    "aat": "'$(date +%s)'",
    "sub": "'$2'",
    "dpr": "'$3'",
    "scp": "'$4'",
    "exp": "'$5'"
}'

# Use jq to set the dynamic `iat` and `exp`
# fields on the header using the current time.
# `iat` is set to now, and `exp` is retrieved from Oauth token.
# Removed:
# header=$(
#     echo "${header}" | jq --arg time_str "$(date +%s)" \
#     '
#     ($time_str | tonumber) as $time_num
#     | .iat=$time_num
#     | .exp=("'$5'")
#     '
# )

# Payload
payload='{
}'
header_base64=$(echo "${header}" | json | base64_encode)
payload_base64=$(echo "${payload}" | json | base64_encode)
header_payload=$(echo "${header_base64}.${payload_base64}")
signature=$(echo "${header_payload}" | hmacsha256_sign | base64_encode)
echo "${header_payload}.${signature}"

