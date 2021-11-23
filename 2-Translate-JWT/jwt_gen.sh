#!/usr/bin/env bash

# REF: https://willhaley.com/blog/generate-jwt-with-bash/
#
# JWT Encoder Bash Script
#

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

# jwt_gen() 
# {

    # usage:
    #   jwt_gen <issuer> <sub> <dpr>
    #   still needs to include exp

    secret='hardsecret'

    # Static header fields.
    # ref:
    #
    # JWT claims in DA-SVID project:
    # issuer (iss) = SPIFFE ID of the workload that generated the DA-SVID (Asserting workload)
    # expiration time (exp) =  as small as is reasonably possible. 
    #   Maybe equals to oauth token ttl?
    # asserted at (aat) = the time at which the assertion made in the DA-SVID was verified by the Asserting Workload
    #   # DA-SVID verification timestamp
    # subject (sub) = the identity about which the assertion is being made. Subject workload's SPIFFE ID.
    # delegated principal (dpr) = it is the sub claim in oauth token? The scope?
    #
    # "iss": "spiffe://example.org/host",
    # "aat": JWT generation timestamp,
    # "sub": "spiffe://example.org/100416421704833135369",
    # "dpr": "https://www.googleapis.com/auth/userinfo.email openid"

    header='{
        "typ": "JWT",
        "alg": "HS256",
        "kid": "0001",
        "iss": "'$1'",
        "aat": "'$(date +%s)'",
        "sub": "'$2'",
        "dpr": "'$3'"
    }'

    # Use jq to set the dynamic `iat` and `exp`
    # fields on the header using the current time.
    # `iat` is set to now, and `exp` is now + 300 seconds.
    header=$(
        echo "${header}" | jq --arg time_str "$(date +%s)" \
        '
        ($time_str | tonumber) as $time_num
        | .iat=$time_num
        | .exp=($time_num + 300)
        '
    )

    payload='{
    }'


    header_base64=$(echo "${header}" | json | base64_encode)
    payload_base64=$(echo "${payload}" | json | base64_encode)

    header_payload=$(echo "${header_base64}.${payload_base64}")
    signature=$(echo "${header_payload}" | hmacsha256_sign | base64_encode)

    echo "${header_payload}.${signature}"
# }
