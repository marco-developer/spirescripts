package main

import (
    "fmt"
    "flag"
    "time"
    "github.com/golang-jwt/jwt"
)

// TODO: implement function to be called by asserting workload
var hmacSampleSecret []byte

func main(){

    // gets current time and sets default for exp time
    issue_time := time.Now().Round(0)
    exp_time := issue_time.Add(time.Second).Round(0).String()

    // TODO: enable entering values as flags or ordered arguments
    // Declaring flags
    iss := flag.String("iss", "", "issuer(iss) = SPIFFE ID of the workload that generated the DA-SVID (Asserting workload")
    aat := flag.String("aat", "", "asserted at(aat) = time at which the assertion made in the DA-SVID was verified by the asserting workload")
    exp := flag.String("exp", exp_time, "expiration time(exp) = as small as reasonably possible, issue time + 1s by default.")
    sub := flag.String("sub", "", "subject (sub) = the identity about which the assertion is being made. Subject workload's SPIFFE ID.")
    dpr := flag.String("dpr", "", "delegated principal (dpr) = it is the sub claim in oauth token? The scope?")

    flag.Parse()

    // Building JWT
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "typ": "JWT",
        "alg": "HS256",
        "kid": "0001",
        "iss": *iss,
        "aat": *aat,
        "sub": *sub,
        "dpr": *dpr,
        "iat": issue_time,
        "exp": *exp,
    })


    tokenString, err := token.SignedString(hmacSampleSecret)

    //JWT gen error handling
    if err != nil {

        fmt.Println(err)

    } else {

        fmt.Println(tokenString)

    }

}
