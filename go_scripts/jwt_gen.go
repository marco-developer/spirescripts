package main

import (
	"fmt"
    "flag"
	"time"
	"github.com/golang-jwt/jwt"
)

var hmacSampleSecret []byte

func main(){

    issue_time := time.Now()
    added := issue_time.Add(time.Second * 1)
    exp_time := added.String()

    
    iss := flag.String("iss", "", "issuer(iss) = SPIFFE ID of the workload that generated the DA-SVID (Asserting workload")
    aat := flag.String("aat", "", "asserted at(aat) = time at which the assertion made in the DA-SVID was verified by the asserting workload")
    
    exp := flag.String("exp", exp_time, "expiration time(exp) = as small as reasonably possible, issue time + 1s by default.")
    
    sub := flag.String("sub", "", "subject (sub) = the identity about which the assertion is being made. Subject workload's SPIFFE ID.")
    dpr := flag.String("dpr", "", "delegated principal (dpr) = it is the sub claim in oauth token? The scope?")
    
    flag.Parse()

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

    if err != nil {

        fmt.Println(err)

    } else {

        fmt.Println(tokenString)

    }

}
