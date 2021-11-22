# Intro
These scripts aims to introspect an Okta oauth access token (oauth2jwt.sh) and generate an JWT based on this token (jwt_gen.sh)

# Details
- oauth2jwt.sh: Needs to inform clientID, clientSecret, Okta Domain, and the token to be introspected  
- jwtgen.sh: Generate a JWT based on the informed claims.  

usage:  
main \<issuer\> \<sub\> \<dpr\>  

Header fields.  
ref:  

JWT claims in DA-SVID project:  
issuer (iss) = SPIFFE ID of the workload that generated the DA-SVID (Asserting workload)  
expiration time (exp) =  as small as is reasonably possible. Maybe equals to oauth token ttl? Still needs to be implemented here.  
asserted at (aat) = the time at which the assertion was made  
subject (sub) = the identity about which the assertion is being made. Subject workload's SPIFFE ID.  
delegated principal (dpr) = Seems strange to be the scope... 

Example:  
"iss": "spiffe://example.org/host",  
"aat": JWT generation timestamp,  
"sub": "spiffe://example.org/100416421704833135369",  
"dpr": "openid email groups"  
