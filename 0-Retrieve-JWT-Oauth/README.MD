# Intro
Scripts to interact with Oauth IdP and retrieve a JWT.

# google_oauth.sh: 
Interacts with google oauth and retrieve a token.
# okta_access_token.sh
Usage example:  
./okta_access_token.sh -b 'https://youroktadomain.okta.com' -c yourclientid -o 'https://example.net/your_application'  
This script requires an additional file (credentials.txt) containing the okta username and password in the format username:password
