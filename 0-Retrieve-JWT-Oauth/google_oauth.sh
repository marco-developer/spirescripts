# REFERENCE: https://gist.github.com/LindaLawton/cff75182aac5fa42930a09f58b63a309

# Client id from Google Developer console
# Client Secret from Google Developer console
# Scope this is a space separated list of the scopes of access you are requesting.

# Authorization link.  Place this in a browser and copy the code that is returned after you accept the scopes.
# https://accounts.google.com/o/oauth2/auth?client_id=<client id>&redirect_uri=urn:ietf:wg:oauth:2.0:oob&scope=<scope>&response_type=code

# Exchange Authorization code for an access token and a refresh token, and store it on token.ggl file
# curl \
# --request POST \
# --data "code=<authorization code>&client_id=<client id>&client_secret=<client secret>&redirect_uri=urn:ietf:wg:oauth:2.0:oob&grant_type=authorization_code" \
# https://accounts.google.com/o/oauth2/token > token.ggl

# Exchange a refresh token for a new access token.
# curl \
# --request POST \
# --data 'client_id=<client id>&client_secret=<client secret>&refresh_token=<refresh token>&grant_type=refresh_token' \
# https://accounts.google.com/o/oauth2/token

# Inspect the token and store data in token.info file
# curl \
# --request POST \
# --data "access_token=<access token>" \
# https://www.googleapis.com/oauth2/v1/tokeninfo > token.info
