package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	
	// To sig. validation 
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	"encoding/binary"
	"math/big"
	
	// to retrieve JWT claims
	// NOTE: look for another JWT lib
	"github.com/dgrijalva/jwt-go"
	"time"
	

	"github.com/gorilla/sessions"
	// Okta
	verifier "github.com/okta/okta-jwt-verifier-golang"
	oktaUtils "github.com/okta/samples-golang/okta-hosted-login/utils"
)

var (
	tpl          *template.Template
	sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))
	state        = generateState()
	nonce        = "NonceNotSetYet"
)

func init() {
	tpl = template.Must(template.ParseGlob("templates/*"))
}

func generateState() string {
	// Generate a random byte array for state paramter
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func main() {
	oktaUtils.ParseEnvironment()

	

	http.HandleFunc("/", HomeHandler)
	http.HandleFunc("/login", LoginHandler)
	http.HandleFunc("/callback", AuthCodeCallbackHandler)
	http.HandleFunc("/profile", ProfileHandler)
	http.HandleFunc("/logout", LogoutHandler)
	http.HandleFunc("/validate", ValidateHandler)
	http.HandleFunc("/decode", DecodeHandler)
	http.Handle("/img/", http.StripPrefix("/img/", http.FileServer(http.Dir("./img"))))

	// IP defined manually for testing purposes. Need to be adjusted
	log.Print("server starting at 192.168.0.5:8080 ... ")
	err := http.ListenAndServe("192.168.0.5:8080", nil)
	if err != nil {
		log.Printf("the HTTP server failed to start: %s", err)
		os.Exit(1)
	}
}

type JWKS struct {
	Keys []JWK
}

type JWK struct {
	Alg string
	Kty string
	X5c []string
	N   string
	E   string
	Kid string
	X5t string
}

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	type customData struct {
		Profile         map[string]string
		IsAuthenticated bool
		// Added access token in the customdata
		AccessToken     string
	}

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Convert access token retrieved from session to string
	strAT := fmt.Sprintf("%v", session.Values["access_token"])
	
	data := customData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		// Pass access token as part of data
		AccessToken:	 strAT,
	}
	tpl.ExecuteTemplate(w, "home.gohtml", data)
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	nonce, _ = oktaUtils.GenerateNonce()
	var redirectPath string

	q := r.URL.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("response_type", "code") // code or token
	q.Add("response_mode", "query") // query or fragment
	q.Add("scope", "openid profile email")
	q.Add("redirect_uri", "http://192.168.0.5:8080/callback")
	q.Add("state", state)
	q.Add("nonce", nonce)

	redirectPath = os.Getenv("ISSUER") + "/v1/authorize?" + q.Encode()

	http.Redirect(w, r, redirectPath, http.StatusFound)
}

func AuthCodeCallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check the state that was returned in the query string is the same as the above state
	if r.URL.Query().Get("state") != state {
		fmt.Fprintln(w, "The state was not as expected")
		return
	}
	// Make sure the code was provided
	if r.URL.Query().Get("code") == "" {
		fmt.Fprintln(w, "The code was not returned or is not accessible")
		return
	}

	exchange := exchangeCode(r.URL.Query().Get("code"), r)
	if exchange.Error != "" {
		fmt.Println(exchange.Error)
		fmt.Println(exchange.ErrorDescription)
		return
	}

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	_, verificationError := verifyToken(exchange.IdToken)

	if verificationError != nil {
		fmt.Println(verificationError)
	}

	if verificationError == nil {
		session.Values["id_token"] = exchange.IdToken
		session.Values["access_token"] = exchange.AccessToken
		

		session.Save(r, w)
	}

	http.Redirect(w, r, "/", http.StatusFound)
}

func ProfileHandler(w http.ResponseWriter, r *http.Request) {
	type customData struct {
		Profile         map[string]string
		IsAuthenticated bool
	}

	data := customData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
	}
	tpl.ExecuteTemplate(w, "profile.gohtml", data)
}


func ValidateHandler(w http.ResponseWriter, r *http.Request) {

	// Define customdata to be passed 
	type customData struct {
		Profile         map[string]string
		IsAuthenticated bool
		// Added filds in the customdata
		AccessToken     string
		PublicKey		string
		SigValidation 	string
		ExpValidation 	string
	}
	
	var sigresult string
	var expresult string

	// Load session
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// Convert access_token to string
	strAT := fmt.Sprintf("%v", session.Values["access_token"])

	// Parse access token without validating signature
    token, _, err := new(jwt.Parser).ParseUnverified(strAT, jwt.MapClaims{})
    if err != nil {
        fmt.Println(err)
        return
    }
	
	// Load claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
        
		// Verify if token is still valid
		tm := time.Unix(int64(claims["exp"].(float64)), 0)
		remaining := tm.Sub(time.Now())
		if remaining > 0 {
			expresult = fmt.Sprintf("Token valid for more %v", remaining) 
		} else {
			expresult = fmt.Sprintf("Token expired!")
		}
    } else {
        fmt.Println(err)
    }

    // Open file containing the keys obtained from /keys endpoint
	// NOTE: Needs to implement a key cache and key retrieve processes.
	jwksFile, err := os.Open("./jwks.json")
	if err != nil {
		fmt.Fprintln(w,"Error in reading jwks")
		return
	}

	// Decode file and retrieve Public key from Okta application
	dec := json.NewDecoder(jwksFile)
	var jwks JWKS
	
	if err := dec.Decode(&jwks); err != nil {
		fmt.Fprintln(w,"Unable to read key %s", err)
		return
	}

	// Verify token signature using extracted Public key
	err = verifySignature(strAT, jwks.Keys[0])
	if err != nil {
		sigresult = fmt.Sprintf("Failed signature verification: %v", err)
	} else {
		sigresult = "Signature successfuly validated!"
	}
	
	data := customData{
		Profile:         getProfileData(r),
		IsAuthenticated: isAuthenticated(r),
		// Token validation info
		AccessToken:	 strAT,
		SigValidation:	 sigresult,
		ExpValidation: 	 expresult,
		PublicKey: 		 fmt.Sprintf("%v", jwks.Keys[0]),
	}
	
	tpl.ExecuteTemplate(w, "validate.gohtml", data)

}

func DecodeHandler(w http.ResponseWriter, r *http.Request) {

	type customData struct {
		Profile         	map[string]string
		IsAuthenticated 	bool
		// Added access token in the customdata
		AccessToken     	string
		IntrospectionResult map[string]interface{}
	}
	
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	strAT := fmt.Sprintf("%v", session.Values["access_token"])
	result := instrospectAccessToken(strAT)
	
	data := customData{
		Profile:         	 getProfileData(r),
		IsAuthenticated: 	 isAuthenticated(r),
		// Pass access token as part of data
		AccessToken:	 	 strAT,
		IntrospectionResult: result,
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	
	tpl.ExecuteTemplate(w, "decode.gohtml", data)

}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	delete(session.Values, "id_token")
	delete(session.Values, "access_token")

	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func exchangeCode(code string, r *http.Request) Exchange {
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	q := r.URL.Query()
	q.Add("grant_type", "authorization_code")
	q.Set("code", code)
	q.Add("redirect_uri", "http://192.168.0.5:8080/callback")

	url := os.Getenv("ISSUER") + "/v1/token?" + q.Encode()

	req, _ := http.NewRequest("POST", url, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Connection", "close")
	h.Add("Content-Length", "0")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	var exchange Exchange
	json.Unmarshal(body, &exchange)

	return exchange
}

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["id_token"] == nil || session.Values["id_token"] == "" {
		return false
	}

	return true
}

func getProfileData(r *http.Request) map[string]string {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m
	}

	reqUrl := os.Getenv("ISSUER") + "/v1/userinfo"

	req, _ := http.NewRequest("GET", reqUrl, bytes.NewReader([]byte("")))
	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}

func verifyToken(t string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["nonce"] = nonce
	tv["aud"] = os.Getenv("CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("ISSUER"),
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified: %s", "")
}

func verifySignature(jwtToken string, key JWK) error {
	parts := strings.Split(jwtToken, ".")
	message := []byte(strings.Join(parts[0:2], "."))
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	n, _ := base64.RawURLEncoding.DecodeString(key.N)
	e, _ := base64.RawURLEncoding.DecodeString(key.E)
	z := new(big.Int)
	z.SetBytes(n)
	//decoding key.E returns a three byte slice, https://golang.org/pkg/encoding/binary/#Read and other conversions fail
	//since they are expecting to read as many bytes as the size of int being returned (4 bytes for uint32 for example)
	var buffer bytes.Buffer
	buffer.WriteByte(0)
	buffer.Write(e)
	exponent := binary.BigEndian.Uint32(buffer.Bytes())
	publicKey := &rsa.PublicKey{N: z, E: int(exponent)}

	// Only small messages can be signed directly; thus the hash of a
	// message, rather than the message itself, is signed.
	hasher := crypto.SHA256.New()
	hasher.Write(message)

	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hasher.Sum(nil), signature)
	return err
}

// func verifyAccessToken(t string) (*verifier.Jwt, error) {
// // verificar se todos os tokens OKTA sao opacos. Precisamos validar assinatura (JWS) localmente e validade do token (exp)
// // NOTE: Esta função está fora de uso. Precisa revisar e provavelmente tirar parte do código da validatehandler e trazer para cá
	
// 	// Define claims to be validated
// 	tv := map[string]string{}
// 	tv["aud"] = "api://default"
// 	tv["cid"] = os.Getenv("CLIENT_ID")

// 	jv := verifier.JwtVerifier{
// 		Issuer:           os.Getenv("ISSUER"),
// 		ClaimsToValidate: tv,
// 	}

// 	result, err := jv.New().VerifyAccessToken(t)
// 	if err != nil {
// 		return nil, fmt.Errorf("%s", err)
// 	}

// 	if result != nil {
// 		return result, nil
// 	}

// 	return nil, fmt.Errorf("token could not be verified: %s", "")
// }

func instrospectAccessToken(t string) map[string]interface{}  {

	payload := strings.NewReader(`token=`+t)

	m := make(map[string]interface{})
	authHeader := base64.StdEncoding.EncodeToString(
		[]byte(os.Getenv("CLIENT_ID") + ":" + os.Getenv("CLIENT_SECRET")))

	reqUrl := os.Getenv("ISSUER") + "/v1/introspect"

	req, _ := http.NewRequest("POST", reqUrl, payload)
	h := req.Header
	h.Add("Content-Type", "application/x-www-form-urlencoded")
	h.Add("Authorization", "Basic "+authHeader)
	h.Add("Accept", "application/json")

	// h.Add("token", t)
	// h.Add("token_type_hint", "access_token")
	
	client := &http.Client{}
	resp, _ := client.Do(req)
	body, _ := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	json.Unmarshal(body, &m)

	return m
}

type Exchange struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int    `json:"expires_in,omitempty"`
	Scope            string `json:"scope,omitempty"`
	IdToken          string `json:"id_token,omitempty"`
}
