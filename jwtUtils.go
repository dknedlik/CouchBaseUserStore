package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

type jwtHeader struct {
	Type      string `json:"typ,omitempty"`
	Algorithm string `json:"alg,omitempty"`
}

type jwtPayload struct {
	Issuer     string `json:"iss,omitempty"`
	Subject    string `json:"sub,omitempty"`
	Expiration int    `json:"exp,omitempty"`
	TokenID    string `json:"jti,omitempty"`
}

type jwtToken struct {
	Issued  string `json:"issued,omitempty"`
	Expires string `json:"expires,omitempty"`
	Token   string `json:"token,omitempty"`
}

func generateJwt(account Account) (jwtToken, error) {
	h, err := json.Marshal(jwtHeader{
		Type:      "jwt",
		Algorithm: "RS256",
	})
	if err != nil {
		return jwtToken{}, err
	}
	headerEncoded := strings.TrimRight(base64.URLEncoding.EncodeToString(h), "=")
	expiration := time.Now().Add(time.Minute * 15)
	p, err := json.Marshal(jwtPayload{
		Issuer:     "https://www.IMCFarms.com",
		Subject:    account.Pid,
		Expiration: int(expiration.Unix()),
		TokenID:    uuid.NewV4().String(),
	})
	if err != nil {
		return jwtToken{}, err
	}

	payloadEncoded := strings.TrimRight(base64.URLEncoding.EncodeToString(p), "=")

	body := fmt.Sprintf("%s.%s", headerEncoded, payloadEncoded)

	hasher := sha256.New()
	hasher.Write([]byte(body))

	key, err := getPrivateKey()
	if err != nil {
		return jwtToken{}, err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hasher.Sum(nil))
	if err != nil {
		return jwtToken{}, err
	}

	signedToken := fmt.Sprintf("%s.%s", body, strings.TrimRight(base64.URLEncoding.EncodeToString(signature), "="))
	token := jwtToken{
		Issued:  time.Now().String(),
		Expires: expiration.String(),
		Token:   signedToken,
	}

	return token, nil
}

func getPrivateKey() (*rsa.PrivateKey, error) {
	kt, err := ioutil.ReadFile("server.key")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(kt)
	privkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return privkey, nil
}

func getPublicKey() (*rsa.PublicKey, error) {
	kt, err := ioutil.ReadFile("server.crt")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(kt)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert.PublicKey.(*rsa.PublicKey), nil
}

func isSignatureValid(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return errors.New("Invalid token format")
	}
	tokenContent := fmt.Sprintf("%s.%s", parts[0], parts[1])
	tokenSignature, err := base64Decode(parts[2])
	if err != nil {
		return err
	}

	hasher := sha256.New()
	hasher.Write([]byte(tokenContent))

	key, err := getPublicKey()
	if err != nil {
		return err
	}
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hasher.Sum(nil), []byte(tokenSignature))
}

func parseAuthorization(authHeader string) (jwtPayload, error) {
	bearerToken := strings.Split(authHeader, " ")
	if len(bearerToken) != 2 {
		return jwtPayload{}, errors.New("No authorization token")
	}

	// Find the bearer token and process it
	if strings.ToLower(bearerToken[0]) != "bearer" {
		return jwtPayload{}, errors.New("No bearer token")
	}
	parts := strings.Split(bearerToken[1], ".")
	if len(parts) != 3 {
		return jwtPayload{}, errors.New("Invalid jwt format")
	}
	headerBytes, err := base64Decode(parts[0])
	if err != nil {
		return jwtPayload{}, errors.New("Unable to base64 decode header")
	}
	payloadBytes, err := base64Decode(parts[1])
	if err != nil {
		return jwtPayload{}, errors.New("Unable to base64 decode payload")
	}

	// de-serialize strings into objects
	headerString := string(headerBytes)
	payloadString := string(payloadBytes)
	var header jwtHeader
	var payload jwtPayload

	err = json.Unmarshal([]byte(headerString), &header)
	if err != nil {
		return jwtPayload{}, errors.New("Unable to unmarshall header")
	}
	err = json.Unmarshal([]byte(payloadString), &payload)
	if err != nil {
		return jwtPayload{}, errors.New("Unable to unmarshall payload")
	}

	// Check for timeout
	if payload.Expiration <= int(time.Now().Unix()) {
		return jwtPayload{}, errors.New("Expired Token")
	}

	// Verify the signature
	if isSignatureValid(bearerToken[1]) != nil {
		return jwtPayload{}, errors.New("Invalid Signature")
	}

	return payload, nil
}

// base64Decode decodes the Base64url encoded string
func base64Decode(s string) ([]byte, error) {
	// add back missing padding
	switch len(s) % 4 {
	case 1:
		s += "==="
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}
