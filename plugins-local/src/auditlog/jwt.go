package auditlog

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Payload struct {
	Account string `json:"account"`
	Exp     int64  `json:"exp"`
	OrigIat int64  `json:"orig_iat"`
}

func createJwtToken(header, secret, payload string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	message := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)

	return fmt.Sprintf(
		"%s.%s",
		message,
		base64.RawURLEncoding.EncodeToString(expectedMAC),
	)
}

// verifyJWT Verifies jwt token with secret
func verifyJWT(header, payload, verification, secret string) (bool, error) {

	mac := hmac.New(sha256.New, []byte(secret))
	message := header + "." + payload
	mac.Write([]byte(message))
	expectedMAC := mac.Sum(nil)

	decodedVerification, errDecode := base64.RawURLEncoding.DecodeString(verification)
	if errDecode != nil {
		return false, errDecode
	}

	if hmac.Equal(decodedVerification, expectedMAC) {
		return true, nil
	}
	return false, nil
	// TODO Add time check to jwt verification
}

func verifyJwtHeader(headerToken string, prefix string, secret string) (verified bool, pay Payload, err error) {

	if len(headerToken) == 0 {
		err = fmt.Errorf("request error: Can Not get Token")
		return
	}

	header, payload, verification, err := preprocessJWT(headerToken, prefix)
	if err != nil {
		err = fmt.Errorf("request err: %s", err)
		return
	}

	verified, err = verifyJWT(header, payload, verification, secret)
	if err != nil {
		err = fmt.Errorf("not allowed err: %s", err)
		return
	}

	exp, pay, err := checkJwtExp(payload)
	if err != nil {
		err = fmt.Errorf("checkJwtExp err: %s", err)
		return
	}

	if exp {
		err = fmt.Errorf("expired token")
		return
	}

	return
}

func checkJwtExp(payload string) (exp bool, pay Payload, err error) {
	decpay, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return
	}

	json.Unmarshal(decpay, &pay)

	if pay.Exp != 0 && pay.Exp < time.Now().Unix() {
		exp = true
	}

	return

}

// preprocessJWT Takes the request header string, strips prefix and whitespaces and returns a Token
func preprocessJWT(reqHeader string, prefix string) (header string, payload string, verification string, err error) {
	// fmt.Println("==> [processHeader] SplitAfter")
	// structuredHeader := strings.SplitAfter(reqHeader, "Bearer ")[1]
	cleanedString := strings.TrimPrefix(reqHeader, prefix)
	cleanedString = strings.TrimSpace(cleanedString)
	// fmt.Println("<== [processHeader] SplitAfter", cleanedString)

	tokenSplit := strings.Split(cleanedString, ".")

	if len(tokenSplit) != 3 {
		err = fmt.Errorf("invalid token %d", len(tokenSplit))
		return
	}
	header = tokenSplit[0]
	payload = tokenSplit[1]
	verification = tokenSplit[2]
	return
}
