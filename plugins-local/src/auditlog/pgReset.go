package auditlog

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

// Token Deconstructed header token
type AuditLog struct {
	TIME          string `json:"time"`
	Account       string `json:"account"`
	Code          int    `json:"code"`
	RequestURI    string `json:"request_uri"`
	Host          string `json:"host"`
	RemoteAddr    string `json:"remote_addr"`
	XForwardedFor string `json:"x_forwarded_for"`
	RequestMethod string `json:"request_method"`
	RequestBody   string `json:"request_body"`
	ResponseBody  string `json:"response_body"`
}

func (a *AuthLog) PgResetClient(data []byte) {
	tr := &http.Transport{
		// Proxy:           http.ProxyFromEnvironment,
		Proxy:           nil,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * a.PgResetTimeOut, //超时时间
	}

	req, err := http.NewRequest("POST", a.PgResetUrl, bytes.NewBuffer(data))
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf("create request %s err: %s\n", a.PgResetUrl, err))
		return
	}

	token := createJwtToken(a.PgResetJwtHeader, a.PgResetJwtSecret, a.PgResetJwtPayload)

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer "+token))

	os.Stdout.WriteString(fmt.Sprintf("request %#v, a.PgResetUrl: %s token: %s\n", req, a.PgResetUrl, token))

	resp, err := client.Do(req)
	if err != nil {
		os.Stdout.WriteString(fmt.Sprintf("request %s err: %s\n", a.PgResetUrl, err))
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		os.Stdout.WriteString(fmt.Sprintf("request %#v,  body %s \n", req, body))
	}

	// body, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	return
	// }

	// os.Stdout.WriteString(fmt.Sprintf("request body %s err: %s\n", body, err))

}
