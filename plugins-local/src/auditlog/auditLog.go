package auditlog

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

	"net"
	"net/http"
	"time"
)

type Config struct {
	JwtCheck        bool   `json:"JwtCheck,omitempty"`
	JwtSecret       string `json:"jwtSecret,omitempty"`
	JwtAuthHeader   string `json:"jwtAuthHeader,omitempty"`
	JwtHeaderPrefix string `json:"jwtHeaderPrefix,omitempty"`

	NotSaveDB         bool          `json:"notSaveDB,omitempty"`
	IgnoreMethod      []string      `json:"ignoreMethod,omitempty"`
	SpecifyMethod     []string      `json:"specifyMethod,omitempty"`
	PgResetUrl        string        `json:"pgResetUrl,omitempty"`
	PgResetJwtSecret  string        `json:"pgResetJwtSecret,omitempty"`
	PgResetJwtHeader  string        `json:"PgResetJwtHeader,omitempty"`
	PgResetJwtPayload string        `json:"PgResetJwtPayload,omitempty"`
	PgResetTimeOut    time.Duration `json:"PgResetTimeOut,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type AuthLog struct {
	next            http.Handler
	JwtCheck        bool
	JwtSecret       string
	JwtAuthHeader   string
	JwtHeaderPrefix string

	NotSaveDB         bool
	IgnoreMethod      []string
	SpecifyMethod     []string
	PgResetUrl        string
	PgResetJwtSecret  string
	PgResetJwtHeader  string
	PgResetJwtPayload string
	PgResetTimeOut    time.Duration
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	fmt.Printf("Get Coifg file: %#v\n", config)

	if len(config.JwtSecret) == 0 {
		config.JwtSecret = "SECRET"
	}

	if len(config.JwtAuthHeader) == 0 {
		config.JwtAuthHeader = "Authorization"
	}
	if len(config.JwtHeaderPrefix) == 0 {
		config.JwtHeaderPrefix = "Bearer"
	}

	return &AuthLog{
		next:            next,
		JwtCheck:        config.JwtCheck,
		JwtSecret:       config.JwtSecret,
		JwtAuthHeader:   config.JwtAuthHeader,
		JwtHeaderPrefix: config.JwtHeaderPrefix,

		NotSaveDB:         config.NotSaveDB,
		PgResetUrl:        config.PgResetUrl,
		PgResetJwtSecret:  config.PgResetJwtSecret,
		PgResetTimeOut:    config.PgResetTimeOut,
		PgResetJwtHeader:  config.PgResetJwtHeader,
		PgResetJwtPayload: config.PgResetJwtPayload,
		IgnoreMethod:      config.IgnoreMethod,
		SpecifyMethod:     config.SpecifyMethod,
	}, nil
}

func (a *AuthLog) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	var account string

	if a.JwtCheck {
		headerToken := req.Header.Get(a.JwtAuthHeader)

		verified, pay, err := verifyJwtHeader(headerToken, a.JwtHeaderPrefix, a.JwtSecret)
		account = pay.Account

		if err != nil {
			http.Error(res, ErrReutnString(fmt.Sprintf("verify Token err: %s", err)), http.StatusUnauthorized)
			return
		}

		if !verified {
			http.Error(res, ErrReutnString("Not allowed"), http.StatusUnauthorized)
		}
	}

	wrappedWriter := &responseWriter{
		lastModified:   true,
		ResponseWriter: res,
	}

	a.next.ServeHTTP(wrappedWriter, req)

	// 审计日志
	// 如不保存
	if a.NotSaveDB {
		return
	}

	// 检查 req Method 是否存在于忽略列表
	for _, v := range a.IgnoreMethod {
		if req.Method == v {
			http.Error(res, ErrReutnString(fmt.Sprintf("Not allowed %s", v)), http.StatusUnauthorized)
			return
		}
	}

	// 检查 req Method 是否指定模式
	var isRun bool

	for _, v := range a.SpecifyMethod {
		if req.Method == v {

			isRun = true
		}
	}

	if len(a.SpecifyMethod) == 0 {
		isRun = true
	}

	if !isRun {
		return
	}

	// 初始化数据

	reqBody, _ := ioutil.ReadAll(req.Body)
	resBody := wrappedWriter.buffer.Bytes()
	res.Write(resBody)

	authLog := AuditLog{
		TIME:          "now()",
		Account:       account,
		RequestURI:    req.RequestURI,
		Host:          req.Host,
		Code:          wrappedWriter.code,
		RemoteAddr:    req.RemoteAddr,
		XForwardedFor: req.Header.Get("X-Forwarded-For"),
		RequestMethod: req.Method,
		RequestBody:   string(reqBody),
		ResponseBody:  string(resBody),
	}

	data, _ := json.Marshal(authLog)

	// os.Stdout.WriteString("res body: " + string(data))

	// 记录日志
	a.PgResetClient(data)

}

func ErrReutnString(data string) string {
	return fmt.Sprintf(
		`{"code": 401, "msg": "%s"}`,
		data,
	)
}

// Token Deconstructed header token

type responseWriter struct {
	buffer       bytes.Buffer
	lastModified bool
	wroteHeader  bool
	code         int

	http.ResponseWriter
}

func (r *responseWriter) WriteHeader(statusCode int) {
	if !r.lastModified {
		r.ResponseWriter.Header().Del("Last-Modified")
	}

	r.wroteHeader = true

	// Delegates the Content-Length Header creation to the final body write.
	r.ResponseWriter.Header().Del("Content-Length")
	r.code = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseWriter) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.WriteHeader(http.StatusOK)
	}

	return r.buffer.Write(p)
}

func (r *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("%T is not a http.Hijacker", r.ResponseWriter)
	}

	return hijacker.Hijack()
}

func (r *responseWriter) Flush() {
	if flusher, ok := r.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}
