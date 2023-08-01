package auditlog

import (
	"fmt"
	"testing"
)

func TestXxx(t *testing.T) {
	token := createJwtToken(
		`{"alg":"HS256","typ":"JWT"}`,
		`h4BZAwLabAzMBi49LGHU5wqLJp/P4tl+t10VqKMk1Cg=`,
		`{"Application":null,"DisplayName":"v.DisplayName","Email":"v.Email","Group":null,"account":"admin","exp":1690892592,"orig_iat":1690856592}`,
	)

	fmt.Println(token)

	header, payload, verification, _ := preprocessJWT(token, "")
	fmt.Println(header)
	fmt.Println(payload)
	fmt.Println(verification)

	verified, _ := verifyJWT(header, payload, verification, "h4BZAwLabAzMBi49LGHU5wqLJp/P4tl+t10VqKMk1Cg=")

	fmt.Println(verified)

	// TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoicG9zdGdyZXMiLCJpYXQiOjE1MTYyMzkwMjJ9.GWZVubmH2_II_206DuGfoefoTSaPpk_rWLarthE2UWA"

}
