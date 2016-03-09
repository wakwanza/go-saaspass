package saaspass

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"
)

// Generate a dummy session id to use in generating qr codes
func NewSessionID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	uuid[8] = uuid[8]&^0xc0 | 0x80
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return fmt.Sprintf("%x0%x1%x2%x3%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

func TestCredentials(t *testing.T) {
	cr := new(APICredentials).SetCredentials()
	if cr == (APICredentials{}) {
		t.Fatalf("No ENV")
	}
}

func TestAuthentication(t *testing.T) {
	m := new(APICredentials).SetCredentials()
	au := new(AuthToken).GetAuth(m)
	if au == (AuthToken{}) {
		t.Fatalf("Falls Over No Auth")
	}
}

func TestOTP(t *testing.T) {
	apr := new(AuthPair).GeneratePair()
	_, err := apr.CheckOTP("myname@mydomain.xyz", "239144")
	if err != nil {
		fmt.Println(err)
	}
}

func TestBarcode(t *testing.T) {
	sess, _ := NewSessionID()
	apr := new(AuthPair).GeneratePair()
	if apr.CheckTokenLife() {
		bcd := &BarCode{Session: sess, CodeType: "ILBT", User: "myname@mydomain.xyz"}
		_, err := apr.GetBarCodeImage(bcd)
		if err != nil {
			t.Fatalf("BarCode generation failed")
		}
	}

}
