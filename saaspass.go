package saaspass

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	sl "github.com/dghubble/sling"
)

const baseURL = "https://www.saaspass.com/sd/rest/applications/"

type Config struct {
	APIkey, APIpass string
}

var (
	conf *Config
)

type AuthToken struct {
	Token string `json:"token"`
}

type AuthPair struct {
	APIKey, Token string
	TeaTime       time.Time
}

type APICredentials struct {
	APIKey, APIPass string
}

type OTPCode struct {
	User, Totp string
}

type BarCode struct {
	Session  string `json:"session"`
	CodeType string `json:"codetype"`
	Tracker  string `json:"tracker"`
	User     string `json:"user"`
}

type CallResponse struct {
	Name, Message, Informationlink string
}

type BCImage struct {
	Barcodeimage string `json:"barcodeimage"`
}

// Set the API credentials acquired from the environment variables
// or from the config file in /etc/saaspass.json returns a APICredential
// object containing the API key and API password
func (s *APICredentials) SetCredentials() APICredentials {
	if conf.APIkey == "" && conf.APIpass == "" {
		log.Println("Unable to determine SAASPASS credentials.")
	}
	return APICredentials{conf.APIkey, conf.APIpass}
}

// Call the server API endpoint to generate the authentication token
// returns a token for accessing the REST API
func (a *AuthToken) GetAuth(m APICredentials) AuthToken {
	at := [2]AuthToken{}
	sPath := fmt.Sprintf("%s/tokens?password=%s", m.APIKey, m.APIPass)
	_, err := sl.New().Base(baseURL).Set("User-Agent", "GO REST/1.0").Get(sPath).ReceiveSuccess(&at[0])
	if err != nil {
		log.Fatalln("Failure in getting SAASPASS AUTH TOKEN.")
	} else if err == nil {
		return at[0]
	}
	return at[1]
}

// Store the session token and app credentials after successful
// authentication
func (a *AuthPair) GeneratePair() AuthPair {
	m := new(APICredentials).SetCredentials()
	au := new(AuthToken).GetAuth(m)
	return AuthPair{m.APIKey, au.Token, time.Now()}
}

// Check token lifetime if current
func (a *AuthPair) CheckTokenLife() bool {
	duration := time.Since(a.TeaTime)
	if duration.Seconds() > 3000 {
		return false
	}
	return true
}

// Send user id and generated one time password to be checked for validity
// returns status of check and error message
func (apr AuthPair) CheckOTP(user string, ocode string) (bool, error) {
	otc := OTPCode{user, ocode}
	cback := [3]CallResponse{}
	sPath := fmt.Sprintf("%s/otpchecks?username=%s&otp=%s&token=%s", apr.APIKey, otc.User, otc.Totp, apr.Token)
	resp, err := sl.New().Base(baseURL).Set("User-Agent", "GO REST/1.0").Get(sPath).Receive(&cback[0], &cback[1])
	if err != nil {
		log.Fatalln("Error processing OTP check.")
	}
	if resp.StatusCode == 200 && cback[0] == cback[2] {
		return true, nil
	}
	return false, fmt.Errorf("%v", cback[1].Name)
}

// Generate qr barcode image as base64 encoded string returns the barcode
// as well as any errors generated
func (apr AuthPair) GetBarCodeImage(bcd *BarCode) (*BCImage, error) {
	img := &BCImage{}
	cback := [2]CallResponse{}
	sPath := fmt.Sprintf("%s/barcodes?session=%s&token=%s&type=%s", apr.APIKey, bcd.Session, apr.Token, bcd.CodeType)
	resp, err := sl.New().Base(baseURL).Set("User-Agent", "GO REST/1.0").Get(sPath).Receive(&img, &cback[0])
	if err != nil {
		log.Fatalln("Error generating barcode images.")
	}
	if resp.StatusCode == 200 && cback[0] == cback[1] {
		return img, nil
	}
	return nil, fmt.Errorf("%v", cback[0].Name)
}

// Validate session tracker sent from the qr barcode authentication
// process
func (b *BarCode) ValidateTracker(a *AuthPair) (bool, error) {
	cback := [3]CallResponse{}
	sPath := fmt.Sprintf("%s/trackers/%s?token=%s&account=%s", a.APIKey, b.Tracker, a.Token, b.User)
	resp, err := sl.New().Base(baseURL).Set("User-Agent", "GO REST/1.0").Get(sPath).Receive(&cback[0], &cback[1])
	if err != nil {
		log.Fatalln("Tracker couldnt be validated.")
	} else if err == nil && resp.StatusCode == 200 {
		return true, nil
	}
	return false, fmt.Errorf("%v", cback[1].Name)
}

// Prefer to get the API credentials from the environment variables
// then check in config file if variables not set in the ENV variables
func init() {
	var cx Config
	if os.Getenv("SAASPASS_API_KEY") == "" && os.Getenv("SAASPASS_API_PASS") == "" {
		log.Println("No SAASPASS environment variables set.Checking config file.")
		fraw, err := ioutil.ReadFile("/etc/saaspass.json")
		if err != nil {
			log.Fatalln("Couldnt open the SAASPASS API config file.")
		}
		err = json.Unmarshal(fraw, &cx)
		os.Setenv("SAASPASS_API_KEY", cx.APIkey)
		os.Setenv("SAASPASS_API_PASS", cx.APIpass)
	} else if os.Getenv("SAASPASS_API_KEY") != "" && os.Getenv("SAASPASS_API_PASS") != "" {
		cx.APIkey = os.Getenv("SAASPASS_API_KEY")
		cx.APIpass = os.Getenv("SAASPASS_API_PASS")
	}
	conf = &cx
}
