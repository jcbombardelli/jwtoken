package jwtoken

import (
	"crypto/rsa"
	"io/ioutil"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

// keys are held in global variables
// i havn't seen a memory corruption/info leakage in go yet
// but maybe it's a better idea, just to store the public key in ram?
// and load the signKey on every signing request? depends on  your usage i guess
var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

//LoadPrivateKey -
func LoadPrivateKey(privKeyPath string) (*rsa.PrivateKey, error) {

	signBytes, err := ioutil.ReadFile(privKeyPath)
	if err != nil {
		return nil, err
	}

	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	if err != nil {
		return nil, err
	}

	return signKey, nil
}

//LoadPublicKey -
func LoadPublicKey(pubKeyPath string) (*rsa.PublicKey, error) {

	verifyBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		return nil, err
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	if err != nil {
		return nil, err
	}
	return verifyKey, nil
}

//GenerateToken -
func GenerateToken(subscriber string, hoursTokenToExpire int64, privKeyPath string) (string, error) {

	// create a signer for rsa 256
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	claims := token.Claims.(jwt.MapClaims)

	claims["exp"] = time.Now().Add(time.Hour * time.Duration(hoursTokenToExpire)).Unix()
	claims["iat"] = time.Now().Unix()
	claims["sub"] = subscriber

	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return "", err
	}
	return tokenString, nil
}
