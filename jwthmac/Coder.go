package jwthmac

import (
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/hthl85/jwtcoder"
	"github.com/hthl85/jwtconf"
	"time"
)

// Encode encodes signed token
func Encode(conf *jwtconf.JwtHmac, userID string, scopes jwtcoder.Scopes) (string, error) {
	// Create the token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"usr":    userID,
		"iss":    conf.Issuer,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Millisecond * time.Duration(conf.ExpiryMS)).Unix(),
		"scopes": scopes,
	})

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString([]byte(conf.SigningKey))
	return tokenString, err
}

// Decode a token string into a token object
func Decode(conf *jwtconf.JwtHmac, tok string) (jwtcoder.Scopes, string, error) {
	// Parse takes the token string and a function for looking up the key.
	// The latter is especially useful if you use multiple keys for your
	// application. The standard is to use 'kid' in the head of the token
	// to identify which key to use, but the parsed token (head and claims)
	// is provided to the callback, providing flexibility.
	token, err := jwt.Parse(tok, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(conf.SigningKey), nil
	})
	if err != nil {
		return nil, "", err
	}

	if !token.Valid {
		return nil, "", errors.New("token is invalid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, "", errors.New("unable to parse token")
	}

	scopes, ok := claims["scopes"].([]interface{})
	if !ok {
		return nil, "", errors.New("unable to parse scopes")
	}

	scopeNames := make([]string, len(scopes))
	for i, name := range scopes {
		if scopeNames[i], ok = name.(string); !ok {
			return nil, "", errors.New("unable to parse scope name")
		}
	}

	userId, ok := claims["usr"].(string)
	if !ok {
		return nil, "", errors.New("unable to parse user id")
	}

	return scopeNames, userId, nil
}
