package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var loginForm = `
<!DOCTYPE html>
<html>
	<body>
		<form action="/auth" method="post">
			<label for="username">Username:</label><br>
			<input type="text" id="username" name="username"><br>
			<label for="password">Password:</label><br>
			<input type="password" id="password" name="password"><br>
			<input type="submit" value="Submit">
		</form>
	</body>
</html>
`

func generateChallenge() string {
	b := make([]byte, 16)
	io.ReadFull(rand.Reader, b)
	return base64.StdEncoding.EncodeToString(b)
}

func generateResponse(challenge, username, password string) string {
	h := hmac.New(md5.New, []byte(password))
	h.Write([]byte(challenge))
	response := fmt.Sprintf("%s %s", username, hex.EncodeToString(h.Sum(nil)))
	return base64.StdEncoding.EncodeToString([]byte(response))
}

func verifyResponse(challenge, response, username, password string) bool {
	expectedResponse := generateResponse(challenge, username, password)
	return response == expectedResponse
}

func cramMd5Auth(w http.ResponseWriter, r *http.Request) {
	const (
		username = "admin"
		password = "password"
	)

	auth := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

	if len(auth) != 2 || auth[0] != "CRAM-MD5" {
		challenge := generateChallenge()
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`CRAM-MD5 challenge="%s"`, challenge))
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	response := strings.Trim(auth[1], `"`)
	challenge := strings.SplitN(w.Header().Get("WWW-Authenticate"), "=", 2)[1]

	if !verifyResponse(challenge, response, username, password) {
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hello, %s!", username)
}

func loginFormHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, loginForm)
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username != "admin" || password != "password" {
		http.Error(w, "Unauthorized.", http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Hello, %s!", username)
}

func main() {
	http.HandleFunc("/", loginFormHandler)
	http.HandleFunc("/auth", authHandler)
	http.ListenAndServe(":8080", nil)
}
