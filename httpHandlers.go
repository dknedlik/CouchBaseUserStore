package main

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/couchbase/gocb"
	"github.com/gorilla/context"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

// RegisterEndpoint creates a new account in the database
func RegisterEndpoint(w http.ResponseWriter, req *http.Request) {
	var data map[string]interface{}
	_ = json.NewDecoder(req.Body).Decode(&data)
	id := uuid.NewV4().String()
	password := data["password"].(string)
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(err.Error()))
		return
	}
	account := Account{
		Type:    "account",
		Pid:     id,
		Email:   data["email"].(string),
		Pasword: string(passwordHash),
	}
	profile := Profile{
		Type:      "profile",
		Firstname: data["firstname"].(string),
		Lastname:  data["lastname"].(string),
	}
	_, err = bucket.Insert(id, profile, 0)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(err.Error()))
		return
	}
	_, err = bucket.Insert(account.Email, account, 0)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(err.Error()))
		return
	}
	json.NewEncoder(w).Encode(account)
}

// LoginEndpoint is the interface for user to authenticate
// into the system
func LoginEndpoint(w http.ResponseWriter, req *http.Request) {
	var data Account
	var account Account

	// Read the user information from the request
	_ = json.NewDecoder(req.Body).Decode(&data)
	// Get the user account from the database
	_, err := bucket.Get(data.Email, &account)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(err.Error()))
		return
	}
	// Validate the password
	err = bcrypt.CompareHashAndPassword([]byte(account.Pasword), []byte(data.Pasword))
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(err.Error()))
		return
	}

	// if we get here the user has been authenticated. Return a JWT
	token, err := generateJwt(account)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(err.Error()))
		return
	}
	json.NewEncoder(w).Encode(token)
}

// AccountEndpoint is used to access user accounts in the system
func AccountEndpoint(w http.ResponseWriter, req *http.Request) {
	pid := context.Get(req, "pid").(string)
	var profile Profile
	_, err := bucket.Get(pid, &profile)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(err.Error()))
		return
	}
	json.NewEncoder(w).Encode(profile)
}

// BlogsEndpoint gets all the information about a blog
func BlogsEndpoint(w http.ResponseWriter, req *http.Request) {
	var n1qlParams []interface{}
	n1qlParams = append(n1qlParams, context.Get(req, "pid").(string))
	query := gocb.NewN1qlQuery("SELECT `" + bucket.Name() + "`.* FROM `" + bucket.Name() + "` WHERE type = 'blog' AND pid = $1")
	query.Consistency(gocb.RequestPlus)
	rows, err := bucket.ExecuteN1qlQuery(query, n1qlParams)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(err.Error()))
		return
	}
	var row Blog
	var result []Blog
	for rows.Next(&row) {
		result = append(result, row)
		row = Blog{}
	}
	rows.Close()
	if result == nil {
		result = make([]Blog, 0)
	}
	json.NewEncoder(w).Encode(result)
}

// BlogEndpoint creates a single blog entry
func BlogEndpoint(w http.ResponseWriter, req *http.Request) {
	var blog Blog
	_ = json.NewDecoder(req.Body).Decode(&blog)
	blog.Type = "blog"
	blog.Pid = context.Get(req, "pid").(string)
	blog.Timestamp = int(time.Now().Unix())
	_, err := bucket.Insert(uuid.NewV4().String(), blog, 0)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte(err.Error()))
		return
	}
	json.NewEncoder(w).Encode(blog)
}

// Validate acts as middleware and authenticates a users token
func Validate(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// Find the authorization header in the request
		authorizationHeader := req.Header.Get("authorization")
		if authorizationHeader == "" {
			w.WriteHeader(401)
			w.Write([]byte("An authorization header is required"))
			return
		}
		payload, err := parseAuthorization(authorizationHeader)
		if err != nil {
			w.WriteHeader(401)
			w.Write([]byte("Invalid token presented"))
			return
		}
		context.Set(req, "pid", payload.Subject)
		next(w, req)
	})
}
