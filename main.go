package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/couchbase/gocb"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

// Account struct is a DTO containing account information which is
// stored in the database
type Account struct {
	Type    string `json:"type,omitempty"`
	Pid     string `json:"pid,omitempty"`
	Email   string `json:"email,omitempty"`
	Pasword string `json:"password,omitempty"`
}

// Profile struct is a DTO containing profile information which is
// stored in the database
type Profile struct {
	Type      string `json:"type,omitempty"`
	Firstname string `json:"firstname,omitempty"`
	Lastname  string `json:"lastname,omitempty"`
}

// Session struct is a DTO containing session information which is
// stored in the database
type Session struct {
	Type      string `json:"type,omitempty"`
	Pid       string `json:"pid,omitempty"`
	Title     string `json:"title,omitempty"`
	Content   string `json:"content,omitempty"`
	Timestamp int    `json:"timestamp,omitempty"`
}

// Blog struct is a DTO containing Blog information which is
// stored in the database
type Blog struct {
	Type      string `json:"type,omitempty"`
	Pid       string `json:"pid,omitempty"`
	Title     string `json:"title,omitempty"`
	Content   string `json:"content,omitempty"`
	Timestamp int    `json:"timestamp,omitempty"`
}

var bucket *gocb.Bucket

func main() {
	fmt.Println("Starting the server")
	router := mux.NewRouter()
	cluster, _ := gocb.Connect("couchbase://localhost")
	bucket, _ = cluster.OpenBucket("default", "")
	router.HandleFunc("/account", RegisterEndpoint).Methods("POST")
	router.HandleFunc("/login", LoginEndpoint).Methods("POST")
	router.HandleFunc("/account", Validate(AccountEndpoint)).Methods("GET")
	router.HandleFunc("/blogs", Validate(BlogsEndpoint)).Methods("GET")
	router.HandleFunc("/blog", Validate(BlogEndpoint)).Methods("POST")
	log.Fatal(http.ListenAndServe(":3000", handlers.CORS(handlers.AllowedHeaders([]string{"X-Requested-With", "Content-Type", "Authorization"}), handlers.AllowedMethods([]string{"GET", "POST", "PUT", "HEAD", "OPTIONS"}), handlers.AllowedOrigins([]string{"*"}))(router)))
}
