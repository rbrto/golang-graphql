package main

import (
	"encoding/json"
	"net/http"
	"time"

	"gopkg.in/couchbase/gocb.v1"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"

	"github.com/graphql-go/graphql"
	uuid "github.com/satori/go.uuid"
)

type Author struct {
	Id        string `json:"id,omitempty" validate:"omitempty,uuid"`
	Firstname string `json:"firstname,omitempty" validate:"required"`
	Lastname  string `json:"lastname,omitempty" validate:"required"`
	Username  string `json:"username,omitempty" validate:"required"`
	Password  string `json:"password,omitempty" validate:"required,gte=4"`
	Type      string `json:"type,omitempty"`
}

var authorType *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Author",
	Fields: graphql.Fields{
		"id": &graphql.Field{
			Type: graphql.String,
		},
		"firstname": &graphql.Field{
			Type: graphql.String,
		},
		"lastname": &graphql.Field{
			Type: graphql.String,
		},
		"username": &graphql.Field{
			Type: graphql.String,
		},
		"password": &graphql.Field{
			Type: graphql.String,
		},
	},
})

var authorInputType *graphql.InputObject = graphql.NewInputObject(graphql.InputObjectConfig{
	Name: "AuthorInput",
	Fields: graphql.InputObjectConfigFieldMap{
		"id": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"firstname": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"lastname": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"username": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
		"password": &graphql.InputObjectFieldConfig{
			Type: graphql.String,
		},
	},
})

func RegisterEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	var author Author
	json.NewDecoder(request.Body).Decode(&author)
	validate := validator.New()
	err := validate.Struct(author)
	if err != nil {
		response.WriteHeader(500)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	author.Id = uuid.Must(uuid.NewV4()).String()
	hash, _ := bcrypt.GenerateFromPassword([]byte(author.Password), 10)
	author.Password = string(hash)
	author.Type = "author"

	_, err = bucket.Insert(author.Id, author, 0)

	if err != nil {
		response.WriteHeader(500)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	json.NewEncoder(response).Encode(author)
}

func LoginEndpoint(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("content-type", "application/json")
	var data Author
	json.NewDecoder(request.Body).Decode(&data)
	validate := validator.New()
	err := validate.StructExcept(data, "Firstname", "Lastname")
	if err != nil {
		response.WriteHeader(500)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	query := gocb.NewN1qlQuery(`SELECT ` + bucket.Name() + `.* FROM ` + bucket.Name() + ` WHERE username = $1`)
	rows, _ := bucket.ExecuteN1qlQuery(query, []interface{}{data.Username})
	var row Author
	err = rows.One(&row)
	if err != nil {
		response.WriteHeader(500)
		response.Write([]byte(`{ "message": "` + err.Error() + `" }`))
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(row.Password), []byte(data.Password))
	if err != nil {
		response.WriteHeader(500)
		response.Write([]byte(`{ "message": "invalid password" }`))
		return
	}
	claims := CustomJWTClaims{
		Id: row.Id,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour).Unix(),
			Issuer:    "robertoesparza3@gmail.com",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString(JWT_SECRET)
	response.Write([]byte(`{ "token": "` + tokenString + `" }`))
}
