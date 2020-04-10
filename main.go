package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/handlers"

	"github.com/dgrijalva/jwt-go"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/couchbase/gocb.v1"
	"gopkg.in/go-playground/validator.v9"

	"github.com/gorilla/mux"
	"github.com/graphql-go/graphql"
	"github.com/mitchellh/mapstructure"
	uuid "github.com/satori/go.uuid"
)

type GraphQLPayload struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

type CustomJWTClaims struct {
	Id string `json:"id"`
	jwt.StandardClaims
}

var JWT_SECRET []byte = []byte("rjesparza")

var bucket *gocb.Bucket

func ValidateJWT(t string) (interface{}, error) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		return JWT_SECRET, nil
	})
	if err != nil {
		return nil, errors.New(`{ "message": "` + err.Error() + `" }`)
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		var tokenData CustomJWTClaims
		mapstructure.Decode(claims, &tokenData)
		return tokenData, nil
	} else {
		return nil, errors.New(`{ "message": "invalid token" }`)
	}
}

var rootQuery *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Query",
	Fields: graphql.Fields{
		"authors": &graphql.Field{
			Type: graphql.NewList(authorType),
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				var authors []Author
				query := gocb.NewN1qlQuery(`SELECT ` + bucket.Name() + `.* FROM ` + bucket.Name() + ` WHERE type = 'author'`)
				rows, err := bucket.ExecuteN1qlQuery(query, nil)
				if err != nil {
					return nil, err
				}
				var row Author
				for rows.Next(&row) {
					authors = append(authors, row)
				}
				return authors, nil
			},
		},
		"author": &graphql.Field{
			Type: authorType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
			},
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				id := params.Args["id"].(string)
				var author Author
				_, err := bucket.Get(id, &author)
				if err != nil {
					return nil, err
				}
				return author, nil
			},
		},
		"articles": &graphql.Field{
			Type: graphql.NewList(articleType),
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				var articles []Article
				query := gocb.NewN1qlQuery(`SELECT ` + bucket.Name() + `.* FROM ` + bucket.Name() + ` WHERE type = 'article'`)
				rows, err := bucket.ExecuteN1qlQuery(query, nil)
				if err != nil {
					return nil, err
				}
				var row Article
				for rows.Next(&row) {
					articles = append(articles, row)
				}
				return articles, nil
			},
		},
		"article": &graphql.Field{
			Type: articleType,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
			},
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				id := params.Args["id"].(string)
				var article Article
				_, err := bucket.Get(id, &article)
				if err != nil {
					return nil, err
				}
				return article, nil
			},
		},
	},
})

var rootMutation *graphql.Object = graphql.NewObject(graphql.ObjectConfig{
	Name: "Mutation",
	Fields: graphql.Fields{
		"deleteAuthor": &graphql.Field{
			Type: graphql.String,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
			},
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				id := params.Args["id"].(string)
				_, err := bucket.Remove(id, 0)
				if err != nil {
					return nil, err
				}
				return id, nil
			},
		},
		"updateAuthor": &graphql.Field{
			Type: authorType,
			Args: graphql.FieldConfigArgument{
				"author": &graphql.ArgumentConfig{
					Type: authorInputType,
				},
			},
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				var changes Author
				mapstructure.Decode(params.Args["author"], &changes)
				validate := validator.New()
				mutation := bucket.MutateIn(changes.Id, 0, 0)
				if changes.Firstname != "" {
					mutation.Upsert("firstname", changes.Firstname, true)
				}
				if changes.Lastname != "" {
					mutation.Upsert("lastname", changes.Lastname, true)
				}
				if changes.Username != "" {
					mutation.Upsert("username", changes.Username, true)
				}
				if changes.Password != "" {
					err := validate.Var(changes.Password, "gte=4")
					if err != nil {
						return nil, err
					}
					hash, _ := bcrypt.GenerateFromPassword([]byte(changes.Password), 10)
					mutation.Upsert("password", string(hash), true)
				}
				mutation.Execute()
				return changes, nil
			},
		},
		"createArticle": &graphql.Field{
			Type: articleType,
			Args: graphql.FieldConfigArgument{
				"article": &graphql.ArgumentConfig{
					Type: articleInputType,
				},
			},
			Resolve: func(params graphql.ResolveParams) (interface{}, error) {
				var article Article
				mapstructure.Decode(params.Args["article"], &article)
				decoded, err := ValidateJWT(params.Context.Value("token").(string))
				if err != nil {
					return nil, err
				}
				validate := validator.New()
				err = validate.Struct(article)
				if err != nil {
					return nil, err
				}
				article.Id = uuid.Must(uuid.NewV4()).String()
				article.Author = decoded.(CustomJWTClaims).Id
				article.Type = "article"
				bucket.Insert(article.Id, article, 0)
				return article, nil
			},
		},
	},
})

func main() {
	fmt.Println("Starting the application...")
	cluster, _ := gocb.Connect("couchbase://" + os.Getenv("COUCHBASE_HOST"))

	cluster.Authenticate(gocb.PasswordAuthenticator{
		Username: os.Getenv("COUCHDB_USER"),
		Password: os.Getenv("COUCHDB_PASSWORD"),
	})

	bucket, _ = cluster.OpenBucket(os.Getenv("COUCHBASE_BUCKET"), "")
	router := mux.NewRouter()
	schema, _ := graphql.NewSchema(graphql.SchemaConfig{
		Query:    rootQuery,
		Mutation: rootMutation,
	})
	router.HandleFunc("/register", RegisterEndpoint).Methods("POST")
	router.HandleFunc("/login", LoginEndpoint).Methods("POST")
	router.HandleFunc("/graphql", func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("content-type", "application/json")
		var payload GraphQLPayload
		json.NewDecoder(request.Body).Decode(&payload)
		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  payload.Query,
			VariableValues: payload.Variables,
			Context:        context.WithValue(context.Background(), "token", request.URL.Query().Get("token")),
		})
		json.NewEncoder(response).Encode(result)
	})
	headers := handlers.AllowedHeaders(
		[]string{
			"Content-Type",
			"Authorization",
			"X-Requested-With",
		},
	)
	methods := handlers.AllowedMethods(
		[]string{
			"GET",
			"POST",
			"PUT",
			"DELETE",
		},
	)
	origins := handlers.AllowedOrigins(
		[]string{
			"*",
		},
	)
	http.ListenAndServe(
		":8080",
		handlers.CORS(headers, methods, origins)(router),
	)
}
