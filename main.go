package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"

	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
type JWT struct {
	Token string `json:"token"`
}
type Error struct {
	Message string `json:"message"`
}

var db *sql.DB

func main() {
	pgUrl, err := pq.ParseURL("URL_HERE")

	if err != nil {
		log.Fatal(err)
	}
	db, err = sql.Open("postgres", pgUrl)

	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping()

	router := mux.NewRouter()
	router.HandleFunc("/signup", signup).Methods("POST")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/protected", TokenVerifyMiddleWare(protectedEndpoint)).Methods("GET")
	log.Println("Listen on port 8083...")
	log.Fatal(http.ListenAndServe(":8083", router))

}
func responseWithError(w http.ResponseWriter, error Error) {
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(error)
}
func responseJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
func signup(w http.ResponseWriter, r *http.Request) {
	var user User
	var error Error
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is missing"
		w.WriteHeader(http.StatusBadRequest)
		responseWithError(w, error)
		return
	}
	if user.Password == "" {
		error.Message = "Password is missing"
		responseWithError(w, error)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), 10)
	if err != nil {
		log.Fatal(err)
	}
	user.Password = string(hash)
	fmt.Println(user.Password)

	stmt := "insert into users (email, password) values ($1, $2) RETURNING id;"
	err = db.QueryRow(stmt, user.Email, user.Password).Scan(&user.ID)
	if err != nil {
		log.Fatal(err)
		error.Message = "Server Error"
		responseWithError(w, error)
		return
	}
	user.Password = ""
	responseJSON(w, user)
	// json.NewEncoder(w).Encode(user)
	// fmt.Println(user)
	// spew.Dump(user)
	// w.Write([]byte("successfully called"))
	// fmt.Println("signup invoked.")
}
func GenerateToken(user User) (string, error) {
	var err error
	secret := "secret"
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": user.Email,
		"iss":   "course",
	})
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatal(err)
	}
	return tokenString, nil
	// return "", nil
}
func login(w http.ResponseWriter, r *http.Request) {
	// var user User
	// json.NewDecoder(r.Body).Decode(&user)
	// token, err := GenerateToken(user)
	// responseJSON

	var user User
	var jwt JWT
	var error Error
	json.NewDecoder(r.Body).Decode(&user)

	if user.Email == "" {
		error.Message = "Email is missing"
		w.WriteHeader(http.StatusBadRequest)
		responseWithError(w, error)
		return
	}
	if user.Password == "" {
		error.Message = "Password is missing"
		w.WriteHeader(http.StatusBadRequest)
		responseWithError(w, error)
		return
	}

	password := user.Password
	row := db.QueryRow("select * from users where email = $1;", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)
	if err != nil {
		if err == sql.ErrNoRows {
			error.Message = "The user does not exist"
			responseWithError(w, error)
		} else {
			log.Fatal(err)
		}

	}
	hashedPassword := user.Password
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		error.Message = "Invalid password"
		responseWithError(w, error)
	}

	token, err := GenerateToken(user)
	if err != nil {
		log.Fatal(err)

	}
	w.WriteHeader(http.StatusOK)
	jwt.Token = token
	responseJSON(w, jwt)
	return
	// fmt.Println("login invoked.")
}
func protectedEndpoint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("protected endpoint invoked.")
}
func TokenVerifyMiddleWare(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var errorObject Error
		authHeader := r.Header.Get("Authorization")
		bearerToken := strings.Split(authHeader, " ")

		if len(bearerToken) == 2 {
			authToken := bearerToken[1]

			token, error := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("There was an error")
				}

				return []byte("secret"), nil
			})

			if error != nil {
				errorObject.Message = error.Error()
				responseWithError(w, errorObject)
				return
			}

			if token.Valid {
				next.ServeHTTP(w, r)
			} else {
				errorObject.Message = error.Error()
				responseWithError(w, errorObject)
				return
			}
		} else {
			errorObject.Message = "Invalid token."
			responseWithError(w, errorObject)
			return
		}
	})
}
