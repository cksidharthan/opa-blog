package main

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/open-policy-agent/opa/rego"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	r := gin.Default()
	r.Use(OpaMiddlware())

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "pong",
		})
	})
	r.Run()
}

func OpaMiddlware() gin.HandlerFunc {
	// open rego file
	authzFile, err := os.Open("auth.rego")
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer authzFile.Close()

	// read rego file
	module, err := io.ReadAll(authzFile)
	if err != nil {
		log.Fatalf("error reading file: %v", err)
	}

	// return middleware
	return func(c *gin.Context) {
		// prepare query
		query, err := rego.New(
			rego.Query("data.authz.allow"),
			rego.Module("authz.rego", string(module)),
		).PrepareForEval(c)
		if err != nil {
			log.Printf("error preparing query: %v\n", err)
		}

		// print the action and username headers
		log.Printf("role: %v\n", c.Request.Header.Get("role"))
		log.Printf("access: %v\n", c.Request.Header.Get("access"))

		// evaluate query
		result, err := query.Eval(context.Background(), rego.EvalInput(map[string]interface{}{
			"role":   c.Request.Header.Get("role"),
			"access": c.Request.Header.Get("access"),
		}))
		if err != nil {
			log.Printf("error evaluating query: %v\n", err)
		}

		// check if the user is allowed to access the resource
		if result[0].Expressions[0].Value == true {
			c.Next()

			return
		} else {
			c.JSON(http.StatusForbidden, gin.H{
				"message": "access forbidden",
			})

			c.Abort()

			return
		}
	}
}
