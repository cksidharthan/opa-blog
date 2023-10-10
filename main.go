package main

import (
	"context"
	"fmt"
	"github.com/cksidharthan/go-jaeger/pkg/client"
	"github.com/cksidharthan/go-jaeger/pkg/trace"
	"github.com/gin-gonic/gin"
	"github.com/open-policy-agent/opa/rego"
	"github.com/sirupsen/logrus"
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	r := gin.Default()
	r.Use(OpaMiddlware())

	traceClient, err := client.New(&client.Opts{
		CollectorURL: "http://localhost:14268/api/traces",
		ServiceName:  "test_service",
		Environment:  "dev",
		Logger:       logrus.StandardLogger(),
	})
	if err != nil {
		fmt.Println(err)
	}

	defer traceClient.Disconnect(context.Background())

	r.GET("/ping", func(c *gin.Context) {
		methodTrace := trace.NewTraceWithContext(context.Background())
		defer methodTrace.Close()

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
