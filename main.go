package main

import (
	"log"
	"os"

	"github.com/genians/kc-ssh-pam/internal/auth"
	"github.com/genians/kc-ssh-pam/internal/conf"
	"github.com/genians/kc-ssh-pam/internal/flags"
)

var (
	version   string
	buildDate string
	commitSha string
)

func main() {
	flags.ParseFlags(version, buildDate, commitSha)
	c, err := conf.LoadConfig()
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	providerEndpoint := c.Endpoint + "/realms/" + c.Realm
	username := os.Getenv("PAM_USER")

	// Analyze the input from stdIn and split the password if it containcts "/"  return otp and pass
	password, otp, err := auth.ReadPasswordWithOTP()
	if err != nil {
		log.Fatal(err)
	}

	client, err := auth.CreateHTTPClient(c.ProxyURL)
	if err != nil {
		log.Fatal(err)
	}

	// Get provider configuration
	provider, err := auth.GetProviderInfo(providerEndpoint, client)
	if err != nil {
		log.Fatalf("Failed to retrieve provider configuration for provider %v with error %v\n", providerEndpoint, err)
	}

	// Retrieve an OIDC token using the password grant type
	accessToken, err := auth.RequestJWT(username, password, otp, provider.TokenURL, c.ClientID, c.ClientSecret, c.ClientScope, client)
	if err != nil {
		log.Fatalf("Failed to retrieve token for %v - error: %v\n", username, err)
		os.Exit(2)
	}

	// Verify the token and retrieve claims
	claims, err := provider.VerifyToken(accessToken, client)
	if err != nil {
		log.Fatalf("Failed to verify token: %v for user %v", err, username)
		os.Exit(3)
	}

	// Authorize based on required role
	if err := provider.AuthorizeTokenByClientRole(claims, c.ClientID, c.ClientRole); err != nil {
		log.Fatalf("Authorization failed: %v", err)
		os.Exit(4)
	}

	log.Println("Token acquired and verified Successfully for user -", username)
}
