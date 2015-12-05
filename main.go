package main

import (
	"log"
	"net/http"
	"net/url"

	"github.com/Luzifer/rconfig"
	"github.com/flosch/pongo2"
	"github.com/gorilla/mux"
)

var (
	cfg = struct {
		ClientID               string `flag:"client-id" default:"" description:"The 'OAuth 2.0 Client ID' of your application"`
		ClientSecret           string `flag:"client-secret" default:"" description:"The corresponding 'Client (Consumer) Secret'"`
		SubscriberVerification string `flag:"verification" default:"" description:"The verification code for this subscriber"`
		RedisConnectionString  string `flag:"redis" default:"" description:"Connection string for Redis database"`
		Listen                 string `flag:"listen" default:":3000" description:"IP/Port to listen on"`
		SelfBaseURL            string `flag:"baseurl" default:"" description:"Base URL where to find this instance"`
	}{}

	userData      *userDB
	metricsRouter *mux.Router
	err           error

	version = "dev"
)

type fitBitAuthorizationAnswer struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

func init() {
	if err := rconfig.Parse(&cfg); err != nil {
		log.Fatalf("Unable to parse CLI parameters: %s", err)
	}

	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		log.Fatalf("You need to provide your client credentials")
	}

	if cfg.RedisConnectionString == "" {
		log.Fatal("You need to provide a Redis connection string")
	}

	if cfg.SelfBaseURL == "" {
		log.Fatal("You need to provide the BaseURL")
	}
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", handleLandingPage)
	r.HandleFunc("/fitbit/callback", handleFitBitCallback)
	r.HandleFunc("/fitbit/subscription", handleSubscription)

	metricsRouter = r.PathPrefix("/metrics").Subrouter()

	if userData, err = loadUserDBFromRedis(cfg.RedisConnectionString); err != nil {
		log.Fatal("Unable to load user database: %s", err)
	}

	http.ListenAndServe(cfg.Listen, r)
}

func handleLandingPage(res http.ResponseWriter, r *http.Request) {
	params := url.Values{
		"response_type": []string{"code"},
		"client_id":     []string{cfg.ClientID},
		"redirect_url":  []string{cfg.SelfBaseURL + "fitbit/callback"},
		"scope":         []string{"activity profile weight nutrition settings sleep"},
	}
	authorizeURL := "https://www.fitbit.com/oauth2/authorize?" + params.Encode()
	renderTemplate(res, "landing", pongo2.Context{
		"authorizeURL": authorizeURL,
	})
}

func renderTemplate(res http.ResponseWriter, templateName string, ctx pongo2.Context) error {
	tpl, err := pongo2.FromFile("templates/" + templateName + ".html")
	if err != nil {
		return err
	}
	return tpl.ExecuteWriter(ctx, res)
}
