package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/flosch/pongo2"
	"github.com/satori/go.uuid"
)

func handleFitBitCallback(res http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	params := url.Values{
		"code":         []string{code},
		"client_id":    []string{cfg.ClientID},
		"redirect_url": []string{cfg.SelfBaseURL + "fitbit/callback"},
		"grant_type":   []string{"authorization_code"},
	}
	req, _ := http.NewRequest("POST", "https://api.fitbit.com/oauth2/token", bytes.NewReader([]byte(params.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("ERR: Unable to get authorization: %s", err)
		http.Redirect(res, r, "/", http.StatusFound)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Printf("ERR: Unable to get authorization (HTTP Status %d)", resp.StatusCode)
		http.Redirect(res, r, "/", http.StatusFound)
		return
	}

	auth := fitBitAuthorizationAnswer{}
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		log.Printf("ERR: Unable to get authorization: %s", err)
		http.Redirect(res, r, "/", http.StatusFound)
		return
	}

	userID, err := extractFitBitProfileID(auth.AccessToken)
	if err != nil {
		log.Printf("ERR: Unable to get profile information: %s", err)
		http.Redirect(res, r, "/", http.StatusFound)
		return
	}

	ud := userDBEntry{
		Secret: uuid.NewV4().String(),
	}
	if _, ok := userData.Users[userID]; !ok {
		userData.Users[userID] = &ud
	}

	userData.Users[userID].AccessToken = auth.AccessToken
	userData.Users[userID].AccessTokenRefreshedAt = time.Now()
	userData.Users[userID].RefreshToken = auth.RefreshToken

	if !userData.Users[userID].Metrics.IsInitialized {
		userData.Users[userID].InitializeMetrics(userID)
	}

	if userData.Users[userID].SubscriberID == 0 {
		userData.MaxSubscriptionID++
		userData.Users[userID].SubscriberID = userData.MaxSubscriptionID
		if err := fitBitHTTPRequest(
			userData.Users[userID].AccessToken,
			"POST", fmt.Sprintf("/user/-/apiSubscriptions/%d.json", userData.Users[userID].SubscriberID),
			nil, nil); err != nil {
			log.Printf("ERR: Unable to register subscriber: %s", err)
			http.Redirect(res, r, "/", http.StatusFound)
			return
		}
	}

	userData.Save()

	renderTemplate(res, "authorized", pongo2.Context{
		"secret":  userData.Users[userID].Secret,
		"userID":  userID,
		"baseURL": cfg.SelfBaseURL,
	})
}

func handleSubscription(res http.ResponseWriter, r *http.Request) {
	// Handle verification of the subscriber
	if r.URL.Query().Get("verify") != "" {
		if r.URL.Query().Get("verify") == cfg.SubscriberVerification {
			res.WriteHeader(204)
			return
		} else {
			res.WriteHeader(404)
			return
		}
	}

}

func fitBitHTTPRequest(token, method, apiCall string, body io.Reader, result interface{}) error {
	req, _ := http.NewRequest(method, "https://api.fitbit.com/1"+apiCall, body)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		io.Copy(os.Stderr, resp.Body)
		return fmt.Errorf("Unexpected HTTP status: %d", resp.StatusCode)
	}

	defer resp.Body.Close()
	if result == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(result)
}

func extractFitBitProfileID(token string) (string, error) {
	res := struct {
		User struct {
			EncodedID string `json:"encodedId"`
		} `json:"user"`
	}{}
	err := fitBitHTTPRequest(token, "GET", "/user/-/profile.json", nil, &res)
	if err != nil {
		return "", err
	}

	log.Printf("DBG: %+v", res)

	if res.User.EncodedID == "" {
		return "", fmt.Errorf("Invalid User-ID received")
	}

	return res.User.EncodedID, nil
}
