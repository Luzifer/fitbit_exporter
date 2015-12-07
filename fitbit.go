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
	"sort"
	"time"

	"github.com/flosch/pongo2"
	"github.com/satori/go.uuid"
)

type fitBitSubscriptionUpdate struct {
	CollectionType string `json:"collectionType"`
	Date           string `json:"date"`
	OwnerID        string `json:"ownerId"`
}

type fitBitBodyData struct {
	Date  string `json:"date"`
	Time  string `json:"time"`
	LogID int64  `json:"logId"`

	// Weight data
	BMI    float64 `json:"bmi"`
	Weight float64 `json:"weight"`

	// Fat data
	Fat float64 `json:"fat"`
}

type fitBitBodyDataByLogID []fitBitBodyData

func (b fitBitBodyDataByLogID) Len() int           { return len(b) }
func (b fitBitBodyDataByLogID) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }
func (b fitBitBodyDataByLogID) Less(i, j int) bool { return b[i].LogID < b[j].LogID }

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
	}
	subscriptionURL := fmt.Sprintf("/user/-/apiSubscriptions/%d.json", userData.Users[userID].SubscriberID)
	if err := fitBitHTTPRequest(userData.Users[userID].AccessToken, "POST", subscriptionURL, nil, nil); err != nil {
		log.Printf("ERR: Unable to register subscriber: %s", err)
		http.Redirect(res, r, "/", http.StatusFound)
		return
	}

	userData.Save()

	userData.Users[userID].RefreshActivityData(fitBitSubscriptionUpdate{Date: time.Now().Format("2006-01-02")})
	userData.Users[userID].RefreshWeightData(fitBitSubscriptionUpdate{Date: time.Now().Format("2006-01-02")})

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
			log.Printf("Got valid verification code: %s", r.URL.Query().Get("verify"))
			res.WriteHeader(204)
			return
		} else {
			log.Printf("Got invalid verification code: %s", r.URL.Query().Get("verify"))
			res.WriteHeader(404)
			return
		}
	}

	// Handle subscription messages
	res.WriteHeader(204)

	updates := []fitBitSubscriptionUpdate{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		log.Printf("Subscriber: Unexpected payload: %s", err)
		return
	}

	for _, u := range updates {
		switch u.CollectionType {
		case "activities":
			if usr, ok := userData.Users[u.OwnerID]; ok {
				go usr.RefreshActivityData(u)
			}
		case "body":
			if usr, ok := userData.Users[u.OwnerID]; ok {
				go usr.RefreshWeightData(u)
			}
		}
	}
}

func fitBitHTTPRequest(token, method, apiCall string, body io.Reader, result interface{}) error {
	req, _ := http.NewRequest(method, "https://api.fitbit.com/1"+apiCall, body)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept-Language", "de_DE")
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

	if res.User.EncodedID == "" {
		return "", fmt.Errorf("Invalid User-ID received")
	}

	return res.User.EncodedID, nil
}

func (u *userDBEntry) UpdateAccessToken() error {
	u.accessTokenLock.Lock()

	if u.AccessTokenRefreshedAt.After(time.Now().Add(-45 * time.Minute)) {
		u.accessTokenLock.Unlock()
		return nil
	}

	params := url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{u.RefreshToken},
	}
	req, _ := http.NewRequest("POST", "https://api.fitbit.com/oauth2/token", bytes.NewBuffer([]byte(params.Encode())))
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	res := struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		Errors       []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}
	if res.AccessToken == "" {
		return fmt.Errorf("Something went wrong: %+v", res)
	}

	u.RefreshToken = res.RefreshToken
	u.AccessToken = res.AccessToken
	u.AccessTokenRefreshedAt = time.Now()

	userData.Save()

	u.accessTokenLock.Unlock()
	return nil
}

func (u *userDBEntry) RefreshActivityData(update fitBitSubscriptionUpdate) error {
	if update.Date != time.Now().Format("2006-01-02") {
		// Drop old updates
		return nil
	}

	if err := u.UpdateAccessToken(); err != nil {
		return err
	}

	d := struct {
		Summary struct {
			Steps     int `json:"steps"`
			Calories  int `json:"caloriesOut"`
			Distances []struct {
				Activity string  `json:"activity"`
				Distance float64 `json:"distance"`
			} `json:"distances"`
			Floors int `json:"floors"`
		} `json:"summary"`
	}{}

	err := fitBitHTTPRequest(u.AccessToken, "GET", fmt.Sprintf("/user/-/activities/date/%s.json", update.Date), nil, &d)
	if err != nil {
		log.Printf("ERR: Unable to fetch activity data: %s", err)
		return err
	}

	u.CurrentValues.Steps = d.Summary.Steps
	u.Metrics.TotalSteps.Set(float64(d.Summary.Steps))
	u.Metrics.DailySteps.Set(float64(d.Summary.Steps))

	u.CurrentValues.Calories = d.Summary.Calories
	u.Metrics.Calories.Set(float64(d.Summary.Calories))

	u.CurrentValues.Floors = d.Summary.Floors
	u.Metrics.Floors.Set(float64(d.Summary.Floors))

	for _, v := range d.Summary.Distances {
		if v.Activity == "total" {
			u.CurrentValues.Distance = v.Distance
			u.Metrics.Distance.Set(v.Distance)
		}
	}

	userData.Save()

	return nil
}

func (u *userDBEntry) RefreshWeightData(update fitBitSubscriptionUpdate) error {
	if update.Date != time.Now().Format("2006-01-02") {
		// Drop old updates
		return nil
	}

	if err := u.UpdateAccessToken(); err != nil {
		return err
	}

	d := struct {
		Weight []fitBitBodyData `json:"weight"`
		Fat    []fitBitBodyData `json:"fat"`
	}{}

	if err := fitBitHTTPRequest(u.AccessToken, "GET", fmt.Sprintf("/user/-/body/log/weight/date/%s/7d.json", update.Date), nil, &d); err != nil {
		log.Printf("ERR: Unable to fetch weight data: %s", err)
		return err
	}

	if err := fitBitHTTPRequest(u.AccessToken, "GET", fmt.Sprintf("/user/-/body/log/fat/date/%s/7d.json", update.Date), nil, &d); err != nil {
		log.Printf("ERR: Unable to fetch fat data: %s", err)
		return err
	}

	sort.Sort(sort.Reverse(fitBitBodyDataByLogID(d.Weight)))
	sort.Sort(sort.Reverse(fitBitBodyDataByLogID(d.Fat)))

	if len(d.Weight) > 0 {
		u.CurrentValues.Weight = d.Weight[0].Weight
		u.Metrics.Weight.Set(d.Weight[0].Weight)
	}

	if len(d.Fat) > 0 {
		u.CurrentValues.BodyFat = d.Fat[0].Fat
		u.Metrics.BodyFat.Set(d.Fat[0].Fat)
	}

	userData.Save()

	return nil
}
