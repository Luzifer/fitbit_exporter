package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/xuyu/goredis"
)

type userDB struct {
	Users                 map[string]*userDBEntry
	MaxSubscriptionID     int
	redisConnectionString string `json:"-"`
}

type userDBEntry struct {
	// FitBit stuff
	RefreshToken           string
	AccessToken            string
	AccessTokenRefreshedAt time.Time
	SubscriberID           int

	// Application stuff
	Secret string

	CurrentValues struct {
		Weight  float64
		BodyFat float64

		Steps    int
		Calories int
		Distance int
		Floors   int
	}

	// In memory storage
	Metrics struct {
		IsInitialized bool
		// body
		Weight  prometheus.Gauge
		BodyFat prometheus.Gauge
		// activity
		Steps    prometheus.Counter
		Calories prometheus.Counter
		Distance prometheus.Counter
		Floors   prometheus.Counter
	} `json:"-"`
}

const redisUserDBStorageKey = "io.luzifer.fitbit_exporter::userDB"

func (u *userDBEntry) InitializeMetrics(userID string) {
	u.Metrics.Weight = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "fitbit_weight",
		Help: "Weight",
		ConstLabels: prometheus.Labels{
			"userID": userID,
		},
	})
	u.Metrics.BodyFat = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "fitbit_bodyfat",
		Help: "Body fat percentage",
		ConstLabels: prometheus.Labels{
			"userID": userID,
		},
	})

	u.Metrics.Steps = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fitbit_steps",
		Help: "Step count",
		ConstLabels: prometheus.Labels{
			"userID": userID,
		},
	})
	u.Metrics.Calories = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fitbit_calories",
		Help: "Calories used",
		ConstLabels: prometheus.Labels{
			"userID": userID,
		},
	})
	u.Metrics.Distance = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fitbit_distance",
		Help: "Distance",
		ConstLabels: prometheus.Labels{
			"userID": userID,
		},
	})
	u.Metrics.Floors = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "fitbit_floors",
		Help: "Floors climbed",
		ConstLabels: prometheus.Labels{
			"userID": userID,
		},
	})

	u.Metrics.Weight.Set(u.CurrentValues.Weight)
	u.Metrics.BodyFat.Set(u.CurrentValues.BodyFat)
	u.Metrics.Steps.Set(float64(u.CurrentValues.Steps))
	u.Metrics.Calories.Set(float64(u.CurrentValues.Calories))
	u.Metrics.Distance.Set(float64(u.CurrentValues.Distance))
	u.Metrics.Floors.Set(float64(u.CurrentValues.Floors))

	prometheus.MustRegister(u.Metrics.BodyFat)
	prometheus.MustRegister(u.Metrics.Weight)
	prometheus.MustRegister(u.Metrics.Steps)
	prometheus.MustRegister(u.Metrics.Calories)
	prometheus.MustRegister(u.Metrics.Distance)
	prometheus.MustRegister(u.Metrics.Floors)

	metricsRouter.Handle(fmt.Sprintf("/%s/%s", userID, u.Secret), prometheus.Handler())
	u.Metrics.IsInitialized = true
}

func (u *userDB) Save() error {
	rConn, err := goredis.DialURL(u.redisConnectionString)
	if err != nil {
		return err
	}

	jsonRaw, err := json.Marshal(u)
	if err != nil {
		return err
	}

	return rConn.Set(redisUserDBStorageKey, string(jsonRaw), 0, 0, false, false)
}

func loadUserDBFromRedis(redisConnectionString string) (*userDB, error) {
	rConn, err := goredis.DialURL(redisConnectionString)
	if err != nil {
		return nil, err
	}

	jsonRaw, err := rConn.Get(redisUserDBStorageKey)
	if err != nil {
		return nil, err
	}

	u := userDB{
		Users: map[string]*userDBEntry{},
		redisConnectionString: redisConnectionString,
	}
	if len(jsonRaw) != 0 {
		if err := json.Unmarshal(jsonRaw, &u); err != nil {
			return nil, err
		}
	}

	for userID, v := range u.Users {
		v.InitializeMetrics(userID)
	}

	return &u, nil
}
