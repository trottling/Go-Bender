package main

import (
	"encoding/json"
	"fmt"

	"gopkg.in/resty.v1"
)

func CheckVulnersKey(key string) (bool, error) {
	type Response struct {
		Result string `json:"result"`
		Data   struct {
			Valid bool `json:"valid"`
		} `json:"data"`
	}

	response := Response{}

	client := resty.New()
	resp, err := client.R().Post("https://vulners.com/api/v3/apiKey/valid/?keyID=" + key)
	if err != nil {
		return false, fmt.Errorf("error checking key: %v", err)
	}
	if resp.StatusCode() != 200 {
		return false, fmt.Errorf("error checking key: resp status %v", resp.Status())
	}
	if err = json.Unmarshal(resp.Body(), &response); err != nil {
		return false, fmt.Errorf("error checking key: %v", err)
	}

	return response.Data.Valid, nil
}
