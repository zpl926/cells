/*
 * Copyright (c) 2023. Abstrium SAS <team (at) pydio.com>
 * This file is part of Pydio Cells.
 *
 * Pydio Cells is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Pydio Cells is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Pydio Cells.  If not, see <http://www.gnu.org/licenses/>.
 *
 * The latest code can be found at <https://pydio.com>.
 */

package google

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type GoogleAuthCallback struct {
}

func NewGoogleAuthCallback(ctx context.Context) *GoogleAuthCallback {
	return &GoogleAuthCallback{}
}

func (h *GoogleAuthCallback) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("state") != "oauthStateString" {
		http.Error(w, "Invalid OAuth state", http.StatusBadRequest)
		return
	}
	code := r.FormValue("code")
	token, err := googleOAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Code exchange failed", http.StatusInternalServerError)
		return
	}

	refreshToken := token.RefreshToken
	accessToken := token.AccessToken

	// idToken := token.Extra("id_token")
	// if idToken == nil {
	// 	http.Error(w, "ID Token not found", http.StatusInternalServerError)
	// 	return
	// }

	// 解析ID令牌以获取用户信息
	// var claims map[string]interface{}
	// if err := json.NewDecoder(strings.NewReader(idToken.(string))).Decode(&claims); err != nil {
	// 	http.Error(w, "Failed to parse ID token", http.StatusInternalServerError)
	// 	return
	// }

	// 获取用户信息
	userInfo, err := fetchGoogleUserInfo(accessToken)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "User Info: access token = %s, refresh token = %s user Info = %v\n", accessToken, refreshToken, userInfo)
}

func fetchGoogleUserInfo(accessToken string) (map[string]interface{}, error) {
	// 使用 access_token 请求用户信息
	req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}
