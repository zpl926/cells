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
	"fmt"
	"net/http"
)

type GoogleAuthCallback struct {
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

	idToken := token.Extra("id_token")
	if idToken == nil {
		http.Error(w, "ID Token not found", http.StatusInternalServerError)
		return
	}

	// 解析ID令牌以获取用户信息
	// var claims map[string]interface{}
	// if err := json.NewDecoder(strings.NewReader(idToken.(string))).Decode(&claims); err != nil {
	// 	http.Error(w, "Failed to parse ID token", http.StatusInternalServerError)
	// 	return
	// }

	fmt.Fprintf(w, "User Info: access token = %s, refresh token = %s\n", accessToken, refreshToken)
}
