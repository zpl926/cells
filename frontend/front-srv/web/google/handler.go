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
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

var (
	googleOAuthConfig = &oauth2.Config{
		RedirectURL: "https://frs.forthtech.io/google/auth/callback",
		Scopes:      []string{"openid", "profile", "email"},
		Endpoint:    google.Endpoint,
	}
)

type GoogleAuthHandler struct {
}

func NewGoogleAuthHandler(ctx context.Context) *GoogleAuthHandler {
	return &GoogleAuthHandler{}
}

func NewGoogleAuthCallback(ctx context.Context) *GoogleAuthCallback {
	return &GoogleAuthCallback{}
}

// ServeHTTP 重定向到google identity 接口
func (h *GoogleAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	url := googleOAuthConfig.AuthCodeURL("oauthStateString")
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}
