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
	"bytes"
	"context"
	"encoding/json"
	"html/template"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/pydio/cells/v4/common"
	"github.com/pydio/cells/v4/common/client/grpc"
	"github.com/pydio/cells/v4/common/proto/idm"
	"github.com/pydio/cells/v4/common/proto/service"
	"google.golang.org/protobuf/types/known/anypb"
)

type GoogleAuthCallback struct {
}

type TokenInfo struct {
	JWT        string    `json:"JWT"`
	ExpireTime int64     `json:"ExpireTime"`
	Token      TokenData `json:"Token"`
}

type TokenData struct {
	AccessToken string `json:"AccessToken"`
	IDToken     string `json:"IDToken"`
	ExpiresAt   string `json:"ExpiresAt"`
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

	accessToken := token.AccessToken

	// 获取用户信息
	userInfo, err := fetchGoogleUserInfo(accessToken)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	email := userInfo["email"]
	// 检查用户是否存在 否则新建
	if isOK := userExists(email.(string)); !isOK {
		err := createUser(email.(string), "1234567890")
		if err != nil {
			http.Error(w, "Failed to get user info", http.StatusInternalServerError)
			return
		}
	}
	// 登录
	resp, err := loginUser(email.(string), "1234567890")
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	// 登录完, 生成cookie, 并且重定向到index 页面
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, err := template.New("loading").Parse(Loader)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	var tokenInfo TokenInfo
	err = json.Unmarshal([]byte(resp), &tokenInfo)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	byteToken, err := json.Marshal(tokenInfo.Token)
	if err != nil {
		http.Error(w, "Failed to get user info", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(200)
	TokenCfg := struct {
		MyToken string
	}{
		MyToken: string(byteToken),
	}
	tmpl.Execute(w, TokenCfg)
	// fmt.Fprintf(w, "resp = %s\n", resp)
}

func longGrpcCallTimeout() grpc.Option {
	var d time.Duration
	d = 60 * time.Minute
	return grpc.WithCallTimeout(d)
}

func loginUser(email string, password string) (string, error) {
	authInfo := map[string]string{
		"login":    email,
		"password": password,
		"type":     "credentials",
	}
	loginRequest := map[string]interface{}{
		"AuthInfo": authInfo,
	}
	jsonLoingRequest, err := json.Marshal(loginRequest)
	if err != nil {
		return "", err
	}
	resp, err := http.Post("http://localhost/a/frontend/session", "application/json", bytes.NewBuffer(jsonLoingRequest))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 读取响应
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func createUser(email string, password string) error {
	r := service.ResourcePolicyAction_READ
	w := service.ResourcePolicyAction_WRITE
	allow := service.ResourcePolicy_allow
	policies := []*service.ResourcePolicy{
		{Action: r, Effect: allow, Subject: "profile:standard"},
		{Action: w, Effect: allow, Subject: "user:" + email},
		{Action: w, Effect: allow, Subject: "profile:admin"},
	}

	newUser := &idm.User{
		Login:      email,
		GroupPath:  "/",
		Password:   password,
		Policies:   policies,
		Attributes: map[string]string{"profile": common.PydioProfileStandard},
	}
	ctx := context.Background()
	userClient := idm.NewUserServiceClient(grpc.GetClientConnFromCtx(ctx, common.ServiceUser))
	response, err := userClient.CreateUser(ctx, &idm.CreateUserRequest{User: newUser})
	if err != nil {
		return err
	}
	u := response.GetUser()
	// Create corresponding role with correct policies
	newRole := idm.Role{
		Uuid:     u.Uuid,
		Policies: policies,
		UserRole: true,
		Label:    "User " + u.Login + " role",
	}
	roleClient := idm.NewRoleServiceClient(grpc.GetClientConnFromCtx(ctx, common.ServiceRole))
	if _, err := roleClient.CreateRole(context.Background(), &idm.CreateRoleRequest{
		Role: &newRole,
	}); err != nil {
		return err
	}
	return nil
}

func userExists(email string) bool {
	ctx := context.Background()
	client := idm.NewUserServiceClient(grpc.GetClientConnFromCtx(ctx, common.ServiceUser, longGrpcCallTimeout()))
	query, _ := anypb.New(&idm.UserSingleQuery{
		Login: email,
	})
	stream, err := client.SearchUser(context.Background(), &idm.SearchUserRequest{
		Query: &service.Query{
			SubQueries: []*anypb.Any{query},
			Limit:      int64(0),
			Offset:     int64(100),
		},
	})
	if err != nil {
		return false
	}

	currNb := 0

	for {
		response, err := stream.Recv()
		if err != nil {
			break
		}
		userName := response.User.Login
		if userName == email {
			return true
		}
		currNb++
	}
	return false
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

var Loader = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Save Data and Redirect</title>
</head>
<body>
    <h1>loading</h1>
    <script>
        // 页面加载时执行
        document.addEventListener('DOMContentLoaded', function() {
            // 将数据保存到 localStorage
            localStorage.setItem('token4', {{.MyToken}});
            // 打印确认信息（仅用于调试）
            console.log('数据已保存到 localStorage');
            // 跳转到 index 页面
            window.location.href = 'index';
        });
    </script>
</body>
</html>
`
