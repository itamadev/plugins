package dexidp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/answerdev/answer/plugin"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-github/github"
	"github.com/itamadev/plugins/connector/dexidp/i18n"
	"github.com/segmentfault/pacman/log"
	"golang.org/x/oauth2"
)

type Connector struct {
	Config *ConnectorConfig
}

type ConnectorConfig struct {
	DexIssuer    string `json:"dex_issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	AuthorizeUrl string `json:"authorize_url"`
	TokenUrl     string `json:"token_url"`
}

func init() {
	plugin.Register(&Connector{
		Config: &ConnectorConfig{},
	})
}

func (d *Connector) Info() plugin.Info {
	return plugin.Info{
		Name:        plugin.MakeTranslator(i18n.InfoName),
		SlugName:    "dexidp_connector",
		Description: plugin.MakeTranslator(i18n.InfoDescription),
		Author:      "itamadev",
		Version:     "0.0.1",
		Link:        "https://github.com/itamadev/plugins/tree/main/connector/dexidp",
	}
}

func (d *Connector) ConnectorLogoSVG() string {
	return `PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4PSIwcHgiIHk9IjBweCIgd2lkdGg9IjI5OHB4IiBoZWlnaHQ9IjEwOXB4IiB2aWV3Qm94PSIwIDAgMjk4IDEwOSIgZW5hYmxlLWJhY2tncm91bmQ9Im5ldyAwIDAgMjk4IDEwOSIgeG1sOnNwYWNlPSJwcmVzZXJ2ZSI+PGc+PGc+PHBhdGggZmlsbD0iIzIzMUYyMCIgZD0iTTE4My41MzcsNjcuNjQ1YzAtNS4wNDUsMC43NzctOS41NjEsMi4zMzItMTMuNTU2YzEuNTU1LTMuOTkyLDMuNjE0LTcuMzc3LDYuMTc5LTEwLjE1MSAgICBjMi41NjQtMi43NzQsNS40ODYtNC44OTYsOC43NjQtNi4zNjhjMy4yNzktMS40NjksNi42ODQtMi4yMDYsMTAuMjE0LTIuMjA2YzMuODY2LDAsNy4zMzQsMC42NzQsMTAuNDA0LDIuMDE3ICAgIGMzLjA2NywxLjM0Niw1LjYzMSwzLjI3OSw3LjY5Miw1LjgwMWMyLjA1OCwyLjUyMiwzLjYzNCw1LjU0OSw0LjcyOCw5LjA3OWMxLjA5MiwzLjUzMiwxLjY0LDcuNDg0LDEuNjQsMTEuODU0ICAgIGMwLDIuMjY5LTAuMTI2LDQuMTYxLTAuMzc4LDUuNjczSDE5My43NWMwLjQyMSw2LjY0MiwyLjQ2LDExLjg5Nyw2LjExNiwxNS43NjNjMy42NTgsMy44NjksOC40MjcsNS44MDEsMTQuMzEzLDUuODAxICAgIGMyLjk0MSwwLDUuNjUzLTAuNDQxLDguMTMzLTEuMzI0YzIuNDc5LTAuODgzLDQuODU1LTIuMDM4LDcuMTI1LTMuNDY3bDMuNjU2LDYuODA4Yy0yLjY5MiwxLjY4My01LjY3MywzLjE1My04Ljk1Myw0LjQxNCAgICBjLTMuMjc4LDEuMjYxLTcuMDIxLDEuODkxLTExLjIyMiwxLjg5MWMtNC4xMjEsMC03Ljk2Ni0wLjczNi0xMS41MzktMi4yMDZjLTMuNTc0LTEuNDctNi42ODQtMy41NzMtOS4zMzEtNi4zMDUgICAgYy0yLjY0OC0yLjczMS00LjcyOS02LjA3Mi02LjI0Mi0xMC4wMjVDMTg0LjI5Myw3Ny4xODcsMTgzLjUzNyw3Mi42ODksMTgzLjUzNyw2Ny42NDV6IE0yMjYuNDEsNjIuOTggICAgYzAtNi4zMDUtMS4zMjQtMTEuMTE3LTMuOTcxLTE0LjQzOWMtMi42NDgtMy4zMjEtNi4zNjgtNC45ODEtMTEuMTU5LTQuOTgxYy0yLjE4NywwLTQuMjY5LDAuNDQxLTYuMjQyLDEuMzI0ICAgIGMtMS45NzYsMC44ODMtMy43NjMsMi4xNDUtNS4zNiwzLjc4NGMtMS41OTgsMS42MzktMi45MjIsMy42NTYtMy45NzEsNi4wNTJjLTEuMDUzLDIuMzk3LTEuNzQ2LDUuMTUyLTIuMDgyLDguMjYxSDIyNi40MXoiLz48cGF0aCBmaWxsPSIjMjMxRjIwIiBkPSJNMjU1Ljc5LDY2LjEzMmwtMTguNTM2LTI5LjI1NmgxMS4yMjJsOC4xOTYsMTMuNDkzYzAuOTI0LDEuNjgzLDEuODkxLDMuMzg1LDIuOSw1LjEwOCAgICBjMS4wMSwxLjcyNCwyLjA2LDMuNDI2LDMuMTUzLDUuMTA2aDAuNTA0YzAuOTI0LTEuNjgsMS44NDktMy4zODIsMi43NzQtNS4xMDZjMC45MjUtMS43MjMsMS44NDktMy40MjUsMi43NzUtNS4xMDhsNy40NC0xMy40OTMgICAgaDEwLjg0NGwtMTguNTM2LDMwLjM5bDE5LjkyMywzMC44OTVoLTExLjIyMmwtOC45NTMtMTQuMjVjLTEuMDk0LTEuODQ3LTIuMTg3LTMuNjk3LTMuMjc5LTUuNTQ5ICAgIGMtMS4wOTQtMS44NDctMi4yMjgtMy42NTYtMy40MDQtNS40MjFoLTAuNTA0Yy0xLjA5NCwxLjc2NS0yLjE0NSwzLjU1Mi16My4xNTMsNS4zNThjLTEuMDA5LDEuODA5LTIuMDE3LDMuNjgtMy4wMjYsNS42MTIgICAgbC04LjMyMywxNC4yNUgyMzUuNzRMMjU1Ljc5LDY2LjEzMnoiLz48cGF0aCBmaWxsPSIjMjMxRjIwIiBkPSJNMTgxLjExNiw5MS4xODljLTEuMDkxLDAuMjQzLTEuNTc2LDAuMjQzLTIuMTgyLDAuMjQzYy0xLjI1MywwLTIuNDEyLTAuOTA4LTIuNzEtMy4xNzRWOC4zNzhoLTEwLjQ2NyAgICB2MjMuNTgxbDAuNDQ5LDkuMjk4djEuMTI0Yy0yLjY3Mi0yLjE2NC01LjMwMi0zLjg3NS03Ljg4OC01LjEyN2MtMi42MDgtMS4yNjEtNS42NzUtMS44OTEtOS4yMDctMS44OTEgICAgYy0zLjUzLDAtNi44OTMsMC43NTYtMTAuMDg4LDIuMjY5Yy0zLjE5NiwxLjUxNC02LjAxMSwzLjY1OC04LjQ0OSw2LjQzMWMtMi40MzksMi43NzQtNC4zOTQsNi4xNTktNS44NjQsMTAuMTUxICAgIGMtMS40NzIsMy45OTUtMi4yMDYsOC40NzEtMi4yMDYsMTMuNDNjMCwxMC4yNTgsMi4yOSwxOC4xNTgsNi44NzMsMjMuNzA3YzQuNTgxLDUuNTQ5LDEwLjczOSw4LjMyMywxOC40NzMsOC4zMjMgICAgYzMuNjE0LDAsNi45OTktMC44NjIsMTAuMTUyLTIuNTg1YzMuMTUyLTEuNzIzLDUuOTQ2LTMuNzYyLDguMzg2LTYuMTE2aDAuMTg5YzEuMDA2LDUuNjUsNC4xNDQsOC43MDEsMTAuMTc1LDguNzAxICAgIGMyLjY2NywwLDQuMzY0LTAuMzYzLDUuNjk3LTAuOTY5TDE4MS4xMTYsOTEuMTg5eiBNMTY1Ljc1Nyw4Mi41MjVjLTIuNTIyLDIuODU5LTUuMDQzLDQuOTgxLTcuNTY1LDYuMzY4ICAgIGMtMi41MjMsMS4zODctNS4yMTUsMi4wOC04LjA3LDIuMDhjLTUuMzgyLDAtOS41NDItMi4wNTgtMTIuNDg1LTYuMTc5Yy0yLjk0NC00LjExOC00LjQxNC05Ljg3Ni00LjQxNC0xNy4yNzUgICAgYzAtMy41MywwLjQ2Mi02LjcyNSwxLjM4OC05LjU4M2MwLjkyNC0yLjg1NywyLjE4NC01LjMxNiwzLjc4Mi03LjM3N2MxLjU5Ni0yLjA2LDMuNDY3LTMuNjU4LDUuNjEyLTQuNzkyICAgIGMyLjE0My0xLjEzNSw0LjQzMy0xLjcwMiw2Ljg3My0xLjcwMmMyLjUyMiwwLDQuOTgsMC40ODUsNy4zNzcsMS40NWMyLjM5NSwwLjk2OCw0Ljg5NSwyLjYyOSw3LjUwMiw0Ljk4MVY4Mi41MjV6Ii8+PC9nPjxnPjxwYXRoIGZpbGw9IiM0NDlGRDgiIGQ9Ik05My4wMTIsNTEuODc4YzcuNTg4LTMuNTUsMTIuNzY0LTEwLjQ5LDE0LjE3NS0xOC41M0MxMDEuMDYzLDE5LjY5OSw4OS4zMjksOS4zNTgsNzQuNzYsNS4xNTUgICAgYzQuOTIzLDcuMTMzLDcuMjcyLDE1LjU4Myw2Ljc3MSwyNC4xN0M4Ny45NzgsMzQuNzcsOTIuMzgzLDQyLjg1NCw5My4wMTIsNTEuODc4eiBNMzEuOTM3LDM4Ljg0NSAgICBjLTguMjA3LTEuMDQ1LTE2LjMzMywxLjk3My0yMS44NTgsOC4wNTRjLTIuMTgzLDE1LjA4OCwyLjQ1NywzMC4yNDUsMTIuNjg3LDQxLjU2M2MtMC41MjctOC42NCwxLjg1Ni0xNy4zMDYsNi44MzEtMjQuNDgzICAgIEMyNi44NTcsNTUuMzUyLDI3Ljk4Nyw0Ni4yNDgsMzEuOTM3LDM4Ljg0NXogTTM3LjY3Nyw3Ny4yMzFjLTIuOTk3LDguMDc5LTEuNzU1LDE3LjE5MywzLjY0MiwyNC4yMTUgICAgYzEyLjE1NSw0Ljk0MywyNi4wNTEsNS4xNDYsMzguNjQzLTAuMDM1Yy03LjgxOC0yLjUxNi0xNC44ODYtNy41MTgtMTkuODg3LTE0LjczMUM1MS45LDg2LjUzMyw0My43OTEsODMuMzM2LDM3LjY3Nyw3Ny4yMzF6ICAgICBNNjcuNzg4LDIyLjUwNmMtMS41MDYtOC4xNTgtNy4wNTMtMTUuMzgzLTE1LjIyOS0xOC43MzJDMzguNDQ1LDYuMDE1LDI1LjQxMSwxNC4yNywxNy40MjYsMjYuOTM1ICAgIGM4LjExNS0yLjQ4NywxNi43NC0yLjE3OCwyNC41MjksMC42MzlDNDkuNDgyLDIyLjMxMiw1OC43MSwyMC40NDgsNjcuNzg4LDIyLjUwNnogTTkwLjU1Nyw2Ni43NjEgICAgYy0zLjA4Niw3LjM5OS04LjcyMiwxMy4xODgtMTUuNjc4LDE2LjYxYzYuMTk0LDUuNjA0LDE0LjgwNSw3Ljc1OCwyMi44NTIsNS44MzRjOS4wNTQtOS41ODcsMTMuODg0LTIyLjE5OCwxMy45LTM1LjAwOSAgICBDMTA2LjIxNSw2MC41MDIsOTguNzk3LDY0Ljk3NCw5MC41NTcsNjYuNzYxeiIvPjxnPjxjaXJjbGUgZmlsbD0iI0YwNEQ1QyIgY3g9IjYwLjcwMiIgY3k9IjU0LjE5NiIgcj0iMTUuOTcyIi8+PC9nPjwvZz48L2c+PC9zdmc+`
}

func (d *Connector) ConnectorName() plugin.Translator {
	return plugin.MakeTranslator(i18n.ConnectorName)
}

func (d *Connector) ConnectorSlugName() string {
	return "dexidp"
}

func (d *Connector) ConnectorSender(ctx *plugin.GinContext, receiverURL string) (redirectURL string) {
	provider, err := oidc.NewProvider(ctx, d.Config.DexIssuer)
	if err != nil {
		fmt.Errorf("failed to query provider %s: %v", d.Config.DexIssuer, err)
		return ""
	}
	oauth2Config := &oauth2.Config{
		ClientID:     d.Config.ClientID,
		ClientSecret: d.Config.ClientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  receiverURL,
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email", "groups"},
	}
	return oauth2Config.AuthCodeURL("state")
}

func (d *Connector) ConnectorReceiver(ctx *plugin.GinContext, receiverURL string) (userInfo plugin.ExternalLoginUserInfo, err error) {
	code := ctx.Query("code")
	provider, err := oidc.NewProvider(ctx, d.Config.DexIssuer)
	if err != nil {
		fmt.Errorf("failed to query provider %s: %v", d.Config.DexIssuer, err)
	}

	// Exchange code for token
	oauth2Config := &oauth2.Config{
		ClientID:     d.Config.ClientID,
		ClientSecret: d.Config.ClientSecret,
		Endpoint:     provider.Endpoint(),
	}
	token, err := oauth2Config.Exchange(context.Background(), code)
	if err != nil {
		return userInfo, fmt.Errorf("code exchange failed: %s", err.Error())
	}

	// Exchange token for user info
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token.AccessToken},
	))
	client.Timeout = 15 * time.Second
	cli := github.NewClient(client)
	resp, _, err := cli.Users.Get(context.Background(), "")
	if err != nil {
		return userInfo, fmt.Errorf("failed getting user info: %s", err.Error())
	}

	metaInfo, _ := json.Marshal(resp)
	userInfo = plugin.ExternalLoginUserInfo{
		ExternalID:  fmt.Sprintf("%d", resp.GetID()),
		DisplayName: resp.GetName(),
		Username:    resp.GetLogin(),
		Email:       resp.GetEmail(),
		MetaInfo:    string(metaInfo),
		Avatar:      resp.GetAvatarURL(),
	}

	// guarantee email was verified
	userInfo.Email = d.guaranteeEmail(userInfo.Email, token.AccessToken)
	return userInfo, nil
}

func (d *Connector) guaranteeEmail(email string, accessToken string) string {
	if len(email) == 0 {
		return ""
	}
	client := oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: accessToken},
	))
	client.Timeout = 15 * time.Second
	cli := github.NewClient(client)

	emails, _, err := cli.Users.ListEmails(context.Background(), &github.ListOptions{Page: 1})
	if err != nil {
		log.Error(err)
		return ""
	}
	for _, e := range emails {
		if e.GetEmail() == email && e.GetVerified() {
			log.Infof("email %s was verified", email)
			return email
		}
	}
	return ""
}

func (d *Connector) ConfigFields() []plugin.ConfigField {
	return []plugin.ConfigField{
		{
			Name:        "dex_issuer",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigDexIssuerTitle),
			Description: plugin.MakeTranslator(i18n.ConfigDexIssuerDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: d.Config.DexIssuer,
		},
		{
			Name:        "auth_url",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigAuthURLTitle),
			Description: plugin.MakeTranslator(i18n.ConfigAuthURLDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: d.Config.AuthorizeUrl,
		},
		{
			Name:        "token_url",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigTokenURLTitle),
			Description: plugin.MakeTranslator(i18n.ConfigTokenURLDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: d.Config.TokenUrl,
		},
		{
			Name:        "client_id",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigClientIDTitle),
			Description: plugin.MakeTranslator(i18n.ConfigClientIDDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: d.Config.ClientID,
		},
		{
			Name:        "client_secret",
			Type:        plugin.ConfigTypeInput,
			Title:       plugin.MakeTranslator(i18n.ConfigClientSecretTitle),
			Description: plugin.MakeTranslator(i18n.ConfigClientSecretDescription),
			Required:    true,
			UIOptions: plugin.ConfigFieldUIOptions{
				InputType: plugin.InputTypeText,
			},
			Value: d.Config.ClientSecret,
		},
	}
}

func (d *Connector) ConfigReceiver(config []byte) error {
	c := &ConnectorConfig{}
	_ = json.Unmarshal(config, c)
	d.Config = c
	return nil
}
