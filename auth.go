package server

import (
	"context"

	ldapserver "github.com/cloudldap/ldapserver"
	"github.com/pkg/errors"
)

const authContextKey string = "auth"

func AuthSessionContext(ctx context.Context) (*AuthSession, error) {
	v := ctx.Value(authContextKey)

	session, ok := v.(*AuthSession)
	if !ok {
		return nil, errors.Errorf("No authSession in the context")
	}

	return session, nil
}

type AuthSession struct {
	DN string
}

func GetSession(m *ldapserver.Message) map[string]interface{} {
	store := m.Client.GetCustomData()
	if sessionMap, ok := store.(map[string]interface{}); ok {
		return sessionMap
	} else {
		sessionMap := map[string]interface{}{}
		m.Client.SetCustomData(sessionMap)
		return sessionMap
	}
}

func GetAuthSession(m *ldapserver.Message) *AuthSession {
	session := GetSession(m)
	if authSession, ok := session["auth"]; ok {
		return authSession.(*AuthSession)
	} else {
		authSession := &AuthSession{}
		session["auth"] = authSession
		return authSession
	}
}

func GetPageSession(m *ldapserver.Message) map[string]int32 {
	session := GetSession(m)
	if pageSession, ok := session["page"]; ok {
		return pageSession.(map[string]int32)
	} else {
		pageSession := map[string]int32{}
		session["page"] = pageSession
		return pageSession
	}
}
