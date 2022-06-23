package server

import (
	"log"

	ldapserver "github.com/cloudldap/ldapserver"
	"github.com/go-ldap/ldap"
)

func handleBind(s *Server, w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetBindRequest()

	// Support simple bind only
	if r.AuthenticationChoice() != "simple" {
		res := ldapserver.NewBindResponse(ldap.LDAPResultUnwillingToPerform)
		res.SetDiagnosticMessage("Authentication choice not supported")
		w.Write(res)
		return
	}

	name := string(r.Name())
	input := string(r.AuthenticationSimple())

	conn, err := s.GetBackendConn(m, name)
	if err != nil {
		res := ldapserver.NewBindResponse(ldap.LDAPResultUnavailable)
		w.Write(res)
		return
	}

	err = conn.Bind(name, input)
	if err != nil {
		defer conn.Close()

		if ldapError, ok := err.(*ldap.Error); ok {
			res := ldapserver.NewBindResponse(int(ldapError.ResultCode))
			w.Write(res)
			return
		} else {
			log.Printf("error: Unexpected backend bind error: %v", err)

			res := ldapserver.NewBindResponse(ldap.LDAPResultUnavailable)
			w.Write(res)
			return
		}
	}

	saveAuthencated(m, name)

	res := ldapserver.NewBindResponse(ldap.LDAPResultSuccess)
	w.Write(res)
}

func saveAuthencated(m *ldapserver.Message, dn string) {
	session := GetAuthSession(m)
	if session.DN != "" {
		log.Printf("info: Switching authenticated user: %s -> %s", session.DN, dn)
	}
	session.DN = dn

	log.Printf("Saved authenticated DN: %s", dn)
}
