package server

import (
	"log"

	"github.com/pkg/errors"

	"github.com/cloudldap/goldap/message"
	ldapserver "github.com/cloudldap/ldapserver"
	"github.com/go-ldap/ldap"
)

func handleSearch(s *Server, w ldapserver.ResponseWriter, m *ldapserver.Message) {
	r := m.GetSearchRequest()

	timeLimit := s.config.TimoutInSeconds
	requestedTimeLimit := r.TimeLimit().Int()
	if requestedTimeLimit < s.config.TimoutInSeconds {
		timeLimit = requestedTimeLimit
	}

	baseDN := string(r.BaseObject())
	scope := int(r.Scope())
	filter := string(r.FilterString())
	attrs := make([]string, len(r.Attributes()))
	for i, v := range r.Attributes() {
		attrs[i] = string(v)
	}
	sizeLimit := 1000 // TODO configurable
	requestSizeLimit := int(r.SizeLimit())
	if requestSizeLimit > 0 {
		sizeLimit = requestSizeLimit
	}

	currentUser := GetAuthSession(m).DN

	log.Printf("info: [%s] handleSearch baseDN=%s, scope=%d, requestedSizeLimit=%d, filter=%s, attributes=%s, requestedTimeLimit=%d, timeLimit=%d",
		currentUser, baseDN, scope, requestSizeLimit, filter, attrs, requestedTimeLimit, timeLimit)

	search := ldap.NewSearchRequest(
		baseDN,
		scope,
		ldap.NeverDerefAliases,
		sizeLimit, // Size Limit
		timeLimit, // Time Limit
		false,
		filter, // The filter to apply
		attrs,  // A list attributes to retrieve
		nil,
	)

	conn, err := s.GetBackendConn(m, currentUser)
	if err != nil {
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnwillingToPerform)
		w.Write(res)
		return
	}

	err = ldapsearch(conn, search, uint32(sizeLimit), func(sr *ldap.SearchResult) error {
		for _, v := range sr.Entries {
			entry := ldapserver.NewSearchResultEntry(v.DN)

			for _, vv := range v.Attributes {
				av := make([]message.AttributeValue, len(vv.Values))
				for i, vvv := range vv.Values {
					av[i] = message.AttributeValue(vvv)
				}
				entry.AddAttribute(message.AttributeDescription(vv.Name), av...)
			}

			w.Write(entry)
		}
		return nil
	})
	if err != nil {
		if ldapError, ok := err.(*ldap.Error); ok {
			res := ldapserver.NewSearchResultDoneResponse(int(ldapError.ResultCode))
			w.Write(res)
			return
		} else {
			log.Printf("error: Unexpected backend search error: %v", err)

			res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultUnavailable)
			w.Write(res)
			return
		}
	}

	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)
}

func ldapsearch(conn *ldap.Conn, searchRequest *ldap.SearchRequest, pagingSize uint32, callback func(*ldap.SearchResult) error) error {
	var pagingControl *ldap.ControlPaging

	control := ldap.FindControl(searchRequest.Controls, ldap.ControlTypePaging)
	if control == nil {
		pagingControl = ldap.NewControlPaging(pagingSize)
		searchRequest.Controls = append(searchRequest.Controls, pagingControl)
	} else {
		castControl, ok := control.(*ldap.ControlPaging)
		if !ok {
			return errors.Errorf("expected paging control to be of type *ControlPaging, got %v", control)
		}
		if castControl.PagingSize != pagingSize {
			return errors.Errorf("paging size given in search request (%d) conflicts with size given in search call (%d)", castControl.PagingSize, pagingSize)
		}
		pagingControl = castControl
	}

	searchResult := new(ldap.SearchResult)
	for {
		result, err := conn.Search(searchRequest)
		log.Printf("Looking for Paging Control...")
		if err != nil {
			return err
		}
		if result == nil {
			return ldap.NewError(ldap.ErrorNetwork, errors.New("ldap: packet not received"))
		}

		err = callback(result)
		if err != nil {
			return err
		}

		for _, referral := range result.Referrals {
			searchResult.Referrals = append(searchResult.Referrals, referral)
		}
		for _, control := range result.Controls {
			searchResult.Controls = append(searchResult.Controls, control)
		}

		log.Printf("Looking for Paging Control...")
		pagingResult := ldap.FindControl(result.Controls, ldap.ControlTypePaging)
		if pagingResult == nil {
			pagingControl = nil
			log.Printf("Could not find paging control.  Breaking...")
			break
		}

		cookie := pagingResult.(*ldap.ControlPaging).Cookie
		if len(cookie) == 0 {
			pagingControl = nil
			log.Printf("Could not find cookie.  Breaking...")
			break
		}
		pagingControl.SetCookie(cookie)
	}

	if pagingControl != nil {
		log.Printf("Abandoning Paging...")
		pagingControl.PagingSize = 0
		conn.Search(searchRequest)
	}

	return nil
}
