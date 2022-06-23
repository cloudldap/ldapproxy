module github.com/cloudldap/ldapproxy

go 1.18

require github.com/go-ldap/ldap v3.0.3+incompatible

require github.com/pkg/errors v0.9.1

require (
	github.com/cloudldap/goldap/message v0.0.0-20220624044827-7916bfae1b74 // indirect
	github.com/cloudldap/ldapserver v1.1.0 // indirect
)

require (
	github.com/comail/colog v0.0.0-20160416085026-fba8e7b1f46c
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
)

// replace github.com/cloudldap/goldap/message => ../goldap/message
// replace github.com/cloudldap/ldapserver => ../ldapserver
