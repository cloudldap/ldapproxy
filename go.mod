module github.com/cloudldap/ldapproxy

go 1.18

require github.com/go-ldap/ldap v3.0.3+incompatible

require github.com/pkg/errors v0.9.1

require (
	github.com/Songmu/retry v0.1.0 // indirect
	github.com/cloudldap/goldap/message v0.0.0-20220624044827-7916bfae1b74 // indirect
	github.com/cloudldap/ldapserver v1.1.0 // indirect
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/google/go-github v17.0.0+incompatible // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/hashicorp/go-version v1.3.0 // indirect
	github.com/mattn/go-colorable v0.1.8 // indirect
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/tcnksm/ghr v0.14.0 // indirect
	github.com/tcnksm/go-gitconfig v0.1.2 // indirect
	github.com/tcnksm/go-latest v0.0.0-20170313132115-e3007ae9052e // indirect
	golang.org/x/net v0.0.0-20210614182718-04defd469f4e // indirect
	golang.org/x/oauth2 v0.0.0-20210514164344-f6687ab2804c // indirect
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c // indirect
	golang.org/x/sys v0.0.0-20210615035016-665e8c7367d1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
)

require (
	github.com/comail/colog v0.0.0-20160416085026-fba8e7b1f46c
	gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d // indirect
)

// replace github.com/cloudldap/goldap/message => ../goldap/message
// replace github.com/cloudldap/ldapserver => ../ldapserver
