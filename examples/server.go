// +build ignore

package main

import (
	"log"
	"net"

	"github.com/nmcclain/ldap"
)

/////////////
// Sample searches you can try against this simple LDAP server:
//
// ldapsearch -H ldap://localhost:3389 -x -b 'dn=test,dn=com'
// ldapsearch -H ldap://localhost:3389 -x -b 'dn=test,dn=com' 'cn=ned'
// ldapsearch -H ldap://localhost:3389 -x -b 'dn=test,dn=com' 'uidnumber=5000'
/////////////

///////////// Run a simple LDAP server
func main() {
	s := ldap.NewServer()

	// register Bind and Search function handlers
	handler := ldapHandler{}
	s.BindFunc("", handler)
	s.SearchFunc("", handler)

	// start the server
	listen := "localhost:3389"
	log.Printf("Starting example LDAP server on %s", listen)
	if err := s.ListenAndServe(listen); err != nil {
		log.Fatalf("LDAP Server Failed: %s", err.Error())
	}
}

type ldapHandler struct{}

///////////// Allow anonymous binds only
func (h ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

///////////// Return some hardcoded search results - we'll respond to any baseDN for testing
func (h ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	entries := []*ldap.Entry{
		{"cn=ned," + searchReq.BaseDN, []*ldap.EntryAttribute{
			{"cn", []string{"ned"}},
			{"uidNumber", []string{"5000"}},
			{"accountStatus", []string{"active"}},
			{"uid", []string{"ned"}},
			{"description", []string{"ned"}},
			{"objectClass", []string{"posixAccount"}},
		}},
		{"cn=trent," + searchReq.BaseDN, []*ldap.EntryAttribute{
			{"cn", []string{"trent"}},
			{"uidNumber", []string{"5005"}},
			{"accountStatus", []string{"active"}},
			{"uid", []string{"trent"}},
			{"description", []string{"trent"}},
			{"objectClass", []string{"posixAccount"}},
		}},
	}
	return ldap.ServerSearchResult{entries, []string{}, []ldap.Control{}, ldap.LDAPResultSuccess}, nil
}
