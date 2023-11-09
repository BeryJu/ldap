package ldap

import (
	"net"
	"os/exec"
	"strings"
	"testing"
)

type compareKnownValues struct{}

func (compareKnownValues) Compare(boundDN string, req CompareRequest, conn net.Conn) (LDAPResultCode, error) {
	if req.dn != "cn=myUser,dc=example,dc=com" {
		// unknown dn
		return LDAPResultCompareFalse, nil
	}

	for _, ava := range req.ava {
		if ava.attributeDesc != "myAttribute" || ava.assertionValue != "myValue" {
			// unheld assertion
			return LDAPResultCompareFalse, nil
		}
	}

	return LDAPResultCompareTrue, nil
}

func TestCompareTrue(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindAnonOK{})
	s.CompareFunc("", compareKnownValues{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapcompare", "-v", "-H", ldapURL, "-x", "cn=myUser,dc=example,dc=com", "myAttribute:myValue")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "Compare Result: Compare True") {
			t.Errorf("ldapcompare failed: %v", string(out))
		}
	})
}

func TestCompareFalse(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindAnonOK{})
	s.CompareFunc("", compareKnownValues{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapcompare", "-v", "-H", ldapURL, "-x", "cn=myUser,dc=example,dc=com", "myAttribute:wrongValue")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "Compare Result: Compare False") {
			t.Errorf("ldapcompare failed: %v", string(out))
		}
	})
}
