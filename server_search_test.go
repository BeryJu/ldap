package ldap

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSearchSimpleOK(t *testing.T) {
	s := NewServer()
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	serverBaseDN := "o=testers,c=test"

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "uidNumber: 5000") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numResponses: 4") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
	})
}

func TestSearchSizelimit(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test") // no limit for this test
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numEntries: 3") {
			t.Errorf("ldapsearch sizelimit unlimited failed - not enough entries: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "9") // effectively no limit for this test
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numEntries: 3") {
			t.Errorf("ldapsearch sizelimit 9 failed - not enough entries: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "2")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numEntries: 2") {
			t.Errorf("ldapsearch sizelimit 2 failed - too many entries: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "1")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numEntries: 1") {
			t.Errorf("ldapsearch sizelimit 1 failed - too many entries: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "0")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numEntries: 3") {
			t.Errorf("ldapsearch sizelimit 0 failed - wrong number of entries: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "1", "(uid=trent)")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numEntries: 1") {
			t.Errorf("ldapsearch sizelimit 1 with filter failed - wrong number of entries: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-z", "0", "(uid=trent)")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numEntries: 1") {
			t.Errorf("ldapsearch sizelimit 0 with filter failed - wrong number of entries: %v", string(out))
		}
	})
}

// ///////////////////////
func TestBindSearchMulti(t *testing.T) {
	s := NewServer()
	s.BindFunc("", bindSimple{})
	s.BindFunc("c=testz", bindSimple2{})
	s.SearchFunc("", searchSimple{})
	s.SearchFunc("c=testz", searchSimple2{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test",
			"-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "cn=ned")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("error routing default bind/search functions: %v", string(out))
		}
		if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
			t.Errorf("search default routing failed: %v", string(out))
		}
		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=testz",
			"-D", "cn=testy,o=testers,c=testz", "-w", "ZLike2test", "cn=hamburger")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("error routing custom bind/search functions: %v", string(out))
		}
		if !strings.Contains(string(out), "dn: cn=hamburger,o=testers,c=testz") {
			t.Errorf("search custom routing failed: %v", string(out))
		}
	})
}

// ///////////////////////
func TestSearchPanic(t *testing.T) {
	s := NewServer()
	s.SearchFunc("", searchPanic{})
	s.BindFunc("", bindAnonOK{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 1 Operations error") {
			t.Errorf("ldapsearch should have returned operations error due to panic: %v", string(out))
		}
	})
}

// ///////////////////////
type compileSearchFilterTest struct {
	name         string
	filterStr    string
	numResponses string
}

var searchFilterTestFilters = []compileSearchFilterTest{
	{name: "equalityOk", filterStr: "(uid=ned)", numResponses: "2"},
	{name: "equalityNo", filterStr: "(uid=foo)", numResponses: "1"},
	{name: "equalityOk", filterStr: "(objectclass=posixaccount)", numResponses: "4"},
	{name: "presentEmptyOk", filterStr: "", numResponses: "4"},
	{name: "presentOk", filterStr: "(objectclass=*)", numResponses: "4"},
	{name: "presentOk", filterStr: "(description=*)", numResponses: "3"},
	{name: "presentNo", filterStr: "(foo=*)", numResponses: "1"},
	{name: "andOk", filterStr: "(&(uid=ned)(objectclass=posixaccount))", numResponses: "2"},
	{name: "andNo", filterStr: "(&(uid=ned)(objectclass=posixgroup))", numResponses: "1"},
	{name: "andNo", filterStr: "(&(uid=ned)(uid=trent))", numResponses: "1"},
	{name: "orOk", filterStr: "(|(uid=ned)(uid=trent))", numResponses: "3"},
	{name: "orOk", filterStr: "(|(uid=ned)(objectclass=posixaccount))", numResponses: "4"},
	{name: "orNo", filterStr: "(|(uid=foo)(objectclass=foo))", numResponses: "1"},
	{name: "andOrOk", filterStr: "(&(|(uid=ned)(uid=trent))(objectclass=posixaccount))", numResponses: "3"},
	{name: "notOk", filterStr: "(!(uid=ned))", numResponses: "3"},
	{name: "notOk", filterStr: "(!(uid=foo))", numResponses: "4"},
	{name: "notAndOrOk", filterStr: "(&(|(uid=ned)(uid=trent))(!(objectclass=posixgroup)))", numResponses: "3"},
	/*
		compileSearchFilterTest{filterStr: "(sn=Mill*)", filterType: FilterSubstrings},
		compileSearchFilterTest{filterStr: "(sn=*Mill)", filterType: FilterSubstrings},
		compileSearchFilterTest{filterStr: "(sn=*Mill*)", filterType: FilterSubstrings},
		compileSearchFilterTest{filterStr: "(sn>=Miller)", filterType: FilterGreaterOrEqual},
		compileSearchFilterTest{filterStr: "(sn<=Miller)", filterType: FilterLessOrEqual},
		compileSearchFilterTest{filterStr: "(sn~=Miller)", filterType: FilterApproxMatch},
	*/
}

// ///////////////////////
func TestSearchFiltering(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	done := make(chan bool)
	shortTimeout := timeout / 20

	LaunchServerForTest(t, s,
		func() {
			for _, i := range searchFilterTestFilters {
				t.Log(i.name)

				go func() {
					cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
						"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", i.filterStr)
					out, _ := cmd.CombinedOutput()
					if !strings.Contains(string(out), "numResponses: "+i.numResponses) {
						t.Errorf("ldapsearch failed - expected numResponses==%s: %v", i.numResponses, string(out))
					}
					done <- true
				}()

				select {
				case <-done:
				case <-time.After(shortTimeout):
					t.Errorf("ldapsearch command timed out")
				}
			}
		})
}

// ///////////////////////
func TestSearchAttributes(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	LaunchServerForTest(t, s, func() {
		filterString := ""
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", filterString, "cn")
		out, _ := cmd.CombinedOutput()

		if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
			t.Errorf("ldapsearch failed - missing requested DN attribute: %v", string(out))
		}
		if !strings.Contains(string(out), "cn: ned") {
			t.Errorf("ldapsearch failed - missing requested CN attribute: %v", string(out))
		}
		if strings.Contains(string(out), "uidNumber") {
			t.Errorf("ldapsearch failed - uidNumber attr should not be displayed: %v", string(out))
		}
		if strings.Contains(string(out), "accountstatus") {
			t.Errorf("ldapsearch failed - accountstatus attr should not be displayed: %v", string(out))
		}
	})
}

func TestSearchAllUserAttributes(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	LaunchServerForTest(t, s, func() {
		filterString := ""
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", filterString, "*")
		out, _ := cmd.CombinedOutput()

		if !strings.Contains(string(out), "dn: cn=ned,o=testers,c=test") {
			t.Errorf("ldapsearch failed - missing requested DN attribute: %v", string(out))
		}
		if !strings.Contains(string(out), "cn: ned") {
			t.Errorf("ldapsearch failed - missing requested CN attribute: %v", string(out))
		}
		if !strings.Contains(string(out), "uidNumber") {
			t.Errorf("ldapsearch failed - missing requested uidNumber attribute: %v", string(out))
		}
		if !strings.Contains(string(out), "accountstatus") {
			t.Errorf("ldapsearch failed - missing requested accountstatus attribute: %v", string(out))
		}
		if !strings.Contains(string(out), "o: ate") {
			t.Errorf("ldapsearch failed - missing requested o attribute: %v", string(out))
		}
		if !strings.Contains(string(out), "description") {
			t.Errorf("ldapsearch failed - missing requested description attribute: %v", string(out))
		}
		if !strings.Contains(string(out), "objectclass") {
			t.Errorf("ldapsearch failed - missing requested objectclass attribute: %v", string(out))
		}
	})
}

// ///////////////////////
func TestSearchScope(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchSimple{})
	s.BindFunc("", bindSimple{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "sub", "cn=trent")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'sub' scope failed - didn't find expected DN: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "o=testers,c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "one", "cn=trent")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'one' scope failed - didn't find expected DN: %v", string(out))
		}
		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "one", "cn=trent")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'one' scope failed - found unexpected DN: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "cn=trent,o=testers,c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "base", "cn=trent")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'base' scope failed - didn't find expected DN: %v", string(out))
		}
		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "o=testers,c=test", "-D", "cn=testy,o=testers,c=test", "-w", "iLike2test", "-s", "base", "cn=trent")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "dn: cn=trent,o=testers,c=test") {
			t.Errorf("ldapsearch 'base' scope failed - found unexpected DN: %v", string(out))
		}

	})
}

// ///////////////////////
func TestSearchScopeCaseInsensitive(t *testing.T) {
	s := NewServer()
	s.EnforceLDAP = true
	s.SearchFunc("", searchCaseInsensitive{})
	s.BindFunc("", bindCaseInsensitive{})

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", "cn=Case,o=testers,c=test", "-D", "cn=CAse,o=testers,c=test", "-w", "iLike2test", "-s", "base", "cn=CASe")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=CASE,o=testers,c=test") {
			t.Errorf("ldapsearch 'base' scope failed - didn't find expected DN: %v", string(out))
		}
	})
}

func TestSearchControls(t *testing.T) {
	s := NewServer()
	s.SearchFunc("", searchControls{})
	s.BindFunc("", bindSimple{})

	serverBaseDN := "o=testers,c=test"

	LaunchServerForTest(t, s, func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test", "-e", "1.2.3.4.5")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "dn: cn=hamburger,o=testers,c=testz") {
			t.Errorf("ldapsearch with control failed: %v", string(out))
		}
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch with control failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numResponses: 2") {
			t.Errorf("ldapsearch with control failed: %v", string(out))
		}

		cmd = exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "dn: cn=hamburger,o=testers,c=testz") {
			t.Errorf("ldapsearch without control failed: %v", string(out))
		}
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch without control failed: %v", string(out))
		}
		if !strings.Contains(string(out), "numResponses: 1") {
			t.Errorf("ldapsearch without control failed: %v", string(out))
		}

	})
}
