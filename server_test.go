package ldap

import (
	"bytes"
	"crypto/tls"
	"log"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

var (
	listenString = "localhost:3389"
	ldapURL      = "ldap://" + listenString
	timeout      = 400 * time.Millisecond
	serverBaseDN = "o=testers,c=test"
)

// ///////////////////////
func TestBindAnonOK(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

// ///////////////////////
func TestBindAnonFail(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	time.Sleep(timeout)
	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	time.Sleep(timeout)
	quit <- true
}

// ///////////////////////
func TestBindSimpleOK(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

// ///////////////////////
func TestBindSimpleFailBadPw(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "BADPassword")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

// ///////////////////////
func TestBindSimpleFailBadDn(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testoy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if string(out) != "ldap_bind: Invalid credentials (49)\n" {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

// ///////////////////////
func TestBindSSL(t *testing.T) {
	ldapURLSSL := "ldaps://" + listenString
	longerTimeout := 300 * time.Millisecond
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServeTLS(listenString, "tests/cert_DONOTUSE.pem", "tests/key_DONOTUSE.pem"); err != nil {
			t.Errorf("s.ListenAndServeTLS failed: %s", err.Error())
		}
	}()

	go func() {
		time.Sleep(longerTimeout * 2)
		cmd := exec.Command("ldapsearch", "-H", ldapURLSSL, "-x", "-b", "o=testers,c=test")
		cmd.Env = append(cmd.Env, "LDAPTLS_REQCERT=never")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(longerTimeout * 5):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

func TestBindStartTLS(t *testing.T) {
	longerTimeout := 300 * time.Millisecond
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		cert, err := tls.LoadX509KeyPair("tests/cert_DONOTUSE.pem", "tests/key_DONOTUSE.pem")
		if err != nil {
			t.Error(err)
		}
		s.StartTLS = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServeTLS failed: %s", err.Error())
		}
	}()

	go func() {
		time.Sleep(longerTimeout * 2)
		cmd := exec.Command("ldapsearch", "-Z", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		cmd.Env = append(cmd.Env, "LDAPTLS_REQCERT=never")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(longerTimeout * 5):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

// ///////////////////////
func TestBindPanic(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindPanic{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Operations error") {
			t.Errorf("ldapsearch should have returned operations error due to panic: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

// ///////////////////////
type testStatsWriter struct {
	buffer *bytes.Buffer
}

func (tsw testStatsWriter) Write(buf []byte) (int, error) {
	tsw.buffer.Write(buf)
	return len(buf), nil
}

func TestSearchStats(t *testing.T) {
	w := testStatsWriter{&bytes.Buffer{}}
	log.SetOutput(w)

	quit := make(chan bool)
	done := make(chan bool)
	s := NewServer()

	go func() {
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindAnonOK{})
		s.SetStats(true)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}

	stats := s.GetStats()
	log.Println(stats)
	if stats.Conns != 1 || stats.Binds != 1 {
		t.Errorf("Stats data missing or incorrect: %v", w.buffer.String())
	}
	quit <- true
}

// ///////////////////////
type bindAnonOK struct{}

func (b bindAnonOK) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple struct{}

func (b bindSimple) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple2 struct{}

func (b bindSimple2) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "cn=testy,o=testers,c=testz" && bindSimplePw == "ZLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindPanic struct{}

func (b bindPanic) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	panic("test panic at the disco")
}

type bindCaseInsensitive struct{}

func (b bindCaseInsensitive) Bind(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if strings.ToLower(bindDN) == "cn=case,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type searchSimple struct{}

func (s searchSimple) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		{"cn=ned,o=testers,c=test", []*EntryAttribute{
			{"cn", []string{"ned"}},
			{"o", []string{"ate"}},
			{"uidNumber", []string{"5000"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"ned"}},
			{"description", []string{"ned via sa"}},
			{"objectclass", []string{"posixaccount"}},
		}},
		{"cn=trent,o=testers,c=test", []*EntryAttribute{
			{"cn", []string{"trent"}},
			{"o", []string{"ate"}},
			{"uidNumber", []string{"5005"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"trent"}},
			{"description", []string{"trent via sa"}},
			{"objectclass", []string{"posixaccount"}},
		}},
		{"cn=randy,o=testers,c=test", []*EntryAttribute{
			{"cn", []string{"randy"}},
			{"o", []string{"ate"}},
			{"uidNumber", []string{"5555"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"randy"}},
			{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchSimple2 struct{}

func (s searchSimple2) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			{"cn", []string{"hamburger"}},
			{"o", []string{"testers"}},
			{"uidNumber", []string{"5000"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"hamburger"}},
			{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchPanic struct{}

func (s searchPanic) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	panic("this is a test panic")
}

type searchControls struct{}

func (s searchControls) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	if len(searchReq.Controls) == 1 && searchReq.Controls[0].GetControlType() == "1.2.3.4.5" {
		newEntry := &Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			{"cn", []string{"hamburger"}},
			{"o", []string{"testers"}},
			{"uidNumber", []string{"5000"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"hamburger"}},
			{"objectclass", []string{"posixaccount"}},
		}}
		entries = append(entries, newEntry)
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchCaseInsensitive struct{}

func (s searchCaseInsensitive) Search(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		{"cn=CASE,o=testers,c=test", []*EntryAttribute{
			{"cn", []string{"CaSe"}},
			{"o", []string{"ate"}},
			{"uidNumber", []string{"5005"}},
			{"accountstatus", []string{"active"}},
			{"uid", []string{"trent"}},
			{"description", []string{"trent via sa"}},
			{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

func TestRouteFunc(t *testing.T) {
	if routeFunc("", []string{"a", "xyz", "tt"}) != "" {
		t.Error("routeFunc failed")
	}
	if routeFunc("a=b", []string{"a=b", "x=y,a=b", "tt"}) != "a=b" {
		t.Error("routeFunc failed")
	}
	if routeFunc("x=y,a=b", []string{"a=b", "x=y,a=b", "tt"}) != "x=y,a=b" {
		t.Error("routeFunc failed")
	}
	if routeFunc("x=y,a=b", []string{"x=y,a=b", "a=b", "tt"}) != "x=y,a=b" {
		t.Error("routeFunc failed")
	}
	if routeFunc("nosuch", []string{"x=y,a=b", "a=b", "tt"}) != "" {
		t.Error("routeFunc failed")
	}
}
