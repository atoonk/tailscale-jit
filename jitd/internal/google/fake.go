package google

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"slices"
	"strings"
	"sync"
)

// Fake is an in-memory Client for tests and the preview.
type Fake struct {
	mu      sync.Mutex
	Groups  map[string]Group           // by ID
	Members map[string]map[string]bool // group ID -> email -> member
	Fail    map[string]error           // "findgroup:<ref>", "ismember:<group>", "add:<group>", "remove:<group>", "check" -> error
	Calls   []string
	// Hook, if set, runs at the start of every call with its name
	// ("findgroup", "ismember", "add", "remove", "check"), before the Fake
	// takes its own lock, so it may call back into the code under test.
	Hook func(call string)
}

// NewFake returns an empty Fake.
func NewFake() *Fake {
	return &Fake{Groups: map[string]Group{}, Members: map[string]map[string]bool{}, Fail: map[string]error{}}
}

func (f *Fake) hook(call string) {
	if f.Hook != nil {
		f.Hook(call)
	}
}

// AddGroup registers a group.
func (f *Fake) AddGroup(id, email string, dynamic bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	email = strings.ToLower(email)
	name, _, _ := strings.Cut(email, "@")
	f.Groups[id] = Group{ID: id, Email: email, Name: name, Dynamic: dynamic}
}

// Member reports whether email is in group.
func (f *Fake) Member(groupID, email string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Members[groupID][strings.ToLower(email)]
}

// SetMember puts email in group, as if done outside jitd.
func (f *Fake) SetMember(groupID, email string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.set(groupID, email)
}

func (f *Fake) set(groupID, email string) {
	if f.Members[groupID] == nil {
		f.Members[groupID] = map[string]bool{}
	}
	f.Members[groupID][strings.ToLower(email)] = true
}

func (f *Fake) FindGroup(ctx context.Context, ref string) (Group, error) {
	f.hook("findgroup")
	f.mu.Lock()
	defer f.mu.Unlock()
	ref = strings.TrimSpace(ref)
	if err := f.Fail["findgroup:"+ref]; err != nil {
		return Group{}, err
	}
	if g, ok := f.Groups[ref]; ok {
		return g, nil
	}
	for _, g := range f.Groups {
		if g.Email == strings.ToLower(ref) {
			return g, nil
		}
	}
	return Group{}, ErrNotFound
}

func (f *Fake) IsMember(ctx context.Context, groupID, email string) (bool, error) {
	f.hook("ismember")
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.Fail["ismember:"+groupID]; err != nil {
		return false, err
	}
	return f.Members[groupID][strings.ToLower(email)], nil
}

func (f *Fake) AddMember(ctx context.Context, groupID, email string) error {
	f.hook("add")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "ADD "+groupID+" "+email)
	if err := f.Fail["add:"+groupID]; err != nil {
		return err
	}
	f.set(groupID, email)
	return nil
}

func (f *Fake) RemoveMember(ctx context.Context, groupID, email string) error {
	f.hook("remove")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "REMOVE "+groupID+" "+email)
	if err := f.Fail["remove:"+groupID]; err != nil {
		return err
	}
	delete(f.Members[groupID], strings.ToLower(email))
	return nil
}

// Check fails with Fail["check"], if set.
func (f *Fake) Check(ctx context.Context) error {
	f.hook("check")
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Fail["check"]
}

// Mutations lists the ADD and REMOVE calls so far, and clears the log.
func (f *Fake) Mutations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.Calls)
	f.Calls = nil
	return out
}

var (
	fakeKeyOnce sync.Once
	fakeKeyPEM  string
)

// FakeKey returns a service account key file as Google writes one, with a
// key made up on the spot: for the preview and for tests, which need
// something ParseKey takes.
func FakeKey(account, project string) string {
	fakeKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			panic(err)
		}
		fakeKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	})
	b, _ := json.Marshal(map[string]string{
		"type":           "service_account",
		"project_id":     project,
		"private_key_id": "fakekey0123456789",
		"private_key":    fakeKeyPEM,
		"client_email":   account,
		"token_uri":      "https://oauth2.googleapis.com/token",
	})
	return string(b)
}
