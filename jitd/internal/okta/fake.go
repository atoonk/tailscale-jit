package okta

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// Fake is an in-memory Client for tests.
type Fake struct {
	mu      sync.Mutex
	Users   map[string]User            // by login
	Groups  map[string]Group           // by ID
	Members map[string]map[string]bool // group ID -> user ID -> member
	Fail    map[string]error           // "add:<group>", "remove:<group>", "find:<login>" -> error
	Calls   []string
}

// NewFake returns an empty Fake.
func NewFake() *Fake {
	return &Fake{Users: map[string]User{}, Groups: map[string]Group{}, Members: map[string]map[string]bool{}, Fail: map[string]error{}}
}

// AddUser registers a user.
func (f *Fake) AddUser(id, login string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := User{ID: id, Status: "ACTIVE"}
	u.Profile.Login, u.Profile.Email = login, login
	f.Users[strings.ToLower(login)] = u
}

// AddGroup registers a group of the given type ("" means OKTA_GROUP).
func (f *Fake) AddGroup(id, name, typ string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := Group{ID: id, Type: typ}
	if g.Type == "" {
		g.Type = "OKTA_GROUP"
	}
	g.Profile.Name = name
	f.Groups[id] = g
}

// Member reports whether user is in group.
func (f *Fake) Member(groupID, userID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Members[groupID][userID]
}

// SetMember puts user in group, as if done outside jitd.
func (f *Fake) SetMember(groupID, userID string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Members[groupID] == nil {
		f.Members[groupID] = map[string]bool{}
	}
	f.Members[groupID][userID] = true
}

func (f *Fake) FindUser(ctx context.Context, login string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "FINDUSER "+login)
	if err := f.Fail["find:"+login]; err != nil {
		return User{}, err
	}
	u, ok := f.Users[strings.ToLower(login)]
	if !ok {
		return User{}, fmt.Errorf("user %s: %w", login, ErrNotFound)
	}
	return u, nil
}

func (f *Fake) FindGroup(ctx context.Context, ref string) (Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if g, ok := f.Groups[ref]; ok {
		return g, nil
	}
	var hits []Group
	for _, g := range f.Groups {
		if g.Profile.Name == ref {
			hits = append(hits, g)
		}
	}
	switch len(hits) {
	case 0:
		return Group{}, fmt.Errorf("group %q: %w", ref, ErrNotFound)
	case 1:
		return hits[0], nil
	}
	return Group{}, fmt.Errorf("more than one group named %q", ref)
}

func (f *Fake) IsMember(ctx context.Context, groupID, userID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.Members[groupID][userID], nil
}

func (f *Fake) AddMember(ctx context.Context, groupID, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "ADD "+groupID+" "+userID)
	if err := f.Fail["add:"+groupID]; err != nil {
		return err
	}
	if f.Members[groupID] == nil {
		f.Members[groupID] = map[string]bool{}
	}
	f.Members[groupID][userID] = true
	return nil
}

func (f *Fake) RemoveMember(ctx context.Context, groupID, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, "REMOVE "+groupID+" "+userID)
	if err := f.Fail["remove:"+groupID]; err != nil {
		return err
	}
	delete(f.Members[groupID], userID)
	return nil
}

// Mutations lists the ADD and REMOVE calls so far, and clears the log.
func (f *Fake) Mutations() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.Calls {
		if strings.HasPrefix(c, "ADD ") || strings.HasPrefix(c, "REMOVE ") {
			out = append(out, c)
		}
	}
	f.Calls = nil
	return slices.Clip(out)
}
