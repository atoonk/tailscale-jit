package google

import (
	"context"
	"fmt"
	"sync"
)

// Dynamic is a Client that (re)builds its backing client from Load on each
// call, so saving a key on the Google page, or editing the env file, takes
// effect without a restart. Until Load returns a key, every call fails with
// ErrUnconfigured.
//
// If Load fails (the env file cannot be read), Dynamic carries on with the
// settings it read last, and says so through OnLoadError: an edit that went
// wrong must not switch Google off while memberships are waiting to be
// removed.
type Dynamic struct {
	Load func() (map[string]string, error)
	// OnLoadError, if set, is called when Load starts failing (with the
	// error) and when it works again (with nil).
	OnLoadError func(err error)
	// New builds the client from what Load returned. It is NewFromValues
	// unless set (the preview and tests put a fake behind it).
	New func(vars map[string]string) (Client, error)

	mu   sync.Mutex
	last map[string]string // what Load returned when it last worked
	lerr string            // the Load error last reported
	key  string
	set  bool
	c    Client
	berr error
}

// Enabled reports whether a service account key is present and usable (not
// whether Google accepts it).
func (d *Dynamic) Enabled() bool { return d.Err() == nil }

// StaleSettings returns why Load failed when it was last called, if Google
// is carrying on with the settings read before that.
func (d *Dynamic) StaleSettings() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == nil {
		return ""
	}
	return d.lerr
}

// Err says why Google is off: ErrUnconfigured, or what is wrong with the
// key or the env file. It is nil while Google is on.
func (d *Dynamic) Err() error {
	_, err := d.get()
	return err
}

// Vars returns the settings in force: what Load returns, or, while Load
// fails, what it returned last. It fails only if Load never worked.
func (d *Dynamic) Vars() (map[string]string, error) {
	if d.Load == nil {
		return map[string]string{}, nil
	}
	vars, err := d.Load()
	d.mu.Lock()
	defer d.mu.Unlock()
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	if msg != d.lerr {
		d.lerr = msg
		if d.OnLoadError != nil {
			d.OnLoadError(err)
		}
	}
	if err == nil {
		d.last = vars
		return vars, nil
	}
	if d.last != nil {
		return d.last, nil
	}
	return nil, fmt.Errorf("reading the Google settings: %w", err)
}

// get returns the client for the key in force. It is rebuilt when the key's
// text changes, so a rotated key is picked up and its token with it.
func (d *Dynamic) get() (Client, error) {
	vars, err := d.Vars()
	if err != nil {
		return nil, err
	}
	key := vars[EnvKey]
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.set || key != d.key {
		d.set, d.key = true, key
		d.c, d.berr = nil, nil
		if d.New != nil && Configured(vars) {
			d.c, d.berr = d.New(vars)
		} else if c, err := NewFromValues(vars); err != nil {
			d.berr = err
		} else {
			d.c = c
		}
	}
	if d.berr != nil {
		return nil, d.berr
	}
	return d.c, nil
}

func (d *Dynamic) FindGroup(ctx context.Context, ref string) (Group, error) {
	c, err := d.get()
	if err != nil {
		return Group{}, err
	}
	return c.FindGroup(ctx, ref)
}

func (d *Dynamic) IsMember(ctx context.Context, groupID, email string) (bool, error) {
	c, err := d.get()
	if err != nil {
		return false, err
	}
	return c.IsMember(ctx, groupID, email)
}

func (d *Dynamic) AddMember(ctx context.Context, groupID, email string) error {
	c, err := d.get()
	if err != nil {
		return err
	}
	return c.AddMember(ctx, groupID, email)
}

func (d *Dynamic) RemoveMember(ctx context.Context, groupID, email string) error {
	c, err := d.get()
	if err != nil {
		return err
	}
	return c.RemoveMember(ctx, groupID, email)
}

func (d *Dynamic) Check(ctx context.Context) error {
	c, err := d.get()
	if err != nil {
		return err
	}
	return c.Check(ctx)
}
