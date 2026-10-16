package jithttp

import (
	"cmp"
	"net/http"
	"slices"
	"time"

	"github.com/atoonk/tailscale-jit/jitd/internal/jit"
)

// dayBar is one day of the requests chart: how many requests were submitted
// that day, split by their current status.
type dayBar struct {
	Label  string
	Total  int
	Counts map[jit.Status]int
	Pct    map[string]float64 // share of the tallest day, for bar heights
}

type activity struct {
	Event   jit.Event
	Request *jit.AccessRequest
}

type requestRow struct {
	R   *jit.AccessRequest
	Can jit.Allowed
}

type flowCount struct {
	Name  string
	ID    string
	Count int
}

type dashboardData struct {
	Admin                bool // the organisation-wide view
	NeedsMe              int  // pending requests the viewer can approve
	ActiveOthers         int  // active access of others through flows the viewer approves for (user view)
	Active, Pending      []requestRow
	Requests7d, Flows    int
	Approved30d, Done30d int
	Days                 []dayBar
	Activity             []activity
	TopFlows             []flowCount
}

const chartDays = 14

// dashboard summarises what is happening: who has access right now, what is
// waiting for approval, request volume and recent activity.
func (s *Server) dashboard(r *http.Request, admin bool) dashboardData {
	d := dashboardData{Admin: admin}
	id, idErr := s.Resolver.Resolve(r.Context(), r)
	if idErr != nil {
		return d
	}
	var all []*jit.AccessRequest
	if admin {
		// The console: everything in the organisation.
		all = s.Svc.ListRequests(r.Context(), jit.ListFilter{Viewer: id, Scope: jit.ScopeAll})
		d.Flows = len(s.Svc.ListWorkflows())
	} else {
		// Personal: the viewer's own requests and the ones they approve for,
		// also for admins; the organisation-wide view lives under /admin.
		seen := map[string]bool{}
		for _, sc := range []jit.Scope{jit.ScopeMine, jit.ScopeApprovals} {
			for _, q := range s.Svc.ListRequests(r.Context(), jit.ListFilter{Viewer: id, Scope: sc}) {
				if !seen[q.ID] {
					seen[q.ID] = true
					all = append(all, q)
				}
			}
		}
		d.Flows = len(s.Svc.Requestable(r.Context(), id))
	}

	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	first := today.AddDate(0, 0, -(chartDays - 1))
	d.Days = make([]dayBar, chartDays)
	for i := range d.Days {
		d.Days[i] = dayBar{Label: first.AddDate(0, 0, i).Format("Jan 2"), Counts: map[jit.Status]int{}, Pct: map[string]float64{}}
	}
	flows := map[string]*flowCount{}

	for _, q := range all {
		row := requestRow{R: q, Can: s.Svc.Permissions(r.Context(), id, q)}
		switch q.Status {
		case jit.StatusApproved:
			if admin || jit.IsMine(id, q) {
				d.Active = append(d.Active, row)
			} else {
				d.ActiveOthers++
			}
		case jit.StatusPending:
			d.Pending = append(d.Pending, row)
			if row.Can.Approve {
				d.NeedsMe++
			}
		}
		age := now.Sub(q.CreatedAt)
		if age <= 7*24*time.Hour {
			d.Requests7d++
		}
		if age <= 30*24*time.Hour {
			if q.Status != jit.StatusPending {
				d.Done30d++
			}
			if q.ApprovedAt != nil {
				d.Approved30d++
			}
			fc := flows[q.WorkflowID]
			if fc == nil {
				fc = &flowCount{Name: q.WorkflowName, ID: q.WorkflowID}
				flows[q.WorkflowID] = fc
			}
			fc.Count++
		}
		if !q.CreatedAt.Before(first) {
			i := int(q.CreatedAt.In(now.Location()).Sub(first).Hours() / 24)
			if i >= 0 && i < chartDays {
				d.Days[i].Total++
				d.Days[i].Counts[q.Status]++
			}
		}
		for _, ev := range q.Timeline {
			d.Activity = append(d.Activity, activity{Event: ev, Request: q})
		}
	}

	peak := 1
	for _, b := range d.Days {
		peak = max(peak, b.Total)
	}
	for i := range d.Days {
		for st, n := range d.Days[i].Counts {
			d.Days[i].Pct[string(st)] = 100 * float64(n) / float64(peak)
		}
	}
	// Soonest expiry first; oldest pending first.
	slices.SortFunc(d.Active, func(a, b requestRow) int { return expiry(a.R).Compare(expiry(b.R)) })
	slices.SortFunc(d.Pending, func(a, b requestRow) int { return a.R.CreatedAt.Compare(b.R.CreatedAt) })
	slices.SortFunc(d.Activity, func(a, b activity) int { return b.Event.At.Compare(a.Event.At) })
	d.Activity = d.Activity[:min(len(d.Activity), 12)]
	for _, fc := range flows {
		d.TopFlows = append(d.TopFlows, *fc)
	}
	slices.SortFunc(d.TopFlows, func(a, b flowCount) int { return cmp.Or(b.Count-a.Count, cmp.Compare(a.Name, b.Name)) })
	return d
}

func expiry(r *jit.AccessRequest) time.Time {
	if r.ExpiresAt == nil {
		return time.Time{}
	}
	return *r.ExpiresAt
}
