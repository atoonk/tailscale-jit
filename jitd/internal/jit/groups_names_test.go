package jit

import "context"

// The Okta tests were written when the group code was Okta's alone. These
// are the names they call, on top of the code every provider shares.

type oktaOutcome = groupOutcome

const oktaBatch = groupBatch

// grantOkta is what grantGroups does for a request with Okta groups only.
func (s *Service) grantOkta(ctx context.Context, r *AccessRequest) *oktaOutcome {
	out := s.planGroups(ctx, s.oktaProvider(), r)
	if out.err == nil {
		s.writeGroups(ctx, r, out)
	}
	return out
}

func (s *Service) takeBackOkta(ctx context.Context, id string, out *oktaOutcome) {
	s.takeBack(ctx, id, out)
}

func (s *Service) releaseOktaOne(ctx context.Context, id string) *AccessRequest {
	return s.releaseOne(ctx, s.oktaProvider(), id)
}
