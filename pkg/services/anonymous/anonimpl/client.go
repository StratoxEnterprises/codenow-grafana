package anonimpl

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/anonymous"
	"github.com/grafana/grafana/pkg/services/anonymous/anonimpl/anonstore"
	"github.com/grafana/grafana/pkg/services/auth/identity"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util/errutil"
)

var (
	errInvalidOrg = errutil.Unauthorized("anonymous.invalid-org")
	errInvalidID  = errutil.Unauthorized("anonymous.invalid-id")
)

var _ authn.ContextAwareClient = new(Anonymous)
var _ authn.IdentityResolverClient = new(Anonymous)

type Anonymous struct {
	cfg               *setting.Cfg
	log               log.Logger
	orgService        org.Service
	anonDeviceService anonymous.Service
}

func (a *Anonymous) Name() string {
	return authn.ClientAnonymous
}

func (a *Anonymous) Authenticate(ctx context.Context, r *authn.Request) (*authn.Identity, error) {
	o, err := a.orgService.GetByName(ctx, &org.GetOrgByNameQuery{Name: a.cfg.AnonymousOrgName})
	if err != nil {
		a.log.FromContext(ctx).Error("Failed to find organization", "name", a.cfg.AnonymousOrgName, "error", err)
		return nil, err
	}

	httpReqCopy := &http.Request{}
	if r.HTTPRequest != nil && r.HTTPRequest.Header != nil {
		// avoid r.HTTPRequest.Clone(context.Background()) as we do not require a full clone
		httpReqCopy.Header = r.HTTPRequest.Header.Clone()
		httpReqCopy.RemoteAddr = r.HTTPRequest.RemoteAddr
	}

	if err := a.anonDeviceService.TagDevice(ctx, httpReqCopy, anonymous.AnonDeviceUI); err != nil {
		if errors.Is(err, anonstore.ErrDeviceLimitReached) {
			return nil, err
		}

		a.log.Warn("Failed to tag anonymous session", "error", err)
	}

	return a.newAnonymousIdentity(o), nil
}

func (a *Anonymous) IsEnabled() bool {
	return a.cfg.AnonymousEnabled
}

func (a *Anonymous) Test(ctx context.Context, r *authn.Request) bool {
	// If anonymous client is register it can always be used for authentication
	return true
}

func (a *Anonymous) Namespace() string {
	return authn.NamespaceAnonymous.String()
}

func (a *Anonymous) ResolveIdentity(ctx context.Context, orgID int64, namespaceID identity.NamespaceID) (*authn.Identity, error) {
	o, err := a.orgService.GetByName(ctx, &org.GetOrgByNameQuery{Name: a.cfg.AnonymousOrgName})
	if err != nil {
		return nil, err
	}

	if o.ID != orgID {
		return nil, errInvalidOrg.Errorf("anonymous user cannot authenticate in org %d", o.ID)
	}

	// Anonymous identities should always have the same namespace id.
	if namespaceID != authn.AnonymousNamespaceID {
		return nil, errInvalidID
	}

	return a.newAnonymousIdentity(o), nil
}

func (a *Anonymous) UsageStatFn(ctx context.Context) (map[string]any, error) {
	m := map[string]any{}

	// Add stats about anonymous auth
	m["stats.anonymous.customized_role.count"] = 0
	if !strings.EqualFold(a.cfg.AnonymousOrgRole, "Viewer") {
		m["stats.anonymous.customized_role.count"] = 1
	}

	return m, nil
}

func (a *Anonymous) Priority() uint {
	return 100
}

func (a *Anonymous) newAnonymousIdentity(o *org.Org) *authn.Identity {
	return &authn.Identity{
		ID:           authn.AnonymousNamespaceID,
		OrgID:        o.ID,
		OrgName:      o.Name,
		OrgRoles:     map[string]org.RoleType{o.Name: org.RoleType(a.cfg.AnonymousOrgRole)},
		ClientParams: authn.ClientParams{SyncPermissions: true},
	}
}
