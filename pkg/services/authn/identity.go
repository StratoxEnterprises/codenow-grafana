package authn

import (
	"fmt"
	"time"

	"golang.org/x/oauth2"

	"github.com/grafana/grafana/pkg/models/usertoken"
	"github.com/grafana/grafana/pkg/services/auth/identity"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/services/user"
)

const GlobalOrgID = int64(0)

type Requester = identity.Requester

var _ Requester = (*Identity)(nil)

type Identity struct {
	// ID is the unique identifier for the entity in the Grafana database.
	// If the entity is not found in the DB or this entity is non-persistent, this field will be empty.
	ID NamespaceID
	// UID is a unique identifier stored for the entity in Grafana database. Not all entities support uid so it can be empty.
	UID NamespaceID
	// OrgID is the active organization for the entity.
	OrgID int64
	// OrgName is the name of the active organization.
	OrgName string
	// OrgRoles is the list of organizations the entity is a member of and their roles.
	OrgRoles map[string]org.RoleType
	// Login is the shorthand identifier of the entity. Should be unique.
	Login string
	// Name is the display name of the entity. It is not guaranteed to be unique.
	Name string
	// Email is the email address of the entity. Should be unique.
	Email string
	// EmailVerified is true if entity has verified their email with grafana.
	EmailVerified bool
	// IsGrafanaAdmin is true if the entity is a Grafana admin.
	IsGrafanaAdmin *bool
	// AuthenticatedBy is the name of the authentication client that was used to authenticate the current Identity.
	// For example, "password", "apikey", "auth_ldap" or "auth_azuread".
	AuthenticatedBy string
	// AuthId is the unique identifier for the entity in the external system.
	// Empty if the identity is provided by Grafana.
	AuthID string
	// IsDisabled is true if the entity is disabled.
	IsDisabled bool
	// HelpFlags1 is the help flags for the entity.
	HelpFlags1 user.HelpFlags1
	// LastSeenAt is the time when the entity was last seen.
	LastSeenAt time.Time
	// Teams is the list of teams the entity is a member of.
	Teams []int64
	// idP Groups that the entity is a member of. This is only populated if the
	// identity provider supports groups.
	Groups []string
	// OAuthToken is the OAuth token used to authenticate the entity.
	OAuthToken *oauth2.Token
	// SessionToken is the session token used to authenticate the entity.
	SessionToken *usertoken.UserToken
	// ClientParams are hints for the auth service on how to handle the identity.
	// Set by the authenticating client.
	ClientParams ClientParams
	// Permissions is the list of permissions the entity has.
	Permissions map[int64]map[string][]string
	// IDToken is a signed token representing the identity that can be forwarded to plugins and external services.
	// Will only be set when featuremgmt.FlagIdForwarding is enabled.
	IDToken string
}

func (i *Identity) GetID() NamespaceID {
	return i.ID
}

func (i *Identity) GetNamespacedID() (namespace identity.Namespace, identifier string) {
	return i.ID.Namespace(), i.ID.ID()
}

func (i *Identity) GetUID() NamespaceID {
	return i.UID
}

func (i *Identity) GetAuthID() string {
	return i.AuthID
}

func (i *Identity) GetAuthenticatedBy() string {
	return i.AuthenticatedBy
}

func (i *Identity) GetCacheKey() string {
	namespace, id := i.GetNamespacedID()
	if !i.HasUniqueId() {
		// Hack use the org role as id for identities that do not have a unique id
		// e.g. anonymous and render key.
		id = string(i.GetOrgRole())
	}

	return fmt.Sprintf("%d-%s-%s", i.GetOrgID(), namespace, id)
}

func (i *Identity) GetDisplayName() string {
	return i.Name
}

func (i *Identity) GetEmail() string {
	return i.Email
}

func (i *Identity) IsEmailVerified() bool {
	return i.EmailVerified
}

func (i *Identity) GetIDToken() string {
	return i.IDToken
}

func (i *Identity) GetIsGrafanaAdmin() bool {
	return i.IsGrafanaAdmin != nil && *i.IsGrafanaAdmin
}

func (i *Identity) GetLogin() string {
	return i.Login
}

func (i *Identity) GetOrgID() int64 {
	return i.OrgID
}

func (i *Identity) GetOrgName() string {
	return i.OrgName
}

func (i *Identity) GetOrgRole() org.RoleType {
	if i.OrgRoles == nil {
		return org.RoleNone
	}

	if i.OrgRoles[i.GetOrgName()] == "" {
		return org.RoleNone
	}

	return i.OrgRoles[i.GetOrgName()]
}

func (i *Identity) GetPermissions() map[string][]string {
	if i.Permissions == nil {
		return make(map[string][]string)
	}

	if i.Permissions[i.GetOrgID()] == nil {
		return make(map[string][]string)
	}

	return i.Permissions[i.GetOrgID()]
}

// GetGlobalPermissions returns the permissions of the active entity that are available across all organizations
func (i *Identity) GetGlobalPermissions() map[string][]string {
	if i.Permissions == nil {
		return make(map[string][]string)
	}

	if i.Permissions[GlobalOrgID] == nil {
		return make(map[string][]string)
	}

	return i.Permissions[GlobalOrgID]
}

func (i *Identity) GetTeams() []int64 {
	return i.Teams
}

func (i *Identity) HasRole(role org.RoleType) bool {
	if i.GetIsGrafanaAdmin() {
		return true
	}

	return i.GetOrgRole().Includes(role)
}

func (i *Identity) HasUniqueId() bool {
	namespace, _ := i.GetNamespacedID()
	return namespace == NamespaceUser || namespace == NamespaceServiceAccount || namespace == NamespaceAPIKey
}

func (i *Identity) IsAuthenticatedBy(providers ...string) bool {
	for _, p := range providers {
		if i.AuthenticatedBy == p {
			return true
		}
	}
	return false
}

func (i *Identity) IsNil() bool {
	return i == nil
}

// SignedInUser returns a SignedInUser from the identity.
func (i *Identity) SignedInUser() *user.SignedInUser {
	u := &user.SignedInUser{
		OrgID:           i.OrgID,
		OrgName:         i.OrgName,
		OrgRole:         i.GetOrgRole(),
		Login:           i.Login,
		Name:            i.Name,
		Email:           i.Email,
		AuthID:          i.AuthID,
		AuthenticatedBy: i.AuthenticatedBy,
		IsGrafanaAdmin:  i.GetIsGrafanaAdmin(),
		IsAnonymous:     i.ID.IsNamespace(NamespaceAnonymous),
		IsDisabled:      i.IsDisabled,
		HelpFlags1:      i.HelpFlags1,
		LastSeenAt:      i.LastSeenAt,
		Teams:           i.Teams,
		Permissions:     i.Permissions,
		IDToken:         i.IDToken,
		NamespacedID:    i.ID,
	}

	if i.ID.IsNamespace(NamespaceAPIKey) {
		id, _ := i.ID.ParseInt()
		u.ApiKeyID = id
	} else {
		id, _ := i.ID.UserID()
		u.UserID = id
		u.UserUID = i.UID.ID()
		u.IsServiceAccount = i.ID.IsNamespace(NamespaceServiceAccount)
	}

	return u
}

func (i *Identity) ExternalUserInfo() login.ExternalUserInfo {
	id, _ := i.ID.UserID()
	return login.ExternalUserInfo{
		OAuthToken:     i.OAuthToken,
		AuthModule:     i.AuthenticatedBy,
		AuthId:         i.AuthID,
		UserId:         id,
		Email:          i.Email,
		Login:          i.Login,
		Name:           i.Name,
		Groups:         i.Groups,
		OrgRoles:       i.OrgRoles,
		IsGrafanaAdmin: i.IsGrafanaAdmin,
		IsDisabled:     i.IsDisabled,
	}
}
