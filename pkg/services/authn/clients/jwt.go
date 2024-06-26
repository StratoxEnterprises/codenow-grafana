package clients

import (
	"context"
	"github.com/grafana/grafana/pkg/models/roletype"
	"net/http"
	"regexp"
	"strings"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/auth"
	authJWT "github.com/grafana/grafana/pkg/services/auth/jwt"
	"github.com/grafana/grafana/pkg/services/authn"
	"github.com/grafana/grafana/pkg/services/login"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/setting"
	"github.com/grafana/grafana/pkg/util"
	"github.com/grafana/grafana/pkg/util/errutil"
)

const authQueryParamName = "auth_token"

var _ authn.ContextAwareClient = new(JWT)

var (
	errJWTInvalid = errutil.Unauthorized(
		"jwt.invalid", errutil.WithPublicMessage("Failed to verify JWT"))
	errJWTMissingClaim = errutil.Unauthorized(
		"jwt.missing_claim", errutil.WithPublicMessage("Missing mandatory claim in JWT"))
	errJWTInvalidRole = errutil.Forbidden(
		"jwt.invalid_role", errutil.WithPublicMessage("Invalid Role in claim"))
)

func ProvideJWT(jwtService auth.JWTVerifierService, cfg *setting.Cfg) *JWT {
	return &JWT{
		cfg:        cfg,
		log:        log.New(authn.ClientJWT),
		jwtService: jwtService,
	}
}

type JWT struct {
	cfg        *setting.Cfg
	log        log.Logger
	jwtService auth.JWTVerifierService
}

func (s *JWT) Name() string {
	return authn.ClientJWT
}

func (s *JWT) Authenticate(ctx context.Context, r *authn.Request) (*authn.Identity, error) {
	jwtToken := s.retrieveToken(r.HTTPRequest)
	s.stripSensitiveParam(r.HTTPRequest)

	claims, err := s.jwtService.Verify(ctx, jwtToken)
	if err != nil {
		s.log.FromContext(ctx).Debug("Failed to verify JWT", "error", err)
		return nil, errJWTInvalid.Errorf("failed to verify JWT: %w", err)
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, errJWTMissingClaim.Errorf("missing mandatory 'sub' claim in JWT")
	}

	id := &authn.Identity{
		AuthenticatedBy: login.JWTModule,
		AuthID:          sub,
		OrgRoles:        map[string]org.RoleType{},
		ClientParams: authn.ClientParams{
			SyncUser:        true,
			FetchSyncedUser: true,
			SyncPermissions: true,
			SyncOrgRoles:    !s.cfg.JWTAuth.SkipOrgRoleSync,
			AllowSignUp:     s.cfg.JWTAuth.AutoSignUp,
			SyncTeams:       s.cfg.JWTAuth.GroupsAttributePath != "",
		}}

	if key := s.cfg.JWTAuth.UsernameClaim; key != "" {
		id.Login, _ = claims[key].(string)
		id.ClientParams.LookUpParams.Login = &id.Login
	} else if key := s.cfg.JWTAuth.UsernameAttributePath; key != "" {
		id.Login, err = util.SearchJSONForStringAttr(s.cfg.JWTAuth.UsernameAttributePath, claims)
		if err != nil {
			return nil, err
		}
		id.ClientParams.LookUpParams.Login = &id.Login
	}

	if key := s.cfg.JWTAuth.EmailClaim; key != "" {
		id.Email, _ = claims[key].(string)
		id.ClientParams.LookUpParams.Email = &id.Email
	} else if key := s.cfg.JWTAuth.EmailAttributePath; key != "" {
		id.Email, err = util.SearchJSONForStringAttr(s.cfg.JWTAuth.EmailAttributePath, claims)
		if err != nil {
			return nil, err
		}
		id.ClientParams.LookUpParams.Email = &id.Email
	}

	if name, _ := claims["name"].(string); name != "" {
		id.Name = name
	}

	orgRoles, isGrafanaAdmin, err := getRoles(s.cfg, func() (map[string]org.RoleType, *bool, error) {
		if s.cfg.JWTAuth.SkipOrgRoleSync {
			return make(map[string]org.RoleType), nil, nil
		}

		roles, grafanaAdmin := s.extractRolesAndAdmin(claims)
		/*if s.cfg.JWTAuth.RoleAttributeStrict && !role.IsValid() {
			return "", nil, errJWTInvalidRole.Errorf("invalid role claim in JWT: %s", role)
		}*/

		/*if !s.cfg.JWTAuth.AllowAssignGrafanaAdmin {
			return role, nil, nil
		}*/

		return roles, &grafanaAdmin, nil
	})

	if err != nil {
		return nil, err
	}

	id.OrgRoles = orgRoles
	id.IsGrafanaAdmin = isGrafanaAdmin

	id.Groups, err = s.extractGroups(claims)
	if err != nil {
		return nil, err
	}

	if id.Login == "" && id.Email == "" {
		s.log.FromContext(ctx).Debug("Failed to get an authentication claim from JWT",
			"login", id.Login, "email", id.Email)
		return nil, errJWTMissingClaim.Errorf("missing login and email claim in JWT")
	}

	return id, nil
}

func (s *JWT) IsEnabled() bool {
	return s.cfg.JWTAuth.Enabled
}

// remove sensitive query param
// avoid JWT URL login passing auth_token in URL
func (s *JWT) stripSensitiveParam(httpRequest *http.Request) {
	if s.cfg.JWTAuth.URLLogin {
		params := httpRequest.URL.Query()
		if params.Has(authQueryParamName) {
			params.Del(authQueryParamName)
			httpRequest.URL.RawQuery = params.Encode()
		}
	}
}

// retrieveToken retrieves the JWT token from the request.
func (s *JWT) retrieveToken(httpRequest *http.Request) string {
	jwtToken := httpRequest.Header.Get(s.cfg.JWTAuth.HeaderName)
	if jwtToken == "" && s.cfg.JWTAuth.URLLogin {
		jwtToken = httpRequest.URL.Query().Get("auth_token")
	}
	// Strip the 'Bearer' prefix if it exists.
	return strings.TrimPrefix(jwtToken, "Bearer ")
}

func (s *JWT) Test(ctx context.Context, r *authn.Request) bool {
	if !s.cfg.JWTAuth.Enabled || s.cfg.JWTAuth.HeaderName == "" {
		return false
	}

	jwtToken := s.retrieveToken(r.HTTPRequest)

	if jwtToken == "" {
		return false
	}

	// If the "sub" claim is missing or empty then pass the control to the next handler
	if !authJWT.HasSubClaim(jwtToken) {
		return false
	}

	return true
}

func (s *JWT) Priority() uint {
	return 20
}

const roleGrafanaAdmin = "GrafanaAdmin"

func (s *JWT) extractRoleAndAdmin(claims map[string]any) (org.RoleType, bool) {
	if s.cfg.JWTAuth.RoleAttributePath == "" {
		return "", false
	}

	role, err := util.SearchJSONForStringAttr(s.cfg.JWTAuth.RoleAttributePath, claims)
	if err != nil || role == "" {
		return "", false
	}

	if role == roleGrafanaAdmin {
		return org.RoleAdmin, true
	}
	return org.RoleType(role), false
}

func (s *JWT) extractRolesAndAdmin(claims map[string]any) (map[string]org.RoleType, bool) {

	resultOrgRoles := make(map[string]org.RoleType)
	if s.cfg.JWTAuth.RoleAttributePath == "" {
		return resultOrgRoles, false
	}

	rolesSlice, err := util.SearchJSONForStringSliceAttr(s.cfg.JWTAuth.RoleAttributePath, claims)
	if err != nil || len(rolesSlice) == 0 {
		return resultOrgRoles, false
	}

	// check if parse roles directly from JWT claim by regex:
	if s.cfg.JWTAuth.RegexOrgRoleMapper != nil && len(s.cfg.JWTAuth.RegexOrgRoleMapper) > 0 {
		for _, jwtRole := range rolesSlice {
			// RegexOrgRoleMapper - map of key = regex to match role agains , value = target gragana to role to be assigned it regex matches
			//https://stackoverflow.com/questions/20750843/using-named-matches-from-go-regex
			for regexString, grafanaRole := range s.cfg.JWTAuth.RegexOrgRoleMapper {

				var myExp = regexp.MustCompile(regexString)
				match := myExp.FindStringSubmatch(jwtRole)
				if len(match) > 0 {
					for i, name := range myExp.SubexpNames() {
						if i != 0 && name == "org" && resultOrgRoles[match[i]] == "" {
							resultOrgRoles[match[i]] = roletype.RoleType(grafanaRole)
						}
					}
				}
			}
		}
		// otherwise parse statically defined roles:
	} else {
		for _, role := range rolesSlice {
			parsedRole := strings.Split(role, ":")
			if len(parsedRole) != 3 {
				continue
			}
			if parsedRole[2] == "admin" {
				resultOrgRoles[parsedRole[1]] = org.RoleEditor

			} else if parsedRole[2] == "viewer" {
				resultOrgRoles[parsedRole[1]] = org.RoleViewer
			}
		}
	}

	/*if role == roleGrafanaAdmin {
		return org.RoleAdmin, true
	}*/
	return resultOrgRoles, false
}

func (s *JWT) extractGroups(claims map[string]any) ([]string, error) {
	if s.cfg.JWTAuth.GroupsAttributePath == "" {
		return []string{}, nil
	}

	return util.SearchJSONForStringSliceAttr(s.cfg.JWTAuth.GroupsAttributePath, claims)
}
