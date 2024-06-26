package clients

import (
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/setting"
)

// roleExtractor should return the org role, optional isGrafanaAdmin or an error
type roleExtractor func() (org.RoleType, *bool, error)
type rolesExtractor func() (map[string]org.RoleType, *bool, error)

// getRole only handles one org role for now, could be subject to change
func getRole(cfg *setting.Cfg, extract roleExtractor) (map[string]org.RoleType, *bool, error) {
	role, isGrafanaAdmin, err := extract()
	orgRoles := make(map[string]org.RoleType, 0)
	if err != nil {
		return orgRoles, nil, err
	}

	if role == "" || !role.IsValid() {
		return orgRoles, nil, nil
	}

	orgName := "Main Org."
	if cfg.AutoAssignOrg && cfg.AutoAssignOrgName != "" {
		orgName = cfg.AutoAssignOrgName
	}
	orgRoles[orgName] = role

	return orgRoles, isGrafanaAdmin, nil
}

func getRoles(cfg *setting.Cfg, extract rolesExtractor) (map[string]org.RoleType, *bool, error) {
	roles, isGrafanaAdmin, err := extract()
	//orgRoles := make(map[string]org.RoleType, 0)
	if err != nil {
		return roles, nil, err
	}

	return roles, isGrafanaAdmin, nil
}
