package connectors

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/org"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	mapperMatchAllOrgID = ""
	escapeStr           = `\`
)

var separatorRegexp = regexp.MustCompile(":")

// OrgRoleMapper maps external orgs/groups to Grafana orgs and basic roles.
type OrgRoleMapper struct {
	cfg        *setting.Cfg
	logger     log.Logger
	orgService org.Service
}

// MappingConfiguration represents the mapping configuration from external orgs to Grafana orgs and roles.
// orgMapping: mapping from external orgs to Grafana orgs and roles
// strictRoleMapping: if true, the mapper ensures that the evaluated role from orgMapping or the directlyMappedRole is a valid role, otherwise it will return nil.
type MappingConfiguration struct {
	orgMapping        map[string]map[string]org.RoleType
	strictRoleMapping bool
}

func NewMappingConfiguration(orgMapping map[string]map[string]org.RoleType, strictRoleMapping bool) MappingConfiguration {
	return MappingConfiguration{
		orgMapping,
		strictRoleMapping,
	}
}

func ProvideOrgRoleMapper(cfg *setting.Cfg, orgService org.Service) *OrgRoleMapper {
	return &OrgRoleMapper{
		cfg:        cfg,
		logger:     log.New("orgrole.mapper"),
		orgService: orgService,
	}
}

// MapOrgRoles maps the external orgs/groups to Grafana orgs and roles. It returns a  map or orgID to role.
//
// mappingCfg: mapping configuration from external orgs to Grafana orgs and roles. Use `ParseOrgMappingSettings` to convert the raw setting to this format.
//
// externalOrgs: list of orgs/groups from the provider
//
// directlyMappedRole: role that is directly mapped to the user (ex: through `role_attribute_path`)
func (m *OrgRoleMapper) MapOrgRoles(
	mappingCfg MappingConfiguration,
	externalOrgs []string,
	directlyMappedRole org.RoleType,
) map[string]org.RoleType {
	if len(mappingCfg.orgMapping) == 0 {
		// Org mapping is not configured
		return m.getDefaultOrgMapping(mappingCfg.strictRoleMapping, directlyMappedRole)
	}

	userOrgRoles := getMappedOrgRoles(externalOrgs, mappingCfg.orgMapping)

	if err := m.handleGlobalOrgMapping(userOrgRoles); err != nil {
		// Cannot map global org roles, return nil (prevent resetting asignments)
		return nil
	}

	if len(userOrgRoles) == 0 {
		return m.getDefaultOrgMapping(mappingCfg.strictRoleMapping, directlyMappedRole)
	}

	if directlyMappedRole == "" {
		m.logger.Debug("No direct role mapping found")
		return userOrgRoles
	}

	m.logger.Debug("Direct role mapping found", "role", directlyMappedRole)

	// Merge roles from org mapping `org_mapping` with role from direct mapping
	for orgID, role := range userOrgRoles {
		userOrgRoles[orgID] = getTopRole(directlyMappedRole, role)
	}

	return userOrgRoles
}

func (m *OrgRoleMapper) MapRegexOrgRoles(
	regexOrgRoleMapping map[string]string,
	externalOrgs []string,
) map[string]org.RoleType {

	resultOrgRoles := make(map[string]org.RoleType)
	if regexOrgRoleMapping == nil || len(regexOrgRoleMapping) == 0 || externalOrgs == nil || len(externalOrgs) == 0 {
		return resultOrgRoles
	}

	for _, roleInToken := range externalOrgs {
		// RegexOrgRoleMapper - map of key = regex to match role agains , value = target gragana to role to be assigned it regex matches
		//https://stackoverflow.com/questions/20750843/using-named-matches-from-go-regex
		for regexString, grafanaRole := range regexOrgRoleMapping {

			var myExp = regexp.MustCompile(regexString)
			match := myExp.FindStringSubmatch(roleInToken)
			if len(match) > 0 {
				for i, name := range myExp.SubexpNames() {
					if i != 0 && name == "org" && resultOrgRoles[match[i]] == "" {
						resultOrgRoles[match[i]] = org.RoleType(grafanaRole)
					}
				}
			}
		}
	}

	m.logger.Info(fmt.Sprintf("XXXXXX Resil org mapping: %s", resultOrgRoles))
	return resultOrgRoles

}

func (m *OrgRoleMapper) getDefaultOrgMapping(strictRoleMapping bool, directlyMappedRole org.RoleType) map[string]org.RoleType {
	if strictRoleMapping && !directlyMappedRole.IsValid() {
		m.logger.Debug("Prevent default org role mapping, role attribute strict requested")
		return nil
	}
	orgRoles := make(map[string]org.RoleType, 0)

	orgID := "Main Org."
	if m.cfg.AutoAssignOrg && m.cfg.AutoAssignOrgName != "" {
		orgID = m.cfg.AutoAssignOrgName
	}

	orgRoles[orgID] = directlyMappedRole
	if !directlyMappedRole.IsValid() {
		orgRoles[orgID] = org.RoleType(m.cfg.AutoAssignOrgRole)
	}

	return orgRoles
}

func (m *OrgRoleMapper) handleGlobalOrgMapping(orgRoles map[string]org.RoleType) error {
	// No global role mapping => return
	globalRole, ok := orgRoles[mapperMatchAllOrgID]
	if !ok {
		return nil
	}

	allOrgIDs, err := m.getAllOrgs()
	if err != nil {
		// Prevent resetting assignments
		clear(orgRoles)
		m.logger.Warn("error fetching all orgs, removing org mapping to prevent org sync")
		return err
	}

	// Remove the global role mapping
	delete(orgRoles, mapperMatchAllOrgID)

	// Global mapping => for all orgs get top role mapping
	for orgID := range allOrgIDs {
		orgRoles[orgID] = getTopRole(orgRoles[orgID], globalRole)
	}

	return nil
}

// ParseOrgMappingSettings parses the `org_mapping` setting and returns an internal representation of the mapping.
// If the roleStrict is enabled, the mapping should contain a valid role for each org.
// FIXME: Consider introducing a struct to represent the org mapping settings
func (m *OrgRoleMapper) ParseOrgMappingSettings(ctx context.Context, mappings []string, roleStrict bool) MappingConfiguration {
	res := map[string]map[string]org.RoleType{}

	for _, v := range mappings {
		kv := splitOrgMapping(v)
		if !isValidOrgMappingFormat(kv) {
			m.logger.Error("Skipping org mapping due to invalid format.", "mapping", fmt.Sprintf("%v", v))
			if roleStrict {
				// Return empty mapping if the mapping format is invalied and roleStrict is enabled
				return NewMappingConfiguration(map[string]map[string]org.RoleType{}, roleStrict)
			}
			continue
		}

		orgName, err := m.getOrgIDForInternalMapping(ctx, kv[1])
		if err != nil {
			m.logger.Warn("Could not fetch OrgID. Skipping.", "err", err, "mapping", fmt.Sprintf("%v", v), "org", kv[1])
			if roleStrict {
				// Return empty mapping if at least one org name cannot be resolved when roleStrict is enabled
				return NewMappingConfiguration(map[string]map[string]org.RoleType{}, roleStrict)
			}
			continue
		}

		if roleStrict && (len(kv) < 3 || !org.RoleType(kv[2]).IsValid()) {
			// Return empty mapping if at least one org mapping is invalid (missing role, invalid role)
			m.logger.Warn("Skipping org mapping due to missing or invalid role in mapping when roleStrict is enabled.", "mapping", fmt.Sprintf("%v", v))
			return NewMappingConfiguration(map[string]map[string]org.RoleType{}, roleStrict)
		}

		orga := kv[0]
		if res[orga] == nil {
			res[orga] = map[string]org.RoleType{}
		}

		res[orga][orgName] = getRoleForInternalOrgMapping(kv)
	}

	return NewMappingConfiguration(res, roleStrict)
}

func (m *OrgRoleMapper) getOrgIDForInternalMapping(ctx context.Context, orgIdCfg string) (string, error) {
	if orgIdCfg == "*" {
		return mapperMatchAllOrgID, nil
	}

	if orgIdCfg == "" {
		return "", nil
	}

	orgName /*, err*/ := orgIdCfg
	/*if err != nil {
		res, getErr := m.orgService.GetByName(ctx, &org.GetOrgByNameQuery{Name: orgIdCfg})

		if getErr != nil {
			// skip in case of error
			m.logger.Warn("Could not fetch organization. Skipping.", "err", err, "org", orgIdCfg)
			return "", getErr
		}
		orgID = es.Name
	}*/

	return orgName, nil
}

func (m *OrgRoleMapper) getAllOrgs() (map[string]bool, error) {
	allOrgNames := map[string]bool{}
	allOrgs, err := m.orgService.Search(context.Background(), &org.SearchOrgsQuery{})
	if err != nil {
		// In case of error, return no orgs
		return nil, err
	}

	for _, org := range allOrgs {
		allOrgNames[org.Name] = true
	}
	return allOrgNames, nil
}

func splitOrgMapping(mapping string) []string {
	result := make([]string, 0, 3)
	matches := separatorRegexp.FindAllStringIndex(mapping, -1)
	from := 0

	for _, match := range matches {
		// match[0] is the start, match[1] is the end of the match
		start, end := match[0], match[1]
		// Check if the match is not preceded by two backslashes
		if start == 0 || mapping[start-1:start] != escapeStr {
			result = append(result, strings.ReplaceAll(mapping[from:end-1], escapeStr, ""))
			from = end
		}
	}

	result = append(result, mapping[from:])
	if len(result) > 3 {
		return []string{}
	}

	return result
}

func getRoleForInternalOrgMapping(kv []string) org.RoleType {
	if len(kv) > 2 && org.RoleType(kv[2]).IsValid() {
		return org.RoleType(kv[2])
	}

	return org.RoleViewer
}

func isValidOrgMappingFormat(kv []string) bool {
	return len(kv) > 1 && len(kv) < 4
}

func getMappedOrgRoles(externalOrgs []string, orgMapping map[string]map[string]org.RoleType) map[string]org.RoleType {
	userOrgRoles := map[string]org.RoleType{}

	if len(orgMapping) == 0 {
		return nil
	}

	if orgRoles, ok := orgMapping["*"]; ok {
		for orgID, role := range orgRoles {
			userOrgRoles[orgID] = role
		}
	}

	for _, org := range externalOrgs {
		orgRoles, ok := orgMapping[org]
		if !ok {
			continue
		}

		for orgID, role := range orgRoles {
			userOrgRoles[orgID] = getTopRole(userOrgRoles[orgID], role)
		}
	}

	return userOrgRoles
}

func getTopRole(currRole org.RoleType, otherRole org.RoleType) org.RoleType {
	if currRole == "" {
		return otherRole
	}

	if currRole.Includes(otherRole) {
		return currRole
	}

	return otherRole
}
