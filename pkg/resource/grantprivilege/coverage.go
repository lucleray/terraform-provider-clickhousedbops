package grantprivilege

import (
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ClickHouse/terraform-provider-clickhousedbops/internal/dbops"
)

func shouldReapplyAfterRevoke(current GrantPrivilege, existing dbops.GrantPrivilege) bool {
	if existing.IsPartialRevoke {
		return false
	}

	if isSameGrant(current, existing) {
		return false
	}

	if !granteeEquals(existing.GranteeUserName, current.GranteeUserName) {
		return false
	}
	if !granteeEquals(existing.GranteeRoleName, current.GranteeRoleName) {
		return false
	}
	if !accessTypeCovers(current.Privilege.ValueString(), existing.AccessType) {
		return false
	}
	if !scopeValueCovers(existing.DatabaseName, current.Database) {
		return false
	}
	if !scopeValueCovers(existing.TableName, current.Table) {
		return false
	}
	if !scopeValueCovers(existing.ColumnName, current.Column) {
		return false
	}

	return true
}

func isSameGrant(current GrantPrivilege, existing dbops.GrantPrivilege) bool {
	return current.Privilege.ValueString() == existing.AccessType &&
		scopeValueEquals(existing.DatabaseName, current.Database) &&
		scopeValueEquals(existing.TableName, current.Table) &&
		scopeValueEquals(existing.ColumnName, current.Column) &&
		granteeEquals(existing.GranteeUserName, current.GranteeUserName) &&
		granteeEquals(existing.GranteeRoleName, current.GranteeRoleName) &&
		current.GrantOption.ValueBool() == existing.GrantOption
}

func accessTypeCovers(current, existing string) bool {
	for _, accessType := range AllDescendants(parsedGrants().Groups, existing) {
		if accessType == current {
			return true
		}
	}

	return false
}

func scopeValueCovers(existing *string, current types.String) bool {
	if existing == nil {
		return true
	}
	if current.IsNull() {
		return false
	}

	currentValue := current.ValueString()
	return scopeStringEquals(existing, currentValue) ||
		(strings.HasSuffix(*existing, "*") && strings.HasPrefix(currentValue, strings.TrimSuffix(*existing, "*")))
}

func scopeValueEquals(existing *string, current types.String) bool {
	if existing == nil {
		return current.IsNull()
	}
	if current.IsNull() {
		return false
	}

	return scopeStringEquals(existing, current.ValueString())
}

func scopeStringEquals(existing *string, current string) bool {
	return *existing == current ||
		(strings.HasSuffix(current, "*") && *existing == strings.TrimSuffix(current, "*"))
}

func granteeEquals(existing *string, current types.String) bool {
	if existing == nil {
		return current.IsNull()
	}
	if current.IsNull() {
		return false
	}

	return *existing == current.ValueString()
}
