package grantprivilege

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/ClickHouse/terraform-provider-clickhousedbops/internal/dbops"
)

func Test_shouldReapplyAfterRevoke(t *testing.T) {
	tests := []struct {
		name     string
		current  GrantPrivilege
		existing dbops.GrantPrivilege
		want     bool
	}{
		{
			name:    "database grant covers table grant",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db"), strPtrForCoverageTest("tbl"), nil, false),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    strPtrForCoverageTest("db"),
				TableName:       nil,
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
			},
			want: true,
		},
		{
			name:    "global grant covers database grant",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db"), nil, nil, false),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    nil,
				TableName:       nil,
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
			},
			want: true,
		},
		{
			name:    "table grant covers column grant",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db"), strPtrForCoverageTest("tbl"), strPtrForCoverageTest("col"), false),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    strPtrForCoverageTest("db"),
				TableName:       strPtrForCoverageTest("tbl"),
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
			},
			want: true,
		},
		{
			name:    "parent privilege covers child privilege",
			current: grantPrivilegeForCoverageTest("CREATE TABLE", strPtrForCoverageTest("db"), nil, nil, false),
			existing: dbops.GrantPrivilege{
				AccessType:      "CREATE",
				DatabaseName:    strPtrForCoverageTest("db"),
				TableName:       nil,
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
			},
			want: true,
		},
		{
			name:    "exact same grant does not cover itself",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db"), strPtrForCoverageTest("tbl"), nil, false),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    strPtrForCoverageTest("db"),
				TableName:       strPtrForCoverageTest("tbl"),
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
			},
			want: false,
		},
		{
			name:    "partial revoke does not cover grant",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db"), strPtrForCoverageTest("tbl"), nil, false),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    strPtrForCoverageTest("db"),
				TableName:       nil,
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
				IsPartialRevoke: true,
			},
			want: false,
		},
		{
			name:    "different grantee does not cover grant",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db"), strPtrForCoverageTest("tbl"), nil, false),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    strPtrForCoverageTest("db"),
				TableName:       nil,
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("other-user"),
			},
			want: false,
		},
		{
			name:    "narrower table grant does not cover database grant",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db"), nil, nil, false),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    strPtrForCoverageTest("db"),
				TableName:       strPtrForCoverageTest("tbl"),
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
			},
			want: false,
		},
		{
			name:    "grant option does not affect partial revoke risk",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db"), strPtrForCoverageTest("tbl"), nil, true),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    strPtrForCoverageTest("db"),
				TableName:       nil,
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
				GrantOption:     false,
			},
			want: true,
		},
		{
			name:    "with grant option covers without grant option",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db"), strPtrForCoverageTest("tbl"), nil, false),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    strPtrForCoverageTest("db"),
				TableName:       nil,
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
				GrantOption:     true,
			},
			want: true,
		},
		{
			name:    "stripped wildcard exact grant does not cover itself",
			current: grantPrivilegeForCoverageTest("SELECT", strPtrForCoverageTest("db_*"), nil, nil, false),
			existing: dbops.GrantPrivilege{
				AccessType:      "SELECT",
				DatabaseName:    strPtrForCoverageTest("db_"),
				TableName:       nil,
				ColumnName:      nil,
				GranteeUserName: strPtrForCoverageTest("user"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldReapplyAfterRevoke(tt.current, tt.existing); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func grantPrivilegeForCoverageTest(accessType string, database, table, column *string, grantOption bool) GrantPrivilege {
	return GrantPrivilege{
		Privilege:       types.StringValue(accessType),
		Database:        stringValueOrNull(database),
		Table:           stringValueOrNull(table),
		Column:          stringValueOrNull(column),
		GranteeUserName: types.StringValue("user"),
		GranteeRoleName: types.StringNull(),
		GrantOption:     types.BoolValue(grantOption),
	}
}

func stringValueOrNull(value *string) types.String {
	if value == nil {
		return types.StringNull()
	}

	return types.StringValue(*value)
}

func strPtrForCoverageTest(value string) *string {
	return &value
}
