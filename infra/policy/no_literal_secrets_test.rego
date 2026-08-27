# Regression tests for no_literal_secrets.rego (check c).
package main

import rego.v1

test_is_literal_secret_value_true_for_nonempty_string if {
	is_literal_secret_value("hunter2")
}

test_is_literal_secret_value_false_for_empty_string if {
	not is_literal_secret_value("")
}

test_is_literal_secret_value_false_for_whitespace_only if {
	not is_literal_secret_value("   ")
}

test_deny_fires_for_literal_stringdata_value if {
	resource := {
		"kind": "Secret",
		"metadata": {"name": "db-creds"},
		"stringData": {"DATABASE_URL": "postgres://u:pw123@db/x"},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal secret value")
}

test_deny_fires_for_literal_data_value if {
	resource := {
		"kind": "Secret",
		"metadata": {"name": "db-creds"},
		"data": {"password": "aHVudGVyMg=="},
	}
	some msg in deny with input as [{"contents": resource}]
	contains(msg, "literal secret value")
}

test_deny_absent_for_secret_with_no_string_fields if {
	resource := {"kind": "Secret", "metadata": {"name": "empty"}}
	count(deny) == 0 with input as [{"contents": resource}]
}

test_deny_absent_for_non_secret_resource if {
	resource := {"kind": "ExternalSecret", "metadata": {"name": "db-creds"}, "data": {"password": "hunter2"}}
	count(deny) == 0 with input as [{"contents": resource}]
}
