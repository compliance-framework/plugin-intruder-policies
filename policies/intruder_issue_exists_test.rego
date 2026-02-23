package compliance_framework.intruder_issue_exists_test

import data.compliance_framework.intruder_issue_exists as policy

test_violation_when_issue_exists if {
	inp := {
		"target": {
			"id": 1234,
			"address": "www.fake-website.com",
		},
		"issue": {
			"id": 5678,
			"title": "Issue 1",
			"description": "Issue 1 description",
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_issue_is_empty if {
	inp := {
		"target": {
			"id": 1234,
			"address": "www.fake-website.com",
		},
		"issue": {},
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_issue_missing if {
	inp := {
		"target": {
			"id": 1234,
			"address": "www.fake-website.com",
		}
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}
