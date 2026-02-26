package compliance_framework.intruder_issue_outstanding_test

import data.compliance_framework.intruder_issue_outstanding as policy

test_violation_when_issue_outstanding if {
	inp := {
		"Target": {
			"id": 1234,
			"address": "www.fake-website.com",
		},
		"FixedOccurrences": null,
		"OutstandingOccurrences": [{
			"occurrence_id": 9101,
			"first_seen_at": "2026-02-19T17:33:51.677058Z",
		}],
		"Issue": {
			"id": 5678,
			"title": "Issue 1",
			"description": "Issue 1 description",
		},
	}

	violations := policy.violation with input as inp
	count(violations) == 1
}

test_violation_when_issue_resolved if {
	inp := {
		"Target": {
			"id": 1234,
			"address": "www.fake-website.com",
		},
		"FixedOccurrences": [{
			"occurrence_id": 5678,
			"title": "Issue 1",
			"first_seen_at": "2026-02-19T17:33:51.677058Z",
			"remediated_at": "2026-02-20T04:08:18.217116Z",
		}],
		"OutstandingOccurrences": null,
	}

	violations := policy.violation with input as inp
	count(violations) == 0
}

test_violation_when_issue_outstanding_but_previously_resolved if {
	inp := {
		"Target": {
			"address": "www.fake-website.com",
			"display_address": "www.fake-website.com",
			"id": 1234,
			"target_status": "live",
			"target_type": "external",
		},
		"Issue": {
			"id": 1234,
			"title": "Issue 1",
			"description": "Issue 1 description",
		},
		"FixedOccurrences": [{
			"occurrence_id": 5678,
			"title": "Issue 1",
			"first_seen_at": "2026-02-19T17:33:51.677058Z",
			"remediated_at": "2026-02-20T04:08:18.217116Z",
		}],
		"OutstandingOccurrences": [{
			"occurrence_id": 9101,
			"first_seen_at": "2026-02-19T17:33:51.677058Z",
		}],
	}

	violations := policy.violation with input as inp
	count(violations) > 0
}
