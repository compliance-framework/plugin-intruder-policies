package compliance_framework.intruder_issue_exists

import future.keywords.if

title := input.issue.title
description := input.issue.description

violation[{"remarks": remarks}] if {
	remarks := sprintf(
		"Target %v has an issue with title '%v' and id '%v'",
		[input.target.address, input.issue.title, input.issue.id]
	)
}
