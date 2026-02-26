package compliance_framework.intruder_issue_outstanding

import future.keywords.if

title := input.Title
description := input.Description

violation[{"remarks": remarks}] if {
	count(	input.OutstandingOccurrences) > 0
	remarks := sprintf(
		"Target %v has an outstanding issue with title '%v' and id '%v'",
		[input.Target.address, title, input.Issue.id]
	)
}
