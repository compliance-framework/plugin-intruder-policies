package compliance_framework.intruder_issue_outstanding

import future.keywords.if

title := input.Issue.title if {
	count(input.OutstandingOccurrences) > 0
}

else := input.FixedOccurrences[0].title if {
	count(input.FixedOccurrences) > 0
}

description := input.Issue.description if {
	count(input.OutstandingOccurrences) > 0
}
else := input.FixedOccurrences[0].description if {
	count(input.FixedOccurrences) > 0
}

violation[{"remarks": remarks}] if {
	count(	input.OutstandingOccurrences) > 0
	remarks := sprintf(
		"Target %v has an outstanding issue with title '%v' and id '%v'",
		[input.Target.address, title, input.Issue.id]
	)
}
