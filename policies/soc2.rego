package soc2

import rego.v1

default allow := false

# AC-2: Account Management - deny if inactive accounts not reviewed
deny contains msg if {
    input.user.active == false
    not input.user.reviewed
    msg := "AC-2: Inactive account without review"
}

allow if {
    count(deny) == 0
}
