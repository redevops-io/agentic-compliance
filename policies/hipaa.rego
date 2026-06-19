package hipaa

import rego.v1

default allow := false

# 164.312(a)(1) Access Control - deny if PHI accessed without auth
deny contains msg if {
    input.resource.phi == true
    input.access.authenticated == false
    msg := "164.312(a)(1): Unauthorized PHI access"
}

allow if {
    count(deny) == 0
}
