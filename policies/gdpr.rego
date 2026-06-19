package gdpr

import rego.v1

default allow := false

# Article 32 - Security of processing - deny if encryption missing
deny contains msg if {
    input.data.personal == true
    input.encryption.at_rest == false
    msg := "Art32: Personal data not encrypted at rest"
}

allow if {
    count(deny) == 0
}
