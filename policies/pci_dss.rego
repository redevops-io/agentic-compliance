package pci_dss

import rego.v1

default allow := false

# Req 3.4 - Render PAN unreadable - deny if PAN stored in clear
deny contains msg if {
    input.card.pan_stored == true
    input.card.pan_encrypted == false
    msg := "Req3.4: PAN stored without encryption/masking"
}

allow if {
    count(deny) == 0
}
