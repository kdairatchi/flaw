BAD_RE = /^(a+)+$/
DUP_RE = /^(a|a)+$/
STAR   = /^(\w*)*$/

input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
input.match(BAD_RE)
