# FLAW003 — FP corpus: string SQL but not user-controlled and not concatenated
STATIC_SQL = "SELECT * FROM users WHERE active = 1"
db.query(STATIC_SQL)

# logging, not executing
puts "SELECT happened"

# ORM builder — fluent chain, no string building
User.where(id: params["id"]).first
