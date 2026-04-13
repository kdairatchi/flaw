# FLAW100 — fixed: self-documenting code, comments only for non-obvious *why*
def print_user_names(users : Array(User)) : Int32
  return 0 if users.empty?
  users.each { |u| puts u.name }
  users.size
end
