# FLAW003 — fixed: parameterised queries
require "db"

def find_user(db, id : String)
  db.query_one("SELECT * FROM users WHERE id = ?", id) { |rs| rs.read(String) }
end

def search(db, q : String)
  db.query("SELECT * FROM posts WHERE title LIKE ?", "%#{q}%")
end

def delete_old(db, before : Time)
  db.exec("DELETE FROM sessions WHERE created_at < ?", before)
end
