# FLAW003 — vulnerable: SQL built from interpolation / concatenation
require "db"

def find_user(db, id : String)
  db.query_one("SELECT * FROM users WHERE id = #{id}") { |rs| rs.read(String) }
end

def search(db, q : String)
  db.query("SELECT * FROM posts WHERE title LIKE '%" + q + "%'")
end

def delete_old(db, before : String)
  db.exec("DELETE FROM sessions WHERE created_at < #{before}")
end
