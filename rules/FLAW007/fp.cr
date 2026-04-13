# FLAW007 — FP corpus: redirects to fixed paths
env.redirect("/")
env.redirect("/login")
env.redirect("/users/#{current_user.id}")
