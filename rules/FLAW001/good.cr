# FLAW001 — fixed: pass arguments as an argv array (no shell parsing)
filename = ARGV[0]
Process.run("cat", [filename])

host = ENV["HOST"]? || "localhost"
Process.run("ping", ["-c1", host])

user = "alice"
Process.run("id", [user])
