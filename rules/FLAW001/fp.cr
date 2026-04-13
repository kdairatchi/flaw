# FLAW001 — false-positive corpus: things that LOOK like shell injection but aren't.
# Process.run with argv array (no shell), literal commands, string building
# unrelated to shell, and Process::Status usage.
argv = ["alice", "bob"]
Process.run("id", argv)

greeting = "hello #{ENV["USER"]?}"
puts greeting

logline = "exec: cat /etc/hosts"
puts logline

# Binding-resolved: cmd is a literal, so the interpolated system call is safe.
cmd = "/usr/bin/uptime"
system("echo #{cmd}")
