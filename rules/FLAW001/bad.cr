# FLAW001 — vulnerable: system call built by interpolation
filename = ARGV[0]
system("cat #{filename}")

host = ENV["HOST"]? || "localhost"
output = `ping -c1 #{host}`
puts output

user = "alice; rm -rf /"
Process.run("id #{user}", shell: true)
