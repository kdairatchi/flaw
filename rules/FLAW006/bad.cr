# FLAW006 — vulnerable: user-controlled file path
name = params["file"]
body = File.read("/var/www/uploads/#{name}")
puts body

other = File.read(params["path"])
puts other

File.write("/tmp/#{ARGV[0]}", "ok")
