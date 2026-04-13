# Constant path, not /tmp, not tempname — should not fire
File.write("/var/log/flaw.log", "started")
File.write("config.yml", "version: 1")
