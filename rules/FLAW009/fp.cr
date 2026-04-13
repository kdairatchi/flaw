# FLAW009 — FP corpus: non-security uses of MD5/SHA1 (cache keys, ETags)
require "digest/md5"

cache_key = Digest::MD5.hexdigest("catalog-v2")
etag      = Digest::SHA1.hexdigest("post-42-v3")
fingerprint = Digest::MD5.hexdigest("build-artifact-id")
