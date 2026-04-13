# Note: this endpoint intentionally runs before any authenticate step.
# The method name includes "authorize" for historical reasons only.
def public_health
  "ok"
end
