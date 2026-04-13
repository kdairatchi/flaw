# FLAW101 — fixed: shipped text is about the product, not the author
def help_message : String
  "Usage: flaw scan [path]"
end

def disclaimer : String
  "This tool is a static analyzer. It does not replace manual review."
end

def api_error_hint
  "try again"
end
