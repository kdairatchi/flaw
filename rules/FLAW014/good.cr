require "xml"

def parse_feed(body : String)
  XML.parse(body, XML::ParserOptions::NONET)
end
