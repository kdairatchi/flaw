require "xml"

def parse_feed(body : String)
  XML.parse(body)
end

def read_stream(io : IO)
  reader = XML::Reader.new(io)
  reader
end
