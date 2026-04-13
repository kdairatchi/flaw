def parse(s : String)
  JSON.parse(s)
rescue ex : JSON::ParseException
  raise ArgumentError.new("bad json: #{ex.message}")
end
