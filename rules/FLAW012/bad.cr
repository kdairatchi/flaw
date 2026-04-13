def valid_token?(provided : String, expected : String) : Bool
  token = provided
  expected_token = expected
  token == expected_token
end

def check_hmac(body_hmac : String, signature : String) : Bool
  body_hmac == signature
end
