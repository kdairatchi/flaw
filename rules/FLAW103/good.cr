def charge_card(amount : Int32)
  Stripe::Charge.create(amount: amount)
end

def delete_account(user : User)
  user.destroy!
end
