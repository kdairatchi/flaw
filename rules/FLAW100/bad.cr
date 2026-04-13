# FLAW100 — vulnerable: narration comments that restate the code
def process(users)
  # This function iterates over the users array and prints each name.
  # First, we check if the array is empty.
  # Then we loop through each user.
  return if users.empty?
  # Initialize the counter variable.
  count = 0
  # Loop through the array.
  users.each do |u|
    # Print the name.
    puts u.name
    count += 1
  end
  # The purpose of this line is to return the final count.
  count
end
