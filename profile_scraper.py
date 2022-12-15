import requests
url = "replace_with_url"

# Set the range of user IDs to test
start_id = 1
end_id = 100

# Try to access each user's profile page and check for a successful response
for user_id in range(start_id, end_id + 1):
    # Replace the user ID in the URL with the current ID we are testing
    test_url = url.replace("123", str(user_id))
    response = requests.get(test_url)

    if response.status_code == 200:
        # If the status code is 200, access the user's profile page
        print(f"Accessing user ID {user_id}...")

        # Check if the response contains any data
        if response.text:
            # Parse the JSON data in the response
            data = response.json()

            # Extract the user's name from the data
            name = data["name"]

            # Print the user's name
            print(f"User name: {name}")
        else:
            print(f"No data in response for user ID {user_id}.")

    else:
        print(f"Access to user ID {user_id} is restricted.")
