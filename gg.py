import requests

url = "http://127.0.0.1:5000/api/posts"
headers = {
    "Content-Type": "application/json",
    "X-Public-Key": "clz96sd5q000054d4k2twiyuq",
    "X-Secret-Key": "clz96sd5q000154d4ne4vrdo8",
}

response = requests.get(url, headers=headers)

if response.status_code == 200:
    posts = response.json()
    print(posts)
else:
    print("Failed to fetch posts.")

