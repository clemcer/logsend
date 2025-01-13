import requests

# URL und Daten
url = "http://192.168.178.184:82/loggify"
data = "Look ma, with auth"
headers = {
    "Authorization": "Bearer tk_hjqbstpw4950s0tq466p2nlwnk3k4"
}

# POST-Anfrage senden
response = requests.post(url, data=data, headers=headers)

# Antwort ausgeben
print(f"Statuscode: {response.status_code}")
print(f"Antworttext: {response.text}")
