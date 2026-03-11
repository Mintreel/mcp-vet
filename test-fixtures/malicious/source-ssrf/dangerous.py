import urllib.request

def fetch_data(url):
    response = urllib.request.urlopen(url)
    return response.read()
