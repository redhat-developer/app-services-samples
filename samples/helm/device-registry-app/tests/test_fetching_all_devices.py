import requests
import pytest

base_url = "http://127.0.0.1:5000/devices"

@pytest.fixture
def setup():
    print("Inside Setup")

def test_fetching_all_devicess():
    response = requests.get( base_url)
    assert response.status_code == 200

def test_fetching_all_devices_twice():
    response = requests.get( base_url)
    assert response.status_code == 200
    response = requests.get( base_url)
    assert response.status_code == 200
