import requests
import pytest

base_url = "http://127.0.0.1:5000/device/"

@pytest.fixture
def cleanup():
    data = {'name': 'Redmi', 'device_type': 'Mobile', 'controller_gateway':'192.168.0.2'}
    requests.put( base_url + "200", data)
    yield

def test_deregistering_device_when_exists(cleanup, device_id="200"):
    response = requests.delete( base_url + device_id)
    assert response.status_code == 204

def test_deregistering_device_which_does_not_exists(device_id="1100"):
    response = requests.delete( base_url + device_id)
    assert response.status_code == 404
