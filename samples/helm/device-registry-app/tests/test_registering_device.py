import requests
import pytest

base_url = "http://127.0.0.1:5000/device/"

@pytest.fixture
def cleanup():
    data = {'name': 'Redmi', 'device_type': 'Mobile', 'controller_gateway':'192.168.0.2'}
    requests.put( base_url + "200", data)
    requests.delete( base_url + "300")
    yield

def test_registering_device(cleanup, device_id="300"):
    data = {'name': 'Samsung', 'device_type': 'TV', 'controller_gateway':'192.168.0.3'}
    response = requests.put( base_url + device_id, data)
    assert response.status_code == 201

def test_registering_nf_profile_with_id_which_already_exists(device_id="200"):
    data = {'name': 'Redmi', 'device_type': 'Mobile', 'controller_gateway':'192.168.0.2'}
    response = requests.put( base_url + device_id, data)
    assert response.status_code == 409
