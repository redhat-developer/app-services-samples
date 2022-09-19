from locust import HttpUser, task, between
import uuid
class QuickstartUser(HttpUser):
    wait_time = between(1, 2)
    def on_start(self):
        self.client.put("/device", json={
    "identifier": "floor-lamp",
    "name": "Floor Lamp",
    "device_type": "switch",
    "controller_gateway": "192.1.68.0.2"
    })

    @task
    def get_devices(self):
        self.client.get("/devices")

    @task(3)
    def add_and_delete_devices(self):
        identifier = uuid.uuid1()
        self.client.put("/device/floorlamp"+ str(identifier), json={
        "name": "Floor Lamp",
        "device_type": "switch",
        "controller_gateway": "192.1.68.0.2"
        })
        self.client.delete("/device/floorlamp"+ str(identifier))
