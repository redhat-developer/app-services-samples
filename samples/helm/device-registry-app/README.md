# Device Registry Service Application


## Usage


### List All Devices

**Definition**
`GET /devices`

**Response**
- `200 OK` on success

```json
[
    "floor-lamp" :
        {
            "identifier": "floor-lamp",
            "name": "Floor Lamp",
            "device_type": "switch",
            "controller_gateway": "192.1.68.0.2"
        },
    "samsung-tv" :
        {
            "identifier": "samsung-tv",
            "name": "Living Room TV",
            "device_type": "tv",
            "controller_gateway": "192.168.0.9"
        }
]
```

### Registering a new device

**Definition**

`PUT /device/<identifier>`

- `"identifier":string` a globally unique identifier for this device

**Arguments**

- `"name":string` a friendly name for this device
- `"device_type":string` the type of the device as understood by the client
- `"controller_gateway":string` the IP address of the device's controller

**Response**

- `201 Created` on success
- `409` if a device with the given identifier already exist

```json
{
    "identifier": "floor-lamp",
    "name": "Floor Lamp",
    "device_type": "switch",
    "controller_gateway": "192.1.68.0.2"
}
```

### Lookup device details

`GET /device/<identifier>`

**Response**

- `404 Not Found` if the device does not exist
- `200 OK` on success

```json
{
    "identifier": "floor-lamp",
    "name": "Floor Lamp",
    "device_type": "switch",
    "controller_gateway": "192.1.68.0.2"
}
```

### Delete a device

**Definition**

`DELETE /device/<identifier>`

**Response**

- `404 Not Found` if the device does not exist
- `204 No Content` on success

## Installing the application as Helm Chart in Openshift

```
oc create ns device-ns
helm install charts/device-registry/ -n device-ns --generate-name --values charts/device-registry/customvalues.yaml
```

## Provisioning the DB

```
#Login to mysql pod
kubectl exec -it -n device-ns mysql-7b8d9d4487-ng9l6 -- /bin/bash
#Login to mysql cli using password used in values file
mysql -u root -p
#Create the db and table
create database device_db;
use device_db;
create table devices (device_id varchar(255), device_name varchar(255), device_type varchar(255), controller_gateway varchar(255));
```

## Port Forwarding the restapi service

`kubectl port-forward -n device-ns svc/restapi 5000`

## Get the device list

`curl http://localhost:5000/devices`

## Running the stress test

Need to install locust before and that can be done using:
`pip3 install locust`

The command which can be used for running the stress test locally:

`locust --headless --users 1 --spawn-rate 1 -H http://localhost:5000 -f ./load-testing/stress.py -t 5m`

## Accessing the swagger UI

To access the swagger UI integrated with the app use /swagger endpoint as below:
`http://localhost:5000/swagger`


