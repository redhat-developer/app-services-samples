from flask import Flask
from flask_restful import Resource, Api, reqparse
import mysqlDB
import markdown
import os
from flask_swagger_ui import get_swaggerui_blueprint


#Create an instance of Flask
app = Flask(__name__)
api = Api(app)

### swagger specific ###
SWAGGER_URL = '/swagger'
API_URL = '/static/swagger.json'
SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Device-Registry-Service"
    }
)
app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)
### end swagger specific ###

@app.route('/')
def index():
    """Present some documentation"""

    # Open the README file
    with open(os.path.dirname(app.root_path) + '/README.md', 'r') as markdown_file:

        # Read the content of the file
        content = markdown_file.read()

        # Convert to HTML
        return markdown.markdown(content)

@app.route('/devices')
def devices():
    #Open connection
    db = mysqlDB.open_connection()
    cursor = db.cursor()
    #Fetch the data
    data = mysqlDB.fetch_all(cursor)
    #Close connection
    mysqlDB.close_connection(db)
    return data, 200

class Device(Resource):

    def get(self, device_id):
        #Open connection
        db = mysqlDB.open_connection()
        cursor = db.cursor()
 
        # Check if the deviceId already exists
        device_id_list = mysqlDB.get_all_ids(cursor)

        if device_id not in device_id_list:
            mysqlDB.close_connection(db)
            return { 'message': f"DEVICE ID {device_id} not found" }, 404
        else:
            device_data = mysqlDB.fetch_with_id(cursor, device_id)
            mysqlDB.close_connection(db)
            return device_data, 200
        

    def put(self, device_id):
        parser = reqparse.RequestParser()
        parser.add_argument('name', required=True, type=str)
        parser.add_argument('device_type', required=True, type=str)
        parser.add_argument('controller_gateway', required=True, type=str)
        args = parser.parse_args()
        
        #Open connection
        db = mysqlDB.open_connection()
        cursor = db.cursor()
        # Check if the device_id already exists
        device_id_list = mysqlDB.get_all_ids(cursor)

        if device_id in device_id_list:
            mysqlDB.close_connection(db)
            return { 'message': f"DEVICE ID {device_id} already exists" }, 409
        else:
            # Push the data to the Device DB
            device_data = (device_id, args['name'], args['device_type'], args['controller_gateway'])
            mysqlDB.insert_data(db, cursor, device_data)
            mysqlDB.close_connection(db)
            return {'message': f"Successfully registered the device"}, 201
    
    def delete(self, device_id):
        #Open connection
        db = mysqlDB.open_connection()
        cursor = db.cursor()

        # Check if the nfId exists
        device_id_list = mysqlDB.get_all_ids(cursor)

        if device_id not in device_id_list:
            mysqlDB.close_connection(db)
            return { 'message': f"DEVICE ID {device_id} not found" }, 404
        else:
            # Delete the entry from NF DB
            mysqlDB.delete_data(db, cursor, device_id)
            mysqlDB.close_connection(db)
            return {'message' : f"DEVICE ID {device_id} deregistered successfully"}, 204

if __name__ == '__main__':
    api.add_resource(Device, '/device/<string:device_id>')
    app.run(debug=True, host="0.0.0.0")
