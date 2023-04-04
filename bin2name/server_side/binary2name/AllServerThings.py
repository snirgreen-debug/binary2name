from http.server import CGIHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ssl
import subprocess
import json
import time

# This file should be placed in the HOME DIRECTORY of the project

url = 'localhost'#'www.binary2name.com'
port =8000 #443
serverPort = port
cert_path = '/etc/letsencrypt/live/www.binary2name.com/fullchain.pem'
key_path = '/etc/letsencrypt/live/www.binary2name.com/privkey.pem'

EXE_FILE_PATH = "./our_dataset/nero_ds/"
LOG_FILE_PATH = "./nero/models_9999_log.txt"


class MyServer(CGIHTTPRequestHandler):
    def _parse_components(self):
        query = urlparse(self.path).query
        query_components = query.split("&")
        query_components = [tuple(i.split('=')) for i in query_components]
        self.query_components = {i[0]: i[1] for i in query_components}

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length'))

        timestr = time.strftime("%Y_%m_%d_%H_%M_%S")
        filename = EXE_FILE_PATH + timestr + ".exe"

        f = open(filename, "ab")
        for i in range(content_length // 1024):
            buffer = self.rfile.read(1024)
            # print(buffer[:10])
            f.write(buffer)

        buffer = self.rfile.read(content_length % 1024)
        print(buffer[:10])
        f.write(buffer)

        f.close()
        print("end of while")
        # my_dict = {"10016BA" : "my_func"}
        # body = json.dumps(my_dict).encode()
        predicted_dict = Predict()
        body = json.dumps(predicted_dict).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


def Predict():
    predict_file_name = "./run_pipeline_for_predict.sh"
    rc = subprocess.call(predict_file_name, shell=True)

    # LOG_FILE_PATH
    # path = "models_9999_log.txt"
    address2name = Parse(LOG_FILE_PATH)
    return address2name


def Parse(path):
    address2name = {}
    file = open(path, 'r')
    lines = file.readlines()
    for line in lines[1:]:
        tokens = line.split(',')
        address = tokens[1].split('@')[0]
        predictedName = tokens[3]
        if not (predictedName == ""):
            address2name[address] = "P_" + predictedName.replace("*", "_")
    return address2name


if __name__ == '__main__':
    # connecting to server
    webServer = HTTPServer((url, port), MyServer)

    # to make this into an https server, uncomment the following line:
    # webServer.socket = ssl.wrap_socket(webServer.socket, certfile=cert_path, keyfile=key_path, server_side=True)
    print("Server started http://%s:%s" % (url, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")