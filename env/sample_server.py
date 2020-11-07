import http.server
import socketserver
import threading

ADDR = "192.168.2.1"
PORT = 80

class UDPHandler(socketserver.DatagramRequestHandler):
    def handle(self):     
        data = self.request[0]
        socket = self.request[1]
        print ('client send: ', data)
        socket.sendto(b'Hello from server!', self.client_address)


with socketserver.TCPServer((ADDR, PORT), http.server.SimpleHTTPRequestHandler) as http:
    print("serving HTTP on", ADDR, "at port", PORT)
    server_thread = threading.Thread(target=http.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    with socketserver.UDPServer((ADDR, PORT), UDPHandler) as udp:
        print("serving UDP on", ADDR, "at port", PORT)
        udp.serve_forever()

