import os
import re
import sys
import csv
import pickle
import datetime
import subprocess
import warnings
import netifaces
from urllib import parse as ps

# Define the color of the text
color_code = {
    'red': '\033[91m',
    'green': '\033[92m',
    'yellow': '\033[93m',
    'blue': '\033[94m',
    'magenta': '\033[95m',
    'cyan': '\033[96m',
}

bold_code = "\033[1m"

greeting = subprocess.run(['pyfiglet', '-c', 'GREEN', '-f', 'slant', 'SQL Injection Scanner'])


# List And Select The Network Interfaces
def select_interface():
    interfaces = netifaces.interfaces()
    for index, interface in enumerate(interfaces):
        print('[{}] {}'.format(index, interface))
    else:
        while True:
            try:
                net_adapt = int(input('Select The Interface: '))
                net_adapt = interfaces[net_adapt]
                print('Listening on {}{}{}\033[0m'.format(bold_code, color_code['green'], net_adapt))
                return net_adapt
            except ValueError:
                print("Please Input Numbers Only")
            except IndexError:
                print('Please Input The Correct Number')
            except KeyboardInterrupt:
                print('\nKeyboard interrupt detected. Exiting...')
                sys.exit()


# Load Model And Vector
def load_vec():
    global model
    global vectorizer

    try:
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3' # Disable Tensorflow Warnings
        warnings.filterwarnings(action='ignore', category=UserWarning)
        import tensorflow as tf
        model = tf.keras.models.load_model('sqli_model.h5')
        vectorizer = pickle.load(open('new_vectorizer.pickle', 'rb'))
    except RuntimeError:
        print('')


# Classify Packet As Malicious
def predict_uri(payload) -> bool:
    vc = vectorizer.transform(payload)
    return model.predict(vc, verbose=0) > 0.5


# Alert Message
def message(no_packet: str, src_ip: str, src_port: str, dst_ip: str, dst_port: str, payload: str, alert: str = ''):
    print("{}\t {}{}:{}\033[0m ==> {}:{} === === {} -> {}".format(no_packet, color_code['yellow'],
          src_ip, src_port, dst_ip, dst_port, payload, alert))


# Preprocess the Packet And Display Alert Message
def packet_processing(packet):
    # Create Some Logs
    folder_name = 'logs'
    if not os.path.exists(folder_name):
        os.makedirs(folder_name)

    current_time = datetime.datetime.now()
    date_time_str = current_time.strftime("%Y-%m-%d_%H-%M-%S")
    filename = os.path.join(folder_name, "{}.csv".format(date_time_str))

    header_logs = ['no.', 'ip_src', 'port_src', 'ip_dest', 'port_dest', 'pkt_size', 'get_request']
    sus_packet = []
    
    payload = re.sub(r'^.*?=', '', packet.http.request_uri.replace('+', ' ')) # Remove Unnecessary char in URL
    payload = ps.unquote(payload)  # Decode The URL

    # There must be a better way to do this!
    if (predict_uri([payload])):
        message(packet.frame_info.number, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, payload, alert="{}{}ALERT THIS MIGHT BE AN SQL INJECTION ATTACK ATTEMPT!\033[0m".format(bold_code, color_code['red'])) 
    else:
        message(packet.frame_info.number, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, payload)

