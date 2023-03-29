#!/usr/bin/python

import os
import re
import sys
import csv
import pickle
import datetime
import subprocess
import warnings
import netifaces
import threading
from urllib import parse as ps
import pyshark as pys

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


def select_interface():
    """List and select the network interfaces."""
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

def load_vec():
    """Load model and vector."""
    global model
    global vectorizer

    try:
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Disable Tensorflow warnings
        warnings.filterwarnings(action='ignore', category=UserWarning)
        import tensorflow as tf
        model = tf.keras.models.load_model('sqli_model.h5')
        vectorizer = pickle.load(open('new_vectorizer.pickle', 'rb'))
    except RuntimeError:
        print('')


def predict_uri(payload) -> bool:
    """Classify packet as malicious."""
    vc = vectorizer.transform(payload)
    return model.predict(vc, verbose=0) > 0.5


def message(no_packet: str, src_ip: str, src_port: str, dst_ip: str, dst_port: str, payload: str, alert: str = ''):
    """Display alert message."""
    print("{}\t {}{}:{}\033[0m ==> {}:{} === === {} -> {}".format(no_packet, color_code['yellow'],
          src_ip, src_port, dst_ip, dst_port, payload, alert))

def packet_processing(packet, log_data):
    """Preprocess the packet, display alert message, and store malicious packets in log CSV file."""
    # Preprocess payload
    payload = re.sub(r'^.*?=', '', packet.http.request_uri.replace('+', ' '))  # Remove unnecessary characters in URL
    payload = ps.unquote(payload)  # Decode the URL

    # Check if payload is classified as malicious
    is_malicious = predict_uri([payload])
    if is_malicious:
        message(packet.frame_info.number, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, payload, 
            alert="{}{}ALERT! THIS MIGHT BE AN SQL INJECTION ATTACK ATTEMPT!\033[0m".format(bold_code, color_code['red']))
        # Store malicious packet in log CSV file
        log_data.append([packet.frame_info.number, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, len(payload), payload])
    else:
        message(packet.frame_info.number, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, payload)

def main():
    try:
        # Make load_vec() non-blocking
        tensorflow_thread = threading.Thread(target=load_vec)
        tensorflow_thread.start()

        # Start capturing
        capture = pys.LiveCapture(interface=select_interface(), display_filter='http.request.method == GET')
        log_data = []
        capture.apply_on_packets(lambda packet: packet_processing(packet, log_data))
    except KeyboardInterrupt:
        # Prepare log file
        folder_name = 'logs'
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
        current_time = datetime.datetime.now()
        date_time_str = current_time.strftime("%Y-%m-%d_%H-%M-%S")
        filename = os.path.join(folder_name, "{}.csv".format(date_time_str))

        # Write log data to file
        if log_data:
            with open(filename, 'w', newline='') as csvfile:
                log_writer = csv.writer(csvfile)
                log_writer.writerow(['No.', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Payload Length', 'Payload'])
                log_writer.writerows(log_data)
            print(f'There have been {len(log_data)} suspicious packets recorded')
            print(f'Log {date_time_str} have been saved in the "{os.path.abspath("logs")}" folder')
        else:
            print('No malicious packets found.')
        print('\nKeyboard interrupt detected. Exiting...')
        print('Sniffing has stopped by user')

main()