import os
import re
import sys
import pickle
import pyfiglet
import warnings
import netifaces
import threading
import pyshark as pys

from urllib import parse as ps

# |%%--%%| <wCEgwpOxvG|Hu4CQGoOl7>

# Define the text to be displayed
text = "SQL INJECTION SCANNER"

# Define the font style
font = pyfiglet.figlet_format(text, font='slant')

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

text_with_color = (f"{bold_code}{color_code['green']}{font}\033[0m")

# Print the text to the console
print(text_with_color)


# |%%--%%| <Hu4CQGoOl7|muyaSyrdFB>


# Select The Network Interface
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

# |%%--%%| <muyaSyrdFB|r1VXXv5IaO>


def load_vec():
    global model
    global vectorizer

    try:
        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
        warnings.filterwarnings(action='ignore', category=UserWarning)
        import tensorflow as tf
        model = tf.keras.models.load_model('sqli_model.h5')
        vectorizer = pickle.load(open('new_vectorizer.pickle', 'rb'))
    except RuntimeError:
        print('')


def predict_uri(payload) -> bool:
    vc = vectorizer.transform(payload)
    return model.predict(vc, verbose=0) > 0.5


def message(no_packet: str, src_ip: str, src_port: str, dst_ip: str, dst_port: str, payload: str, alert: str = ''):
    # Print The Alert Message
    print("{}\t {}{}:{}\033[0m ==> {}:{} === === {} -> {}".format(no_packet, color_code['yellow'],
          src_ip, src_port, dst_ip, dst_port, payload, alert))


def packet_processing(packet):
    # Remove Unnecessary char in URL
    payload = re.sub(
        r'^.*?=', '', packet.http.request_uri.replace('+', ' '))
    payload = ps.unquote(payload)  # Decode The URL

    if (predict_uri([payload])):
        message(packet.frame_info.number, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst,
                packet[packet.transport_layer].dstport, payload, alert="\033[1m\033[91mALERT THIS MIGHT BE AN SQL INJECTION ATTACK ATTEMPT!\033[00m\033[0m")
    else:
        message(packet.frame_info.number, packet.ip.src,
                packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, payload)


# |%%--%%| <r1VXXv5IaO|KLoPb9b0Xa>


try:
    tensorflow_thread = threading.Thread(target=load_vec)
    tensorflow_thread.start()
    capture = pys.LiveCapture(interface=select_interface(), display_filter='http.request.method == GET')
    capture.apply_on_packets(packet_processing)
except KeyboardInterrupt: 
    print('\nKeyboard interrupt detected. Exiting...')
    print('Sniffing has stopped by user')

    # |%%--%%| <KLoPb9b0Xa|GBfB53oBTP>

# Unsolved Tasks

"""
    - Might change the model algorithm
"""


# |%%--%%| <GBfB53oBTP|wSdniQla0W>

# Perhaps You Need This Function Latter

# print(model.predict(vectorizer.transform([payload]), verbose=0))

# |%%--%%| <wSdniQla0W|uppP3N3cWN>
