import os
import re
import sys
import pickle
import netifaces
import pyshark as pys
from urllib import parse as ps

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

# |%%--%%| <wCEgwpOxvG|Hu4CQGoOl7>

print('Welcome To SQL Injection Scanner'.upper().center(50, '-'))

# |%%--%%| <Hu4CQGoOl7|muyaSyrdFB>


def select_interface():
    interfaces = netifaces.interfaces()
    for index, interface in enumerate(interfaces):
        print('[{}] {}'.format(index, interface))
    else:
        while True:
            try:
                net_adapt = int(input('Select The Interface: '))
                net_adapt = interfaces[net_adapt]
                print('Listening on {}'.format(net_adapt))
                return net_adapt
            except ValueError:
                print("Please Input Numbers Only")
            except IndexError:
                print('Please Input The Correct Number')
            except KeyboardInterrupt:
                print('\nKeyboard interrupt detected. Exiting...')
                sys.exit()

# |%%--%%| <muyaSyrdFB|r1VXXv5IaO>


import tensorflow as tf
model = tf.keras.models.load_model('sqli_model.h5')
vectorizer = pickle.load(open('new_vectorizer.pickle', 'rb'))


def predict_uri(payload) -> bool:
    vc = vectorizer.transform(payload)
    return model.predict(vc, verbose=0) > 0.5


def message(no_packet: str, src_ip: str, src_port: str, dst_ip: str, dst_port: str, payload: str, alert: str = ''):
    # Print The Alert Message
    print("{}\t {}:{} ==> {}:{} === === {} -> {}".format(no_packet,
          src_ip, src_port, dst_ip, dst_port, payload, alert))


def packet_processing(packet):
    # Remove Unnecessary char in URL
    payload = re.sub(
        r'^.*?=', '', packet.http.request_uri.replace('+', ' '))
    payload = ps.unquote(payload)  # Decode The URL

    # print(model.predict(vectorizer.transform([payload]), verbose=0))
    if (predict_uri([payload])):
        message(packet.frame_info.number, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst,
                packet[packet.transport_layer].dstport, payload, alert="\033[1m\033[91mALERT THIS MIGHT BE AN SQL INJECTION ATTACK ATTEMPT!\033[00m\033[0m")
    else:
        message(packet.frame_info.number, packet.ip.src,
                packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, payload)


# |%%--%%| <r1VXXv5IaO|KLoPb9b0Xa>


try:
    capture = pys.LiveCapture(interface=select_interface(), display_filter='http.request.method == GET')
    capture.apply_on_packets(packet_processing)
except KeyboardInterrupt: 
    print('\nKeyboard interrupt detected. Exiting...')
    print('Sniffing has stopped by user')

    # |%%--%%| <KLoPb9b0Xa|GBfB53oBTP>

# Unsolved Tasks

"""
    - Handle The Blocking Code
    - Proper Welcome Message When Start
"""


# |%%--%%| <GBfB53oBTP|wSdniQla0W>

# Perhaps You Need This Function Latter

# def print_color(text, color):
#     colors = {
#         'red': '\033[91m',
#         'green': '\033[92m'
#     }
#
#     if color in colors:
#         print('{}{}\033[00m]'.format(colors[color], text))
#     else:
#         print(text)

# |%%--%%| <wSdniQla0W|uppP3N3cWN>
