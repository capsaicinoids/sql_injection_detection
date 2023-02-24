import os
import re
import pickle
import netifaces
import pyshark as pys
from urllib import parse as ps

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow as tf

#|%%--%%| <wCEgwpOxvG|Hu4CQGoOl7>

print('WELCOME!')

# |%%--%%| <Hu4CQGoOl7|muyaSyrdFB>

def select_interface() -> str:
    interfaces = netifaces.interfaces()
    for index, interface in enumerate(interfaces):
        print('[{}] {}'.format(index, interface))
    else:
        net_adapt = int(input('Select The Interface: '))
        net_adapt = interfaces[net_adapt]
        print('Listening on {}'.format(net_adapt))
    return net_adapt

# |%%--%%| <muyaSyrdFB|r1VXXv5IaO>

model = tf.keras.models.load_model('sqli_model.h5')
vectorizer = pickle.load(open('new_vectorizer.pickle', 'rb'))

def predict_uri(payload) -> bool:
    vc = vectorizer.transform(payload)
    return True if model.predict(vc, verbose=0) > 0.5 else False


def message(no_packet: str, src_ip: str, src_port: str, dst_ip: str, dst_port: str, payload: str, alert: str = ''): 
    # Print The Alert Message
    print("{}\t {}:{} ==> {}:{} === === {} -> {}".format(no_packet, src_ip, src_port, dst_ip, dst_port, payload, alert))


# |%%--%%| <r1VXXv5IaO|KLoPb9b0Xa>

capture = pys.LiveCapture(interface=select_interface(), display_filter='http.request.method == GET')
request_uri = []

for index, packet in enumerate(capture):
    payload = re.sub(r'^.*?=', '', packet.http.request_uri.replace('+', ' ')) # Remove Unnecessary char in URL
    payload = ps.unquote(payload)  # Decode The URL

    # print(model.predict(vectorizer.transform([payload]), verbose=0))
    if (predict_uri([payload])):
        message(packet.frame_info.number, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst,
                packet[packet.transport_layer].dstport, payload, alert="ALERT THIS MIGHT BE AN SQL INJECTION ATTACK ATTEMPT!")
    else:
        message(packet.frame_info.number, packet.ip.src,
                packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, payload)

    # |%%--%%| <KLoPb9b0Xa|GBfB53oBTP>

# Unsolved Tasks

"""
    - Handle The Blocking Code
    - Catch The Error
    - Welcome Message When Start
"""


# |%%--%%| <GBfB53oBTP|uppP3N3cWN>
