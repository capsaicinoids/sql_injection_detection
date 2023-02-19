import re
import pickle
import warnings
import asyncio
import pyshark as pys
from urllib import parse as ps
from tensorflow.keras.models import load_model

# |%%--%%| <dW3ZLyaAkT|wCEgwpOxvG>

# import signal
# import sys
# import threading
# warnings.filterwarnings('ignore', category=DeprecationWarning)
# warnings.filterwarnings('ignore', category=FileNotFoundError)
# warnings.filterwarnings('ignore', category=FutureWarning)

warnings.filterwarnings('ignore')

# |%%--%%| <wCEgwpOxvG|muyaSyrdFB>

load_dnn = load_model('sqli_model.h5')
load_vectorizer = pickle.load(open('new_vectorizer.pickle', 'rb'))

# |%%--%%| <muyaSyrdFB|r1VXXv5IaO>

def predict_uri(payload):
    vc = load_vectorizer.transform(payload)
    return True if load_dnn.predict(vc, verbose=0) > 0.5 else False


def message(no_packet: str, src_ip: str, src_port: str, dst_ip: str, dst_port: str, payload: str, alert: str = '') -> str:
    print("{}\t {}:{} ==> {}:{} === === {} -> {}".format(no_packet,
          src_ip, src_port, dst_ip, dst_port, payload, alert))


def signal_handler(signal, frame):
    print('bye bye')
    sys.exit(0)

# signal.signal(signal.SIGINT, signal_handler)
# print('To exit just interrupt the keyboard!')
# forever_wait = threading.Event()
# forever_wait.wait()

# |%%--%%| <r1VXXv5IaO|KLoPb9b0Xa>


capture = pys.LiveCapture(
    interface='lo', display_filter='http.request.method == GET')
request_uri = []

for index, packet in enumerate(capture):
    payload = re.sub(r'^.*?=', '', packet.http.request_uri.replace('+', ' '))
    payload = ps.unquote(payload)

    print(load_dnn.predict(load_vectorizer.transform([payload]), verbose=0))
    if (predict_uri([payload])) == True:
        message(packet.frame_info.number, packet.ip.src, packet[packet.transport_layer].srcport, packet.ip.dst,
                packet[packet.transport_layer].dstport, payload, alert="ALERT THIS MIGHT BE AN SQL INJECTION ATTACK ATTEMPT!")
    else:
        message(packet.frame_info.number, packet.ip.src,
                packet[packet.transport_layer].srcport, packet.ip.dst, packet[packet.transport_layer].dstport, payload)

    # |%%--%%| <KLoPb9b0Xa|GBfB53oBTP>

# Unsolved Tasks

"""
    - Catch The Error
    - Print All Available Network Interface
    - 
"""


# |%%--%%| <GBfB53oBTP|uppP3N3cWN>
