import logging
from satella.os import hang_until_sig

from ngtt.orders import Order
from ngtt.uplink import NGTTConnection


def on_order(order: Order):
    print(order.data)
    order.acknowledge()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('urllib3.connectionpool').setLevel(logging.WARN)

    ngtt = NGTTConnection('dev.crt', 'key.crt', on_new_order=on_order)

    hang_until_sig()

    ngtt.stop()
