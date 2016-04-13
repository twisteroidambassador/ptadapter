from .baseserverclient import PluggableTransportBaseAdapter, \
    PluggableTransportServerAdapter, PluggableTransportClientSOCKSAdapter

__ALL__ = ["PluggableTransportServerAdapter", \
        "PluggableTransportClientSOCKSAdapter"]

try:
    from .tcpclient import PluggableTransportClientTCPAdapter
except ImportError:
    # If tcpclient.py or any of its dependencies are missing, silently skip import
    pass
else:
    __ALL__.append("PluggableTransportClientTCPAdapter")
