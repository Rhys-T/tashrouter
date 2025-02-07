import socket, select, logging
from threading import Thread, Event
from . import EtherTalkPort

class B2UdpTunnelPort(EtherTalkPort):
  DEFAULT_UDP_PORT = 6066
  SELECT_TIMEOUT = 0.25
  B2_TUNNEL_MAC_PREFIX = b'B2'
  B2_TUNNEL_LOOPBACK_MAC = B2_TUNNEL_MAC_PREFIX + b'\x7f\x00\x00\x01' # 'B':'2':127.0.0.1
  def __init__(self, intf_address=None, udp_port=DEFAULT_UDP_PORT, remap_addresses_hack=False, **kwargs):
    if intf_address is None:
      with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fakeSocket:
        fakeSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        fakeSocket.connect(('<broadcast>', 9999))
        intf_address = fakeSocket.getsockname()[0]
    hw_addr = self.B2_TUNNEL_MAC_PREFIX + socket.inet_aton(intf_address)
    super().__init__(hw_addr=hw_addr, **kwargs)
    self._intf_address = intf_address
    self._udp_port = udp_port
    self._remap_addresses_hack = remap_addresses_hack
    if remap_addresses_hack:
      self._real_addresses = {}
    self._tunnel_thread = None
    self._tunnel_started_event = Event()
    self._tunnel_stopped_event = Event()
    self._tunnel_stop_requested = False
  
  def short_str(self):
    result = f'B2UDP:{self._intf_address}'
    if self._udp_port != self.DEFAULT_UDP_PORT:
      result += f':{self._udp_port}'
    return result
  __str__ = short_str
  __repr__ = short_str
  
  def start(self, router):
    self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, 'SO_REUSEPORT'): self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    self._socket.bind((self._intf_address, self._udp_port))
    self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    super().start(router)
    self._tunnel_thread = Thread(target=self._tunnel_run)
    self._tunnel_thread.start()
    self._tunnel_started_event.wait()
  def stop(self):
    self._tunnel_stop_requested = True
    self._tunnel_stopped_event.wait()
    super().stop()
  
  def _tunnel_run(self):
    self._tunnel_started_event.set()
    while not self._tunnel_stop_requested:
      rlist, _, _ = select.select((self._socket,), (), (), self.SELECT_TIMEOUT)
      if self._socket not in rlist: continue
      data, sender_addr = self._socket.recvfrom(65535)
      if self._remap_addresses_hack and data[6:8] == self.B2_TUNNEL_MAC_PREFIX:
        ip = socket.inet_ntoa(data[8:12])
        real_addr = sender_addr[0]
        if ip in self._real_addresses and self._real_addresses[ip] != real_addr:
          logging.warning("%s replacing real address for %s: %s -> %s", str(self), data[6:12].hex(':'), self._real_addresses[ip], real_addr)
        self._real_addresses[ip] = sender_addr[0]
      self.inbound_frame(data)
    self._tunnel_stopped_event.set()
  
  def send_frame(self, frame_data):
    dest = frame_data[0:6]
    if dest == self.ELAP_BROADCAST_ADDR or dest in self.ELAP_MULTICAST_ADDRS:
      ip = '255.255.255.255'
    elif dest[0:2] == self.B2_TUNNEL_MAC_PREFIX:
      ip = socket.inet_ntoa(dest[2:6])
      if self._remap_addresses_hack and ip in self._real_addresses:
        ip = self._real_addresses[ip]
      elif ip == '127.0.0.1':
        logging.warning("%s probably can't send frame to %s: Basilisk II is using loopback IP for fake MAC", str(self), dest.hex(':'))
    else:
      logging.warning("%s couldn't send frame to %s: bad tunnel MAC", str(self), dest.hex(":"))
      return
    logging.debug('%s sending from %s to %s', str(self), self._intf_address, ip)
    self._socket.sendto(frame_data, (ip, self._udp_port))
