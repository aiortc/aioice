import asyncio
import ipaddress
import logging
import socket
import struct
from typing import Any, Callable, Dict, Optional, Tuple, Union, cast

logger = logging.getLogger(__name__)

# SOCKS5 protocol constants
SOCKS5_VERSION = 0x05

# Authentication methods
SOCKS5_AUTH_NONE = 0x00
SOCKS5_AUTH_GSSAPI = 0x01
SOCKS5_AUTH_USERNAME_PASSWORD = 0x02
SOCKS5_AUTH_NO_ACCEPTABLE = 0xFF

# Commands
SOCKS5_CMD_CONNECT = 0x01
SOCKS5_CMD_BIND = 0x02
SOCKS5_CMD_UDP_ASSOCIATE = 0x03

# Address types
SOCKS5_ATYP_IPV4 = 0x01
SOCKS5_ATYP_DOMAINNAME = 0x03
SOCKS5_ATYP_IPV6 = 0x04

# Reply codes
SOCKS5_REPLY_SUCCESS = 0x00
SOCKS5_REPLY_GENERAL_FAILURE = 0x01
SOCKS5_REPLY_CONNECTION_NOT_ALLOWED = 0x02
SOCKS5_REPLY_NETWORK_UNREACHABLE = 0x03
SOCKS5_REPLY_HOST_UNREACHABLE = 0x04
SOCKS5_REPLY_CONNECTION_REFUSED = 0x05
SOCKS5_REPLY_TTL_EXPIRED = 0x06
SOCKS5_REPLY_COMMAND_NOT_SUPPORTED = 0x07
SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class Socks5Error(Exception):
    """Exception raised for SOCKS5 protocol errors."""
    pass


class Socks5TransportWrapper(asyncio.DatagramTransport):
    """
    A wrapper for asyncio.DatagramTransport that routes UDP traffic through a SOCKS5 proxy.
    
    This class implements the asyncio.DatagramTransport interface and wraps an existing
    transport, redirecting all UDP traffic through a SOCKS5 proxy according to RFC 1928.
    """
    def __init__(
        self, 
        transport: asyncio.DatagramTransport,
        proxy_host: str,
        proxy_port: int,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ):
        self._transport = transport
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._username = username
        self._password = password
        
        # SOCKS5 control connection
        self._tcp_reader: Optional[asyncio.StreamReader] = None
        self._tcp_writer: Optional[asyncio.StreamWriter] = None
        
        # UDP relay information
        self._udp_relay_host: Optional[str] = None
        self._udp_relay_port: Optional[int] = None
        
        # Connection state
        self._connected = False
        self._closed = False
        
        # Keep track of the protocol
        self._protocol: Optional[asyncio.DatagramProtocol] = None
        
        # Start the connection process
        self._connection_task = asyncio.create_task(self._connect_to_proxy())
        
        logger.debug(
            "Socks5TransportWrapper created with proxy %s:%d", proxy_host, proxy_port
        )
    
    async def _connect_to_proxy(self) -> None:
        """Establish connection to the SOCKS5 proxy and set up UDP relay."""
        try:
            await self._socks5_handshake()
            await self._udp_associate()
            self._connected = True
            logger.debug("SOCKS5 UDP relay established at %s:%d", 
                        self._udp_relay_host, self._udp_relay_port)
            
            # Start monitoring the TCP control connection
            asyncio.create_task(self._monitor_tcp_connection())
        except Exception as e:
            logger.error("Failed to establish SOCKS5 connection: %s", str(e))
            self.close()
    
    async def _socks5_handshake(self) -> None:
        """
        Perform SOCKS5 handshake with the proxy server.
        
        This method establishes a TCP connection to the SOCKS5 proxy and
        performs the initial handshake, including authentication if required.
        """
        if self._tcp_reader is not None and self._tcp_writer is not None:
            return  # Already connected
            
        logger.debug("Establishing SOCKS5 control connection to %s:%d", 
                    self._proxy_host, self._proxy_port)
                    
        # Open TCP connection to SOCKS5 proxy
        self._tcp_reader, self._tcp_writer = await asyncio.open_connection(
            self._proxy_host, self._proxy_port
        )
        
        # Initial handshake - authenticate
        auth_methods = [SOCKS5_AUTH_NONE]
        if self._username and self._password:
            auth_methods.append(SOCKS5_AUTH_USERNAME_PASSWORD)
            
        # Send auth methods
        self._tcp_writer.write(
            struct.pack("!BB", SOCKS5_VERSION, len(auth_methods)) + bytes(auth_methods)
        )
        await self._tcp_writer.drain()
        
        # Receive server choice
        data = await self._tcp_reader.readexactly(2)
        version, method = struct.unpack("!BB", data)
        
        if version != SOCKS5_VERSION:
            raise Socks5Error(f"Invalid SOCKS version: {version}")
            
        if method == SOCKS5_AUTH_NO_ACCEPTABLE:
            raise Socks5Error("No acceptable authentication methods")
            
        # Handle username/password authentication if required
        if method == SOCKS5_AUTH_USERNAME_PASSWORD:
            if not self._username or not self._password:
                raise Socks5Error("Proxy requires authentication but no credentials provided")
                
            # Auth version 1
            auth_packet = bytearray([0x01])
            # Username
            auth_packet.append(len(self._username))
            auth_packet.extend(self._username.encode())
            # Password
            auth_packet.append(len(self._password))
            auth_packet.extend(self._password.encode())
            
            self._tcp_writer.write(auth_packet)
            await self._tcp_writer.drain()
            
            # Get auth response
            auth_response = await self._tcp_reader.readexactly(2)
            auth_version, auth_status = struct.unpack("!BB", auth_response)
            
            if auth_status != 0:
                raise Socks5Error("Authentication failed")
                
        logger.debug("SOCKS5 authentication successful")

    async def _udp_associate(self) -> None:
        """
        Establish UDP association with the SOCKS5 proxy.
        
        This method sends the UDP ASSOCIATE command to the SOCKS5 proxy
        and obtains the UDP relay address and port for sending datagrams.
        """
        if self._udp_relay_host is not None and self._udp_relay_port is not None:
            return  # Already associated
            
        await self._socks5_handshake()
        
        # For UDP ASSOCIATE, we typically bind to 0.0.0.0:0 on the client side
        # The SOCKS server will use this to filter incoming UDP packets
        client_bind_addr = "0.0.0.0"
        client_bind_port = 0
        
        # Prepare UDP ASSOCIATE command
        cmd_packet = bytearray([SOCKS5_VERSION, SOCKS5_CMD_UDP_ASSOCIATE, 0x00])
        
        # Add bind address (where we'll send UDP packets from)
        try:
            # Try to parse as IPv4
            ipv4 = ipaddress.IPv4Address(client_bind_addr)
            cmd_packet.append(SOCKS5_ATYP_IPV4)
            cmd_packet.extend(ipv4.packed)
        except ipaddress.AddressValueError:
            try:
                # Try to parse as IPv6
                ipv6 = ipaddress.IPv6Address(client_bind_addr)
                cmd_packet.append(SOCKS5_ATYP_IPV6)
                cmd_packet.extend(ipv6.packed)
            except ipaddress.AddressValueError:
                # Use domain name
                encoded_addr = client_bind_addr.encode()
                cmd_packet.append(SOCKS5_ATYP_DOMAINNAME)
                cmd_packet.append(len(encoded_addr))
                cmd_packet.extend(encoded_addr)
        
        # Add bind port
        cmd_packet.extend(struct.pack("!H", client_bind_port))
        
        # Send UDP ASSOCIATE command
        self._tcp_writer.write(cmd_packet)
        await self._tcp_writer.drain()
        
        # Read response
        resp_header = await self._tcp_reader.readexactly(3)
        version, reply, reserved = struct.unpack("!BBB", resp_header)
        
        if version != SOCKS5_VERSION:
            raise Socks5Error(f"Invalid SOCKS version in response: {version}")
            
        if reply != SOCKS5_REPLY_SUCCESS:
            error_messages = {
                SOCKS5_REPLY_GENERAL_FAILURE: "General SOCKS server failure",
                SOCKS5_REPLY_CONNECTION_NOT_ALLOWED: "Connection not allowed by ruleset",
                SOCKS5_REPLY_NETWORK_UNREACHABLE: "Network unreachable",
                SOCKS5_REPLY_HOST_UNREACHABLE: "Host unreachable",
                SOCKS5_REPLY_CONNECTION_REFUSED: "Connection refused",
                SOCKS5_REPLY_TTL_EXPIRED: "TTL expired",
                SOCKS5_REPLY_COMMAND_NOT_SUPPORTED: "Command not supported",
                SOCKS5_REPLY_ADDRESS_TYPE_NOT_SUPPORTED: "Address type not supported",
            }
            error_msg = error_messages.get(reply, f"Unknown error code: {reply}")
            raise Socks5Error(f"UDP ASSOCIATE failed: {error_msg}")
        
        # Read address type
        atyp = await self._tcp_reader.readexactly(1)
        atyp = struct.unpack("!B", atyp)[0]
        
        # Read the UDP relay address and port
        if atyp == SOCKS5_ATYP_IPV4:
            addr_bytes = await self._tcp_reader.readexactly(4)
            addr = socket.inet_ntop(socket.AF_INET, addr_bytes)
        elif atyp == SOCKS5_ATYP_IPV6:
            addr_bytes = await self._tcp_reader.readexactly(16)
            addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        elif atyp == SOCKS5_ATYP_DOMAINNAME:
            addr_len = await self._tcp_reader.readexactly(1)
            addr_len = struct.unpack("!B", addr_len)[0]
            addr_bytes = await self._tcp_reader.readexactly(addr_len)
            addr = addr_bytes.decode()
        else:
            raise Socks5Error(f"Unsupported address type: {atyp}")
            
        port_bytes = await self._tcp_reader.readexactly(2)
        port = struct.unpack("!H", port_bytes)[0]
        
        self._udp_relay_host = addr
        self._udp_relay_port = port
        
        logger.debug("UDP ASSOCIATE successful, relay at %s:%d", addr, port)

    async def _monitor_tcp_connection(self) -> None:
        """
        Monitor the TCP control connection to the SOCKS5 proxy.
        
        This method continuously monitors the TCP connection to the SOCKS5 proxy
        and closes the transport if the connection is lost.
        """
        try:
            # Wait for EOF or error
            if self._tcp_reader:
                await self._tcp_reader.read()
            logger.warning("SOCKS5 control connection closed by server")
        except Exception as e:
            logger.warning("SOCKS5 control connection error: %s", str(e))
        finally:
            # If we reach here, the connection was closed
            if not self._closed:
                logger.warning("SOCKS5 proxy connection lost, closing transport")
                self.close()

    def _wrap_udp_packet(self, data: bytes, addr: Tuple[str, int]) -> bytes:
        """
        Wrap UDP packet with SOCKS5 UDP header.
        
        According to RFC 1928, UDP packets sent through SOCKS5 must be wrapped
        with a special header containing the destination address and port.
        
        :param data: The original UDP packet data
        :param addr: The destination address tuple (host, port)
        :return: The wrapped packet with SOCKS5 UDP header
        """
        host, port = addr
        
        # Create header with zeros for RSV and no fragmentation
        header = bytearray([0, 0, 0])
        
        # Add destination address
        try:
            # Try to parse as IPv4
            ipv4 = ipaddress.IPv4Address(host)
            header[2] = SOCKS5_ATYP_IPV4
            header.extend(ipv4.packed)
        except ipaddress.AddressValueError:
            try:
                # Try to parse as IPv6
                ipv6 = ipaddress.IPv6Address(host)
                header[2] = SOCKS5_ATYP_IPV6
                header.extend(ipv6.packed)
            except ipaddress.AddressValueError:
                # Use domain name
                encoded_host = host.encode()
                header[2] = SOCKS5_ATYP_DOMAINNAME
                header.append(len(encoded_host))
                header.extend(encoded_host)
        
        # Add destination port
        header.extend(struct.pack("!H", port))
        
        # Combine header and data
        return bytes(header) + data

    def _unwrap_udp_packet(self, data: bytes) -> Tuple[bytes, Tuple[str, int]]:
        """
        Unwrap UDP packet from SOCKS5 UDP header.
        
        This method extracts the original UDP packet data and the source address
        from a packet received from the SOCKS5 proxy.
        
        :param data: The wrapped UDP packet with SOCKS5 header
        :return: A tuple of (original_data, source_address)
        :raises Socks5Error: If the packet is malformed
        """
        if len(data) < 4:  # Minimum header size
            raise Socks5Error("UDP packet too small to contain SOCKS5 header")
            
        # Parse header
        if data[0] != 0 or data[1] != 0:  # Check RSV bytes
            raise Socks5Error("Invalid SOCKS5 UDP header RSV bytes")
            
        frag = data[2]
        if frag != 0:
            raise Socks5Error(f"UDP fragmentation not supported, got fragment {frag}")
            
        atyp = data[3]
        
        # Parse address and port
        offset = 4
        if atyp == SOCKS5_ATYP_IPV4:
            if len(data) < offset + 4 + 2:  # IPv4 (4) + port (2)
                raise Socks5Error("UDP packet too small for IPv4 address")
            addr = socket.inet_ntop(socket.AF_INET, data[offset:offset+4])
            offset += 4
        elif atyp == SOCKS5_ATYP_IPV6:
            if len(data) < offset + 16 + 2:  # IPv6 (16) + port (2)
                raise Socks5Error("UDP packet too small for IPv6 address")
            addr = socket.inet_ntop(socket.AF_INET6, data[offset:offset+16])
            offset += 16
        elif atyp == SOCKS5_ATYP_DOMAINNAME:
            if len(data) < offset + 1:  # Need at least length byte
                raise Socks5Error("UDP packet too small for domain name length")
            addr_len = data[offset]
            offset += 1
            if len(data) < offset + addr_len + 2:  # domain + port (2)
                raise Socks5Error("UDP packet too small for domain name")
            addr = data[offset:offset+addr_len].decode()
            offset += addr_len
        else:
            raise Socks5Error(f"Unsupported address type in UDP packet: {atyp}")
            
        # Parse port
        port = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        
        # Extract payload
        payload = data[offset:]
        
        return payload, (addr, port)

    # DatagramTransport interface implementation
    
    def close(self) -> None:
        """
        Close the transport.
        
        This method closes both the SOCKS5 control connection and the
        underlying UDP transport.
        """
        if self._closed:
            return
            
        self._closed = True
        
        # Close TCP control connection
        if self._tcp_writer is not None:
            try:
                self._tcp_writer.close()
            except Exception as e:
                logger.warning("Error closing SOCKS5 control connection: %s", str(e))
            self._tcp_writer = None
            self._tcp_reader = None
            
        # Close underlying transport
        self._transport.close()
        
        logger.debug("SOCKS5 transport closed")

    def sendto(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Send data to a given address through the SOCKS5 proxy.
        
        This method wraps the data with a SOCKS5 UDP header and sends it
        to the UDP relay address.
        
        :param data: The UDP packet data to send
        :param addr: The destination address tuple (host, port)
        """
        if self._closed:
            return
            
        if not self._connected or self._udp_relay_host is None or self._udp_relay_port is None:
            # Queue the packet to be sent once connected
            asyncio.create_task(self._send_when_connected(data, addr))
            return
            
        # Wrap the packet with SOCKS5 UDP header
        wrapped_data = self._wrap_udp_packet(data, addr)
        
        # Send through the underlying transport to the UDP relay
        self._transport.sendto(wrapped_data, (self._udp_relay_host, self._udp_relay_port))

    async def _send_when_connected(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Send data once the SOCKS5 connection is established.
        
        This method waits for the SOCKS5 connection to be established before
        sending the data.
        
        :param data: The UDP packet data to send
        :param addr: The destination address tuple (host, port)
        """
        try:
            # Wait for connection to complete (with timeout)
            for _ in range(50):  # 5 seconds timeout (100ms * 50)
                if self._connected and self._udp_relay_host is not None and self._udp_relay_port is not None:
                    # Wrap the packet with SOCKS5 UDP header
                    wrapped_data = self._wrap_udp_packet(data, addr)
                    
                    # Send through the underlying transport to the UDP relay
                    self._transport.sendto(wrapped_data, (self._udp_relay_host, self._udp_relay_port))
                    return
                await asyncio.sleep(0.1)
                
            logger.warning("Timeout waiting for SOCKS5 connection, packet not sent")
        except Exception as e:
            logger.error("Error sending delayed packet: %s", str(e))

    def abort(self) -> None:
        """Abort the transport."""
        self.close()

    def is_closing(self) -> bool:
        """Return True if the transport is closing or closed."""
        return self._closed or self._transport.is_closing()

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """Get optional transport information."""
        return self._transport.get_extra_info(name, default)

    # The following methods are specific to DatagramTransport
    
    def set_protocol(self, protocol: asyncio.DatagramProtocol) -> None:
        """Set the protocol."""
        self._protocol = protocol
        self._transport.set_protocol(protocol)

    def get_protocol(self) -> Optional[asyncio.DatagramProtocol]:
        """Get the protocol."""
        return self._protocol


class Socks5DatagramProtocolWrapper(asyncio.DatagramProtocol):
    """
    A wrapper for DatagramProtocol that handles SOCKS5 UDP packet unwrapping.
    
    This class wraps an existing DatagramProtocol and handles unwrapping
    SOCKS5 UDP packets before passing them to the original protocol.
    """
    def __init__(self, protocol: asyncio.DatagramProtocol):
        self._protocol = protocol
        self._transport: Optional[Socks5TransportWrapper] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """Called when a connection is made."""
        self._transport = cast(Socks5TransportWrapper, transport)
        self._protocol.connection_made(transport)

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Called when the connection is lost or closed."""
        self._protocol.connection_lost(exc)

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Called when a datagram is received.
        
        This method unwraps SOCKS5 UDP packets if they come from the UDP relay
        and passes the original data to the wrapped protocol.
        
        :param data: The received UDP packet data
        :param addr: The source address tuple (host, port)
        """
        try:
            # Only unwrap if it's from the SOCKS5 relay
            if (self._transport and 
                addr[0] == self._transport._udp_relay_host and 
                addr[1] == self._transport._udp_relay_port):
                
                # Unwrap the SOCKS5 UDP header
                unwrapped_data, src_addr = self._transport._unwrap_udp_packet(data)
                
                # Pass the unwrapped data to the original protocol
                self._protocol.datagram_received(unwrapped_data, src_addr)
            else:
                # Direct packet (not from relay), pass as-is
                self._protocol.datagram_received(data, addr)
        except Exception as e:
            logger.warning("Error unwrapping SOCKS5 UDP packet: %s", str(e))
            # If unwrapping fails, pass the original data
            self._protocol.datagram_received(data, addr)

    def error_received(self, exc: Exception) -> None:
        """Called when a send or receive operation raises an OSError."""
        self._protocol.error_received(exc)


async def create_socks5_datagram_endpoint(
    loop: asyncio.AbstractEventLoop,
    protocol_factory: Callable[[], asyncio.DatagramProtocol],
    local_addr: Optional[Tuple[str, int]] = None,
    remote_addr: Optional[Tuple[str, int]] = None,
    *,
    family: int = 0,
    proto: int = 0,
    flags: int = 0,
    reuse_address: Optional[bool] = None,
    reuse_port: Optional[bool] = None,
    allow_broadcast: Optional[bool] = None,
    sock: Optional[socket.socket] = None,
    proxy_host: str,
    proxy_port: int,
    proxy_username: Optional[str] = None,
    proxy_password: Optional[str] = None,
) -> Tuple[asyncio.DatagramTransport, asyncio.DatagramProtocol]:
    """
    Create a datagram connection through a SOCKS5 proxy.
    
    This function is similar to asyncio.create_datagram_endpoint but routes
    all UDP traffic through a SOCKS5 proxy.
    
    :param loop: The event loop
    :param protocol_factory: Factory function for creating the protocol
    :param local_addr: Optional local address to bind to
    :param remote_addr: Optional remote address to connect to
    :param family: Socket family
    :param proto: Socket protocol
    :param flags: Socket flags
    :param reuse_address: Allow reuse of address
    :param reuse_port: Allow reuse of port
    :param allow_broadcast: Allow broadcast
    :param sock: Optional existing socket to use
    :param proxy_host: SOCKS5 proxy host
    :param proxy_port: SOCKS5 proxy port
    :param proxy_username: Optional username for proxy authentication
    :param proxy_password: Optional password for proxy authentication
    :return: (transport, protocol) pair
    """
    # Create the original transport and protocol
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: Socks5DatagramProtocolWrapper(protocol_factory()),
        local_addr=local_addr,
        remote_addr=remote_addr,
        family=family,
        proto=proto,
        flags=flags,
        reuse_address=reuse_address,
        reuse_port=reuse_port,
        allow_broadcast=allow_broadcast,
        sock=sock,
    )
    
    # Wrap the transport with our SOCKS5 wrapper
    socks5_transport = Socks5TransportWrapper(
        transport,
        proxy_host=proxy_host,
        proxy_port=proxy_port,
        username=proxy_username,
        password=proxy_password,
    )
    
    # Update the protocol's transport reference
    protocol.connection_made(socks5_transport)
    
    return socks5_transport, protocol._protocol


def create_socks5_proxy_config(
    host: str, 
    port: int, 
    username: Optional[str] = None, 
    password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a SOCKS5 proxy configuration dictionary.
    
    This function creates a configuration dictionary for use with
    the Connection class or create_socks5_datagram_endpoint function.
    
    :param host: SOCKS5 proxy host
    :param port: SOCKS5 proxy port
    :param username: Optional username for authentication
    :param password: Optional password for authentication
    :return: A configuration dictionary for use with aioice.Connection
    """
    config = {
        'host': host,
        'port': port,
    }
    
    if username is not None:
        config['username'] = username
    
    if password is not None:
        config['password'] = password
        
    return config
