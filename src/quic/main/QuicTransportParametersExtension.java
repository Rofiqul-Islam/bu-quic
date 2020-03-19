/*
 * Copyright © 2019, 2020 Peter Doornbosch
 *
 * This file is part of Kwik, a QUIC client Java library
 *
 * Kwik is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * Kwik is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package quic.main;

import quic.log.Logger;
import net.luminis.tls.ByteUtils;
import net.luminis.tls.Extension;
import quic.util.Util;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

import static quic.main.QuicConstants.TransportParameterId.*;

// https://tools.ietf.org/html/draft-ietf-quic-transport-16#section-18
public class QuicTransportParametersExtension extends Extension {

    private final Version quicVersion;
    private byte[] data;
    private TransportParameters params;

    public QuicTransportParametersExtension() {
        this(Version.getDefault());
    }

    public QuicTransportParametersExtension(Version quicVersion) {
        this.quicVersion = quicVersion;
        params = new TransportParameters();
    }

    /**
     * Creates a Quic Transport Parameters Extension for use in a Client Hello.
     * @param quicVersion
     */
    public QuicTransportParametersExtension(Version quicVersion, TransportParameters params) {
        this.quicVersion = quicVersion;

        ByteBuffer buffer = ByteBuffer.allocate(1500);

        // https://tools.ietf.org/html/draft-ietf-quic-tls-17#section-8.2:
        // "quic_transport_parameters(0xffa5)"
        buffer.putShort((short) 0xffa5);

        // Format is same as any TLS extension, so next are 2 bytes length
        buffer.putShort((short) 0);  // PlaceHolder, will be correctly set at the end of this method.

        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-18.1:
        // "Those
        //   transport parameters that are identified as integers use a variable-
        //   length integer encoding (see Section 16) and have a default value of
        //   0 if the transport parameter is absent, unless otherwise stated."

        // https://tools.ietf.org/html/draft-ietf-quic-transport-25#section-18.1
        // "The max idle timeout is a value in milliseconds
        //      that is encoded as an integer, see (Section 10.2)."
        addTransportParameter(buffer, idle_timeout, params.getMaxIdleTimeout() * 1000);
        addTransportParameter(buffer,max_packet_size,1500);

        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-18.1:
        // "The initial maximum data parameter is an
        //      integer value that contains the initial value for the maximum
        //      amount of data that can be sent on the connection.  This is
        //      equivalent to sending a MAX_DATA (Section 19.9) for the connection
        //      immediately after completing the handshake."
        addTransportParameter(buffer, initial_max_data, params.getInitialMaxData());

        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-18.1:
        // "This parameter is an
        //      integer value specifying the initial flow control limit for
        //      locally-initiated bidirectional streams.  This limit applies to
        //      newly created bidirectional streams opened by the endpoint that
        //      sends the transport parameter."
        addTransportParameter(buffer, initial_max_stream_data_bidi_local, params.getInitialMaxStreamDataBidiLocal());

        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-18.1:
        // "This parameter is an
        //      integer value specifying the initial flow control limit for peer-
        //      initiated bidirectional streams.  This limit applies to newly
        //      created bidirectional streams opened by the endpoint that receives
        //      the transport parameter."
        addTransportParameter(buffer, initial_max_stream_data_bidi_remote, params.getInitialMaxStreamDataBidiRemote());

        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-18.1:
        // "This parameter is an integer
        //      value specifying the initial flow control limit for unidirectional
        //      streams.  This limit applies to newly created bidirectional
        //      streams opened by the endpoint that receives the transport
        //      parameter."
        addTransportParameter(buffer, initial_max_stream_data_uni, params.getInitialMaxStreamDataUni());

        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-18.1:
        // " The initial maximum bidirectional
        //      streams parameter is an integer value that contains the initial
        //      maximum number of bidirectional streams the peer may initiate.  If
        //      this parameter is absent or zero, the peer cannot open
        //      bidirectional streams until a MAX_STREAMS frame is sent."
        addTransportParameter(buffer, initial_max_streams_bidi, params.getInitialMaxStreamsBidi());

        // https://tools.ietf.org/html/draft-ietf-quic-transport-17#section-18.1:
        // "The initial maximum unidirectional
        //      streams parameter is an integer value that contains the initial
        //      maximum number of unidirectional streams the peer may initiate.
        //      If this parameter is absent or zero, the peer cannot open
        //      unidirectional streams until a MAX_STREAMS frame is sent."
        addTransportParameter(buffer, initial_max_streams_uni, params.getInitialMaxStreamsUni());

        // https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-18.2
        // "The maximum number of connection IDs from the peer that an endpoint is willing to store."
        addTransportParameter(buffer, active_connection_id_limit, params.getActiveConnectionIdLimit());

        int length = buffer.position();
        buffer.limit(length);

        int extensionsSize = length - 2 - 2;  // 2 bytes for the length itself and 2 for the type
        buffer.putShort(2, (short) extensionsSize);

        data = new byte[length];
        buffer.flip();
        buffer.get(data);
    }

    @Override
    public byte[] getBytes() {
        return data;
    }

    // Assuming Handshake message type encrypted_extensions
    public void parse(ByteBuffer buffer, Logger log) {
        int extensionType = buffer.getShort() & 0xffff;
        if (extensionType != 0xffa5) {
            throw new RuntimeException();  // Must be programming error
        }
        int extensionLength = buffer.getShort();
        int startPosition = buffer.position();

        log.debug("Transport parameters: ");
        while (buffer.remaining() > 0) {
            parseTransportParameter(buffer, log);
        }

        int realSize = buffer.position() - startPosition;
        if (realSize != extensionLength) {
           // throw new ProtocolError("inconsistent size in transport parameter" + "  should be: " + realSize);
        }
    }

    void parseTransportParameter(ByteBuffer buffer, Logger log) {
        int parameterId = VariableLengthInteger.parse(buffer);
        int size = VariableLengthInteger.parse(buffer);
        int startPosition = buffer.position();

        if (parameterId == initial_max_stream_data_bidi_local.value) {
            int maxStreamDataBidiLocal = VariableLengthInteger.parse(buffer);
            log.debug("- initial max stream data bidi local: " + maxStreamDataBidiLocal);
            params.setInitialMaxStreamDataBidiLocal(maxStreamDataBidiLocal);
        }
        else if (parameterId == initial_max_data.value) {
            long maxData = VariableLengthInteger.parseLong(buffer);
            log.debug("- initial max data: " + maxData);
            params.setInitialMaxData(maxData);
        }
        else if (parameterId == initial_max_streams_bidi.value) {
            long maxBidiStreams = VariableLengthInteger.parseLong(buffer);
            log.debug("- initial max bidi streams: " + maxBidiStreams);
            params.setInitialMaxStreamsBidi(maxBidiStreams);
        }
        else if (parameterId == idle_timeout.value) {
            long idleTimeout = VariableLengthInteger.parseLong(buffer);
            log.debug("- max idle timeout: " + idleTimeout);
            params.setMaxIdleTimeout(idleTimeout);
        }
        else if (parameterId == preferred_address.value) {
            parsePreferredAddress(buffer, log);
        }
        else if (parameterId == max_packet_size.value) {
            int maxPacketSize = VariableLengthInteger.parse(buffer);
            log.debug("- max packet size: " + maxPacketSize);
        }
        else if (parameterId == stateless_reset_token.value) {
            byte[] resetToken = new byte[16];
            buffer.get(resetToken);
            log.debug("- stateless reset token: " + ByteUtils.bytesToHex(resetToken));
        }
        else if (parameterId == ack_delay_exponent.value) {
            int ackDelayExponent = VariableLengthInteger.parse(buffer);
            log.debug("- ack delay exponent: " + ackDelayExponent);
            params.setAckDelayExponent(ackDelayExponent);
        }
        else if (parameterId == initial_max_streams_uni.value) {
            long maxUniStreams = VariableLengthInteger.parseLong(buffer);
            log.debug("- max uni streams: " + maxUniStreams);
            params.setInitialMaxStreamsUni(maxUniStreams);
        }
        else if (parameterId == disable_active_migration.value) {
            log.debug("- disable migration");
            params.setDisableMigration(true);
        }
        else if (parameterId == initial_max_stream_data_bidi_remote.value) {
            long maxStreamDataBidiRemote = VariableLengthInteger.parseLong(buffer);
            log.debug("- initial max stream data bidi remote: " + maxStreamDataBidiRemote);
            params.setInitialMaxStreamDataBidiRemote(maxStreamDataBidiRemote);
        }
        else if (parameterId == initial_max_stream_data_uni.value) {
            long maxStreamDataUni = VariableLengthInteger.parseLong(buffer);
            log.debug("- initial max stream data uni: " + maxStreamDataUni);
            params.setInitialMaxStreamDataUni(maxStreamDataUni);
        }
        else if (parameterId == max_ack_delay.value) {
            int maxAckDelay = VariableLengthInteger.parse(buffer);
            log.debug("- max ack delay: " + maxAckDelay);
            params.setMaxAckDelay(maxAckDelay);
        }
        else if (parameterId == original_connection_id.value) {
            byte[] originalConnectionId = new byte[size];
            buffer.get(originalConnectionId);
            log.debug("- original connection id: ", originalConnectionId);
            params.setOriginalConnectionId(originalConnectionId);
        }
        else if (parameterId == active_connection_id_limit.value) {
            int activeConnectionIdLimit = VariableLengthInteger.parse(buffer);
            log.debug("- active connection id limit: " + activeConnectionIdLimit);
            params.setActiveConnectionIdLimit(activeConnectionIdLimit);
        }
        else {
            log.debug("- unknown transport parameter " + parameterId + ", (" + size + " bytes)");
            buffer.get(new byte[size]);
        }

        int realSize = buffer.position() - startPosition;
        if (realSize != size) {
            //throw new ProtocolError("inconsistent size in transport parameter" + "   moet zijn: " + realSize);
        }
    }

    private void parsePreferredAddress(ByteBuffer buffer, Logger log) {
        try {
            TransportParameters.PreferredAddress preferredAddress = new TransportParameters.PreferredAddress();

            byte[] ip4 = new byte[4];
            buffer.get(ip4);
            if (!Util.allZero(ip4)) {
                preferredAddress.ip4 = InetAddress.getByAddress(ip4);
            }
            preferredAddress.ip4Port = (buffer.get() << 8) | buffer.get();
            byte[] ip6 = new byte[16];
            buffer.get(ip6);
            if (!Util.allZero(ip6)) {
                preferredAddress.ip6 = InetAddress.getByAddress(ip6);
            }
            preferredAddress.ip6Port = (buffer.get() << 8) | buffer.get();

            if (preferredAddress.ip4 == null && preferredAddress.ip6 == null) {
                //throw new ProtocolError("Preferred address: no valid IP address");
            }

            int connectionIdSize = buffer.get();
            preferredAddress.connectionId = new byte[connectionIdSize];
            buffer.get(preferredAddress.connectionId);
            preferredAddress.statelessResetToken = new byte[16];
            buffer.get(preferredAddress.statelessResetToken);

            params.setPreferredAddress(preferredAddress);
        }
        catch (UnknownHostException invalidIpAddressLength) {
            // Impossible
            throw new RuntimeException();
        }
    }

    private void addTransportParameter(ByteBuffer buffer, QuicConstants.TransportParameterId id, long value) {
        VariableLengthInteger.encode(id.value, buffer);
        buffer.mark();
        int encodedValueLength = VariableLengthInteger.encode(value, buffer);
        buffer.reset();
        VariableLengthInteger.encode(encodedValueLength, buffer);
        VariableLengthInteger.encode(value, buffer);
    }

    public TransportParameters getTransportParameters() {
        return params;
    }
}
