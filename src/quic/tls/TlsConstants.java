package quic.tls;

public class TlsConstants {
    public enum ContentType {
        invalid(0),
        change_cipher_spec(20),
        alert(21),
        handshake(22),
        application_data(23);

        public final byte value;

        ContentType(int value) {
            this.value = (byte)value;
        }
    }

    public enum HandshakeType {
        client_hello(1),
        server_hello(2),
        new_session_ticket(4),
        end_of_early_data(5),
        encrypted_extensions(8),
        certificate(11),
        certificate_request(13),
        certificate_verify(15),
        finished(20),
        key_update(24),
        message_hash(254);

        public final byte value;

        HandshakeType(int value) {
            this.value = (byte)value;
        }
    }

    public enum ExtensionType {
        server_name(0),
        max_fragment_length(1),
        status_request(5),
        supported_groups(10),
        signature_algorithms(13),
        use_srtp(14),
        heartbeat(15),
        application_layer_protocol_negotiation(16),
        signed_certificate_timestamp(18),
        client_certificate_type(19),
        server_certificate_type(20),
        padding(21),
        pre_shared_key(41),
        early_data(42),
        supported_versions(43),
        cookie(44),
        psk_key_exchange_modes(45),
        certificate_authorities(47),
        oid_filters(48),
        post_handshake_auth(49),
        signature_algorithms_cert(50),
        key_share(51);

        public final short value;

        ExtensionType(int value) {
            this.value = (short)value;
        }
    }

    public enum NamedGroup {
        secp256r1(23),
        secp384r1(24),
        secp521r1(25),
        x25519(29),
        x448(30),
        ffdhe2048(256),
        ffdhe3072(257),
        ffdhe4096(258),
        ffdhe6144(259),
        ffdhe8192(260);

        public short value;

        NamedGroup(int value) {
            this.value = (short)value;
        }
    }

    public enum SignatureScheme {
        rsa_pkcs1_sha256(1025),
        rsa_pkcs1_sha384(1281),
        rsa_pkcs1_sha512(1537),
        ecdsa_secp256r1_sha256(1027),
        ecdsa_secp384r1_sha384(1283),
        ecdsa_secp521r1_sha512(1539),
        rsa_pss_rsae_sha256(2052),
        rsa_pss_rsae_sha384(2053),
        rsa_pss_rsae_sha512(2054),
        ed25519(2055),
        ed448(2056),
        rsa_pss_pss_sha256(2057),
        rsa_pss_pss_sha384(2058),
        rsa_pss_pss_sha512(2059),
        rsa_pkcs1_sha1(513),
        ecdsa_sha1(515);

        public final short value;

        SignatureScheme(int value) {
            this.value = (short)value;
        }
    }

    public enum PskKeyExchangeMode {
        psk_ke(0),
        psk_dhe_ke(1);

        public final byte value;

        PskKeyExchangeMode(int value) {
            this.value = (byte)value;
        }
    }

    enum CertificateType {
        X509(0),
        RawPublicKey(2);

        public final byte value;

        CertificateType(int value) {
            this.value = (byte)value;
        }
    }

    public static byte[] TLS_AES_128_GCM_SHA256 = new byte[] { 19, 1 };

    public static byte[] TLS_AES_256_GCM_SHA384 = new byte[] { 19, 2 };

    public static byte[] TLS_CHACHA20_POLY1305_SHA256 = new byte[] { 19, 3 };

    public static byte[] TLS_AES_128_CCM_SHA256 = new byte[] { 19, 4 };

    public static byte[] TLS_AES_128_CCM_8_SHA256 = new byte[] { 19, 5 };
}

