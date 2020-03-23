package quic.tls.extension;

import quic.tls.TlsConstants;

import java.nio.ByteBuffer;

public class SignatureAlgorithmsExtension extends Extension {
    private TlsConstants.SignatureScheme[] algorithms;

    public SignatureAlgorithmsExtension() {
        this.algorithms = new TlsConstants.SignatureScheme[] { TlsConstants.SignatureScheme.ecdsa_secp256r1_sha256, TlsConstants.SignatureScheme.rsa_pss_rsae_sha256, TlsConstants.SignatureScheme.rsa_pkcs1_sha256, TlsConstants.SignatureScheme.ecdsa_secp384r1_sha384, TlsConstants.SignatureScheme.rsa_pss_rsae_sha384, TlsConstants.SignatureScheme.rsa_pkcs1_sha384, TlsConstants.SignatureScheme.rsa_pss_rsae_sha512, TlsConstants.SignatureScheme.rsa_pkcs1_sha512, TlsConstants.SignatureScheme.rsa_pkcs1_sha1 };
    }

    public SignatureAlgorithmsExtension(TlsConstants.SignatureScheme[] signatureAlgorithms) {
        this.algorithms = signatureAlgorithms;
    }

    public byte[] getBytes() {
        int extensionLength = 2 + this.algorithms.length * 2;
        ByteBuffer buffer = ByteBuffer.allocate(4 + extensionLength);
        buffer.putShort(TlsConstants.ExtensionType.signature_algorithms.value);
        buffer.putShort((short)extensionLength);
        buffer.putShort((short)(this.algorithms.length * 2));
        for (TlsConstants.SignatureScheme namedGroup : this.algorithms)
            buffer.putShort(namedGroup.value);
        return buffer.array();
    }
}

