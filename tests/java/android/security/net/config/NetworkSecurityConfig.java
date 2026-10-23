package android.security.net.config;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Small AOSP-shaped fixture for config inheritance and per-source trust semantics. */
public final class NetworkSecurityConfig {
    private final List<CertificatesEntryRef> anchors;
    private final boolean requiresCT;

    private NetworkSecurityConfig(List<CertificatesEntryRef> anchors, boolean requiresCT) {
        this.anchors = new ArrayList<>(anchors);
        this.requiresCT = requiresCT;
    }

    public List<String> trustSources() {
        List<String> result = new ArrayList<>();
        for (CertificatesEntryRef ref : anchors) result.add(ref.mSource.name);
        return result;
    }

    public boolean pinsEnforcedFor(String source) {
        for (CertificatesEntryRef ref : anchors) {
            if (ref.mSource.name.equals(source)) return !ref.overridesPins;
        }
        throw new IllegalArgumentException("Untrusted source: " + source);
    }

    public boolean requiresCT() { return requiresCT; }

    public static final class Builder {
        private List<CertificatesEntryRef> mCertificatesEntryRefs;
        private Builder parent;
        private Boolean explicitCT;
        private RuntimeException failure;
        public int buildCalls;

        public Builder parent(Builder parent) {
            this.parent = parent;
            return this;
        }

        public Builder anchors(String... names) {
            List<CertificatesEntryRef> refs = new ArrayList<>();
            for (String name : names) {
                boolean user = name.equals("user");
                refs.add(new CertificatesEntryRef(user ? UserCertificateSource.getInstance() :
                    name.equals("system") ? SystemCertificateSource.getInstance() : new CertificateSource(name), false, user));
            }
            mCertificatesEntryRefs = Collections.unmodifiableList(refs);
            return this;
        }

        public Builder failWith(RuntimeException error) {
            failure = error;
            return this;
        }

        private List<CertificatesEntryRef> getEffectiveCertificatesEntryRefs() {
            if (mCertificatesEntryRefs != null) return mCertificatesEntryRefs;
            return parent == null ? Collections.emptyList() : parent.getEffectiveCertificatesEntryRefs();
        }

        public Builder setCertificateTransparencyVerificationRequired(boolean required) {
            explicitCT = required;
            return this;
        }

        private boolean getCertificateTransparencyVerificationRequired() {
            if (explicitCT != null) return explicitCT;
            if (mCertificatesEntryRefs != null) {
                for (CertificatesEntryRef ref : mCertificatesEntryRefs) if (ref.disableCT) return false;
            }
            return parent == null || parent.getCertificateTransparencyVerificationRequired();
        }

        public NetworkSecurityConfig build() {
            buildCalls++;
            if (failure != null) throw failure;
            return new NetworkSecurityConfig(getEffectiveCertificatesEntryRefs(),
                getCertificateTransparencyVerificationRequired());
        }
    }
}

class CertificateSource {
    final String name;
    CertificateSource(String name) { this.name = name; }
}

final class SystemCertificateSource extends CertificateSource {
    private static final SystemCertificateSource INSTANCE = new SystemCertificateSource();
    private SystemCertificateSource() { super("system"); }
    static SystemCertificateSource getInstance() { return INSTANCE; }
}

final class UserCertificateSource extends CertificateSource {
    private static final UserCertificateSource INSTANCE = new UserCertificateSource();
    private UserCertificateSource() { super("user"); }
    static UserCertificateSource getInstance() { return INSTANCE; }
}

final class CertificatesEntryRef {
    final CertificateSource mSource;
    final boolean overridesPins;
    final boolean disableCT;
    CertificatesEntryRef(CertificateSource source, boolean overridesPins, boolean disableCT) {
        mSource = source;
        this.overridesPins = overridesPins;
        this.disableCT = disableCT;
    }
}
