import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/** Loaded only in an explicitly selected app, before its network config is built. */
public final class HookBridge {
    private final int flags;
    private final Method target;
    private final Method effectiveAnchors;
    private final Method ctSetter;
    private final Field anchors;
    private final Field source;
    private final List<Object> addedSources = new ArrayList<>();
    private final List<Object> addedRefs = new ArrayList<>();
    private volatile Method backup;

    public HookBridge(int requested) throws ReflectiveOperationException {
        if (requested <= 0 || (requested & ~7) != 0) throw new IllegalArgumentException("Invalid hook flags");
        Class<?> builder = Class.forName("android.security.net.config.NetworkSecurityConfig$Builder");
        target = method(builder, "build");
        Method setter = null;
        if ((requested & 1) != 0) {
            try { setter = method(builder, "setCertificateTransparencyVerificationRequired", boolean.class); }
            catch (NoSuchMethodException unsupported) { requested &= ~1; }
        }
        ctSetter = setter;
        flags = requested;
        if ((flags & 6) != 0) {
            Class<?> ref = Class.forName("android.security.net.config.CertificatesEntryRef");
            Class<?> certificateSource = Class.forName("android.security.net.config.CertificateSource");
            for (int bit : new int[]{2, 4}) {
                if ((flags & bit) == 0) continue;
                Class<?> store = Class.forName("android.security.net.config." +
                    (bit == 2 ? "UserCertificateSource" : "SystemCertificateSource"));
                Object storeSource = method(store, "getInstance").invoke(null);
                Constructor<?> constructor;
                Object[] arguments;
                try {
                    constructor = ref.getDeclaredConstructor(certificateSource, boolean.class, boolean.class);
                    arguments = new Object[]{storeSource, false, bit == 2};
                } catch (NoSuchMethodException olderAndroid) {
                    constructor = ref.getDeclaredConstructor(certificateSource, boolean.class);
                    arguments = new Object[]{storeSource, false};
                }
                constructor.setAccessible(true);
                addedSources.add(storeSource);
                addedRefs.add(constructor.newInstance(arguments));
            }
            effectiveAnchors = method(builder, "getEffectiveCertificatesEntryRefs");
            anchors = field(builder, "mCertificatesEntryRefs");
            source = field(ref, "mSource");
        } else {
            effectiveAnchors = null;
            anchors = null;
            source = null;
        }
    }

    public int activeFlags() { return flags; }
    public Method target() { return target; }
    public Method callback() throws NoSuchMethodException { return method(HookBridge.class, "onBuild", Object[].class); }
    public void setBackup(Method method) {
        if (method == null) throw new IllegalArgumentException("Missing original builder method");
        method.setAccessible(true);
        backup = method;
    }

    public Object onBuild(Object[] args) throws Throwable {
        if (args == null || args.length != 1 || !target.getDeclaringClass().isInstance(args[0])) {
            throw new IllegalArgumentException("Invalid network config builder callback");
        }
        Method original = backup;
        if (original == null) throw new IllegalStateException("Network config hook is not ready");
        Object builder = args[0];
        try {
            if ((flags & 6) != 0) {
                List<?> inherited = (List<?>) effectiveAnchors.invoke(builder);
                List<Object> entries = new ArrayList<>(inherited);
                for (int i = 0; i < addedSources.size(); i++) {
                    boolean found = false;
                    for (Object entry : inherited) if (source.get(entry) == addedSources.get(i)) found = true;
                    if (!found) entries.add(addedRefs.get(i));
                }
                // Keep inherited raw anchors and avoid mutating parent/sibling builders.
                if (entries.size() != inherited.size()) anchors.set(builder, entries);
            }
            if ((flags & 1) != 0) ctSetter.invoke(builder, false);
            return original.invoke(builder);
        } catch (InvocationTargetException error) {
            throw error.getCause();
        }
    }

    private static Method method(Class<?> owner, String name, Class<?>... parameters) throws NoSuchMethodException {
        Method method = owner.getDeclaredMethod(name, parameters);
        method.setAccessible(true);
        return method;
    }

    private static Field field(Class<?> owner, String name) throws NoSuchFieldException {
        Field field = owner.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }
}
