import android.security.net.config.NetworkSecurityConfig;
import android.security.net.config.NetworkSecurityConfig.Builder;
import java.lang.reflect.Method;
import java.util.Arrays;

public final class HookBridgeTest {
    private interface Action { void run() throws Throwable; }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static Throwable rejects(Class<? extends Throwable> type, Action action) throws Throwable {
        try { action.run(); }
        catch (Throwable error) {
            if (type.isInstance(error)) return error;
            throw new AssertionError("Expected " + type.getName() + ", got " + error, error);
        }
        throw new AssertionError("Expected " + type.getName());
    }

    private static HookBridge hook(int flags) throws Exception {
        HookBridge hook = new HookBridge(flags);
        hook.setBackup(Builder.class.getDeclaredMethod("build"));
        check(hook.activeFlags() == flags, "Supported flags must stay active");
        return hook;
    }

    private static NetworkSecurityConfig build(HookBridge hook, Builder builder) throws Throwable {
        return (NetworkSecurityConfig) hook.onBuild(new Object[]{builder});
    }

    private static void sources(NetworkSecurityConfig config, String... expected) {
        check(config.trustSources().equals(Arrays.asList(expected)),
            "Unexpected trust sources: " + config.trustSources());
    }

    public static void main(String[] args) throws Throwable {
        HookBridge user = hook(2);
        Builder parent = new Builder().anchors("system", "raw/resource");
        Builder sibling = new Builder().parent(parent);
        Builder child = new Builder().parent(parent);
        NetworkSecurityConfig config = build(user, child);
        sources(config, "system", "raw/resource", "user");
        check(config.pinsEnforcedFor("user"), "Added user trust must enforce pins");
        check(config.pinsEnforcedFor("system") && config.pinsEnforcedFor("raw/resource"),
            "Existing trust sources must keep enforcing pins");
        sources(parent.build(), "system", "raw/resource");
        sources(sibling.build(), "system", "raw/resource");
        sources(build(user, child), "system", "raw/resource", "user");
        check(child.buildCalls == 2, "Each callback must invoke the original builder once");

        Builder inheritedUser = new Builder().parent(new Builder().anchors("system", "user"));
        sources(build(user, inheritedUser), "system", "user");
        sources(build(user, new Builder().anchors("user", "raw/resource")), "user", "raw/resource");
        sources(build(user, new Builder()), "user");

        Builder explicitCT = new Builder().anchors("system")
            .setCertificateTransparencyVerificationRequired(true);
        check(build(user, explicitCT).requiresCT(), "User-only option must preserve an explicit CT requirement");
        check(!config.requiresCT(), "Implicit CT follows Android's normal user-anchor exemption");

        HookBridge ct = hook(1);
        Builder ctParent = new Builder().anchors("system", "raw/resource")
            .setCertificateTransparencyVerificationRequired(true);
        NetworkSecurityConfig ctConfig = build(ct, new Builder().parent(ctParent));
        sources(ctConfig, "system", "raw/resource");
        check(!ctConfig.requiresCT(), "CT-only option must disable CT");
        check(ctParent.build().requiresCT(), "A child CT override must not change its parent");
        check(ctConfig.pinsEnforcedFor("system") && ctConfig.pinsEnforcedFor("raw/resource"),
            "CT-only option must preserve pin enforcement");

        NetworkSecurityConfig both = build(hook(3), new Builder().anchors("system", "raw/resource")
            .setCertificateTransparencyVerificationRequired(true));
        sources(both, "system", "raw/resource", "user");
        check(!both.requiresCT() && both.pinsEnforcedFor("user"), "Both options must compose without bypassing pins");

        for (int flags = 4; flags <= 7; flags++) {
            HookBridge system = hook(flags);
            Builder rawParent = new Builder().anchors("raw/resource")
                .setCertificateTransparencyVerificationRequired(true);
            Builder rawChild = new Builder().parent(rawParent)
                .setCertificateTransparencyVerificationRequired(true);
            NetworkSecurityConfig result = build(system, rawChild);
            if ((flags & 2) != 0) sources(result, "raw/resource", "user", "system");
            else sources(result, "raw/resource", "system");
            check(result.requiresCT() == ((flags & 1) == 0), "System hook must preserve explicit CT unless disabled");
            check(result.pinsEnforcedFor("system"), "System trust must enforce pins");
            sources(rawParent.build(), "raw/resource");
            check(build(system, rawChild).trustSources().equals(result.trustSources()), "Repeated builds must not duplicate anchors");
            check(rawChild.buildCalls == 2, "System callback must invoke original exactly once");
        }
        sources(build(hook(4), new Builder().anchors("system", "raw/resource")), "system", "raw/resource");
        check(build(hook(4), new Builder().anchors("raw/resource")).requiresCT(),
            "Adding system trust must not implicitly disable CT");

        RuntimeException original = new IllegalStateException("Original config validation failed");
        Builder failing = new Builder().anchors("system").failWith(original);
        check(rejects(IllegalStateException.class, () -> build(user, failing)) == original,
            "Original build failure must propagate without a reflection wrapper");
        check(failing.buildCalls == 1, "A failing original build must not be retried");

        for (int flags : new int[]{0, -1, 8, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
            rejects(IllegalArgumentException.class, () -> new HookBridge(flags));
        }
        rejects(IllegalArgumentException.class, () -> user.onBuild(null));
        rejects(IllegalArgumentException.class, () -> user.onBuild(new Object[0]));
        rejects(IllegalArgumentException.class, () -> user.onBuild(new Object[]{child, child}));
        rejects(IllegalArgumentException.class, () -> user.onBuild(new Object[]{null}));
        rejects(IllegalArgumentException.class, () -> user.onBuild(new Object[]{"wrong receiver"}));
        rejects(IllegalArgumentException.class, () -> user.setBackup(null));
        rejects(IllegalStateException.class, () -> new HookBridge(2).onBuild(new Object[]{child}));
        Method callback = user.callback();
        check(callback.getDeclaringClass() == HookBridge.class &&
            Arrays.equals(callback.getParameterTypes(), new Class<?>[]{Object[].class}), "Unexpected callback ABI");
        check(user.target().equals(Builder.class.getDeclaredMethod("build")), "Unexpected hook target");
        System.out.println("PASS: hook trust inheritance, pin enforcement, CT options, deduplication and original failures");
    }
}
