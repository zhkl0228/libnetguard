package eu.faircode.netguard;

import java.io.DataInput;
import java.io.IOException;

/**
 * The iOS process that owns a connection, reported by inspectorvpnd ({@code ios/inspectorvpnd}) on jailbroken devices.
 * <p>
 * {@link #getPackageName()} is the bundle identifier when the executable is the main executable of a bundle, and the
 * process name otherwise. {@link #getLabel()} is the bundle's CFBundleDisplayName, else its CFBundleName, and the
 * process name for executables outside a bundle. iOS has no integer version code, so {@link #getVersionCode()} is the
 * pid; see {@link #getShortVersionString()} and {@link #getBundleVersion()} for the version.
 * <p>
 * When a system process makes the connection on behalf of an app (for example com.apple.WebKit.Networking for Safari),
 * this is the app and {@link #getDelegate()} is the process that holds the socket.
 */
public class IOSApplication extends Application {

    /**
     * Decodes {@code Process owner, bool delegated, [Process delegate]}.
     */
    static IOSApplication decodeOwner(DataInput in) throws IOException {
        Process owner = Process.decode(in);
        IOSApplication delegate = readFlag(in, "delegated") ? Process.decode(in).toApplication(null) : null;
        return owner.toApplication(delegate);
    }

    private static boolean readFlag(DataInput in, String name) throws IOException {
        int value = in.readUnsignedByte();
        if (value != 0 && value != 1) {
            throw new IOException("Flag " + name + " should be 0 or 1: " + value);
        }
        return value == 1;
    }

    private static String readOptionalUTF(DataInput in, String name) throws IOException {
        return readFlag(in, name) ? in.readUTF() : null;
    }

    /**
     * {@code i32 pid, UTF processName, UTF executablePath, bool bundle, [UTF CFBundleIdentifier,
     * OptUTF CFBundleDisplayName, OptUTF CFBundleName, OptUTF CFBundleShortVersionString, OptUTF CFBundleVersion]}
     */
    private static class Process {
        static Process decode(DataInput in) throws IOException {
            Process p = new Process();
            p.pid = in.readInt();
            p.processName = in.readUTF();
            p.executablePath = in.readUTF();
            if (readFlag(in, "bundle")) {
                p.bundleIdentifier = in.readUTF();
                p.bundleDisplayName = readOptionalUTF(in, "CFBundleDisplayName");
                p.bundleName = readOptionalUTF(in, "CFBundleName");
                p.shortVersionString = readOptionalUTF(in, "CFBundleShortVersionString");
                p.bundleVersion = readOptionalUTF(in, "CFBundleVersion");
            }
            return p;
        }

        int pid;
        String processName;
        String executablePath;
        String bundleIdentifier;
        String bundleDisplayName;
        String bundleName;
        String shortVersionString;
        String bundleVersion;

        IOSApplication toApplication(IOSApplication delegate) {
            return new IOSApplication(this, delegate);
        }
    }

    private final int pid;
    private final String processName;
    private final String executablePath;
    private final String bundleIdentifier;
    private final String bundleDisplayName;
    private final String bundleName;
    private final String shortVersionString;
    private final String bundleVersion;
    private final IOSApplication delegate;

    private IOSApplication(Process p, IOSApplication delegate) {
        super(p.bundleIdentifier == null ? p.processName : p.bundleIdentifier,
                p.bundleIdentifier == null ? p.processName : (p.bundleDisplayName == null ? p.bundleName : p.bundleDisplayName),
                p.pid);
        this.pid = p.pid;
        this.processName = p.processName;
        this.executablePath = p.executablePath;
        this.bundleIdentifier = p.bundleIdentifier;
        this.bundleDisplayName = p.bundleDisplayName;
        this.bundleName = p.bundleName;
        this.shortVersionString = p.shortVersionString;
        this.bundleVersion = p.bundleVersion;
        this.delegate = delegate;
    }

    public int getPid() {
        return pid;
    }

    public String getProcessName() {
        return processName;
    }

    public String getExecutablePath() {
        return executablePath;
    }

    /**
     * @return CFBundleIdentifier, or null when the executable is not the main executable of a bundle
     */
    public String getBundleIdentifier() {
        return bundleIdentifier;
    }

    /**
     * @return CFBundleDisplayName, or null when absent or not a bundle
     */
    public String getBundleDisplayName() {
        return bundleDisplayName;
    }

    /**
     * @return CFBundleName, or null when absent or not a bundle
     */
    public String getBundleName() {
        return bundleName;
    }

    /**
     * @return CFBundleShortVersionString, or null when absent or not a bundle
     */
    public String getShortVersionString() {
        return shortVersionString;
    }

    /**
     * @return CFBundleVersion, or null when absent or not a bundle
     */
    public String getBundleVersion() {
        return bundleVersion;
    }

    /**
     * @return the process that holds the socket on behalf of this application, or null when this application holds it
     */
    public IOSApplication getDelegate() {
        return delegate;
    }

    @Override
    public String toString() {
        return getLabel() + "(" + getPackageName() + ", pid=" + pid + ")" + (delegate == null ? "" : " via " + delegate);
    }
}
