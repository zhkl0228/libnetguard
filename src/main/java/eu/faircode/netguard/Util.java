package eu.faircode.netguard;

public class Util {


    private static native String jni_getprop(String name);

    private static native boolean is_numeric_address(String ip);

}
