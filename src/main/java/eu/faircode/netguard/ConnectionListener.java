package eu.faircode.netguard;

public interface ConnectionListener {

    void notifyConnected(Connected connected);

    void notifyDisconnected(Connected connected);

}
