package tech.httptoolkit.android.vpn;

import com.github.netguard.vpn.PortRedirector;
import eu.faircode.netguard.Allowed;

public interface Mitm extends PortRedirector {

    Allowed mitm(String ip, int port);

}
