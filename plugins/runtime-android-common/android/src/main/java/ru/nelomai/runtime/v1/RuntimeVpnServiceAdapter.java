package ru.nelomai.runtime.v1;

import android.app.Service;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.net.Network;
import android.net.VpnService;

/** Stable host forwarding only; versioned GoBackend owns tunnel behavior. */
public class RuntimeVpnServiceAdapter extends ContextWrapper {
    private final VpnService service;
    public static final int START_STICKY = Service.START_STICKY;
    public static final int START_NOT_STICKY = Service.START_NOT_STICKY;

    public RuntimeVpnServiceAdapter(VpnService service) {
        super(service);
        this.service = service;
    }
    public final VpnService getSystemServiceHost() { return service; }
    public static Intent prepare(Context context) { return VpnService.prepare(context); }
    public VpnService.Builder getBuilder() { return service.new Builder(); }
    public final boolean protect(int socket) { return service.protect(socket); }
    public final boolean setUnderlyingNetworks(Network[] networks) { return service.setUnderlyingNetworks(networks); }
    public final void stopSelf() { service.stopSelf(); }
    public final void stopSelf(int startId) { service.stopSelf(startId); }
    public void onCreate() {}
    public int onStartCommand(Intent intent, int flags, int startId) { return START_STICKY; }
    public void onDestroy() {}
    public void onTaskRemoved(Intent intent) {}
    public void onRevoke() { service.stopSelf(); }
}
