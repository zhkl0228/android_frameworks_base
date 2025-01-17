/*
 * Copyright (C) 2010 The Android-X86 Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net.ethernet;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicBoolean;

import android.R;
import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.bluetooth.BluetoothHeadset;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.DhcpInfo;
import android.net.DhcpResults;
import android.net.InterfaceConfiguration;
import android.net.LinkAddress;
import android.net.LinkCapabilities;
import android.net.LinkProperties;
import android.net.LinkQualityInfo;
import android.net.NetworkStateTracker;
import android.net.NetworkUtils;
import android.net.NetworkInfo;
import android.net.NetworkInfo.DetailedState;
import android.net.RouteInfo;
import android.net.SamplingDataTracker;
import android.net.wifi.WifiManager;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.INetworkManagementService;
import android.os.Looper;
import android.os.Message;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.os.SystemProperties;
import android.util.*;
import android.os.UserHandle;
import android.net.BaseNetworkStateTracker;
import android.os.Messenger;

/**
 * Track the state of Ethernet connectivity. All event handling is done here,
 * and all changes in connectivity state are initiated here.
 *
 * @hide
 */
public class EthernetStateTracker implements NetworkStateTracker {

    private static final String TAG = "EthernetStateTracker";
    private static final boolean DBG = true;

    public static final int EVENT_DHCP_START            = 0;
    public static final int EVENT_IF_CONFIG_SUCCEEDED   = 1;
    public static final int EVENT_IF_CONFIG_FAILED      = 2;
    public static final int EVENT_HW_CONNECTED          = 3;
    public static final int EVENT_HW_DISCONNECTED       = 4;
    public static final int EVENT_HW_PHYCONNECTED       = 5;
    public static final int EVENT_HW_PHYDISCONNECTED    = 6;
    // Temporary event for Settings until this supports multiple interfaces
    public static final int EVENT_HW_CHANGED            = 7;

    private EthernetManager             mEM;
    private boolean                     mServiceStarted;

    private AtomicBoolean               mTeardownRequested = new AtomicBoolean(false);
    private AtomicBoolean               mPrivateDnsRouteSet = new AtomicBoolean(false);
    private AtomicBoolean               mDefaultRouteSet = new AtomicBoolean(false);

    private LinkProperties              mLinkProperties;
    private LinkCapabilities            mLinkCapabilities;
    private NetworkInfo                 mNetworkInfo;
    private NetworkInfo.State           mLastState = NetworkInfo.State.UNKNOWN;

    private boolean                     mStackConnected;
    private boolean                     mHWConnected;
    private boolean                     mInterfaceStopped;
    private INetworkManagementService   mNwService;
    private Handler                     mDhcpTarget;
    private String                      mInterfaceName;
    private DhcpResults                 mDhcpResults;
    private EthernetMonitor             mMonitor;
    private boolean                     mStartingDhcp;
    private Handler                     mTarget;
    private Handler                     mTrackerTarget;
    private Context                     mContext;

    public EthernetStateTracker(int netType, String networkName) {
        if (DBG) Slog.i(TAG, "Starting...");

        mNetworkInfo = new NetworkInfo(netType, 0, networkName, "");
        mLinkProperties = new LinkProperties();
        mLinkCapabilities = new LinkCapabilities();

        mNetworkInfo.setIsAvailable(false);
        setTeardownRequested(false);

        if (EthernetNative.initEthernetNative() != 0 ) {
            Slog.e(TAG, "Failed to initialize ethernet device");
            return;
        }

        IBinder b = ServiceManager.getService(Context.NETWORKMANAGEMENT_SERVICE);
        mNwService = INetworkManagementService.Stub.asInterface(b);

        if (DBG) Slog.i(TAG, "Success");

        mServiceStarted = true;
        HandlerThread dhcpThread = new HandlerThread("DHCP Handler Thread");
        dhcpThread.start();
        mDhcpTarget = new Handler(dhcpThread.getLooper(), mDhcpHandlerCallback);
        mMonitor = new EthernetMonitor(this);
        mDhcpResults = new DhcpResults();
    }

    public void setTeardownRequested(boolean isRequested) {
        mTeardownRequested.set(isRequested);
    }

    public boolean isTeardownRequested() {
        return mTeardownRequested.get();
    }

    /**
     * Stop etherent interface
     *
     * @param suspend
     *    {@code false} disable the interface
     *    {@code true}  only reset the connection without disable the interface
     * @return true
     */
    public boolean stopInterface(boolean suspend) {
        if (mEM != null) {
            EthernetDevInfo info = mEM.getSavedEthConfig();
            if (info != null && mEM.ethConfigured()) {
                synchronized (mDhcpTarget) {
                    mInterfaceStopped = true;
                    if (DBG) Slog.i(TAG, "Stop DHCP and interface");
                    mDhcpTarget.removeMessages(EVENT_DHCP_START);
                    mStartingDhcp = false;

                    String ifname = info.getIfName();
                    if (!NetworkUtils.stopDhcp(ifname)) {
                        Slog.e(TAG, "Failed to stop DHCP");
                    }
                    NetworkUtils.resetConnections(ifname, NetworkUtils.RESET_ALL_ADDRESSES);

                    try {
                        mNwService.clearInterfaceAddresses(mInterfaceName);
                    } catch (Exception e) {
                        Slog.e(TAG, "Failed to clear addresses" + e);
                    }

                    if (!suspend)
                        NetworkUtils.disableInterface(ifname);
                }
            }
        }
        return true;
    }

/*
    private boolean configureInterfaceStatic(String ifname, DhcpInfoInternal dhcpInfoInternal) {
        IBinder b = ServiceManager.getService(Context.NETWORKMANAGEMENT_SERVICE);
        INetworkManagementService netd = INetworkManagementService.Stub.asInterface(b);
        InterfaceConfiguration ifcg = new InterfaceConfiguration();
        ifcg.setLinkAddress(dhcpInfoInternal.makeLinkAddress());
        ifcg.setInterfaceUp();
        try {
            netd.setInterfaceConfig(ifname, ifcg);
            mLinkProperties = dhcpInfoInternal.makeLinkProperties();
            mLinkProperties.setInterfaceName(ifname);
            Log.v(TAG, "Static IP configuration succeeded");
            return true;
        } catch (RemoteException re) {
            Log.v(TAG, "Static IP configuration failed: " + re);
            return false;
        } catch (IllegalStateException e) {
            Log.v(TAG, "Static IP configuration failed: " + e);
            return false;
        }
    }
*/

    private boolean configureInterface(EthernetDevInfo info) throws UnknownHostException {
        mInterfaceName = info.getIfName();
        mStackConnected = false;
        mHWConnected = false;
        mInterfaceStopped = false;

        if (info.getConnectMode().equals(EthernetDevInfo.ETH_CONN_MODE_DHCP)) {
            if (!mStartingDhcp) {
                Slog.i(TAG, "trigger dhcp for device " + info.getIfName());
                mStartingDhcp = true;
                mLinkProperties.clear();
                mDhcpTarget.sendEmptyMessage(EVENT_DHCP_START);
            }
        } else {
            int event;

            try {
                InetAddress ia = NetworkUtils.numericToInetAddress(info.getNetMask());
                int prefix = NetworkUtils.netmaskIntToPrefixLength(
                        NetworkUtils.inetAddressToInt((Inet4Address)ia));

                mDhcpResults.clear();
                mDhcpResults.setInterfaceName(mInterfaceName);
                mDhcpResults.setServerAddress(info.getRouteAddr());
                mDhcpResults.addLinkAddress(info.getIpAddress(), prefix);
                mDhcpResults.addGateway(info.getRouteAddr());
                mDhcpResults.addDns(info.getDnsAddr());
                mDhcpResults.setLeaseDuration(-1);

                if (DBG) Slog.i(TAG, "Use IP address: " + mDhcpResults.toString());
                //if (info.getIfName() != null)
                //    NetworkUtils.resetConnections(info.getIfName(), NetworkUtils.RESET_ALL_ADDRESSES);

                LinkAddress linkAddress = new LinkAddress(
                        NetworkUtils.numericToInetAddress(info.getIpAddress()), prefix);
                InterfaceConfiguration ifcg = new InterfaceConfiguration();
                ifcg.setLinkAddress(linkAddress);
                ifcg.setInterfaceUp();

                mNwService.setInterfaceConfig(info.getIfName(), ifcg);
                mLinkProperties = mDhcpResults.linkProperties;

                event = EVENT_IF_CONFIG_SUCCEEDED;
                Slog.v(TAG, "Static IP configuration succeeded");

            } catch (Exception e) {
                event = EVENT_IF_CONFIG_FAILED;
                Slog.v(TAG, "Static IP configuration failed: " + e);
            }

            mTrackerTarget.sendEmptyMessage(event);
        }
        return true;
    }

    /**
     * reset ethernet interface
     *
     * @return true
     * @throws UnknownHostException
     */
    public boolean resetInterface() throws UnknownHostException {
        /*
         * This will guide us to enabled the enabled device
         */
        if (mEM != null) {
            EthernetDevInfo info = mEM.getSavedEthConfig();
            if (info != null && mEM.ethConfigured()) {
                synchronized (this) {
                    mInterfaceName = info.getIfName();
                    if (DBG) Slog.i(TAG, "Reset interface " + mInterfaceName);
                    if (mInterfaceName != null)
                        NetworkUtils.resetConnections(mInterfaceName, NetworkUtils.RESET_ALL_ADDRESSES);
                    // Stop DHCP
                    if (mDhcpTarget != null) {
                        mDhcpTarget.removeMessages(EVENT_DHCP_START);
                    }
                    mStartingDhcp = false;
                    if (!NetworkUtils.stopDhcp(mInterfaceName)) {
                        Slog.e(TAG, "Could not stop DHCP");
                    }
                    if (DBG) Slog.i(TAG, "Force the connection disconnected before configuration");
                    setEthState(false, EVENT_HW_DISCONNECTED);

                    if (mInterfaceName != null)
                        NetworkUtils.enableInterface(mInterfaceName);
                    configureInterface(info);
                }
            }
            else {
                Slog.e(TAG, "Failed to resetInterface for EthernetManager is null");
            }
        }
        return true;
    }

    @Override
    public String getTcpBufferSizesPropName() {
        return "net.tcp.buffersize.default";
    }

    public void StartPolling() {
        Slog.v(TAG, "start polling");
        mMonitor.startMonitoring();
    }

    @Override
    public boolean isAvailable() {
        // Only say available if we have interfaces and user did not disable us.
        return ((mEM.getTotalInterface() != 0) &&
                (mEM.getEthState() != EthernetManager.ETH_STATE_DISABLED));
    }

    @Override
    public boolean reconnect() {
        mTeardownRequested.set(false);
        try {
            synchronized (this) {
                if (mHWConnected && mStackConnected) {
                    Slog.i(TAG, "$$reconnect() returns DIRECTLY)");
                    return true;
                }
            }
            if (mEM.getEthState() != EthernetManager.ETH_STATE_DISABLED) {
                // maybe this is the first time we run, so set it to enabled
                mEM.setEthEnabled(true);
                if (!mEM.ethConfigured()) {
                    mEM.ethSetDefaultConf();
                }
                Slog.i(TAG, "$$reconnect call resetInterface()");
                return resetInterface();
            }
        } catch (UnknownHostException e) {
            e.printStackTrace();
        }
        return false;
    }

    @Override
    public boolean setRadio(boolean turnOn) {
        return false;
    }

    /**
     * Begin monitoring ethernet connectivity
     */
    @Override
    public void startMonitoring(Context context, Handler target) {
        Slog.i(TAG, "start to monitor the Ethernet devices");
        if (mServiceStarted) {
            mContext = context;
            mEM = (EthernetManager) mContext.getSystemService(Context.ETH_SERVICE);
            mTarget = target;
            mTrackerTarget = new Handler(target.getLooper(), mTrackerHandlerCallback);

            int state = mEM.getEthState();
            if (state == mEM.ETH_STATE_UNKNOWN) {
                // maybe this is the first time we run, so set it to disable
                mEM.setEthEnabled(false);
            } else if (state != mEM.ETH_STATE_DISABLED) {
                // Nothing here as reconnect() will be called by ConnectivityService
                /*
                Slog.i(TAG, "startMonitoring call resetInterface()");
                try {
                    resetInterface();
                } catch (UnknownHostException e) {
                    Slog.e(TAG, "Wrong Ethernet configuration");
                }
                */
            }
        }
    }

    public void setUserDataEnable(boolean enabled) {
        Slog.d(TAG, "ignoring setUserDataEnable(" + enabled + ")");
    }

    public void setPolicyDataEnable(boolean enabled) {
        Slog.d(TAG, "ignoring setPolicyDataEnable(" + enabled + ")");
    }

    /**
     * Check if private DNS route is set for the network
     */
    public boolean isPrivateDnsRouteSet() {
        return mPrivateDnsRouteSet.get();
    }

    /**
     * Set a flag indicating private DNS route is set
     */
    public void privateDnsRouteSet(boolean enabled) {
        mPrivateDnsRouteSet.set(enabled);
    }

    /**
     * Check if default route is set
     */
    public boolean isDefaultRouteSet() {
        return mDefaultRouteSet.get();
    }

    /**
     * Set a flag indicating default route is set for the network
     */
    public void defaultRouteSet(boolean enabled) {
        mDefaultRouteSet.set(enabled);
    }

    /**
     * Fetch NetworkInfo for the network
     */
    public NetworkInfo getNetworkInfo() {
        return new NetworkInfo(mNetworkInfo);
    }

    /**
     * Fetch LinkProperties for the network
     */
    public LinkProperties getLinkProperties() {
        return new LinkProperties(mLinkProperties);
    }

    /**
     * A capability is an Integer/String pair, the capabilities
     * are defined in the class LinkSocket#Key.
     *
     * @return a copy of this connections capabilities, may be empty but never null.
     */
    public LinkCapabilities getLinkCapabilities() {
        return new LinkCapabilities(mLinkCapabilities);
    }

    public boolean teardown() {
        mTeardownRequested.set(true);
        if (mEM != null) {
            EthernetDevInfo info = mEM.getSavedEthConfig();
            if (info.getAlwaysOn() > 0) {
                // Keep interface up but cheat ConnectivityService we are gone
                // TODO: handle default gateway when two connection exist
                return true;
            }
            return stopInterface(false);
        }
        return true;
    }

    private void postNotification(int event) {
        final Intent intent = new Intent(EthernetManager.ETH_STATE_CHANGED_ACTION);
        intent.addFlags(Intent.FLAG_RECEIVER_REGISTERED_ONLY_BEFORE_BOOT);
        intent.putExtra(EthernetManager.EXTRA_ETH_STATE, event);
        mContext.sendStickyBroadcastAsUser(intent, UserHandle.ALL);

        Message msg = mTarget.obtainMessage(EVENT_STATE_CHANGED, new NetworkInfo(mNetworkInfo));
        msg.sendToTarget();
    }

    private void setEthState(boolean state, int event) {
        Slog.d(TAG, "setEthState: " + mNetworkInfo.isConnected() + " -> " + state + " event=" + event);
        if (mNetworkInfo.isConnected() != state) {
            if (state) {
                mNetworkInfo.setDetailedState(DetailedState.CONNECTED, null, null);
            } else {
                mNetworkInfo.setDetailedState(DetailedState.DISCONNECTED, null, null);
                if (event == EVENT_HW_DISCONNECTED) {
                    Slog.d(TAG, "EVENT_HW_DISCONNECTED: StopInterface");
                    stopInterface(true);
                }
            }
            Slog.d(TAG, "***isConnected: " + mNetworkInfo.isConnected());
            mNetworkInfo.setIsAvailable(state);
            Message msg = mTarget.obtainMessage(EVENT_CONFIGURATION_CHANGED, mNetworkInfo);
            msg.sendToTarget();
        }
        postNotification(event);
    }

    public DhcpInfo getDhcpInfo() {
        if (mDhcpResults.linkProperties == null) return null;

        DhcpInfo info = new DhcpInfo();
        for (LinkAddress la : mDhcpResults.linkProperties.getLinkAddresses()) {
            InetAddress addr = la.getAddress();
            if (addr instanceof Inet4Address) {
                info.ipAddress = NetworkUtils.inetAddressToInt((Inet4Address)addr);
                break;
            }
        }
        for (RouteInfo r : mDhcpResults.linkProperties.getRoutes()) {
            if (r.isDefaultRoute()) {
                InetAddress gateway = r.getGateway();
                if (gateway instanceof Inet4Address) {
                    info.gateway = NetworkUtils.inetAddressToInt((Inet4Address)gateway);
                }
            } else if (r.hasGateway() == false) {
                LinkAddress dest = r.getDestination();
                if (dest.getAddress() instanceof Inet4Address) {
                    info.netmask = NetworkUtils.prefixLengthToNetmaskInt(
                            dest.getNetworkPrefixLength());
                }
            }
        }
        int dnsFound = 0;
        for (InetAddress dns : mDhcpResults.linkProperties.getDnses()) {
            if (dns instanceof Inet4Address) {
                if (dnsFound == 0) {
                    info.dns1 = NetworkUtils.inetAddressToInt((Inet4Address)dns);
                } else {
                    info.dns2 = NetworkUtils.inetAddressToInt((Inet4Address)dns);
                }
                if (++dnsFound > 1) break;
            }
        }
        InetAddress serverAddress = mDhcpResults.serverAddress;
        if (serverAddress instanceof Inet4Address) {
            info.serverAddress = NetworkUtils.inetAddressToInt((Inet4Address)serverAddress);
        }
        info.leaseDuration = mDhcpResults.leaseDuration;

        return info;
    }

    private Handler.Callback mTrackerHandlerCallback = new Handler.Callback() {
        /** {@inheritDoc} */
        public boolean handleMessage(Message msg) {
            synchronized (this) { //TODO correct 'this' object?
                EthernetDevInfo info;
                boolean newNetworkstate = false;
                Slog.i(TAG, "Old status stackConnected=" + mStackConnected + " HWConnected=" + mHWConnected + " msg.what is " + msg.what);
                switch (msg.what) {
                case EVENT_IF_CONFIG_SUCCEEDED:
                    Slog.i(TAG, "[EVENT_IF_CONFIG_SUCCEEDED]");
                    mStackConnected = true;
                    mHWConnected = true;
                    if (mEM.isEthDeviceAdded()) {
                        Slog.i(TAG, "Ether is added" );
                        newNetworkstate = true;
                    }
                    setEthState(newNetworkstate, msg.what);
                    Slog.i(TAG, "New status, stackConnected=" + mStackConnected + " HWConnected=" + mHWConnected );
                    break;
                case EVENT_IF_CONFIG_FAILED:
                    Slog.i(TAG, "[EVENT_IF_CONFIG_FAILED]");
                    mStackConnected = false;
                    Slog.i(TAG, "New status, stackConnected=" + mStackConnected + " HWConnected=" + mHWConnected );
                    setEthState(newNetworkstate, msg.what);
                    //start to retry ?
                    break;
                case EVENT_HW_CONNECTED:
                    Slog.i(TAG, "[EVENT: IP is configured]");
                    mHWConnected = true;
                    if (mEM.isEthDeviceAdded()) {
                        Slog.i(TAG, "Ether is added" );
                        newNetworkstate = true;
                    }

                    setEthState(newNetworkstate, msg.what);
                    Slog.i(TAG, "New status, stackConnected=" + mStackConnected + " HWConnected=" + mHWConnected );
                    break;
                case EVENT_HW_DISCONNECTED:
                    Slog.i(TAG, "[EVENT: ether is removed]");
                    mHWConnected = false;
                    setEthState(false, msg.what);
                    Slog.i(TAG, "New status, stackConnected=" + mStackConnected + " HWConnected=" + mHWConnected );
                    break;
                case EVENT_HW_PHYCONNECTED:
                    Slog.i(TAG, "[EVENT: Ether is up]");
                    mHWConnected = true;
                    newNetworkstate = mNetworkInfo.isConnected();
                    info = mEM.getSavedEthConfig();
                    if (mEM.isEthDeviceAdded() && (info != null) &&
                            info.getConnectMode().equals(EthernetDevInfo.ETH_CONN_MODE_MANUAL)) {
                        newNetworkstate = true;
                        Slog.i(TAG, "Ether is added" );
                        Slog.i(TAG, "Static IP configured, make network connected" );
                    }

                    setEthState(newNetworkstate, EVENT_HW_PHYCONNECTED);
                    Slog.i(TAG, "New status, stackConnected=" + mStackConnected + " HWConnected=" + mHWConnected );
                    if (!mStartingDhcp) {
                        int state = mEM.getEthState();
                        if (state != mEM.ETH_STATE_DISABLED) {
                            info = mEM.getSavedEthConfig();
                            if (info == null || !mEM.ethConfigured()) {
                                // new interface, default to DHCP
                                String ifname = (String)msg.obj;
                                info = new EthernetDevInfo();
                                info.setIfName(ifname);
                                mEM.updateEthDevInfo(info);
                            }
                            try {
                                configureInterface(info);
                            } catch (UnknownHostException e) {
                                 e.printStackTrace();
                            }
                        }
                    }
                    break;
                }
            }
            return true;
        }
    };

    private Handler.Callback mDhcpHandlerCallback = new Handler.Callback() {
        /** {@inheritDoc} */
        public boolean handleMessage(Message msg) {
            int event;

            switch (msg.what) {
            case EVENT_DHCP_START:
                synchronized (mDhcpTarget) {
                    if (!mInterfaceStopped) {
                        Slog.d(TAG, "DhcpHandler: DHCP request started");
                        setEthState(false, msg.what);
                        if (NetworkUtils.runDhcp(mInterfaceName, mDhcpResults)) {
                            event = EVENT_IF_CONFIG_SUCCEEDED;
                            Slog.d(TAG, "DhcpHandler: DHCP request succeeded: " + mDhcpResults.toString());
                            mLinkProperties = mDhcpResults.linkProperties;
                            mLinkProperties.setInterfaceName(mInterfaceName);
                        } else {
                            String DhcpError = NetworkUtils.getDhcpError() ;
                            Slog.i(TAG, "DhcpHandler: DHCP request failed: " + DhcpError);
                            if (DhcpError.contains("dhcpcd to start")) {
                                event = EVENT_HW_PHYDISCONNECTED;
                            } else
                                event = EVENT_IF_CONFIG_FAILED;
                        }
                        mTrackerTarget.sendEmptyMessage(event);
                    } else {
                        mInterfaceStopped = false;
                    }
                    mStartingDhcp = false;
                }
                break;
            }
            return true;
        }
    };

    public void notifyPhyConnected(String ifname) {
        Slog.i(TAG, "report interface up for " + ifname);
        synchronized(this) {
            Message msg = mTrackerTarget.obtainMessage(EVENT_HW_PHYCONNECTED, ifname);
            msg.sendToTarget();
        }
    }

    public void notifyStateChange(String ifname, DetailedState state) {
        Slog.v(TAG, "report new state " + state.toString() + " on " + ifname);
        if (ifname.equals(mInterfaceName)) {
            Slog.v(TAG, "update network state tracker");
            synchronized(this) {
                mTrackerTarget.sendEmptyMessage(state.equals(DetailedState.CONNECTED)
                        ? EVENT_HW_CONNECTED : EVENT_HW_DISCONNECTED);
            }
        }
        else if (ifname.equals("(pulledout)"))
            postNotification(EVENT_HW_PHYDISCONNECTED);
        else
            postNotification(EVENT_HW_CHANGED);
    }

    public void setDependencyMet(boolean met) {
        // not supported on this network
    }

    @Override
    public void addStackedLink(LinkProperties link) {
        mLinkProperties.addStackedLink(link);
    }

    @Override
    public void removeStackedLink(LinkProperties link) {
        mLinkProperties.removeStackedLink(link);
    }

    @Override
    public void supplyMessenger(Messenger messenger) {
        // not supported on this network
    }

    @Override
    public String getNetworkInterfaceName() {
        if (mLinkProperties != null) {
            return mLinkProperties.getInterfaceName();
        } else {
            return null;
        }
    }

    @Override
    public void startSampling(SamplingDataTracker.SamplingSnapshot s) {
        // nothing to do
    }

    @Override
    public void stopSampling(SamplingDataTracker.SamplingSnapshot s) {
        // nothing to do
    }

    @Override
    public void captivePortalCheckComplete() {
        // not implemented
    }

    @Override
    public void captivePortalCheckCompleted(boolean isCaptivePortal) {
        // not implemented
    }

    @Override
    public LinkQualityInfo getLinkQualityInfo() {
        // not implemented
        return null;
    }
}
