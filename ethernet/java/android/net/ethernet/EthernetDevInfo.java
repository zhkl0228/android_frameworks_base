package android.net.ethernet;

import android.net.ethernet.EthernetDevInfo;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;

public class EthernetDevInfo implements Parcelable {
    private String dev_name;
    private String ipaddr;
    private String netmask;
    private String route;
    private String dns;
    private String mode;
    private int always_on;
    public static final String ETH_CONN_MODE_DHCP= "dhcp";
    public static final String ETH_CONN_MODE_MANUAL = "manual";

    public EthernetDevInfo () {
        dev_name = null;
        ipaddr = null;
        dns = null;
        route = null;
        netmask = null;
        always_on = 0;
        mode = ETH_CONN_MODE_DHCP;
    }

    public void setIfName(String ifname) {
        this.dev_name = ifname;
    }

    public String getIfName() {
        return this.dev_name;
    }

    public void setIpAddress(String ip) {
        this.ipaddr = ip;
    }

    public String getIpAddress() {
        return this.ipaddr;
    }

    public void setNetMask(String ip) {
        this.netmask = ip;
    }

    public String getNetMask() {
        return this.netmask;
    }

    public void setRouteAddr(String route) {
        this.route = route;
    }

    public String getRouteAddr() {
        return this.route;
    }

    public void setDnsAddr(String dns) {
        this.dns = dns;
    }

    public String getDnsAddr() {
        return this.dns;
    }

    public boolean setConnectMode(String mode) {
        if (mode.equals(ETH_CONN_MODE_DHCP) || mode.equals(ETH_CONN_MODE_MANUAL)) {
            this.mode = mode;
            return true;
        }
        return false;
    }

    public String getConnectMode() {
        return this.mode;
    }

    public void setAlwaysOn(int on) {
        this.always_on = on;
    }

    public int getAlwaysOn() {
        return this.always_on;
    }

    public int describeContents() {
        // TODO Auto-generated method stub
        return 0;
    }

    public void writeToParcel(Parcel dest, int flags) {
        dest.writeString(this.dev_name);
        dest.writeString(this.ipaddr);
        dest.writeString(this.netmask);
        dest.writeString(this.route);
        dest.writeString(this.dns);
        dest.writeString(this.mode);
        dest.writeInt(this.always_on);
    }

    /** Implement the Parcelable interface {@hide} */
    public static final Creator<EthernetDevInfo> CREATOR =
        new Creator<EthernetDevInfo>() {
            public EthernetDevInfo createFromParcel(Parcel in) {
                EthernetDevInfo info = new EthernetDevInfo();
                info.setIfName(in.readString());
                info.setIpAddress(in.readString());
                info.setNetMask(in.readString());
                info.setRouteAddr(in.readString());
                info.setDnsAddr(in.readString());
                info.setConnectMode(in.readString());
                info.setAlwaysOn(in.readInt());
                return info;
            }

            public EthernetDevInfo[] newArray(int size) {
                return new EthernetDevInfo[size];
            }
        };
}
