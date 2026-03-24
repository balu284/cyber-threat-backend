package com.cyberthreat.dto;

public class DeviceDTO {

    private Long id;
    private String deviceId;
    private String deviceName;
    private String operatingSystem;
    private String ipAddress;
    private String macAddress;
    private String status;

    public DeviceDTO() {}

    public DeviceDTO(Long id, String deviceId, String deviceName,
                     String operatingSystem, String ipAddress,
                     String macAddress, String status) {
        this.id = id;
        this.deviceId = deviceId;
        this.deviceName = deviceName;
        this.operatingSystem = operatingSystem;
        this.ipAddress = ipAddress;
        this.macAddress = macAddress;
        this.status = status;
    }

    public Long getId() { return id; }
    public String getDeviceId() { return deviceId; }
    public String getDeviceName() { return deviceName; }
    public String getOperatingSystem() { return operatingSystem; }
    public String getIpAddress() { return ipAddress; }
    public String getMacAddress() { return macAddress; }
    public String getStatus() { return status; }

    public void setId(Long id) { this.id = id; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    public void setDeviceName(String deviceName) { this.deviceName = deviceName; }
    public void setOperatingSystem(String operatingSystem) { this.operatingSystem = operatingSystem; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }
    public void setStatus(String status) { this.status = status; }
}