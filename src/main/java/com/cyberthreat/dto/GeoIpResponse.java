package com.cyberthreat.dto;

public class GeoIpResponse {

    private Double lat;
    private Double lon;
    private String country;

    public Double getLat() { return lat; }
    public void setLat(Double lat) { this.lat = lat; }

    public Double getLon() { return lon; }
    public void setLon(Double lon) { this.lon = lon; }

    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }
}
