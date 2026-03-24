package com.cyberthreat.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/geo")
@CrossOrigin(origins = "http://localhost:4200")
public class GeoLocationController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/{ip}")
    public ResponseEntity<String> getGeo(@PathVariable String ip) {
        String url = "https://ipapi.co/" + ip + "/json/";
        return ResponseEntity.ok(
                restTemplate.getForObject(url, String.class)
        );
    }
}
