package com.ltm.ids.controller;

import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ltm.ids.service.PacketSnifferService;

@RestController
@RequestMapping("/api/config")
public class ConfigController {

    @Autowired
    private PacketSnifferService snifferService;

    @GetMapping("/interfaces")
    public List<Map<String, String>> getInterfaces() throws Exception {
        return snifferService.getNetworkInterfaces();
    }

    @PostMapping("/start")
    public String startSniffer(
            @RequestParam int devIndex,
            @RequestParam int port,
            @RequestParam int threshold,
            @RequestParam(defaultValue = "") String whitelistIp) {
        return snifferService.updateConfigAndStart(devIndex, port, threshold, whitelistIp);
    }

    @PostMapping("/stop")
    public String stopSniffer() {
        snifferService.stopSniffing();
        return "STOPPED";
    }
}