package com.ltm.ids;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        // Tắt tính năng GUI Headless để Pcap4j tương thích tốt với WinPcap/Npcap trên Windows
        System.setProperty("java.awt.headless", "false");
        SpringApplication.run(Application.class, args);
    }
}