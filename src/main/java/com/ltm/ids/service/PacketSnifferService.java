package com.ltm.ids.service;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.TcpPacket;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import com.ltm.ids.controller.RuleController;
import com.ltm.ids.dto.RuleModel;

import jakarta.annotation.PostConstruct;


@Service
public class PacketSnifferService {

    

    @Autowired
    private RuleService ruleService;

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    @Autowired
    private RuleController ruleController; // Đấu nối RuleController vào Sniffer

    private String selectedDeviceName = "";
    private int targetPort = 0;
    private int threshold = 10;
    private String whitelistedIp = "";
    private boolean isSniffing = false;

    private PcapHandle currentHandle;

    private final ConcurrentHashMap<String, AtomicInteger> synCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ConcurrentHashMap.KeySetView<Integer, Boolean>> portScanTracker = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> icmpCounts = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        startResetScheduler();
    }

    public List<Map<String, String>> getNetworkInterfaces() throws Exception {
        List<Map<String, String>> devList = new ArrayList<>();
        List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
        if (allDevs != null) {
            for (int i = 0; i < allDevs.size(); i++) {
                PcapNetworkInterface dev = allDevs.get(i);
                Map<String, String> map = new HashMap<>();
                map.put("id", String.valueOf(i));
                map.put("name", dev.getName());
                map.put("description", dev.getDescription() != null ? dev.getDescription() : dev.getName());
                devList.add(map);
            }
        }
        return devList;
    }

    public synchronized String updateConfigAndStart(int devIndex, int port, int newThreshold, String ignoreIp) {
        try {
            stopSniffing();

            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (devIndex < 0 || devIndex >= allDevs.size()) return "Card mạng không hợp lệ!";

            PcapNetworkInterface device = allDevs.get(devIndex);
            this.selectedDeviceName = device.getDescription();
            this.targetPort = port;
            this.threshold = newThreshold;
            this.whitelistedIp = ignoreIp.trim();

            new Thread(() -> runSniffer(device)).start();
            return "SUCCESS";
        } catch (Exception e) {
            return "Lỗi cấu hình: " + e.getMessage();
        }
    }

    public synchronized void stopSniffing() {
        isSniffing = false;
        if (currentHandle != null && currentHandle.isOpen()) {
            try {
                currentHandle.breakLoop();
                currentHandle.close();
            } catch (Exception ignored) {}
        }
    }

    private void runSniffer(PcapNetworkInterface device) {
        try {
            currentHandle = device.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            
            if (targetPort > 0) {
                currentHandle.setFilter("tcp port " + targetPort + " or icmp", BpfProgram.BpfCompileMode.OPTIMIZE);
            } else {
                currentHandle.setFilter("ip", BpfProgram.BpfCompileMode.OPTIMIZE);
            }

            isSniffing = true;

            PacketListener listener = packet -> {
                if (!isSniffing) return;
                
                if (packet.contains(IpV4Packet.class)) {
                    IpV4Packet ip = packet.get(IpV4Packet.class);
                    String srcIp = ip.getHeader().getSrcAddr().getHostAddress();
                    String dstIp = ip.getHeader().getDstAddr().getHostAddress();
                    String timeStr = new SimpleDateFormat("HH:mm:ss").format(new Date());

                    if (!whitelistedIp.isEmpty() && srcIp.equals(whitelistedIp)) {
                        return;
                    }

                    // 1. KIỂM TRA ICMP (PING) VỚI DYNAMIC RULE ENGINE
                    if (packet.contains(IcmpV4CommonPacket.class)) {
                        sendTrafficLog(srcIp, dstIp, 0, 0, "ICMP Echo", timeStr);

                        int icmpCount = icmpCounts.computeIfAbsent(srcIp, k -> new AtomicInteger(0)).incrementAndGet();

                        // Gọi RuleService để check
                        RuleModel matchedRule = ruleService.matchRule("ICMP", "ANY", icmpCount);
                        if (matchedRule != null) {
                            sendAlert(matchedRule.getName(), srcIp, 0, icmpCount, timeStr, matchedRule.getSeverity());
                        }
                    }

                    // 2. KIỂM TRA TCP (SYN / PORT SCAN) VỚI DYNAMIC RULE ENGINE
                    if (packet.contains(TcpPacket.class)) {
                        TcpPacket tcp = packet.get(TcpPacket.class);

                        int srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                        int dstPort = tcp.getHeader().getDstPort().valueAsInt();
                        boolean isSyn = tcp.getHeader().getSyn();
                        boolean isAck = tcp.getHeader().getAck();

                        sendTrafficLog(srcIp, dstIp, srcPort, dstPort, String.format("SYN=%b ACK=%b", isSyn, isAck), timeStr);

                        // Quét cổng
                        portScanTracker.computeIfAbsent(srcIp, k -> ConcurrentHashMap.newKeySet()).add(dstPort);
                        int uniquePorts = portScanTracker.get(srcIp).size();
                        RuleModel scanRule = ruleService.matchRule("TCP", "ANY", uniquePorts);
                        if (scanRule != null) {
                           sendAlert(scanRule.getName(), srcIp, dstPort, uniquePorts, timeStr, scanRule.getSeverity());
                        }

                        // SYN Flood
                        if (isSyn && !isAck) {
                            int count = synCounts.computeIfAbsent(srcIp, k -> new AtomicInteger(0)).incrementAndGet();
                            RuleModel synRule = ruleService.matchRule("TCP", "SYN", count);
                            if (synRule != null) {
                                sendAlert(synRule.getName(), srcIp, dstPort, count, timeStr, synRule.getSeverity());
                            }
                        }
                    }
                }
            };

            currentHandle.loop(-1, listener);
        } catch (Exception e) {
            System.err.println("Sniffer Stopped: " + e.getMessage());
        }
    }

    private void sendTrafficLog(String srcIp, String dstIp, int srcPort, int dstPort, String flags, String timeStr) {
        Map<String, Object> trafficData = new HashMap<>();
        trafficData.put("srcIp", srcIp);
        trafficData.put("dstIp", dstIp);
        trafficData.put("srcPort", srcPort);
        trafficData.put("dstPort", dstPort);
        trafficData.put("flags", flags);
        trafficData.put("time", timeStr);
        messagingTemplate.convertAndSend("/topic/traffic", trafficData);
    }

    private void sendAlert(String title, String srcIp, int dstPort, int count, String timeStr, String severity) {
        Map<String, Object> alert = new HashMap<>();
        alert.put("title", title);
        alert.put("srcIp", srcIp);
        alert.put("dstPort", dstPort);
        alert.put("count", count);
        alert.put("time", timeStr);
        alert.put("severity", severity);
        messagingTemplate.convertAndSend("/topic/alerts", alert);
    }

    private void startResetScheduler() {
        Thread t = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                    synCounts.clear();
                    icmpCounts.clear();
                    portScanTracker.clear();
                } catch (InterruptedException e) { break; }
            }
        });
        t.setDaemon(true);
        t.start();
    }
}