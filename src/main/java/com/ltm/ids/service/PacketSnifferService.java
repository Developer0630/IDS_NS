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

import jakarta.annotation.PostConstruct;

@Service
public class PacketSnifferService {

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    // Các tham số TCP/IP cấu hình từ Web Dashboard
    private String selectedDeviceName = "";
    private int targetPort = 0;             // 0: Tất cả các port, hoặc chỉ định (80, 443, 8080...)
    private int threshold = 10;              // Ngưỡng SYN/giây
    private String whitelistedIp = "";      // IP bỏ qua không cảnh báo
    private boolean isSniffing = false;

    private PcapHandle currentHandle;

    // Bộ đếm phát hiện các loại hình tấn công (Reset mỗi 1 giây)
    private final ConcurrentHashMap<String, AtomicInteger> synCounts = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, ConcurrentHashMap.KeySetView<Integer, Boolean>> portScanTracker = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, AtomicInteger> icmpCounts = new ConcurrentHashMap<>();

    @PostConstruct
    public void init() {
        startResetScheduler();
    }

    // Lấy danh sách các Card Mạng (Interfaces) gửi lên Web
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

    // Hàm cập nhật Cấu hình TCP/IP từ Web và Khởi chạy lại Sniffer
    public synchronized String updateConfigAndStart(int devIndex, int port, int newThreshold, String ignoreIp) {
        try {
            stopSniffing(); // Dừng tiến trình cũ nếu đang chạy

            List<PcapNetworkInterface> allDevs = Pcaps.findAllDevs();
            if (devIndex < 0 || devIndex >= allDevs.size()) return "Card mạng không hợp lệ!";

            PcapNetworkInterface device = allDevs.get(devIndex);
            this.selectedDeviceName = device.getDescription();
            this.targetPort = port;
            this.threshold = newThreshold;
            this.whitelistedIp = ignoreIp.trim();

            // Chạy Sniffer trên Thread mới với tham số TCP/IP mới
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
            
            // Thiết lập Filter ở tầng IP/TCP nếu người dùng chọn Port cụ thể
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

                    // Bỏ qua nếu IP trùng với Whitelist IP do người dùng cấu hình
                    if (!whitelistedIp.isEmpty() && srcIp.equals(whitelistedIp)) {
                        return;
                    }

                    // -------------------------------------------------------------
                    // 1. PHÁT HIỆN TẤN CÔNG ICMP FLOOD (PING FLOOD)
                    // -------------------------------------------------------------
                    if (packet.contains(IcmpV4CommonPacket.class)) {
                        sendTrafficLog(srcIp, dstIp, 0, 0, "ICMP Echo", timeStr);

                        int icmpCount = icmpCounts.computeIfAbsent(srcIp, k -> new AtomicInteger(0)).incrementAndGet();
                        if (icmpCount > threshold) {
                            sendAlert("Tấn công ICMP/Ping Flood", srcIp, 0, icmpCount, timeStr);
                        }
                    }

                    // -------------------------------------------------------------
                    // 2. PHÁT HIỆN XỬ LÝ GÓI TIN TCP (SYN FLOOD & PORT SCANNING)
                    // -------------------------------------------------------------
                    if (packet.contains(TcpPacket.class)) {
                        TcpPacket tcp = packet.get(TcpPacket.class);

                        int srcPort = tcp.getHeader().getSrcPort().valueAsInt();
                        int dstPort = tcp.getHeader().getDstPort().valueAsInt();
                        boolean isSyn = tcp.getHeader().getSyn();
                        boolean isAck = tcp.getHeader().getAck();

                        sendTrafficLog(srcIp, dstIp, srcPort, dstPort, String.format("SYN=%b ACK=%b", isSyn, isAck), timeStr);

                        // A. Kiểm tra Port Scanning (Quét nhiều Port khác nhau từ 1 IP)
                        portScanTracker.computeIfAbsent(srcIp, k -> ConcurrentHashMap.newKeySet()).add(dstPort);
                        int uniquePortsScanned = portScanTracker.get(srcIp).size();
                        if (uniquePortsScanned > 10) { // Ngưỡng: Quét hơn 10 ports/giây
                            sendAlert("Hành vi Quét Cổng (Port Scanning)", srcIp, dstPort, uniquePortsScanned, timeStr);
                        }

                        // B. Kiểm tra SYN Flood Attack
                        if (isSyn && !isAck) {
                            int count = synCounts.computeIfAbsent(srcIp, k -> new AtomicInteger(0)).incrementAndGet();
                            if (count > threshold) {
                                sendAlert("Tấn công DoS (SYN Flood)", srcIp, dstPort, count, timeStr);
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

    // Hàm phụ trợ gửi Log Traffic lên giao diện Web
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

    // Hàm phụ trợ gửi Alert Tấn công lên giao diện Web
    private void sendAlert(String title, String srcIp, int dstPort, int count, String timeStr) {
        Map<String, Object> alert = new HashMap<>();
        alert.put("title", title);
        alert.put("srcIp", srcIp);
        alert.put("dstPort", dstPort);
        alert.put("count", count);
        alert.put("time", timeStr);
        messagingTemplate.convertAndSend("/topic/alerts", alert);
    }

    // Thread tự động dọn dẹp (Reset) bộ đếm sau mỗi 1 giây
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