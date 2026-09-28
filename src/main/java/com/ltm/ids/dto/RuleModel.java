package com.ltm.ids.dto;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "rules")
public class RuleModel {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String name;
    private String proto;      // TCP, UDP, ICMP
    private String flags;      // SYN, ACK, ANY
    private int threshold;     // số gói / giây
    private String severity;   // CRITICAL, HIGH, MEDIUM

    public RuleModel() {}

    public RuleModel(String name, String proto, String flags, int threshold, String severity) {
        this.name = name;
        this.proto = proto;
        this.flags = flags;
        this.threshold = threshold;
        this.severity = severity;
    }

    // Getters và Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getProto() { return proto; }
    public void setProto(String proto) { this.proto = proto; }
    public String getFlags() { return flags; }
    public void setFlags(String flags) { this.flags = flags; }
    public int getThreshold() { return threshold; }
    public void setThreshold(int threshold) { this.threshold = threshold; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
}