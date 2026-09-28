package com.ltm.ids.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ltm.ids.dto.RuleModel;
import com.ltm.ids.repository.RuleRepository;

import jakarta.annotation.PostConstruct;

@Service
public class RuleService {

    @Autowired
    private RuleRepository ruleRepository;

    @PostConstruct
    public void init() {
        // Tự động khởi tạo dữ liệu mẫu vào DB nếu bảng đang trống
        if (ruleRepository.count() == 0) {
            ruleRepository.save(new RuleModel("SYN Flood Attack", "TCP", "SYN", 10, "CRITICAL"));
            ruleRepository.save(new RuleModel("Port Scanning Behavior", "TCP", "ANY", 20, "MEDIUM"));
            ruleRepository.save(new RuleModel("Kiểm tra ICMP Ping Flood", "ICMP", "ANY", 1, "CRITICAL"));
            System.out.println("✅ [DATABASE] Khởi tạo các Rule mặc định vào DB thành công.");
        }
    }

    public List<RuleModel> getAllRules() {
        return ruleRepository.findAll();
    }

    public void addRule(RuleModel rule) {
        RuleModel saved = ruleRepository.save(rule);
        System.out.println("✅ [DATABASE STORED] " + saved.getName() + " | Proto: " + saved.getProto() + " | Threshold: " + saved.getThreshold());
    }

    public boolean deleteRule(Long id) {
        if (ruleRepository.existsById(id)) {
            ruleRepository.deleteById(id);
            return true;
        }
        return false;
    }

    public RuleModel matchRule(String proto, String flags, int count) {
        List<RuleModel> rules = ruleRepository.findAll();
        for (RuleModel rule : rules) {
            boolean protoMatch = rule.getProto().equalsIgnoreCase("ANY") || rule.getProto().equalsIgnoreCase(proto);
            boolean flagMatch = rule.getFlags().equalsIgnoreCase("ANY") || flags.contains(rule.getFlags());

            if (protoMatch && flagMatch && count >= rule.getThreshold()) {
                return rule;
            }
        }
        return null;
    }
}