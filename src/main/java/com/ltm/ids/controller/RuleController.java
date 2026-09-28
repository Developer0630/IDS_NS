package com.ltm.ids.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ltm.ids.dto.RuleModel;
import com.ltm.ids.service.RuleService;

@RestController
@RequestMapping("/api/rules")
public class RuleController {

    @Autowired
    private RuleService ruleService;

    @GetMapping
    public List<RuleModel> getRules() {
        return ruleService.getAllRules();
    }

    @PostMapping("/add")
    public ResponseEntity<String> addRule(@RequestBody RuleModel rule) {
        ruleService.addRule(rule);
        return ResponseEntity.ok("RULE_ADDED");
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<String> deleteRule(@PathVariable Long id) {
        ruleService.deleteRule(id);
        return ResponseEntity.ok("RULE_DELETED");
    }
}