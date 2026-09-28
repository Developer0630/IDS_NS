package com.ltm.ids.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ltm.ids.dto.RuleModel;

@Repository
public interface RuleRepository extends JpaRepository<RuleModel, Long> {
}