package com.alertme.sistema_alertme.repository;

import com.alertme.sistema_alertme.model.SmsLinks;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SmsRepository extends JpaRepository<SmsLinks, Long> {
}