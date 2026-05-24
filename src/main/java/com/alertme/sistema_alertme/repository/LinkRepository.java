package com.alertme.sistema_alertme.repository;

import com.alertme.sistema_alertme.model.Links;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LinkRepository extends JpaRepository<Links, Long> {
    // JpaRepository já fornece métodos básicos como save, findAll, findById, delete, etc.
}