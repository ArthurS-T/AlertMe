package com.alertme.sistema_alertme.repository;

import com.alertme.sistema_alertme.model.Links;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface LinkRepository extends JpaRepository<Links, Long> {
    
    Optional<Links> findByUrl(String url);
}