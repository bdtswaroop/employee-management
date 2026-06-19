package com.example.employee.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Data;

import java.time.Instant;

@Entity
@Table(name = "employee_documents")
@Data
public class EmployeeDocument {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String documentName;

    @Column(name = "document_path")
    private String documentPath;

    private String contentType;

    private Long sizeBytes;

    private Instant uploadedAt;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "employee_id")
    private Employee employee;
}
