package com.example.employee.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "employees")
@Data
public class Employee {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String name;
    private String email;
    private String department;

    @Column(name = "custom_tenant_id")
    private String customTenantId;

    @Column(name = "internal_code")
    private String internalCode;

    @Column(name = "profile_path")
    private String profilePicturePath;

    @OneToMany(mappedBy = "employee", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<EmployeeDocument> documents = new ArrayList<>();
}
