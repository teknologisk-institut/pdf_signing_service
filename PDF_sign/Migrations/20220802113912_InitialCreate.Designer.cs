﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using PDF_sign;

#nullable disable

namespace PDF_sign.Migrations
{
    [DbContext(typeof(SqlContext))]
    [Migration("20220802113912_InitialCreate")]
    partial class InitialCreate
    {
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "6.0.7");

            modelBuilder.Entity("PDF_sign.SqlAuth", b =>
                {
                    b.Property<string>("Name")
                        .HasColumnType("TEXT");

                    b.Property<string>("Password")
                        .HasColumnType("TEXT");

                    b.HasKey("Name");

                    b.ToTable("Auth");
                });

            modelBuilder.Entity("PDF_sign.SqlLog", b =>
                {
                    b.Property<long?>("Date")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("AppName")
                        .HasColumnType("TEXT");

                    b.Property<float?>("BottomMM")
                        .HasColumnType("REAL");

                    b.Property<string>("Contact")
                        .HasColumnType("TEXT");

                    b.Property<string>("EmployeeID")
                        .HasColumnType("TEXT");

                    b.Property<string>("FileHash")
                        .HasColumnType("TEXT");

                    b.Property<string>("FileName")
                        .HasColumnType("TEXT");

                    b.Property<string>("Language")
                        .HasColumnType("TEXT");

                    b.Property<float?>("LeftMM")
                        .HasColumnType("REAL");

                    b.Property<string>("Location")
                        .HasColumnType("TEXT");

                    b.Property<string>("Reason")
                        .HasColumnType("TEXT");

                    b.HasKey("Date");

                    b.ToTable("Logs");
                });
#pragma warning restore 612, 618
        }
    }
}