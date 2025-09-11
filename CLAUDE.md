# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Rust workspace project called "podb-poc" - a proof-of-concept for a Persistent Ordered Database (PODB) system. The project uses file-based storage with JSON serialization and automatic indexing.

## Architecture

**Workspace Structure**: 
- `lib/` - Core library implementing file-based state management with indexed JSON storage
- `client/` - Client application (currently minimal)  
- `server/` - Server application (currently minimal)

**Core Functionality**: The `lib` crate provides `FileState` - a file-based state management system that:
- Stores indexed JSON objects in JSONL format
- Supports append-only operations with automatic indexing
- Handles generic serializable data types
- Provides comprehensive error handling

## Development Commands

**Building and Testing**:
- `cargo build` - Build all workspace members
- `cargo check` - Quick compile check  
- `cargo test` - Run all tests (tests are in `lib/src/lib.rs`)
- `cargo test -p lib` - Run tests only in the lib crate

**Running Applications**:
- `cargo run --bin client` - Run the client application
- `cargo run --bin server` - Run the server application

**Code Quality**:
- `cargo fmt` - Format code
- `cargo clippy` - Run linting

## Code Conventions

- Uses Rust 2024 edition with standard naming conventions
- Comprehensive error handling with custom error enums and `From` trait implementations
- Serde for JSON serialization with derive macros
- Unit tests in `#[cfg(test)]` modules using temporary files (`/tmp/test_*` pattern)
- Public APIs clearly marked, helper methods kept private

## Task Completion Checklist

When completing tasks:
1. Run `cargo check` to ensure compilation
2. Run `cargo test` to verify all tests pass
3. Add unit tests for new functionality
4. Ensure `cargo build` succeeds
5. Test relevant binaries with `cargo run --bin <name>`