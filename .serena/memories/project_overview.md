# Project Overview

This is a Rust workspace project called "podb-poc" (Proof of Concept for PODB) structured as a monorepo with three main components:

## Architecture
- **Workspace Structure**: Uses Cargo workspace with resolver "3" 
- **Components**: 
  - `lib/` - Core library with file-based state management
  - `client/` - Client application (currently minimal)
  - `server/` - Server application (currently minimal)

## Tech Stack
- **Language**: Rust (2024 edition)
- **Serialization**: serde with JSON support
- **File Format**: JSONL (JSON Lines) for data storage

## Core Functionality
The main functionality is implemented in the `lib` crate, which provides:
- `FileState` - A file-based state management system that stores indexed JSON objects
- Append-only file operations with automatic indexing
- Support for generic serializable data types
- Error handling for IO, serialization, and indexing issues

## Project Purpose
Based on the code structure, this appears to be a proof-of-concept for a Persistent Ordered Database (PODB) system that uses file-based storage with JSON serialization and automatic indexing.