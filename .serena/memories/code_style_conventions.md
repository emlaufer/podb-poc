# Code Style and Conventions

## General Rust Conventions
- Uses Rust 2024 edition
- Standard Rust naming conventions (snake_case for functions/variables, PascalCase for types)
- Comprehensive error handling with custom error types

## Code Structure Patterns

### Error Handling
- Custom error enums with descriptive variants
- `From` trait implementations for error conversion
- Result types for fallible operations

### Serialization
- Uses serde with derive macros for serialization/deserialization
- JSON format for data persistence
- Generic types with trait bounds for flexibility

### File I/O Patterns  
- Uses standard library file operations
- BufReader for efficient line-by-line reading
- OpenOptions for controlled file access

### Testing
- Unit tests in `#[cfg(test)]` modules
- Uses temporary files for testing file operations
- Comprehensive test coverage with setup/teardown

## Code Organization
- Public interfaces clearly marked with `pub`
- Helper methods kept private
- Logical grouping of related functionality in impl blocks