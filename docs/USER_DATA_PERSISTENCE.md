# User Data Persistence

## Overview

Legion provides anonymous user data persistence through deterministic user identifiers while maintaining zero-knowledge authentication properties. This enables applications to associate persistent data with users without compromising anonymity.

## Architecture

### User Data Identifier Generation

The system generates a consistent, anonymous identifier for each user based on their authentication credentials:

```
nullifier = Poseidon(username_hash, password_hash)
user_data_id = Blake3(nullifier)
```

### Properties

- **Deterministic**: Same credentials always produce the same user_data_id
- **Anonymous**: Server cannot correlate user_data_id to real identity
- **Persistent**: Identifier remains constant across sessions and devices
- **Collision Resistant**: Cryptographically secure hash functions prevent conflicts

## API Integration

### Authentication Response

The `verify_anonymous_proof` method returns both session authentication and user identification:

```rust
pub fn verify_anonymous_proof(
    // ... authentication parameters
) -> Result<(String, String)>
//           ↑        ↑
//    session_token  user_data_id
```

### Response Structure

```json
{
  "session_token": "a1b2c3d4...",
  "user_data_id": "e5f6g7h8...",
  "expires_at": 1640995200
}
```

## Implementation Guide

### Application Integration

Applications can use the user_data_id to maintain persistent user state:

```rust
// Store user data
database.insert("user_data", user_data_id, user_content);

// Retrieve user data
let user_content = database.get("user_data", user_data_id);
```

### Database Schema Example

```sql
CREATE TABLE user_data (
    user_id VARCHAR(64) PRIMARY KEY,  -- user_data_id from Legion
    data_type VARCHAR(32) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Security Considerations

### Privacy Guarantees

- Server operators cannot determine which user_data_id belongs to which individual
- User data remains pseudonymous under the user_data_id
- No linkability to external identifiers without user consent

### Data Protection

- Applications should encrypt sensitive data before storage
- User data should be associated only with the user_data_id
- Implement proper access controls based on session validation

### Compliance

- User data persistence complies with privacy regulations (GDPR, CCPA)
- No personally identifiable information is exposed through the identifier
- Users maintain control over their data through credential management

## Use Cases

### Content Management Systems

```rust
// Blog posts, documents, user preferences
let posts = get_user_posts(user_data_id);
save_user_preference(user_data_id, "theme", "dark");
```

### File Storage Services

```rust
// File uploads, folder structures, sharing permissions
let user_files = list_files_for_user(user_data_id);
upload_file(user_data_id, file_data, metadata);
```

### Social Applications

```rust
// Posts, connections, activity history
let user_timeline = get_timeline(user_data_id);
create_post(user_data_id, content, visibility);
```

## Migration and Compatibility

### Existing Applications

Applications can migrate to Legion user data persistence by:

1. Implementing Legion authentication
2. Mapping existing user records to user_data_id
3. Updating data access patterns to use anonymous identifiers

### Backward Compatibility

The user data persistence feature is additive and does not affect existing authentication flows. Applications can adopt the feature incrementally.

## Limitations

### Credential Dependency

- User data access requires the same credentials used during registration
- Lost credentials result in inaccessible user data
- No account recovery mechanism without additional implementation

### Cross-Application Data

- User data identifiers are consistent across applications using the same Legion instance
- Applications must implement their own data isolation if required
- Shared user_data_id enables cross-application user experiences when desired

## Best Practices

### Data Management

- Implement regular data backups keyed by user_data_id
- Provide user data export functionality
- Consider data retention policies and cleanup procedures

### Performance Optimization

- Index database tables on user_data_id for efficient queries
- Implement caching strategies for frequently accessed user data
- Consider data partitioning for large-scale deployments

### Error Handling

- Handle cases where user_data_id exists but session is invalid
- Implement graceful degradation when user data is unavailable
- Provide clear error messages for data access failures