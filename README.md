# Summary
Credential service provides simple APIs to enable straight forward authentication and authorization, including:
- createUser
- deleteUser
- createRole
- deleteRole
- addRoleToUser
- authorize
- authenticate
- invalidate
- checkRole
- getAllRoles

# Features
It has thread safe ```Singleton``` class ```CredentialService``` that exposes all API and unified class ```ApiResult``` for API caller to parse returned result, which includes simple state identifier, payload data and message;

```ConcurrentHashMap``` is used to save user, role and token data to make sure of thread safe high concurrency;
Password is stored in encrypted format by using secured hash algorithm ```SHA-256``` and token will be encoded by ```Base64```;

Token cache table is created to avoid deserialize for better performance, LinkedHashMap is adopted for that purpose;

Expire threshold is a static constant in current version and could be move to property file for better flexibility;

Thorough test cases have been provided and the line coverage is more than 90%.

# Usage
The deliverable is a self-contained project that can easily open and run the tests in Intellij