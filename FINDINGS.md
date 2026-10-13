# Vulnerability Findings — Lerrica Jeremy Torreno \& Mariella Janine Sola

There are **6** security bugs planted in `app/main.py`. Fill one row per bug.

|#|OWASP 2025 code \& name|Where (route / line)|How an attacker abuses it|Your fix (1 line)|
|-|-|-|-|-|
|1  |A01 - Broken Access Control|GET /notes/{note\_id} - get\_notes{}|Attackers can access other users' private notes by changing the note ID because the system does not check ownership.|Verify that the requested note belongs to the logged-in user before returning it|
|2 |A02 - Security Misconfiguration|SECRET\_KEY, CORS middleware, and handle\_everything()|Hardcoded secrets, unrestricted CORS, and detailed error messages can expose sensitive system information.|Store secrets in environment variables, restrict CORS, and hide detailed errors.|
|3 |A04 - Cryptographic Failures|init\_db(), POST /register, and GET /admin/users|Passwords are stored in plain text, allowing attackers to steal user credentials if they gain access to the database or user records.|Hash passwords using PBKDF2 with a unique salt and prevent passwords from being exposed.|
|4 |A05 - Injection|POST /login — SQL query using an f-string|Attackers can enter malicious SQL code in the username field to manipulate the database query.|Use parameterized SQL queries instead of f-strings.|
|5 |A07 - Authentication Failures|POST /login and current\_user()|Tokens are predictable user IDs that never expire, allowing attackers to impersonate other users. Different login errors also reveal whether accounts exist.|Use signed, expiring tokens and generic login error messages.|
|6 |A10 - Exceptional Conditions|GET /admin/users — list\_all\_users()|The "try-except" block ignores permission errors, allowing unauthorized users to access admin-only information.|Remove the exception bypass and ensure only authenticated admins can access the route.|

## Reflection (3–4 sentences)

Which bug would do the most damage in a real app, and why?

I think the A10 - Mishandling of Exceptional Conditions is the most dangerous vulnerability because it allows unauthorized users to access admin-only information. The system ignores permission errors instead of denying access, which exposes sensitive user data. Since passwords are also stored in plain text, attackers could potentially steal login credentials. This can be prevented by properly handling authorization errors and blocking unauthorized requests. 

