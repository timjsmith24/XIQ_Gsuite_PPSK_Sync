# PCG API Script Notice – Release 25r3

### ⚠️ Important Update for PCG API Users

With the upcoming **25r3 release**, the PCG API will be updated to support **pagination**. This change aligns with how other APIs like PPSK operate, enabling you to retrieve users in pages (e.g., 100 users at a time).

#### What This Means for You

If you're using an existing script that interacts with the PCG API, **it will break** once 25r3 is deployed. The current script does not support the new pagination logic.

- By default, **only 10 users will be returned** in each API response if your script is not updated.
- This means your existing script may appear to work but will only process a subset of users, leading to incomplete results.

#### Required Action

A new version of the script (**v2.1.0**) will be released to support pagination. You will need to **upgrade to v2.1.0** to continue using the API successfully after the 25r3 update.

---

Stay tuned for the release announcement and updated usage instructions.