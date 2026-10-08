# Security Vulnerability Advisory: Insecure Email Update Logic

## Overview
This repository contains a detailed security vulnerability report regarding an **Insecure Email Update Logic** flaw that allows a user/attacker to change their registered email address without re-authenticating with their current password.

* **Vulnerability Type:** Broken Authentication / Missing Re-Authentication
* **Endpoint:** `POST /public/customer/account/profile/edit`
* **Affected Component:** `packages/Webkul/Shop/src/Http/Controllers/Customer/CustomerController.php`
* **Severity:** Medium / High

---

## Proof of Concept (PoC) Video
You can find the demonstration video for this vulnerability below:

🎥 **[Watch / Download PoC Video (poc.mp4)](https://github.com/user-attachments/assets/00a10e63-d3c1-470e-a264-bead51aed4a2)**

*(Place your recorded video file named `poc.mp4` in the root of this folder or embed it using the link above.)*

---

## Vulnerability Details

### Preconditions
* The target user must have an active, authenticated session on the customer portal.
* An unauthorized user or attacker has temporary access to the victim's active session (e.g., via a shared computer, unattended device, or client-side script execution).
* The application allows profile updates via the endpoint: `POST http://<base_url>/public/customer/account/profile/edit`.

---

### Issue Description
The customer profile update functionality allows users to change their registered email address without requiring them to enter their current password.

When a logged-in customer navigates to their profile, updates only the email address field, and leaves the password fields blank, the application updates the email in the database directly. Furthermore, the `is_verified` status incorrectly remains unchanged (`1`), bypassing proper re-authentication controls.

---

### Steps to Reproduce
1. **Login** to the customer portal using valid credentials.
2. Navigate to the **Account Profile** section (`GET /customer/account/profile/edit`).
3. Enter a **new email address** while leaving all password fields completely blank.
4. Click **Submit** to save changes (`POST /customer/account/profile/edit`).
5. Run the database query to check status:
   ```sql
   SELECT id, first_name, email, is_verified FROM customers;
   ```

---

### Expected Result
* The application should **strictly require** the user to input their **current password** whenever sensitive attributes (such as the email address) are modified.
* If no current password is provided, or if it is incorrect, the profile update should be blocked, and an error message should be displayed.
* If the email is successfully changed, the `is_verified` status should be reset to `0` until the user re-verifies the new email address.

---

### Actual Result
* The email address is successfully updated in the database without any password prompt or verification.
* The `is_verified` flag remains set to `1`, treating the unconfirmed new email as already verified.
* An attacker can successfully change the account's login identifier using only an active session.

---

### Vulnerable Code Location (`CustomerController.php`)
```php
if (! empty($data['current_password'])) {
    if (Hash::check($data['current_password'], auth()->guard('customer')->user()->password)) {
        $isPasswordChanged = true;
        $data['password'] = bcrypt($data['new_password']);
    } else {
        return redirect()->back();
    }
} else {
    unset($data['new_password']);
}

$this->customerRepository->update($data, auth()->guard('customer')->user()->id);
```

---

### Security & Business Impact
* **Account Compromise:** An attacker with temporary session access can hijack the account by changing its primary identifier (email) permanently.
* **Lack of Re-verification:** Critical account modifications lack defense-in-depth security controls.

---

### Defensive Remediation
Ensure that whenever a sensitive attribute like the **email address** is modified, providing the `current_password` is made strictly mandatory, and the verification flag is reset:

```diff
--- CustomerController.php.vulnerable
+++ CustomerController.php.secure
@@ -10,6 +10,14 @@
+        // Enforce re-authentication when email is changed
+        if (isset($data['email']) && $data['email'] !== auth()->guard('customer')->user()->email) {
+            if (empty($data['current_password']) || ! Hash::check($data['current_password'], auth()->guard('customer')->user()->password)) {
+                session()->flash('warning', trans('shop::app.customers.account.profile.index.unmatched'));
+                return redirect()->back();
+            }
+            $data['is_verified'] = 0; // Reset verification status
+        }
+
         if (! empty($data['current_password'])) {
             if (Hash::check($data['current_password'], auth()->guard('customer')->user()->password)) {
                 $isPasswordChanged = true;
                 $data['password'] = bcrypt($data['new_password']);
             } else {
                 return redirect()->back();
             }
         } else {
             unset($data['new_password']);
         }
         
         $this->customerRepository->update($data, auth()->guard('customer')->user()->id);
```
