export const firestoreRules = `rules_version = '2';
service cloud.firestore {
    match /databases/{database}/documents {
        function isAuth() { return request.auth != null; }
        // NOTE: Make sure the UID below is replaced with your actual Owner UID
        function isOwner() { return isAuth() && request.auth.uid == "wXBFgqsr3gcAjFkgpn2UcHmEF6M2"; }
        function isUser(userId) { return isAuth() && request.auth.uid == userId; }

        // Users: A user can only access their own profile.
        match /users/{userId} {
            allow create: if isUser(userId);
            // Allow read/update/delete only if owner OR the user is the userId
            allow read, update, delete: if isOwner() || isUser(userId);
            allow list: if isOwner();
        }

        // Messages: Allow any authenticated user to create a message, but only the owner can read them.
        match /messages/{messageId} {
            allow create: if isAuth(); 
            allow read: if isOwner();
        }

        // Orders: Allow any authenticated user to create an order, and read only their own orders.
        match /orders/{orderId} {
            allow create: if isAuth(); 
            // FIX: Allows user to read if owner OR if the order's UID matches the current user's UID.
            allow read: if isOwner() || (isAuth() && resource.data.uid == request.auth.uid);
            // Only the owner/admin can update/delete the order status/details
            allow write: if isOwner(); 
        }

        // Activities/logs: only owner (server/admin) can read/write
        match /activities/{doc=**} {
            allow read, write: if isOwner();
        }

        // Default: deny all except owner
        match /{document=**} {
            allow read, write: if isOwner();
        }
    }
}`;
