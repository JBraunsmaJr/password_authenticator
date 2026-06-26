# Desktop Password Authenticator and MFA Tool 

Enable multi-factor authentication and securely store usernames and passwords.

Strong passwords aren't enough. Use Authenticator to enable multi-factor authentication across all your online accounts and applications. 

The app is open source.

I just started this project. Please try out and test at your own risk; the program is still very much BETA.

The password is inside the encrypted ciphertext and cannot be read without:

The master password.
Deriving the key from the master password.
Decrypting the vault's data encryption key (DEK).
Decrypting the ciphertext with AES-256-GCM.

Everything in the database is encrypted. 

I am looking to add more features

- Dark mode and light mode.
- Service logos (Google, Microsoft, GitHub, Steam, Discord, etc.).
- QR code import from screenshots.
- Camera/webcam QR scanner.
- Password generator.
- Automatic database backups.
- Windows installer and executable.
- Mac pkg or dmg
- Auto-lock after inactivity.
- Sorting and filtering.
- Chrome Extension
- biometric unlocking (Windows Hello) / TouchID
- Logging
- Secure Attachments
- hotkey support
- ssh key storage
