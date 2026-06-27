<img width="357" height="327" alt="NxTPass-Logo" src="https://github.com/user-attachments/assets/9d7e3dbe-ccc7-4981-85c3-9047a82d08d5" />

## Desktop Password Authenticator and MFA Tool 

Enable multi-factor authentication and securely store usernames and passwords. Strong passwords aren't enough. Use Authenticator to enable multi-factor authentication across all your online accounts and applications. 

The app is open source.

I just started this project. Please try out and test at your own risk; the program is still very much BETA.

The password is inside the encrypted ciphertext and cannot be read without:

The master password.
Deriving the key from the master password.
Decrypting the vault's data encryption key (DEK).
Decrypting the ciphertext with AES-256-GCM.

Everything in the database is encrypted. Even if someone steals your database, they cannot simply read the master password. This key is never stored.

I am looking to add more features

- Dark mode and light mode.
- Service logos (Google, Microsoft, GitHub, Steam, Discord, etc.).
- QR code import from screenshots.
- Camera/webcam QR scanner.
- Password generator.
- Automatic database backups.
- Windows installer and executable.
- Mac pkg or dmg
- Sorting and filtering.
- Chrome Extension
- biometric unlocking (Windows Hello) / TouchID
- Logging
- Secure Attachments
- hotkey support
- ssh key storage

<img width="464" height="919" alt="create-vault" src="https://github.com/user-attachments/assets/23108817-b125-45a1-a4d5-dcb8f66c387b" />
<img width="370" height="471" alt="vault-login" src="https://github.com/user-attachments/assets/25f16aed-9e7c-41eb-ad93-c9c196150111" />
<img width="1038" height="676" alt="codes" src="https://github.com/user-attachments/assets/4ae621a4-00c8-4b26-b85f-8512d3664078" />
<img width="1053" height="687" alt="add-code" src="https://github.com/user-attachments/assets/b2a87820-af7a-4b3f-9339-faf91731f80b" />


