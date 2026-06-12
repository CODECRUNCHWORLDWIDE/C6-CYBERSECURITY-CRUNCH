#!/bin/bash

# Step 1: Generate AES Key and Save to File
echo "Generating AES Key..."
echo "SecretKey123" > aes_key.txt
echo "AES Key (secret key) saved to aes_key.txt"

# Step 2: Generate RSA Private and Public Keys (2048 bits)
echo "Generating RSA Private and Public Key Pair..."
openssl genpkey -algorithm RSA -out rsa_private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in rsa_private_key.pem -out rsa_public_key.pem
cat rsa_private_key.pem rsa_public_key.pem > rsa_keypair.pem
echo "RSA key pair saved to rsa_keypair.pem"

# Step 3: Create a Plaintext Message (For AES Encryption)
echo "Creating plaintext message for AES encryption..."
echo "This is your first clue!" > message.txt
echo "Message saved to message.txt"

# Step 4: AES Encrypt the Message (with the generated AES key)
echo "Encrypting message using AES..."
openssl enc -aes-256-cbc -in message.txt -out message.enc -pass file:./aes_key.txt
echo "Encrypted message saved to message.enc"

# Step 5: Create a Message for RSA Encryption
echo "Creating plaintext message for RSA encryption..."
message="Next clue: SHA256 hash your name!"
echo "$message" > rsa_message.txt
echo "RSA message saved to rsa_message.txt"

# Step 6: RSA Encrypt the Message (with the public key)
echo "Encrypting message using RSA (with public key)..."
openssl rsautl -encrypt -inkey rsa_public_key.pem -pubin -in rsa_message.txt -out rsa_message.enc
echo "RSA encrypted message saved to rsa_message.enc"

# Step 7: Create Hashable Message for MD5 and SHA256
echo "Creating messages for MD5 and SHA256 hashing..."
echo "Find your first clue!" > hashed_message.txt
echo "securityrocks" > sha256_message.txt
echo "Hashable messages saved to hashed_message.txt and sha256_message.txt"

# Step 8: Calculate MD5 Hash of the 'hashed_message.txt'
echo "Calculating MD5 hash for 'hashed_message.txt'..."
md5sum hashed_message.txt | awk '{ print $1 }' > md5_hash.txt
echo "MD5 hash saved to md5_hash.txt"

# Step 9: Calculate SHA256 Hash of the 'sha256_message.txt'
echo "Calculating SHA256 hash for 'sha256_message.txt'..."
sha256sum sha256_message.txt | awk '{ print $1 }' > sha256_hash.txt
echo "SHA256 hash saved to sha256_hash.txt"

# Step 10: Create the Challenge Script (challenge.sh)
echo "Creating the challenge script..."
cat > challenge.sh <<EOL
#!/bin/bash

echo "Welcome to the Cryptography Challenge!\n"

# AES Challenge
echo "AES Challenge: Decrypt the following ciphertext using AES with the provided key."
echo "Ciphertext (AES encrypted):"
cat message.enc

echo -n "\nProvide your AES Decrypted Message: "
read aes_decrypted_message

correct_aes="This is your first clue!"
if [ "\$aes_decrypted_message" == "\$correct_aes" ]; then
    echo "AES Challenge Completed Successfully!"
else
    echo "Incorrect! Try again."
fi

# RSA Challenge
echo -e "\nRSA Challenge: Use the private key to decrypt the following message."
cat rsa_message.enc

echo -n "\nProvide your RSA Decrypted Message: "
read rsa_decrypted_message

correct_rsa="Next clue: SHA256 hash your name!"
if [ "\$rsa_decrypted_message" == "\$correct_rsa" ]; then
    echo "RSA Challenge Completed Successfully!"
else
    echo "Incorrect! Try again."
fi

# MD5 Hash Challenge
echo -e "\nMD5 Challenge: Find the MD5 hash of the message 'Find your first clue!'"
correct_md5=$(cat md5_hash.txt)
md5_hash=\$(md5sum hashed_message.txt | awk '{ print \$1 }')
echo "Your MD5 hash: \$md5_hash"

if [ "\$md5_hash" == "\$correct_md5" ]; then
    echo "MD5 Challenge Completed Successfully!"
else
    echo "Incorrect! Try again."
fi

# SHA256 Hash Challenge
echo -e "\nSHA256 Challenge: Find the SHA256 hash of the message 'securityrocks'"
correct_sha256=$(cat sha256_hash.txt)
sha256_hash=\$(sha256sum sha256_message.txt | awk '{ print \$1 }')
echo "Your SHA256 hash: \$sha256_hash"

if [ "\$sha256_hash" == "\$correct_sha256" ]; then
    echo "SHA256 Challenge Completed Successfully!"
else
    echo "Incorrect! Try again."
fi

echo -e "\nCongratulations on completing the cryptography challenge!"
EOL
chmod +x challenge.sh
echo "Challenge script created: challenge.sh"

# Final message
echo -e "\nAll files have been created successfully!"
echo "Run './challenge.sh' to begin the cryptography challenge."
