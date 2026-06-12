#!/bin/bash

echo "Welcome to the Cryptography Challenge!\n"

# AES Challenge
echo "AES Challenge: Decrypt the following ciphertext using AES with the provided key."
echo "Ciphertext (AES encrypted):"
cat message.enc

echo -n "\nProvide your AES Decrypted Message: "
read aes_decrypted_message

correct_aes="This is your first clue!"
if [ "$aes_decrypted_message" == "$correct_aes" ]; then
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
if [ "$rsa_decrypted_message" == "$correct_rsa" ]; then
    echo "RSA Challenge Completed Successfully!"
else
    echo "Incorrect! Try again."
fi

# MD5 Hash Challenge
echo -e "\nMD5 Challenge: Find the MD5 hash of the message 'Find your first clue!'"
correct_md5=c42cca8a3f5b0303aadc17e19276d781
md5_hash=$(md5sum hashed_message.txt | awk '{ print $1 }')
echo "Your MD5 hash: $md5_hash"

if [ "$md5_hash" == "$correct_md5" ]; then
    echo "MD5 Challenge Completed Successfully!"
else
    echo "Incorrect! Try again."
fi

# SHA256 Hash Challenge
echo -e "\nSHA256 Challenge: Find the SHA256 hash of the message 'securityrocks'"
correct_sha256=b68674ea1af26bbac44e92dc86e1c63a225386ccf02857ebae987d6acd138602
sha256_hash=$(sha256sum sha256_message.txt | awk '{ print $1 }')
echo "Your SHA256 hash: $sha256_hash"

if [ "$sha256_hash" == "$correct_sha256" ]; then
    echo "SHA256 Challenge Completed Successfully!"
else
    echo "Incorrect! Try again."
fi

echo -e "\nCongratulations on completing the cryptography challenge!"
